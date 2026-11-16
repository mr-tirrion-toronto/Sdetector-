import { describe, expect, it } from "vitest";
import { inspectLiveDomain } from "../src/live-inspection";

function providers(options: { firecrawlStatus?: number; address?: string; sans?: string[]; ctNames?: string[]; pageHtml?: string; pageTitle?: string } = {}) {
  let requestedUrl = "";
  let requestedRdapUrl = "";
  let requestedCtDomain = "";
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url === "https://tools.trustico.com/api/chain/analyze-url") {
      return Response.json({ success: true, data: { certificate: {
        subject: { commonName: "example.com" }, issuer: { commonName: "Example CA" },
        notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z",
        isExpired: false, daysUntilExpiry: 46, signatureAlgorithm: "ecdsa-with-SHA256",
        publicKey: { algorithm: "ECC", bits: 256 }, extensions: { subjectAltName: (options.sans ?? ["example.com"]).map(value => ({ type: "dns", value })) }
      }, chain: [{}, {}], validation: { chainComplete: true, problems: [] } } });
    }
    if (url.startsWith("https://cloudflare-dns.com/")) {
      const type = new URL(url).searchParams.get("type");
      return Response.json({ Status: 0, Answer: type === "A"
        ? [{ type: 1, data: options.address ?? "93.184.216.34", TTL: 300 }]
        : [] });
    }
    if (url.startsWith("https://api.certspotter.com/v1/issuances")) {
      requestedCtDomain = new URL(url).searchParams.get("domain") ?? "";
      return Response.json([{ not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z", dns_names: options.ctNames ?? ["example.com"] }]);
    }
    if (url === "https://data.iana.org/rdap/dns.json") {
      return Response.json({ services: [[["com"], ["https://rdap.verisign.com/com/v1/"]]] });
    }
    if (url.startsWith("https://rdap.verisign.com/com/v1/domain/")) {
      requestedRdapUrl = url;
      return Response.json({ events: [{ eventAction: "registration", eventDate: "2026-01-01T00:00:00Z" }], entities: [] });
    }
    if (url === "https://api.firecrawl.dev/v2/scrape") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      requestedUrl = body.url;
      if (options.firecrawlStatus && options.firecrawlStatus !== 200) {
        return Response.json({ error: "rate limited" }, { status: options.firecrawlStatus });
      }
      return Response.json({ success: true, data: {
        html: options.pageHtml ?? "<form><input type=\\"password\\"></form> Verify your account immediately",
        metadata: { title: options.pageTitle ?? "Account verification", url: body.url, statusCode: 200, contentType: "text/html" }
      } });
    }
    throw new Error("Unexpected provider URL: " + url);
  };
  return { fetcher, getRequestedUrl: () => requestedUrl, getRequestedRdapUrl: () => requestedRdapUrl, getRequestedCtDomain: () => requestedCtDomain };
}

describe("inspectLiveDomain", () => {
  it("collects live DNS, TLS, certificate transparency, RDAP and page-content signals", async () => {
    const mock = providers();
    const result = await inspectLiveDomain("https://example.com/login?token=private", "example.com", mock.fetcher);
    expect(result.dns.status).toBe("available");
    expect(result.dns.data?.records[0]?.value).toBe("93.184.216.34");
    expect(result.certificateTransparency.status).toBe("available");
    expect(result.tls.status).toBe("available");
    expect(result.tls.data?.chainComplete).toBe(true);
    expect(result.tls.data?.hostnameMatch).toBe(true);
    expect(result.tls.data?.subjectAltNames).toContain("example.com");
    expect(result.registration.status).toBe("available");
    expect(result.registration.data?.queriedDomain).toBe("example.com");
    expect(result.certificateTransparency.data?.found).toBe(true);
    expect(result.websiteContent.status).toBe("available");
    expect(result.websiteContent.data?.source).toBe("Firecrawl keyless scrape");
    expect(result.websiteContent.data?.indicators).toContain("password_input");
    expect(result.websiteContent.data?.indicators).toContain("form_detected");
    expect(result.websiteContent.data?.indicators).toContain("urgent_account_pressure");
    expect(result.findings.map(f => f.code)).toContain("LIVE_PASSWORD_INPUT");
    expect(mock.getRequestedUrl()).toBe("https://example.com/login");
  });


  it("detects a parked or for-sale domain instead of treating it as an operating business", async () => {
    const mock = providers({ pageHtml: "Buy this domain. This domain is parked.", pageTitle: "example.com - Resources and Information." });
    const result = await inspectLiveDomain("https://example.com/", "example.com", mock.fetcher);
    expect(result.websiteContent.data?.indicators).toContain("domain_parked_or_for_sale");
    expect(result.findings.map(f => f.code)).toContain("DOMAIN_PARKED_OR_FOR_SALE");
  });

  it("uses the registrable domain for RDAP and CT while validating TLS against the exact hostname", async () => {
    const mock = providers({ sans: ["*.toscrape.com"], ctNames: ["*.toscrape.com", "toscrape.com"] });
    const result = await inspectLiveDomain("https://quotes.toscrape.com/login", "quotes.toscrape.com", mock.fetcher);
    expect(result.registrableDomain).toBe("toscrape.com");
    expect(result.certificateTransparency.data?.queriedDomain).toBe("toscrape.com");
    expect(result.registration.data?.queriedDomain).toBe("toscrape.com");
    expect(mock.getRequestedRdapUrl()).toContain("/domain/toscrape.com");
    expect(mock.getRequestedCtDomain()).toBe("toscrape.com");
    expect(result.tls.data?.hostnameMatch).toBe(true);
    expect(result.findings.map(f => f.code)).not.toContain("TLS_HOSTNAME_MISMATCH");
  });

  it("raises a finding when the live TLS certificate SAN does not cover the hostname", async () => {
    const mock = providers({ sans: ["unrelated.example.net"] });
    const result = await inspectLiveDomain("https://example.com/", "example.com", mock.fetcher);
    expect(result.tls.data?.hostnameMatch).toBe(false);
    expect(result.findings.map(f => f.code)).toContain("TLS_HOSTNAME_MISMATCH");
  });

  it("does not forward query strings, fragments or credentials to the content provider", async () => {
    const mock = providers();
    await inspectLiveDomain("https://user:secret@example.com/path?token=private#fragment", "example.com", mock.fetcher);
    expect(mock.getRequestedUrl()).toBe("https://example.com/path");
    expect(mock.getRequestedUrl()).not.toContain("token");
    expect(mock.getRequestedUrl()).not.toContain("secret");
    expect(mock.getRequestedUrl()).not.toContain("fragment");
  });

  it("does not send pages whose DNS resolves to private addresses to the content provider", async () => {
    const mock = providers({ address: "127.0.0.1" });
    const result = await inspectLiveDomain("https://example.com/", "example.com", mock.fetcher);
    expect(result.websiteContent.status).toBe("unavailable");
    expect(result.websiteContent.errorCode).toBe("NO_VERIFIED_PUBLIC_ADDRESS");
    expect(mock.getRequestedUrl()).toBe("");
  });

  it("reports keyless content rate limits as unavailable, not a clean result", async () => {
    const mock = providers({ firecrawlStatus: 429 });
    const result = await inspectLiveDomain("https://example.com/", "example.com", mock.fetcher);
    expect(result.websiteContent.status).toBe("unavailable");
    expect(result.websiteContent.errorCode).toBe("FIRECRAWL_RATE_LIMITED");
  });
});
