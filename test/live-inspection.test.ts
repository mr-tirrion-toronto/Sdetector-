import { describe, expect, it } from "vitest";
import { inspectLiveDomain } from "../src/live-inspection";

describe("inspectLiveDomain", () => {
  it("collects DNS, certificate transparency, RDAP and page-content signals", async () => {
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url === "https://tools.trustico.com/api/chain/analyze-url") {
        return Response.json({ success: true, data: { certificate: { subject: { commonName: "example.com" }, issuer: { commonName: "Example CA" }, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", isExpired: false, daysUntilExpiry: 46, signatureAlgorithm: "ecdsa-with-SHA256", publicKey: { algorithm: "ECC", bits: 256 } }, chain: [{},{}], validation: { chainComplete: true, problems: [] } } });
      }
      if (url.startsWith("https://cloudflare-dns.com/")) {
        return Response.json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34", TTL: 300 }] });
      }
      if (url.startsWith("https://crt.sh/")) {
        return Response.json([{ not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z", issuer_name: "Example CA", common_name: "example.com" }]);
      }
      if (url.startsWith("https://rdap.org/")) {
        return Response.json({ events: [{ eventAction: "registration", eventDate: "2026-01-01T00:00:00Z" }], entities: [] });
      }
      if (url.startsWith("https://r.jina.ai/")) {
        return Response.json({ code: 200, data: { title: "Account verification", url: "https://example.com/login", content: '<form><input type="password"></form> Verify your account immediately' } });
      }
      throw new Error("Unexpected provider URL");
    };
    const result = await inspectLiveDomain("https://example.com/login?token=private", "example.com", fetcher);
    expect(result.dns.status).toBe("available");
    expect(result.dns.data?.records[0]?.value).toBe("93.184.216.34");
    expect(result.certificateTransparency.status).toBe("available");
    expect(result.tls.status).toBe("available");
    expect(result.tls.data?.chainComplete).toBe(true);
    expect(result.registration.status).toBe("available");
    expect(result.websiteContent.status).toBe("available");
    expect(result.websiteContent.data?.indicators).toContain("password_input");
    expect(result.websiteContent.data?.indicators).toContain("urgent_account_pressure");
    expect(result.findings.map(f => f.code)).toContain("LIVE_PASSWORD_INPUT");
  });

  it("does not send query strings to the external content reader", async () => {
    let requested = "";
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url.startsWith("https://r.jina.ai/")) requested = url;
      if (url.startsWith("https://cloudflare-dns.com/")) return Response.json({ Status: 0, Answer: [] });
      if (url.startsWith("https://crt.sh/")) return Response.json([]);
      if (url.startsWith("https://rdap.org/")) return new Response("not found", { status: 404 });
      return Response.json({ code: 200, data: { title: "Example", url: "https://example.com/", content: "Ordinary page" } });
    };
    await inspectLiveDomain("https://example.com/path?token=secret#fragment", "example.com", fetcher);
    expect(requested).toContain("/path");
    expect(requested).not.toContain("token");
    expect(requested).not.toContain("secret");
    expect(requested).not.toContain("fragment");
  });
});
