import { describe, expect, it, vi } from "vitest";
import { lookupExternalThreatIntelligence } from "../src/external-threat-intel";

const env = {
  GOOGLE_SAFE_BROWSING_API_KEY: "test-google",
  URLHAUS_AUTH_KEY: "test-urlhaus",
  PHISHTANK_API_KEY: "test-phishtank",
  VIRUSTOTAL_API_KEY: "test-virustotal"
};

describe("optional multi-source threat intelligence", () => {
  it("reports all providers as not configured when no credentials exist", async () => {
    const fetcher = vi.fn();
    const result = await lookupExternalThreatIntelligence({}, "https://example.com/login", fetcher as any);
    expect(result.status).toBe("not_configured");
    expect(result.providers).toHaveLength(4);
    expect(result.providers.every(provider => provider.status === "not_configured")).toBe(true);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("normalizes successful provider results and distinguishes authoritative matches from VT consensus", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("safebrowsing.googleapis.com")) {
        return new Response(JSON.stringify({ matches: [{ threatType: "SOCIAL_ENGINEERING" }] }), { status: 200 });
      }
      if (url.includes("urlhaus-api.abuse.ch")) {
        return new Response(JSON.stringify({ query_status: "ok", url_status: "online" }), { status: 200 });
      }
      if (url.includes("checkurl.phishtank.com")) {
        return new Response(JSON.stringify({ results: { in_database: true, verified: true, valid: true } }), { status: 200 });
      }
      if (url.includes("virustotal.com")) {
        return new Response(JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 5 } } } }), { status: 200 });
      }
      return new Response("unexpected provider", { status: 404 });
    });

    const result = await lookupExternalThreatIntelligence(env, "https://example.com/login", fetcher as any);
    expect(result.status).toBe("available");
    expect(result.providers).toHaveLength(4);
    expect(result.providers.filter(provider => provider.matched)).toHaveLength(4);
    expect(result.providers.filter(provider => provider.confirmed)).toHaveLength(3);
    expect(result.findings).toHaveLength(4);
    expect(result.providers.find(provider => provider.source === "virustotal")?.confirmed).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(4);
  });

  it("keeps provider failures separate and reports partial coverage", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("safebrowsing.googleapis.com")) {
        return new Response(JSON.stringify({ matches: [] }), { status: 200 });
      }
      return new Response("provider unavailable", { status: 503 });
    });
    const result = await lookupExternalThreatIntelligence(
      { GOOGLE_SAFE_BROWSING_API_KEY: "test-google", URLHAUS_AUTH_KEY: "test-urlhaus" },
      "https://example.com",
      fetcher as any
    );
    expect(result.status).toBe("partial");
    expect(result.providers.find(provider => provider.source === "google_safe_browsing")?.status).toBe("ok");
    expect(result.providers.find(provider => provider.source === "urlhaus")?.status).toBe("unavailable");
    expect(result.providers.find(provider => provider.source === "phishtank")?.status).toBe("not_configured");
  });

  it("uses only fixed provider endpoints and strips credentials, query strings and fragments", async () => {
    const urls: string[] = [];
    const requestBodies: string[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      urls.push(String(input));
      if (typeof init?.body === "string") requestBodies.push(init.body);
      return new Response(JSON.stringify({ matches: [] }), { status: 200 });
    });
    await lookupExternalThreatIntelligence({ GOOGLE_SAFE_BROWSING_API_KEY: "test-google" }, "https://user:pass@example.com/path?token=private#fragment", fetcher as any);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toContain("safebrowsing.googleapis.com");
    expect(urls[0]).not.toContain("example.com");
    expect(requestBodies.join(" ")).toContain("https%3A%2F%2Fexample.com%2Fpath");
    expect(requestBodies.join(" ")).not.toContain("private");
  });
});
