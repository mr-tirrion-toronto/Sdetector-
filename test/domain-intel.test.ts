import { describe, expect, it, vi } from "vitest";
import { investigateDomain } from "../src/domain-intel";

describe("PhishDestroy domain investigation", () => {
  it("sends only the normalized hostname to the fixed provider endpoint", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      expect(url.origin).toBe("https://api.destroy.tools");
      expect(url.pathname).toBe("/v1/investigate");
      expect(url.searchParams.get("domain")).toBe("example.com");
      return Response.json({
        domain: "example.com",
        verdict: { status: "whitelisted", threat: false, note: "Reviewed" },
        assessment: null,
        infrastructure: { resolved_ips: ["93.184.216.34"], cloudflare: false },
        registration: { created: "1995-08-14", registrar: "Example Registrar", age_days: 10000 },
        checked_at: "2026-11-16T18:00:00Z"
      });
    });
    const result = await investigateDomain("EXAMPLE.COM.", fetcher);
    expect(result.status).toBe("available");
    expect(result.verdict?.status).toBe("whitelisted");
    expect(result.registration?.ageDays).toBe(10000);
  });

  it("treats rate limiting as unavailable intelligence, not a clean verdict", async () => {
    const fetcher = vi.fn(async () => new Response("{}", { status: 429 }));
    const result = await investigateDomain("example.com", fetcher);
    expect(result.status).toBe("rate_limited");
    expect(result.verdict).toBeNull();
  });

  it("rejects malformed hostnames without making a network request", async () => {
    const fetcher = vi.fn();
    const result = await investigateDomain("https://example.com/path", fetcher);
    expect(result.status).toBe("unavailable");
    expect(fetcher).not.toHaveBeenCalled();
  });
});
