import { describe, expect, it } from "vitest";
import { hashThreatUrl, lookupThreatIntelligence } from "../src/threat-intel";

describe("threat intelligence URL hashing", () => {
  it("ignores URL fragments and userinfo consistently", async () => {
    const a = await hashThreatUrl("https://user:pass@example.com/login#fragment");
    const b = await hashThreatUrl("https://example.com/login");
    expect(a).toBe(b);
  });

  it("preserves path and query values for exact feed matching", async () => {
    const a = await hashThreatUrl("https://example.com/login?next=account");
    const b = await hashThreatUrl("https://example.com/login?next=home");
    expect(a).not.toBe(b);
  });

  it("normalizes hostname case", async () => {
    const a = await hashThreatUrl("https://EXAMPLE.com/path");
    const b = await hashThreatUrl("https://example.com/path");
    expect(a).toBe(b);
  });
});


describe("threat-intelligence feed coverage", () => {
  function mockSql(feedRows: Array<Record<string, unknown>>) {
    return async (parts: TemplateStringsArray) => {
      const query = parts.join(" ");
      if (query.includes("FROM threat_indicators")) return [];
      if (query.includes("FROM threat_feed_status")) return feedRows;
      throw new Error("Unexpected SQL query");
    };
  }

  const healthy = (source: string) => ({
    source, status: "ok", last_checked_at: new Date().toISOString(),
    last_success_at: new Date().toISOString(), item_count: 123
  });

  it("reports partial coverage when only Phishunt is configured", async () => {
    const result = await lookupThreatIntelligence(mockSql([healthy("phishunt")]) as any, "https://example.com");
    expect(result.status).toBe("partial");
    expect(result.feeds).toHaveLength(3);
    expect(result.feeds.find(feed => feed.source === "phishunt")?.status).toBe("ok");
    expect(result.feeds.find(feed => feed.source === "urlhaus")?.status).toBe("not_configured");
    expect(result.feeds.find(feed => feed.source === "phishtank")?.status).toBe("not_configured");
  });

  it("reports no feed coverage when none of the supported feeds is configured", async () => {
    const result = await lookupThreatIntelligence(mockSql([]) as any, "https://example.com");
    expect(result.status).toBe("not_configured");
    expect(result.feeds).toHaveLength(3);
    expect(result.feeds.every(feed => feed.status === "not_configured")).toBe(true);
  });

  it("reports complete coverage only when all supported feeds are fresh", async () => {
    const result = await lookupThreatIntelligence(
      mockSql([healthy("urlhaus"), healthy("phishtank"), healthy("phishunt")]) as any,
      "https://example.com"
    );
    expect(result.status).toBe("available");
    expect(result.feeds.every(feed => feed.status === "ok")).toBe(true);
  });
});
