import { describe, expect, it } from "vitest";
import { makePhishuntIndicators } from "../src/phishunt-feed";

describe("Phishunt feed normalization", () => {
  it("stores unique hostnames and hashes rather than raw feed URLs", async () => {
    const feed = [
      "# public phishing indicators",
      "https://bad.example/login?token=do-not-store",
      "bad.example/another-path",
      "http://credential-theft.test/reset",
      "http://127.0.0.1/internal",
      "localhost",
      "https://another-bad.example/path"
    ].join("\n");

    const indicators = await makePhishuntIndicators(feed);
    expect(indicators.map(item => item.hostname)).toEqual([
      "bad.example",
      "credential-theft.test",
      "another-bad.example"
    ]);
    expect(indicators.every(item => /^[a-f0-9]{64}$/.test(item.indicator_hash))).toBe(true);
    expect(JSON.stringify(indicators)).not.toContain("token=do-not-store");
    expect(JSON.stringify(indicators)).not.toContain("/login");
  });
});
