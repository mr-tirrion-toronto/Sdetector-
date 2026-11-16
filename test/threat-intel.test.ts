import { describe, expect, it } from "vitest";
import { hashThreatUrl } from "../src/threat-intel";

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
