import { describe, expect, it } from "vitest";
import { analyzeUrl } from "../src/analyzer";

describe("analyzeUrl", () => {
  it("rejects invalid and unsupported URLs", () => {
    expect(() => analyzeUrl("not a url")).toThrow();
    expect(() => analyzeUrl("ftp://example.com")).toThrow();
  });

  it("returns a low-risk heuristic result for a plain HTTPS URL", () => {
    const result = analyzeUrl("https://example.com/about");
    expect(result.hostname).toBe("example.com");
    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe("low");
  });

  it("flags HTTP and sensitive URL terms", () => {
    const result = analyzeUrl("http://example.com/login/verify");
    expect(result.findings.map(item => item.code)).toContain("NO_HTTPS");
    expect(result.findings.map(item => item.code)).toContain("SENSITIVE_ACTION_TERMS");
    expect(result.score).toBeGreaterThan(0);
  });

  it("does not call the website or execute remote content", () => {
    const result = analyzeUrl("https://bit.ly/login");
    expect(result.findings.map(item => item.code)).toContain("URL_SHORTENER");
    expect(result.limitations.length).toBeGreaterThan(0);
  });
});
