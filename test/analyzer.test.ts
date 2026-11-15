import { describe, expect, it } from "vitest";
import { analyzeUrl } from "../src/analyzer";

describe("analyzeUrl", () => {
  it("rejects invalid and unsupported URLs", () => {
    expect(() => analyzeUrl("not a url")).toThrow();
    expect(() => analyzeUrl("ftp://example.com")).toThrow();
  });

  it("does not claim a clean URL is verified safe", () => {
    const result = analyzeUrl("https://example.com/about");
    expect(result.hostname).toBe("example.com");
    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe("low");
    expect(result.assessmentStatus).toBe("insufficient_evidence");
    expect(result.confidence).toBe("limited");
    expect(result.limitations.some(item => item.includes("not mean the website is verified safe"))).toBe(true);
  });

  it("flags HTTP and sensitive URL terms", () => {
    const result = analyzeUrl("http://example.com/login/verify");
    expect(result.findings.map(item => item.code)).toContain("NO_HTTPS");
    expect(result.findings.map(item => item.code)).toContain("SENSITIVE_ACTION_TERMS");
    expect(result.score).toBeGreaterThan(0);
    expect(result.assessmentStatus).toBe("preliminary_signals_detected");
  });

  it("flags user information in the URL authority", () => {
    const result = analyzeUrl("https://user:password@example.com/login");
    expect(result.findings.map(item => item.code)).toContain("URL_CREDENTIALS_OR_AT");
  });

  it("flags an empty user-information authority marker", () => {
    const result = analyzeUrl("https://@example.com/");
    expect(result.findings.map(item => item.code)).toContain("URL_CREDENTIALS_OR_AT");
  });

  it("does not flag at-signs in ordinary path or query values", () => {
    const result = analyzeUrl("https://example.com/contact/user@example.com?email=help@example.com");
    expect(result.findings.map(item => item.code)).not.toContain("URL_CREDENTIALS_OR_AT");
  });

  it("flags an IP literal hostname", () => {
    const result = analyzeUrl("http://192.0.2.1/login");
    expect(result.findings.map(item => item.code)).toContain("IP_LITERAL_HOST");
  });

  it("does not connect to submitted websites", () => {
    const result = analyzeUrl("https://bit.ly/login");
    expect(result.findings.map(item => item.code)).toContain("URL_SHORTENER");
    expect(result.limitations.length).toBeGreaterThan(0);
  });
});
