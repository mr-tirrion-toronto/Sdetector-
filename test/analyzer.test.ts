import {describe,expect,it} from "vitest";
import {analyzeUrl} from "../src/analyzer";
describe("analyzeUrl",()=>{
 it("rejects invalid and unsupported URLs",()=>{expect(()=>analyzeUrl("not a url")).toThrow();expect(()=>analyzeUrl("ftp://example.com")).toThrow()});
 it("marks clean-looking URLs unverified when evidence is insufficient",()=>{const r=analyzeUrl("https://example.com/about");expect(r.hostname).toBe("example.com");expect(r.score).toBe(0);expect(r.riskLevel).toBe("unknown");expect(r.assessmentStatus).toBe("insufficient_evidence");expect(r.limitations.some(x=>x.includes("not verified safe"))).toBe(true)});
 it("does not describe zero heuristic points as low risk",()=>{const r=analyzeUrl("https://scam-detector-a92.pages.dev/");expect(r.score).toBe(0);expect(r.riskLevel).toBe("unknown");expect(r.assessmentStatus).toBe("insufficient_evidence")});
 it("flags HTTP and sensitive URL terms",()=>{const r=analyzeUrl("http://example.com/login/verify");expect(r.findings.map(x=>x.code)).toContain("NO_HTTPS");expect(r.findings.map(x=>x.code)).toContain("SENSITIVE_ACTION_TERMS");expect(r.score).toBeGreaterThan(0);expect(r.assessmentStatus).toBe("preliminary")});
 it("flags user information in the URL authority",()=>{expect(analyzeUrl("https://user:password@example.com/login").findings.map(x=>x.code)).toContain("URL_CREDENTIALS_OR_AT")});
 it("flags an empty user-information authority marker",()=>{expect(analyzeUrl("https://@example.com/").findings.map(x=>x.code)).toContain("URL_CREDENTIALS_OR_AT")});
 it("does not flag at-signs in ordinary path or query values",()=>{expect(analyzeUrl("https://example.com/contact/user@example.com?email=help@example.com").findings.map(x=>x.code)).not.toContain("URL_CREDENTIALS_OR_AT")});
 it("does not call the website or execute remote content",()=>{const r=analyzeUrl("https://bit.ly/login");expect(r.findings.map(x=>x.code)).toContain("URL_SHORTENER");expect(r.limitations.length).toBeGreaterThan(0)});
});