import {describe,expect,it} from "vitest";
import {analyzeMultiChannel} from "../src/multichannel-analysis";
describe("multi-channel scam analysis",()=>{
 it("flags OTP requests in SMS",()=>{const r=analyzeMultiChannel({channel:"sms",content:"Your bank account is blocked. Verify immediately and send your OTP to customer care."});expect(r.signals.map(s=>s.code)).toContain("CREDENTIAL_HARVESTING");expect(r.riskLevel).toBe("high");});
 it("extracts URLs but never visits them",()=>{const r=analyzeMultiChannel({channel:"whatsapp",content:"Claim your prize now https://bit.ly/claim"});expect(r.extractedUrls).toHaveLength(1);expect(r.signals.map(s=>s.code)).toContain("SHORTENED_URL");});
 it("does not claim phone subscriber registration or carrier status",()=>{const r=analyzeMultiChannel({channel:"phone",content:"Call +255 712 345 678",countryCode:"TZ"});expect(r.phoneNumbers).toContain("+255712345678");expect(r.checks.phone).toContain("not verified");});
 it("detects job application fee requests",()=>{const r=analyzeMultiChannel({channel:"job",content:"Pay registration fee to apply for this job."});expect(r.signals.map(s=>s.code)).toContain("JOB_FEE_REQUEST");});
 it("detects guaranteed investment returns",()=>{const r=analyzeMultiChannel({channel:"investment",content:"Guaranteed returns of 100% profit daily."});expect(r.signals.map(s=>s.code)).toContain("INVESTMENT_GUARANTEE");});
 it("marks missing email headers as unavailable",()=>{const r=analyzeMultiChannel({channel:"email",content:"Hello, verify your password."});expect(r.signals.map(s=>s.code)).toContain("EMAIL_HEADERS_MISSING");});
 it("rejects empty and excessive content",()=>{expect(()=>analyzeMultiChannel({channel:"sms",content:" "})).toThrow();expect(()=>analyzeMultiChannel({channel:"sms",content:"a".repeat(12001)})).toThrow();});
});
