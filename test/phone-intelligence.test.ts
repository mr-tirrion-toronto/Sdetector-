import {afterEach,describe,expect,it,vi} from "vitest";
import {lookupPhoneIntelligence} from "../src/phone-intelligence";
afterEach(()=>vi.unstubAllGlobals());
describe("optional phone intelligence provider",()=>{
 it("reports provider as not configured when no key exists",async()=>{
  const result=await lookupPhoneIntelligence("+255712345678");
  expect(result.status).toBe("not_configured");
  expect(result.valid).toBeNull();
 });
 it("returns carrier and VoIP line type from the provider",async()=>{
  vi.stubGlobal("fetch",vi.fn().mockResolvedValue(new Response(JSON.stringify({valid:true,carrier:"Example Telecom",line_type:"VoIP",country_code:"TZ",risk_score:0.1}),{status:200,headers:{"content-type":"application/json"}})));
  const result=await lookupPhoneIntelligence("+255712345678","test-key");
  expect(result.status).toBe("available");
  expect(result.carrier).toBe("Example Telecom");
  expect(result.lineType).toBe("VoIP");
  expect(result.limitations.some(x=>x.includes("does not prove"))).toBe(true);
 });
 it("does not invent a provider verdict after an HTTP error",async()=>{
  vi.stubGlobal("fetch",vi.fn().mockResolvedValue(new Response("unavailable",{status:503})));
  const result=await lookupPhoneIntelligence("+255712345678","test-key");
  expect(result.status).toBe("unavailable");
  expect(result.valid).toBeNull();
 });
});
