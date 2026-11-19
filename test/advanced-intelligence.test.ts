import { describe, expect, it } from "vitest";
import { detectBrandImpersonation } from "../src/brand-intelligence";
import { buildRelationshipGraph } from "../src/relationship-graph";
import { buildScamDna } from "../src/scam-dna";
import { compareSnapshots, fingerprintSnapshot, type WebsiteSnapshot } from "../src/change-monitoring";
import type { Finding } from "../src/analyzer";
import { assessLegitimacy } from "../src/legitimacy-assessment";
import { buildIndependentEvidence } from "../src/independent-evidence";

const sampleFinding:Finding={code:"SENSITIVE_ACTION_TERMS",title:"Sensitive URL terms",severity:"medium",points:12,evidence:"login and verify terms",recommendation:"Verify the domain."};
const snapshot:WebsiteSnapshot={
 title:"Example",finalHostname:"example.com",httpStatus:200,ipAddresses:["203.0.113.10"],
 tlsIssuer:"Example CA",tlsExpiry:"2027-01-01T00:00:00.000Z",certificateNames:["example.com"],
 domainAgeDays:300,contentIndicators:[],businessSignals:[],threatSources:[],brandMatches:[],scamDnaFingerprint:"a".repeat(64)
};

describe("brand impersonation intelligence",()=>{
 it("does not flag an exact official domain",()=>{
  expect(detectBrandImpersonation({hostname:"www.paypal.com",pageTitle:"PayPal"}).matches).toHaveLength(0);
 });
 it("flags a one-character lookalike brand domain",()=>{
  const result=detectBrandImpersonation({hostname:"paypa1-login.example",pageTitle:"Sign in"});
  expect(result.matches[0]?.brand).toBe("PayPal");
  expect(result.matches[0]?.matchType).toBe("lookalike_hostname");
  expect(result.findings[0]?.points).toBeGreaterThan(0);
 });
 it("uses page-title brand context only with credential indicators",()=>{
  const plain=detectBrandImpersonation({hostname:"example.net",pageTitle:"PayPal community discussion"});
  const auth=detectBrandImpersonation({hostname:"example.net",pageTitle:"PayPal Sign In",indicators:["password_input"]});
  expect(plain.matches).toHaveLength(0);
  expect(auth.matches[0]?.matchType).toBe("brand_in_page_title");
 });
});

describe("relationship intelligence graph",()=>{
 it("labels shared certificates as low-confidence leads, not ownership",()=>{
  const graph=buildRelationshipGraph({hostname:"login.example.net",ips:["203.0.113.8"],certificateNames:["example.net","other.example.org"],relatedDomains:["phish.example"]});
  expect(graph.edges.some(edge=>edge.type==="shares_certificate"&&edge.confidence==="low")).toBe(true);
  expect(graph.limitations.some(text=>text.includes("not ownership"))).toBe(true);
 });
 it("keeps nodes and edges bounded",()=>{
  const graph=buildRelationshipGraph({hostname:"example.com",ips:Array.from({length:100},(_,i)=>"203.0.113."+i),relatedDomains:Array.from({length:100},(_,i)=>"bad"+i+".example")});
  expect(graph.nodes.length).toBeLessThanOrEqual(40);
  expect(graph.edges.length).toBeLessThanOrEqual(40);
 });
});

describe("scam DNA",()=>{
 it("creates a stable credential-harvesting family fingerprint",async()=>{
  const input={hostname:"example.com",findings:[sampleFinding],brands:[],live:null,threatSources:[],businessSignals:[]};
  const first=await buildScamDna(input),second=await buildScamDna(input);
  expect(first.family).toBe("credential_harvesting");
  expect(first.fingerprint).toBe(second.fingerprint);
  expect(first.fingerprint).toHaveLength(64);
 });
 it("prioritizes a confirmed threat over heuristic families",async()=>{
  const dna=await buildScamDna({hostname:"example.com",findings:[sampleFinding],brands:[],live:null,threatSources:["Phishunt"],businessSignals:[]});
  expect(dna.family).toBe("known_threat");
 });
});

describe("website change monitoring",()=>{
 it("creates a stable snapshot hash",async()=>{
  expect(await fingerprintSnapshot(snapshot)).toBe(await fingerprintSnapshot(snapshot));
 });
 it("detects meaningful changes and ignores unchanged snapshots",async()=>{
  const same=await compareSnapshots(snapshot,snapshot);
  const changed=await compareSnapshots({...snapshot,title:"New title",ipAddresses:["203.0.113.11"]},snapshot);
  expect(same.status).toBe("unchanged");
  expect(changed.status).toBe("changed");
  expect(changed.changedFields).toContain("title");
  expect(changed.changedFields).toContain("ipAddresses");
 });
 it("marks the first observation as a baseline",async()=>{
  const baseline=await compareSnapshots(snapshot,null);
  expect(baseline.status).toBe("baseline");
  expect(baseline.fingerprint).toHaveLength(64);
 });
});

describe("evidence-based legitimacy assessment",()=>{
 it("never calls an unverified website legitimate",()=>{
  const assessment=assessLegitimacy({
   brands:detectBrandImpersonation({hostname:"example.com"}),
   live:null,
   threat:{status:"available",matched:false,feeds:[],findings:[]},
   findings:[],
   independentEvidence:buildIndependentEvidence({hostname:"example.com"})
  });
  expect(assessment.status).toBe("not_verified");
  expect(assessment.label).toContain("not verified");
  expect(assessment.checks.find(check=>check.id==="payouts")?.status).toBe("manual_review");
  expect(assessment.notVerified.length).toBeGreaterThan(0);
 });
 it("prioritizes confirmed threat evidence over positive technical observations",()=>{
  const assessment=assessLegitimacy({
   brands:detectBrandImpersonation({hostname:"example.com"}),
   live:null,
   threat:{status:"available",matched:true,feeds:[],findings:[]},
   findings:[],
   independentEvidence:buildIndependentEvidence({hostname:"example.com"})
  });
  expect(assessment.status).toBe("known_threat");
 });
});
