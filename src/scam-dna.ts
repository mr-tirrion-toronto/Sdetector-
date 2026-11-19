import type { Finding } from "./analyzer";
import type { BrandMatch } from "./brand-intelligence";
import type { LiveInspection } from "./live-inspection";

export interface ScamDna {
  version:"1.0";
  fingerprint:string;
  family:"known_threat"|"brand_impersonation"|"credential_harvesting"|"advance_fee_earnings"|"malware_delivery"|"generic_phishing"|"suspicious_infrastructure"|"unknown";
  familyLabel:string;
  signalCodes:string[];
  infrastructureTraits:{punycode:boolean;shortener:boolean;ipLiteral:boolean;nonStandardPort:boolean;youngDomain:boolean;tlsHostnameMismatch:boolean};
  matchedBrand:string|null;
  threatSources:string[];
  interpretation:string;
  limitations:string[];
}
async function sha256(value:string):Promise<string>{
 const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
}
export async function buildScamDna(input:{
 hostname:string;findings:Finding[];brands:BrandMatch[];live:LiveInspection|null;
 threatSources:string[];businessSignals:string[];
}):Promise<ScamDna>{
 const codes=[...new Set(input.findings.map(f=>f.code).concat(input.businessSignals.map(s=>"BUSINESS:"+s)))].sort();
 const infra=input.live;
 const traits={
  punycode:input.hostname.split(".").some(part=>part.startsWith("xn--")),
  shortener:codes.includes("URL_SHORTENER"),
  ipLiteral:codes.includes("IP_LITERAL_HOST"),
  nonStandardPort:codes.includes("NONSTANDARD_PORT"),
  youngDomain:typeof infra?.registration.data?.ageDays==="number"&&infra.registration.data.ageDays<30,
  tlsHostnameMismatch:infra?.tls.data?.hostnameMatch===false
 };
 const family:ScamDna["family"]=input.threatSources.length?"known_threat":
  input.brands.length?"brand_impersonation":
  codes.some(c=>c.includes("PAY_TO_WITHDRAW")||c.includes("UPFRONT_WORK_FEE")||c.includes("RECHARGE_TO_EARN"))?"advance_fee_earnings":
  codes.some(c=>c.includes("CREDENTIAL")||c.includes("SENSITIVE_ACTION"))?"credential_harvesting":
  codes.some(c=>c.includes("MALWARE"))?"malware_delivery":
  codes.some(c=>c.includes("PHISH"))?"generic_phishing":
  traits.youngDomain||traits.punycode||traits.tlsHostnameMismatch?"suspicious_infrastructure":"unknown";
 const familyLabel=family.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase());
 const material=JSON.stringify({version:"1.0",family,codes,traits,brands:input.brands.map(b=>b.brand).sort(),threatSources:[...input.threatSources].sort()});
 const fingerprint=await sha256("scam-dna:v1:"+material);
 const interpretation=family==="known_threat"?"This evidence pattern matches at least one configured threat-intelligence source.":
 family==="brand_impersonation"?"The hostname or credential-oriented page content resembles a known brand without matching its curated official domains.":
 family==="advance_fee_earnings"?"The public page contains language linking work, earnings or withdrawals with upfront payments or recharges.":
 family==="credential_harvesting"?"The URL or page contains credential-collection indicators; static inspection does not prove that submitted data is captured.":
 family==="malware_delivery"?"A malware-distribution indicator was identified in the available evidence.":
 family==="suspicious_infrastructure"?"One or more infrastructure traits warrant review, but do not independently prove fraud.":
 "No strong scam-family signature was established from the currently available observations.";
 return {version:"1.0",fingerprint,family,familyLabel,signalCodes:codes.slice(0,40),infrastructureTraits:traits,matchedBrand:input.brands[0]?.brand??null,threatSources:[...new Set(input.threatSources)],interpretation,limitations:[
  "Scam DNA is a deterministic evidence fingerprint, not a malware-family attribution or proof that two operators are the same.",
  "The fingerprint changes when its included evidence changes and may not match older scans created with different analyzer versions."
 ]};
}
