import type { LiveInspection } from "./live-inspection";
import type { ScamDna } from "./scam-dna";
import type { BrandAssessment } from "./brand-intelligence";
import type { ThreatIntelResult } from "./threat-intel";
export interface WebsiteSnapshot {
 title:string|null;finalHostname:string|null;httpStatus:number|null;ipAddresses:string[];
 tlsIssuer:string|null;tlsExpiry:string|null;certificateNames:string[];
 domainAgeDays:number|null;contentIndicators:string[];businessSignals:string[];
 threatSources:string[];brandMatches:string[];scamDnaFingerprint:string;
}
export interface ChangeSummary {
 status:"baseline"|"changed"|"unchanged"|"history_unavailable";
 fingerprint:string|null;previousFingerprint:string|null;changedFields:string[];
 previousCheckedAt:string|null;checkedAt:string;note:string;
}
async function sha256(value:string):Promise<string>{
 const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
}
export function buildWebsiteSnapshot(input:{live:LiveInspection|null;dna:ScamDna;brands:BrandAssessment;threat:ThreatIntelResult}):WebsiteSnapshot{
 const live=input.live;const page=live?.websiteContent.data;const dns=live?.dns.data;const tls=live?.tls.data;const reg=live?.registration.data;
 return {
  title:page?.title??null,
  finalHostname:page?.fetchedUrl?(()=>{try{return new URL(page.fetchedUrl!).hostname.toLowerCase()}catch{return null}})():null,
  httpStatus:page?.httpStatus??null,
  ipAddresses:[...new Set((dns?.records||[]).filter(r=>r.type==="A"||r.type==="AAAA").map(r=>r.value))].sort(),
  tlsIssuer:tls?.issuer??null,tlsExpiry:tls?.notAfter??null,
  certificateNames:[...(tls?.subjectAltNames||[])].sort().slice(0,40),
  domainAgeDays:reg?.ageDays??null,
  contentIndicators:[...(page?.indicators||[])].sort(),
  businessSignals:[...(page?.businessSignals||[])].sort(),
  threatSources:input.threat.feeds.filter(f=>f.status==="ok").map(f=>f.source).sort(),
  brandMatches:input.brands.matches.map(m=>m.brand+":"+m.matchType).sort(),
  scamDnaFingerprint:input.dna.fingerprint
 };
}
export async function fingerprintSnapshot(snapshot:WebsiteSnapshot):Promise<string>{
 return sha256("website-snapshot:v1:"+JSON.stringify(snapshot));
}
export async function compareSnapshots(current:WebsiteSnapshot,previous:WebsiteSnapshot|null,checkedAt=new Date().toISOString()):Promise<ChangeSummary>{
 const fingerprint=await fingerprintSnapshot(current);
 if(!previous)return {status:"baseline",fingerprint,previousFingerprint:null,changedFields:[],previousCheckedAt:null,checkedAt,note:"Baseline snapshot recorded. Future scheduled checks can compare against this observation."};
 const changedFields=(Object.keys(current) as Array<keyof WebsiteSnapshot>).filter(key=>key!=="domainAgeDays"&&JSON.stringify(current[key])!==JSON.stringify(previous[key])).map(String);
 return {status:changedFields.length?"changed":"unchanged",fingerprint,previousFingerprint:await fingerprintSnapshot(previous),changedFields,previousCheckedAt:null,checkedAt,note:changedFields.length?"Website observations differ from the previous stored snapshot. Review each changed field; a change is not automatically malicious.":"No tracked fields changed compared with the previous stored snapshot."};
}
