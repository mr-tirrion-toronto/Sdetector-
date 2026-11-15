import { neon } from "@neondatabase/serverless";
import { analyzeUrl, type Finding, type ScanResult } from "../../src/analyzer";

interface Env { DATABASE_URL?: string }
interface IntelligenceResult {
 provider:"phishdestroy";
 status:"primary_match"|"community_match"|"no_match"|"allowlisted"|"unavailable";
 checkedAt:string;
 matchedDomain?:string;
 listedSince?:string;
 lists?:string[];
 liveness?:string;
}

function json(data:unknown,status=200):Response {
 return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"}});
}
async function readBoundedBody(request:Request,maxBytes:number):Promise<string>{
 if(!request.body)throw new Error("Request body is empty.");
 const reader=request.body.getReader(),decoder=new TextDecoder();let bytes=0,out="";
 try{while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;
  if(bytes>maxBytes){await reader.cancel();throw new Error("Request body is too large.");}
  out+=decoder.decode(value,{stream:true});
 }return out+decoder.decode();}finally{reader.releaseLock();}
}
function safeStoredUrl(value:string):string{
 const u=new URL(value);u.username="";u.password="";u.search="";u.hash="";
 u.pathname=u.pathname.split("/").map(segment=>{let decoded=segment;try{decoded=decodeURIComponent(segment)}catch{}
  return decoded.length>32||/^[^/\s@]+@[^/\s@]+\.[^/\s@]+$/.test(decoded)||
   /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(decoded)?"[redacted]":segment;
 }).join("/");
 return u.toString();
}
async function checkIntelligence(domain:string):Promise<IntelligenceResult>{
 const checkedAt=new Date().toISOString();
 try{
  const endpoint="https://api.destroy.tools/v1/check?domain="+encodeURIComponent(domain);
  const response=await fetch(endpoint,{headers:{accept:"application/json","user-agent":"ScamDetector/0.2 (+https://scam-detector-a92.pages.dev/)"},
   signal:AbortSignal.timeout(4500)});
  if(!response.ok)return{provider:"phishdestroy",status:"unavailable",checkedAt};
  const data:unknown=await response.json();
  if(!data||typeof data!=="object")return{provider:"phishdestroy",status:"unavailable",checkedAt};
  const item=data as Record<string,unknown>;
  const lists=item.lists&&typeof item.lists==="object"?item.lists as Record<string,unknown>:{};
  const matchedDomain=typeof item.matched_domain==="string"?item.matched_domain:undefined;
  const listedSince=typeof item.listed_since==="string"?item.listed_since:undefined;
  const liveness=typeof item.liveness==="string"?item.liveness:undefined;
  const present=Object.entries(lists).filter(([,value])=>value===true).map(([key])=>key);
  if(item.whitelisted===true)return{provider:"phishdestroy",status:"allowlisted",checkedAt,matchedDomain,listedSince,lists:present,liveness};
  if(item.threat===true){
   const primary=lists.primary===true||lists.primary_active===true||lists.primary_content===true;
   return{provider:"phishdestroy",status:primary?"primary_match":"community_match",checkedAt,matchedDomain,listedSince,lists:present,liveness};
  }
  if(item.threat===false)return{provider:"phishdestroy",status:"no_match",checkedAt,matchedDomain,lists:present,liveness};
  return{provider:"phishdestroy",status:"unavailable",checkedAt};
 }catch{return{provider:"phishdestroy",status:"unavailable",checkedAt};}
}
function applyIntelligence(result:ScanResult,intel:IntelligenceResult):void{
 if(intel.status!=="primary_match"&&intel.status!=="community_match")return;
 const primary=intel.status==="primary_match";
 const finding:Finding={
  code:primary?"PHISHDESTROY_PRIMARY_MATCH":"PHISHDESTROY_COMMUNITY_MATCH",
  title:primary?"Domain listed in curated phishing threat feed":"Domain listed in community phishing feed",
  severity:primary?"high":"medium",points:primary?100:60,
  evidence:"PhishDestroy reports a "+(primary?"curated primary":"community aggregate")+" phishing-domain match"+
   (intel.matchedDomain?": "+intel.matchedDomain:"")+
   (intel.listedSince?". First listed: "+intel.listedSince:"")+
   (intel.liveness?". Last liveness status: "+intel.liveness:"")+".",
  recommendation:"Do not enter credentials or payment details. Verify the sender through an independent channel and report the link to the relevant service.",
  source:"PhishDestroy"
 };
 result.findings.push(finding);
 result.score=Math.max(result.score,finding.points);
 result.riskLevel=result.score>=70?"critical":result.score>=40?"high":result.score>=20?"guarded":"low";
 result.assessmentStatus="threat_intel_match";
}
export const onRequestPost:PagesFunction<Env>=async({request,env})=>{
 const type=request.headers.get("content-type")??"";
 if(!/^application\/json(?:\s*;|$)/i.test(type))return json({error:"Content-Type must be application/json."},415);
 const origin=request.headers.get("origin");
 if(origin){try{if(new URL(origin).origin!==new URL(request.url).origin)return json({error:"Cross-origin scan requests are not allowed."},403)}catch{return json({error:"Invalid request origin."},403)}}
 const length=request.headers.get("content-length");
 if(length){const n=Number(length);if(!Number.isFinite(n)||n<0||n>4096)return json({error:"Request body is too large or has an invalid length."},413)}
 let raw:string;try{raw=await readBoundedBody(request,4096)}catch(e){const large=e instanceof Error&&e.message==="Request body is too large.";return json({error:large?"Request body is too large.":"Could not read request body."},large?413:400)}
 let body:unknown;try{body=JSON.parse(raw)}catch{return json({error:"Request body must be valid JSON."},400)}
 if(!body||typeof body!=="object"||Array.isArray(body)||!("url"in body)||typeof(body as {url?:unknown}).url!=="string")
  return json({error:"Provide a URL string in the 'url' field."},400);
 let result:ScanResult;try{result=analyzeUrl((body as {url:string}).url)}catch(e){return json({error:e instanceof Error?e.message:"URL analysis failed."},400)}
 // Send only the normalized hostname to a fixed threat-intelligence API; never fetch the submitted website.
 const intelligence=await checkIntelligence(result.hostname);
 applyIntelligence(result,intelligence);
 if(intelligence.status==="unavailable")result.limitations.push("Threat-intelligence provider unavailable; reputation status is unknown.");
 else if(intelligence.status==="no_match")result.limitations.push("No matching phishing-domain entry was returned by this provider at check time. This is not proof of safety.");
 else if(intelligence.status==="allowlisted")result.limitations.push("This provider allowlists the domain to suppress false positives. Allowlisting is not a safety certification.");
 else if(intelligence.status==="community_match")result.limitations.push("The match is from aggregated community intelligence and should be treated as a strong warning, not a standalone legal or forensic finding.");
 const scanId=crypto.randomUUID();let saved=false;
 if(env.DATABASE_URL){try{
  const sql=neon(env.DATABASE_URL),stored=safeStoredUrl(result.normalizedUrl),findings=JSON.stringify(result.findings);
  await sql`WITH saved_scan AS (
   INSERT INTO scans(id,input_url,normalized_url,hostname,risk_score,risk_level,assessment_status,created_at)
   VALUES(${scanId},${stored},${stored},${result.hostname},${result.score},${result.riskLevel},${result.assessmentStatus},NOW()) RETURNING id
  ), saved_findings AS (
   INSERT INTO scan_findings(scan_id,code,title,severity,points,evidence,recommendation)
   SELECT saved_scan.id,f.code,f.title,f.severity,f.points,f.evidence,f.recommendation FROM saved_scan
   CROSS JOIN LATERAL jsonb_to_recordset(${findings}::jsonb) AS f(code text,title text,severity text,points integer,evidence text,recommendation text)
   RETURNING id
  ) SELECT (SELECT count(*) FROM saved_findings) AS findings_saved`;
  saved=true;
 }catch(error){console.error("DATABASE_SCAN_WRITE_FAILED",error)}}
 return json({scanId,...result,threatIntel:[intelligence],persistence:saved?"saved":"not_configured_or_unavailable"});
};