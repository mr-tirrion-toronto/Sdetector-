import { neon } from "@neondatabase/serverless";
import { analyzeUrl, type ScanResult } from "../../src/analyzer";
interface Env { DATABASE_URL?: string }
function json(data:unknown,status=200):Response {
 return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"}});
}
async function readBoundedBody(request:Request,maxBytes:number):Promise<string>{
 if(!request.body)throw new Error("Request body is empty.");
 const reader=request.body.getReader(),decoder=new TextDecoder();let bytes=0,out="";
 try{
  while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;
   if(bytes>maxBytes){await reader.cancel();throw new Error("Request body is too large.");}
   out+=decoder.decode(value,{stream:true});
  }
  return out+decoder.decode();
 }finally{reader.releaseLock();}
}
function safeStoredUrl(value:string):string{
 const u=new URL(value);u.username="";u.password="";u.search="";u.hash="";
 u.pathname=u.pathname.split("/").map(segment=>{
  let decoded=segment;try{decoded=decodeURIComponent(segment)}catch{}
  return decoded.length>32||/^[^/\s@]+@[^/\s@]+\.[^/\s@]+$/.test(decoded)||
   /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(decoded)?"[redacted]":segment;
 }).join("/");
 return u.toString();
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
 return json({scanId,...result,threatIntel:[],persistence:saved?"saved":"not_configured_or_unavailable"});
};