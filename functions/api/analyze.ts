import { neon } from "@neondatabase/serverless";
import { analyzeMultiChannel, type AnalysisChannel } from "../../src/multichannel-analysis";
import { getAuthenticatedUser, json } from "../../src/auth";
interface Env { DATABASE_URL?:string }
const CHANNELS=new Set<AnalysisChannel>(["sms","email","phone","whatsapp","telegram","social","job","investment","qr","file"]);
export const onRequestPost:PagesFunction<Env>=async({request,env})=>{
 if(!request.headers.get("content-type")?.toLowerCase().includes("application/json"))return json({error:"Content-Type must be application/json."},415);
 const declaredLength=Number(request.headers.get("content-length")??"0");
 if(declaredLength>16000)return json({error:"Request body is too large."},413);
 let rawBody:string;try{rawBody=await request.text();}catch{return json({error:"Could not read request body."},400);}
 if(rawBody.length>16000)return json({error:"Request body is too large."},413);
 let body:unknown;try{body=JSON.parse(rawBody);}catch{return json({error:"Request body must be valid JSON."},400);}
 if(!body||typeof body!=="object")return json({error:"A JSON object is required."},400);
 const data=body as Record<string,unknown>;
 if(typeof data.channel!=="string"||!CHANNELS.has(data.channel as AnalysisChannel))return json({error:"Choose a supported analysis channel."},400);
 if(typeof data.content!=="string")return json({error:"Provide text or content to analyse."},400);
 if(data.content.length>12000)return json({error:"Content exceeds the 12000-character limit."},413);
 if(data.headers!==undefined&&typeof data.headers!=="string")return json({error:"Email headers must be text."},400);
 if(data.fileName!==undefined&&typeof data.fileName!=="string")return json({error:"File name must be text."},400);
 if(data.mimeType!==undefined&&typeof data.mimeType!=="string")return json({error:"MIME type must be text."},400);
 try{
  const result=analyzeMultiChannel({channel:data.channel as AnalysisChannel,content:data.content,countryCode:typeof data.countryCode==="string"?data.countryCode:undefined,headers:typeof data.headers==="string"?data.headers:undefined,fileName:typeof data.fileName==="string"?data.fileName:undefined,mimeType:typeof data.mimeType==="string"?data.mimeType:undefined});
  let persistence:"saved"|"not_configured_or_unavailable"="not_configured_or_unavailable";
  if(env.DATABASE_URL){
   try{
    const sql=neon(env.DATABASE_URL);
    const ip=request.headers.get("CF-Connecting-IP");
    if(ip){
     const bucketWindow=Math.floor(Date.now()/600000);
     const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode("channel:"+ip+":"+bucketWindow));
     const bucket=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
     const limited=await sql`INSERT INTO scan_rate_limits(bucket_key,request_count,created_at)
       VALUES (${bucket},1,NOW())
       ON CONFLICT(bucket_key) DO UPDATE SET request_count=scan_rate_limits.request_count+1
       RETURNING request_count`;
     if(Number((limited as Array<{request_count:number}>)[0]?.request_count??0)>20)return json({error:"Rate limit reached. Try again in a few minutes."},429);
    }
    const user=await getAuthenticatedUser(sql,request);
    if(user?.id){
     await sql`INSERT INTO channel_analyses(id,user_id,channel,risk_score,risk_level,signals,created_at)
       VALUES (${crypto.randomUUID()},${user.id},${result.channel},${result.score},${result.riskLevel},${JSON.stringify(result.signals)}::jsonb,NOW())`;
     persistence="saved";
    }
   }catch(error){console.error("CHANNEL_ANALYSIS_PERSISTENCE_FAILED",error instanceof Error?error.name:"UnknownError");}
  }
  return json({...result,persistence,privacy:{rawContentStored:false,stored:"channel, risk score, risk level and findings only"}});
 }catch(error){return json({error:error instanceof Error?error.message:"Analysis failed."},400);}
};
