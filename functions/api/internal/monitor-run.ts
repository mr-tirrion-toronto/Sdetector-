import { neon } from "@neondatabase/serverless";

interface Env { DATABASE_URL?: string; FEED_SYNC_SECRET?: string }
function equalConstantTime(left:string,right:string):boolean{
 const a=new TextEncoder().encode(left),b=new TextEncoder().encode(right);
 if(a.length!==b.length)return false;
 let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0;
}
function json(data:unknown,status=200):Response{
 return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"}});
}
export const onRequestPost:PagesFunction<Env>=async({request,env})=>{
 if(!env.DATABASE_URL||!env.FEED_SYNC_SECRET)return json({error:"Monitoring scheduler is not configured."},503);
 const auth=request.headers.get("Authorization")??"";
 const supplied=auth.startsWith("Bearer ")?auth.slice(7):"";
 if(!supplied||!equalConstantTime(supplied,env.FEED_SYNC_SECRET))return json({error:"Unauthorized."},401);
 const sql=neon(env.DATABASE_URL);
 try{
  const due=await sql`WITH due AS (
    SELECT id FROM monitored_domains
    WHERE enabled=TRUE AND next_check_at<=NOW()
    ORDER BY next_check_at ASC,created_at ASC
    LIMIT 1 FOR UPDATE SKIP LOCKED
  )
  UPDATE monitored_domains m SET
    next_check_at=NOW()+(m.interval_hours*INTERVAL '1 hour'),
    last_checked_at=NOW(),last_error=NULL,updated_at=NOW()
  FROM due WHERE m.id=due.id
  RETURNING m.id,m.hostname,m.interval_hours`;
  const targets=due as Array<{id:string;hostname:string;interval_hours:number}>;
  if(!targets.length)return json({status:"ok",processed:0,message:"No monitoring targets are due."});
  const target=targets[0];
  try{
   const scanUrl=new URL("/api/scan",request.url);
   const response=await fetch(scanUrl.toString(),{
    method:"POST",headers:{"content-type":"application/json","accept":"application/json"},
    body:JSON.stringify({url:"https://"+target.hostname+"/"}),redirect:"manual"
   });
   if(!response.ok)throw new Error("SCAN_HTTP_"+response.status);
   const result=await response.json() as Record<string,any>;
   if(typeof result.scanId!=="string"||!result.websiteSnapshot||!result.changeMonitoring)throw new Error("SCAN_RESULT_INCOMPLETE");
   const fingerprint=String(result.changeMonitoring.fingerprint??"");
   if(!/^[a-f0-9]{64}$/.test(fingerprint))throw new Error("SNAPSHOT_FINGERPRINT_INVALID");
   const savedScan=result.persistence==="saved"?result.scanId:null;
   await sql`INSERT INTO monitor_snapshots
     (id,monitor_id,scan_id,snapshot_fingerprint,snapshot,change_summary,checked_at)
     VALUES (${crypto.randomUUID()},${target.id},${savedScan},${fingerprint},
       ${JSON.stringify(result.websiteSnapshot)}::jsonb,
       ${JSON.stringify(result.changeMonitoring)}::jsonb,NOW())`;
   await sql`UPDATE monitored_domains SET last_scan_id=${savedScan},last_error=NULL,updated_at=NOW()
     WHERE id=${target.id}`;
   return json({
    status:"ok",processed:1,hostname:target.hostname,scanId:result.scanId,
    changeStatus:result.changeMonitoring.status,
    changedFields:result.changeMonitoring.changedFields??[],
    nextCheckHours:target.interval_hours
   });
  }catch(error){
   const code=error instanceof Error?error.message.slice(0,100):"UNKNOWN_ERROR";
   await sql`UPDATE monitored_domains SET last_error=${code},
     next_check_at=NOW()+INTERVAL '15 minutes',updated_at=NOW() WHERE id=${target.id}`;
   console.error("MONITOR_TARGET_FAILED",code);
   return json({status:"partial",processed:1,failed:1,error:"One monitoring check failed and was rescheduled."},502);
  }
 }catch(error){
  console.error("MONITOR_SCHEDULER_FAILED",error instanceof Error?error.name:"UnknownError");
  return json({error:"Monitoring scheduler could not claim due targets."},503);
 }
};
