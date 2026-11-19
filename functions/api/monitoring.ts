import { neon } from "@neondatabase/serverless";
import { analyzeUrl } from "../../src/analyzer";
import { getAuthenticatedUser, isSameOriginMutation, json } from "../../src/auth";

interface Env { DATABASE_URL?: string }
const BODY_LIMIT=2048;

export const onRequestGet: PagesFunction<Env> = async ({request,env}) => {
  if(!env.DATABASE_URL)return json({error:"Monitoring storage is unavailable."},503);
  const sql=neon(env.DATABASE_URL);
  const user=await getAuthenticatedUser(sql,request).catch(()=>null);
  if(!user)return json({error:"Sign in to manage website monitoring."},401);
  try{
    const rows=await sql`SELECT m.id,m.hostname,m.interval_hours,m.enabled,m.next_check_at,
      m.last_checked_at,m.last_scan_id,m.last_error,m.created_at,
      latest.change_summary,latest.checked_at AS latest_snapshot_at
      FROM monitored_domains m
      LEFT JOIN LATERAL (
        SELECT change_summary,checked_at FROM monitor_snapshots
        WHERE monitor_id=m.id ORDER BY checked_at DESC LIMIT 1
      ) latest ON TRUE
      WHERE m.user_id=${user.id}
      ORDER BY m.created_at DESC LIMIT 50`;
    return json({monitors:rows,limit:50,privacy:"Only your own monitored hostnames and snapshots are returned."});
  }catch(error){
    console.error("MONITOR_LIST_FAILED",error instanceof Error?error.name:"UnknownError");
    return json({error:"Could not load monitoring targets."},503);
  }
};

export const onRequestPost: PagesFunction<Env> = async ({request,env}) => {
  if(!env.DATABASE_URL)return json({error:"Monitoring storage is unavailable."},503);
  if(!isSameOriginMutation(request))return json({error:"Cross-origin request rejected."},403);
  const contentType=request.headers.get("content-type")??"";
  if(!contentType.toLowerCase().includes("application/json"))return json({error:"Content-Type must be application/json."},415);
  const declared=Number(request.headers.get("content-length")??"0");
  if(declared>BODY_LIMIT)return json({error:"Request body is too large."},413);
  let body:unknown;
  try{body=await request.json()}catch{return json({error:"Provide valid JSON."},400)}
  if(!body||typeof body!=="object"||!("url" in body)||typeof (body as {url?:unknown}).url!=="string")return json({error:"Provide a URL string."},400);
  const input=body as {url:string;intervalHours?:number};
  let parsed;
  try{parsed=analyzeUrl(input.url)}catch(error){return json({error:error instanceof Error?error.message:"Invalid URL."},400)}
  const interval=Number(input.intervalHours??24);
  if(!Number.isInteger(interval)||interval<6||interval>168)return json({error:"Monitoring interval must be between 6 and 168 hours."},400);
  const sql=neon(env.DATABASE_URL);
  const user=await getAuthenticatedUser(sql,request).catch(()=>null);
  if(!user)return json({error:"Sign in to enable monitoring."},401);
  if(user.authType==="session"&&!isSameOriginMutation(request))return json({error:"Cross-origin request rejected."},403);
  try{
    const countRows=await sql`SELECT COUNT(*)::int AS count FROM monitored_domains WHERE user_id=${user.id} AND enabled=TRUE`;
    const count=Number((countRows as Array<{count:number}>)[0]?.count??0);
    const existing=await sql`SELECT id FROM monitored_domains WHERE user_id=${user.id} AND hostname=${parsed.hostname} LIMIT 1`;
    if(count>=20&&!existing.length)return json({error:"You can monitor up to 20 domains on this account."},429);
    const rows=await sql`INSERT INTO monitored_domains
      (id,user_id,hostname,interval_hours,enabled,next_check_at,created_at,updated_at)
      VALUES (${crypto.randomUUID()},${user.id},${parsed.hostname},${interval},TRUE,NOW(),NOW(),NOW())
      ON CONFLICT (user_id,hostname) DO UPDATE SET
        interval_hours=EXCLUDED.interval_hours,enabled=TRUE,next_check_at=NOW(),
        last_error=NULL,updated_at=NOW()
      RETURNING id,hostname,interval_hours,enabled,next_check_at`;
    return json({monitor:(rows as Array<Record<string,unknown>>)[0],message:"Monitoring enabled. The first scheduled check will run shortly."},201);
  }catch(error){
    console.error("MONITOR_CREATE_FAILED",error instanceof Error?error.name:"UnknownError");
    return json({error:"Could not enable monitoring. Please retry."},503);
  }
};

export const onRequestDelete: PagesFunction<Env> = async ({request,env}) => {
  if(!env.DATABASE_URL)return json({error:"Monitoring storage is unavailable."},503);
  if(!isSameOriginMutation(request))return json({error:"Cross-origin request rejected."},403);
  const id=new URL(request.url).searchParams.get("id")??"";
  if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Provide a valid monitor ID."},400);
  const sql=neon(env.DATABASE_URL);
  const user=await getAuthenticatedUser(sql,request).catch(()=>null);
  if(!user)return json({error:"Sign in to manage monitoring."},401);
  try{
    const rows=await sql`UPDATE monitored_domains SET enabled=FALSE,updated_at=NOW()
      WHERE id=${id} AND user_id=${user.id} RETURNING id`;
    if(!rows.length)return json({error:"Monitoring target not found."},404);
    return json({deleted:true});
  }catch(error){
    console.error("MONITOR_DELETE_FAILED",error instanceof Error?error.name:"UnknownError");
    return json({error:"Could not disable monitoring."},503);
  }
};
