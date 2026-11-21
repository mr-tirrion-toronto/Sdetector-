import { neon } from "@neondatabase/serverless";
interface Env { DATABASE_URL?: string }
function json(data:unknown,status=200){return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}})}
export const onRequestPost: PagesFunction<Env> = async ({request,env}) => {
 if(!env.DATABASE_URL)return json({ok:false},503);
 const origin=request.headers.get("Origin");if(origin&&origin!==new URL(request.url).origin)return json({ok:false},403);
 let body:any;try{body=await request.json()}catch{return json({ok:false},400)}
 const page=typeof body?.page==="string"?body.page:"/";if(!/^\\/[a-zA-Z0-9/_-]{1,100}$/.test(page))return json({ok:false},400);
 let referrerHost:string|null=null;try{referrerHost=body?.referrer?new URL(String(body.referrer)).hostname.slice(0,180):null}catch{}
 const ua=request.headers.get("user-agent")??"";const device=/tablet|ipad/i.test(ua)?"tablet":/mobile|android|iphone/i.test(ua)?"mobile":ua?"desktop":"unknown";
 const country=((request as Request & {cf?:{country?:string}}).cf?.country??request.headers.get("CF-IPCountry")??"").toUpperCase();const cc=/^[A-Z]{2}$/.test(country)?country:null;
 try{const sql=neon(env.DATABASE_URL);await sql\`INSERT INTO site_events(id,event_type,country_code,page_path,referrer_host,device_type) VALUES(\${crypto.randomUUID()},'page_view',\${cc},\${page},\${referrerHost},\${device})\`;return json({ok:true},202)}
 catch(error){console.error("ANALYTICS_EVENT_FAILED",error instanceof Error?error.name:"UnknownError");return json({ok:false},503)}
};