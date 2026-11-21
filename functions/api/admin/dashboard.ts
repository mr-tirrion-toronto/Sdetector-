import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, json } from "../../../src/auth";
interface Env { DATABASE_URL?: string; ADMIN_EMAIL?: string }
export const onRequestGet: PagesFunction<Env> = async ({request,env}) => {
 if(!env.DATABASE_URL||!env.ADMIN_EMAIL)return json({error:"Admin access is not configured."},503);
 try{
  const sql=neon(env.DATABASE_URL);const user=await getAuthenticatedUser(sql,request);
  if(!user||user.authType!=="session")return json({error:"Please sign in with the administrator account."},401);
  if(user.email.toLowerCase()!==env.ADMIN_EMAIL.trim().toLowerCase())return json({error:"Administrator access is restricted."},403);
  const [summary,countries,pages,referrers,daily,devices,feeds]=await Promise.all([
   sql\`SELECT (SELECT COUNT(*)::int FROM app_users) total_users,(SELECT COUNT(*)::int FROM app_users WHERE created_at>=NOW()-INTERVAL '30 days') new_users_30d,(SELECT COUNT(*)::int FROM scans) total_scans,(SELECT COUNT(*)::int FROM scans WHERE created_at>=NOW()-INTERVAL '24 hours') scans_24h,(SELECT COUNT(*)::int FROM scans WHERE created_at>=NOW()-INTERVAL '30 days') scans_30d,(SELECT COUNT(*)::int FROM site_events WHERE event_type='page_view') total_page_views,(SELECT COUNT(*)::int FROM site_events WHERE event_type='page_view' AND created_at>=NOW()-INTERVAL '30 days') page_views_30d,(SELECT COUNT(DISTINCT country_code)::int FROM site_events WHERE country_code IS NOT NULL) countries_seen,(SELECT COUNT(*)::int FROM scans WHERE risk_level IN ('high','critical')) elevated_scans\`,
   sql\`SELECT COALESCE(country_code,'Unknown') country,COUNT(*)::int visits FROM site_events WHERE event_type='page_view' AND created_at>=NOW()-INTERVAL '30 days' GROUP BY country_code ORDER BY visits DESC LIMIT 15\`,
   sql\`SELECT page_path page,COUNT(*)::int views FROM site_events WHERE event_type='page_view' AND created_at>=NOW()-INTERVAL '30 days' GROUP BY page_path ORDER BY views DESC LIMIT 12\`,
   sql\`SELECT COALESCE(referrer_host,'Direct / unknown') source,COUNT(*)::int visits FROM site_events WHERE event_type='page_view' AND created_at>=NOW()-INTERVAL '30 days' GROUP BY referrer_host ORDER BY visits DESC LIMIT 10\`,
   sql\`SELECT TO_CHAR(day,'YYYY-MM-DD') day,TO_CHAR(day,'Dy') label,COUNT(e.id)::int visits FROM generate_series(CURRENT_DATE-INTERVAL '13 days',CURRENT_DATE,INTERVAL '1 day') days(day) LEFT JOIN site_events e ON DATE(e.created_at)=DATE(day) AND e.event_type='page_view' GROUP BY day ORDER BY day\`,
   sql\`SELECT device_type device,COUNT(*)::int visits FROM site_events WHERE event_type='page_view' AND created_at>=NOW()-INTERVAL '30 days' GROUP BY device_type ORDER BY visits DESC\`,
   sql\`SELECT source,status,last_success_at,item_count FROM threat_feed_status ORDER BY source\`
  ]);
  const feedsOut=(feeds as any[]).map(f=>({source:f.source,status:f.status,lastSuccessAt:f.last_success_at,itemCount:Number(f.item_count??0)}));
  return json({generatedAt:new Date().toISOString(),summary:Object.fromEntries(Object.entries((summary as any[])[0]??{}).map(([k,v])=>[k,Number(v??0)])),countries:(countries as any[]).map(x=>({country:x.country,visits:Number(x.visits)})),pages:(pages as any[]).map(x=>({page:x.page,views:Number(x.views)})),referrers:(referrers as any[]).map(x=>({source:x.source,visits:Number(x.visits)})),daily:(daily as any[]).map(x=>({day:x.day,label:x.label,visits:Number(x.visits)})),devices:(devices as any[]).map(x=>({device:x.device,visits:Number(x.visits)})),feeds:feedsOut,privacy:"Country is derived from Cloudflare country code. No raw IP address is stored. Analytics are aggregate and retained for 90 days."});
 }catch(error){console.error("ADMIN_DASHBOARD_FAILED",error instanceof Error?error.name:"UnknownError");return json({error:"Admin analytics could not be loaded."},503)}
};