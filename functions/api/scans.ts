import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, json } from "../../src/auth";
interface Env { DATABASE_URL?: string }
export const onRequestGet: PagesFunction<Env> = async ({request,env}) => {
  if(!env.DATABASE_URL)return json({error:"Scan history is unavailable."},503);
  try {
    const sql=neon(env.DATABASE_URL);
    const user=await getAuthenticatedUser(sql,request);
    if(!user)return json({error:"Sign in to view your personal scan history."},401);
    const rows=await sql`
      SELECT s.id,s.hostname,s.input_url,s.risk_score,s.risk_level,s.created_at,
        COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'code',f.code,'title',f.title,'severity',f.severity,
          'evidence',f.evidence,'recommendation',f.recommendation
        ) ORDER BY f.id) FROM scan_findings f WHERE f.scan_id=s.id),'[]'::jsonb) AS findings
      FROM scans s WHERE s.user_id=${user.id}
      ORDER BY s.created_at DESC LIMIT 50
    `;
    return json({scans:rows});
  } catch(error) {
    console.error("USER_SCAN_HISTORY_FAILED",error instanceof Error?error.name:"UnknownError");
    return json({error:"Could not load your scan history."},503);
  }
};
