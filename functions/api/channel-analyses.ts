import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, json } from "../../src/auth";
interface Env { DATABASE_URL?:string }
export const onRequestGet:PagesFunction<Env>=async({request,env})=>{
 if(!env.DATABASE_URL)return json({error:"Analysis history is temporarily unavailable."},503);
 try{
  const sql=neon(env.DATABASE_URL);
  const user=await getAuthenticatedUser(sql,request);
  if(!user)return json({error:"Sign in to view your private analysis history."},401);
  const rows=await sql`SELECT id,channel,risk_score,risk_level,signals,created_at
    FROM channel_analyses WHERE user_id=${user.id}
    ORDER BY created_at DESC LIMIT 30`;
  return json({analyses:rows});
 }catch(error){console.error("CHANNEL_ANALYSIS_HISTORY_FAILED",error instanceof Error?error.name:"UnknownError");return json({error:"Could not load analysis history."},503);}
};
