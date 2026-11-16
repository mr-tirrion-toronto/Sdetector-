import { neon } from "@neondatabase/serverless";
import { cookieValue, isSameOriginMutation, json, SESSION_COOKIE, sha256 } from "../../../src/auth";
interface Env { DATABASE_URL?: string }
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Request origin was not accepted." }, 403);
  const token = cookieValue(request, SESSION_COOKIE);
  if (token && env.DATABASE_URL) {
    try {
      const sql = neon(env.DATABASE_URL);
      await sql`UPDATE user_sessions SET revoked_at = NOW() WHERE token_hash = ${await sha256(token)} AND revoked_at IS NULL`;
    } catch { return json({ error: "Could not end the session. Please retry." }, 503); }
  }
  return json({ message: "Signed out." }, 200, { "set-cookie": SESSION_COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
};
