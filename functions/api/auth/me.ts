import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, json } from "../../../src/auth";
interface Env { DATABASE_URL?: string }
export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  if (!env.DATABASE_URL) return json({ authenticated: false }, 503);
  try {
    const sql = neon(env.DATABASE_URL);
    const user = await getAuthenticatedUser(sql, request);
    return json({ authenticated: Boolean(user), user: user ? { id: user.id, email: user.email } : null });
  } catch { return json({ authenticated: false }, 503); }
};
