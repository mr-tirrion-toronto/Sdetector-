import { neon } from "@neondatabase/serverless";
import { authRateAllowed, createSession, hashPassword, isSameOriginMutation, json, sessionCookie } from "../../../src/auth";

interface Env { DATABASE_URL?: string }
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Request origin was not accepted." }, 403);
  if (!env.DATABASE_URL) return json({ error: "Account service is unavailable." }, 503);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Send valid JSON." }, 400); }
  if (!body || typeof body !== "object") return json({ error: "Invalid login details." }, 400);
  const email = String((body as any).email ?? "").trim().toLowerCase();
  const password = String((body as any).password ?? "");
  if (email.length > 254 || password.length > 128) return json({ error: "Invalid email or password." }, 401);
  const sql = neon(env.DATABASE_URL);
  try {
    if (!(await authRateAllowed(sql, request, "login"))) return json({ error: "Too many login attempts. Try again in 15 minutes." }, 429);
    const rows = await sql`SELECT id, email, password_hash, password_salt FROM app_users WHERE LOWER(email) = ${email} AND status = 'active' LIMIT 1`;
    const user = (rows as Array<{id:string;email:string;password_hash:string;password_salt:string}>)[0];
    const candidate = user ? await hashPassword(password, user.password_salt) : await hashPassword(password || "invalid-password", "AAAAAAAAAAAAAAAAAAAAAA");
    if (!user || candidate !== user.password_hash) return json({ error: "Invalid email or password." }, 401);
    const token = await createSession(sql, user.id);
    return json({ user: { id: user.id, email: user.email }, message: "Signed in." }, 200, { "set-cookie": sessionCookie(token) });
  } catch (error) {
    console.error("ACCOUNT_LOGIN_FAILED", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Sign in is temporarily unavailable." }, 503);
  }
};
