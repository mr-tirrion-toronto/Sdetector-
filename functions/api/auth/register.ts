import { neon } from "@neondatabase/serverless";
import { authRateAllowed, createSession, hashPassword, isSameOriginMutation, json, newSalt, passwordPolicyError, sessionCookie } from "../../../src/auth";

interface Env { DATABASE_URL?: string }
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Request origin was not accepted." }, 403);
  if (!env.DATABASE_URL) return json({ error: "Account service is unavailable." }, 503);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Send valid JSON." }, 400); }
  if (!body || typeof body !== "object") return json({ error: "Invalid account details." }, 400);
  const email = String((body as any).email ?? "").trim().toLowerCase();
  const password = String((body as any).password ?? "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Enter a valid email address." }, 400);
  const passwordError = passwordPolicyError(password, email);
  if (passwordError) return json({ error: passwordError }, 400);
  const sql = neon(env.DATABASE_URL);
  let stage = "rate_limit";
  try {
    if (!(await authRateAllowed(sql, request, "register"))) return json({ error: "Too many signup attempts. Try again in 15 minutes." }, 429);
    stage = "password_hash";
    const salt = newSalt();
    const passwordHash = await hashPassword(password, salt);
    stage = "account_insert";
    const userId = crypto.randomUUID();
    await sql`INSERT INTO app_users (id, email, password_hash, password_salt) VALUES (${userId}, ${email}, ${passwordHash}, ${salt})`;
    stage = "session_create";
    const token = await createSession(sql, userId);
    return json({ user: { id: userId, email }, message: "Account created. You are signed in." }, 201, { "set-cookie": sessionCookie(token) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/unique|duplicate/i.test(message)) return json({ error: "An account with this email already exists." }, 409);
    console.error("ACCOUNT_REGISTER_FAILED", stage, error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Account could not be created. Please retry.", code: "ACCOUNT_CREATE_" + stage.toUpperCase() }, 500);
  }
};