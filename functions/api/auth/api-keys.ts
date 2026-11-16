import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, isSameOriginMutation, json, randomToken, sha256 } from "../../../src/auth";
interface Env { DATABASE_URL?: string }
export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  if (!env.DATABASE_URL) return json({ error: "API key service is unavailable." }, 503);
  try {
    const sql = neon(env.DATABASE_URL);
    const user = await getAuthenticatedUser(sql, request);
    if (!user || user.authType !== "session") return json({ error: "Sign in to manage API keys." }, 401);
    const rows = await sql`SELECT id, name, key_prefix, created_at, last_used_at, revoked_at FROM user_api_keys WHERE user_id = ${user.id} ORDER BY created_at DESC LIMIT 50`;
    return json({ keys: rows });
  } catch { return json({ error: "Could not load API keys." }, 503); }
};
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Request origin was not accepted." }, 403);
  if (!env.DATABASE_URL) return json({ error: "API key service is unavailable." }, 503);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Send valid JSON." }, 400); }
  const name = String((body as any)?.name ?? "").trim();
  if (!name || name.length > 60) return json({ error: "Give this key a name (1–60 characters)." }, 400);
  try {
    const sql = neon(env.DATABASE_URL);
    const user = await getAuthenticatedUser(sql, request);
    if (!user || user.authType !== "session") return json({ error: "Sign in to create API keys." }, 401);
    const countRows = await sql`SELECT COUNT(*)::int AS count FROM user_api_keys WHERE user_id = ${user.id} AND revoked_at IS NULL`;
    if (Number((countRows as Array<{count:number}>)[0]?.count ?? 0) >= 10) return json({ error: "You can have up to 10 active API keys. Revoke one first." }, 409);
    const secret = "sd_live_" + randomToken(32);
    const id = crypto.randomUUID();
    await sql`INSERT INTO user_api_keys (id, user_id, name, key_prefix, key_hash) VALUES (${id}, ${user.id}, ${name}, ${secret.slice(0, 16)}, ${await sha256(secret)})`;
    return json({ key: secret, id, name, message: "Copy this key now. It will not be shown again." }, 201);
  } catch { return json({ error: "Could not create API key." }, 503); }
};
export const onRequestDelete: PagesFunction<Env> = async ({ request, env }) => {
  if (!isSameOriginMutation(request)) return json({ error: "Request origin was not accepted." }, 403);
  if (!env.DATABASE_URL) return json({ error: "API key service is unavailable." }, 503);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Send valid JSON." }, 400); }
  const id = String((body as any)?.id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid key identifier." }, 400);
  try {
    const sql = neon(env.DATABASE_URL);
    const user = await getAuthenticatedUser(sql, request);
    if (!user || user.authType !== "session") return json({ error: "Sign in to revoke API keys." }, 401);
    await sql`UPDATE user_api_keys SET revoked_at = NOW() WHERE id = ${id} AND user_id = ${user.id} AND revoked_at IS NULL`;
    return json({ message: "API key revoked." });
  } catch { return json({ error: "Could not revoke API key." }, 503); }
};
