export function passwordPolicyError(password: string, email = ""): string | null {
  if (password.length < 12 || password.length > 128) return "Use a password between 12 and 128 characters.";
  if (/(.)\1{3,}/.test(password)) return "Avoid repeating the same character four or more times.";
  const normalized = password.toLowerCase().replace(/[@]/g, "a").replace(/[0]/g, "o").replace(/[1!]/g, "i").replace(/[3]/g, "e").replace(/[4]/g, "a").replace(/[$5]/g, "s").replace(/[7]/g, "t");
  if (/(password|qwerty|letmein|welcome|admin|iloveyou|monkey|dragon|sunshine|football|baseball|master|abc123|123456|1234|abcd|bcde)/i.test(normalized)) return "Avoid common passwords and predictable sequences.";
  const emailName = email.toLowerCase().split("@")[0] ?? "";
  if (emailName.length >= 4 && password.toLowerCase().includes(emailName)) return "Do not include your email name in your password.";
  return null;
}

export interface AuthUser {
  id: string;
  email: string;
  authType: "session" | "api_key";
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
}
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
export async function sha256(value: string): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
export function randomToken(byteLength = 32): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}
export async function hashPassword(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: Uint8Array.from(atob(salt.replace(/-/g, "+").replace(/_/g, "/") + "=="), char => char.charCodeAt(0)), iterations: 100000, hash: "SHA-256" },
    key, 256
  );
  return bytesToHex(new Uint8Array(bits));
}
export function newSalt(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}
export function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return Response.json(data, { status, headers: {
    "cache-control": "no-store", "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer", "content-type": "application/json; charset=utf-8", ...extra
  }});
}
export function isSameOriginMutation(request: Request): boolean {
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return false;
  const fetchSite = request.headers.get("Sec-Fetch-Site");
  return fetchSite !== "cross-site";
}
export function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}
export const SESSION_COOKIE = "sd_session";
export const SESSION_SECONDS = 60 * 60 * 24 * 14;

export async function authRateAllowed(sql: any, request: Request, action: "register" | "login"): Promise<boolean> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "local-development";
  const bucket = await sha256(action + ":" + ip);
  const rows = await sql`
    INSERT INTO auth_rate_limits (bucket_key, action, request_count, window_started_at)
    VALUES (${bucket}, ${action}, 1, NOW())
    ON CONFLICT (bucket_key, action) DO UPDATE SET
      request_count = CASE WHEN auth_rate_limits.window_started_at < NOW() - INTERVAL '15 minutes'
        THEN 1 ELSE auth_rate_limits.request_count + 1 END,
      window_started_at = CASE WHEN auth_rate_limits.window_started_at < NOW() - INTERVAL '15 minutes'
        THEN NOW() ELSE auth_rate_limits.window_started_at END
    RETURNING request_count
  `;
  const count = Number((rows as Array<{request_count:number}>)[0]?.request_count ?? 0);
  return count <= (action === "register" ? 5 : 10);
}

export async function createSession(sql: any, userId: string): Promise<string> {
  const token = randomToken(32);
  await sql`
    INSERT INTO user_sessions (id, user_id, token_hash, expires_at)
    VALUES (${crypto.randomUUID()}, ${userId}, ${await sha256(token)}, NOW() + INTERVAL '14 days')
  `;
  return token;
}

export async function getAuthenticatedUser(sql: any, request: Request): Promise<AuthUser | null> {
  const authorization = request.headers.get("Authorization") ?? "";
  if (authorization.startsWith("Bearer ")) {
    const token = authorization.slice(7).trim();
    if (!token.startsWith("sd_live_") || token.length < 40 || token.length > 120) return null;
    const rows = await sql`
      SELECT user_id FROM user_api_keys
      WHERE key_hash = ${await sha256(token)} AND revoked_at IS NULL
    `;
    const userId = (rows as Array<{user_id:string}>)[0]?.user_id;
    if (!userId) return null;
    await sql`UPDATE user_api_keys SET last_used_at = NOW() WHERE key_hash = ${await sha256(token)}`;
    const users = await sql`SELECT id, email FROM app_users WHERE id = ${userId} AND status = 'active'`;
    const user = (users as Array<{id:string;email:string}>)[0];
    return user ? { id: user.id, email: user.email, authType: "api_key" } : null;
  }

  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || token.length > 128) return null;
  const rows = await sql`
    SELECT u.id, u.email
    FROM user_sessions s JOIN app_users u ON u.id = s.user_id
    WHERE s.token_hash = ${await sha256(token)}
      AND s.revoked_at IS NULL AND s.expires_at > NOW() AND u.status = 'active'
    LIMIT 1
  `;
  const user = (rows as Array<{id:string;email:string}>)[0];
  return user ? { id: user.id, email: user.email, authType: "session" } : null;
}
export function sessionCookie(token: string, maxAge = SESSION_SECONDS): string {
  return SESSION_COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + maxAge;
}
