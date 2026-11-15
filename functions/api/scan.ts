import { neon } from "@neondatabase/serverless";
import { analyzeUrl } from "../../src/analyzer";

interface Env {
  DATABASE_URL?: string;
}

const BODY_LIMIT = 4096;
const RATE_WINDOW_SECONDS = 600;
const RATE_LIMIT = 20;

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...extraHeaders
    }
  });
}

async function readBodyLimited(request: Request): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > BODY_LIMIT) {
        await reader.cancel();
        throw new Error("BODY_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

function redactUrlForStorage(rawUrl: string): string {
  const url = new URL(rawUrl);
  url.username = "";
  url.password = "";
  url.hash = "";
  const sensitiveKeys = new Set([
    "token", "access_token", "refresh_token", "auth", "authorization",
    "code", "state", "session", "sessionid", "sid", "key", "api_key",
    "password", "passwd", "email", "phone", "otp", "secret", "signature",
    "sig", "jwt", "reset", "verification"
  ]);
  for (const key of new Set(Array.from(url.searchParams.keys()))) {
    if (sensitiveKeys.has(key.toLowerCase())) url.searchParams.set(key, "[REDACTED]");
  }
  return url.toString();
}

async function applyRateLimit(sql: any, request: Request): Promise<boolean> {
  const clientIp = request.headers.get("CF-Connecting-IP");
  if (!clientIp) return true; // Local development may not provide Cloudflare's client-IP header.

  const window = Math.floor(Date.now() / (RATE_WINDOW_SECONDS * 1000));
  const material = new TextEncoder().encode(clientIp + ":" + window);
  const digest = await crypto.subtle.digest("SHA-256", material);
  const bucketKey = Array.from(new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, "0")).join("");

  const rows = await sql`
    INSERT INTO scan_rate_limits (bucket_key, request_count, created_at)
    VALUES (${bucketKey}, 1, NOW())
    ON CONFLICT (bucket_key)
    DO UPDATE SET request_count = scan_rate_limits.request_count + 1
    RETURNING request_count
  `;

  const count = Number((rows as unknown as Array<{ request_count: number }>)[0]?.request_count ?? 0);
  if (count === 1 && window % 6 === 0) {
    await sql`DELETE FROM scan_rate_limits WHERE created_at < NOW() - INTERVAL '1 day'`;
  }
  return count <= RATE_LIMIT;
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > BODY_LIMIT) {
    return json({ error: "Request body is too large." }, 413);
  }

  let rawBody: string;
  try {
    rawBody = await readBodyLimited(request);
  } catch (error) {
    if (error instanceof Error && error.message === "BODY_TOO_LARGE") {
      return json({ error: "Request body is too large." }, 413);
    }
    return json({ error: "Could not read request body." }, 400);
  }

  let body: unknown;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: "Request body must be valid JSON." }, 400);
  }

  if (!body || typeof body !== "object" || !("url" in body) ||
      typeof (body as { url?: unknown }).url !== "string") {
    return json({ error: "Provide a URL string in the 'url' field." }, 400);
  }

  let result;
  try {
    result = analyzeUrl((body as { url: string }).url);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "URL analysis failed." }, 400);
  }

  const scanId = crypto.randomUUID();
  let saved = false;

  if (env.DATABASE_URL) {
    try {
      const sql = neon(env.DATABASE_URL);
      if (!(await applyRateLimit(sql, request))) {
        return json(
          { error: "Scan limit reached. Please wait a few minutes before trying again." },
          429,
          { "retry-after": String(RATE_WINDOW_SECONDS) }
        );
      }

      const storedUrl = redactUrlForStorage(result.inputUrl);
      const findingsJson = JSON.stringify(result.findings);
      await sql`
        WITH inserted_scan AS (
          INSERT INTO scans
            (id, input_url, normalized_url, hostname, risk_score, risk_level, created_at)
          VALUES
            (${scanId}, ${storedUrl}, ${storedUrl}, ${result.hostname},
             ${result.score}, ${result.riskLevel}, NOW())
          RETURNING id
        ),
        inserted_findings AS (
          INSERT INTO scan_findings
            (scan_id, code, title, severity, points, evidence, recommendation)
          SELECT inserted_scan.id, finding.code, finding.title, finding.severity,
                 finding.points, finding.evidence, finding.recommendation
          FROM inserted_scan
          CROSS JOIN LATERAL jsonb_to_recordset(${findingsJson}::jsonb)
            AS finding(code TEXT, title TEXT, severity TEXT, points INTEGER,
                       evidence TEXT, recommendation TEXT)
          RETURNING id
        )
        SELECT
          (SELECT COUNT(*) FROM inserted_scan) AS scans_saved,
          (SELECT COUNT(*) FROM inserted_findings) AS findings_saved
      `;
      saved = true;
    } catch (error) {
      console.error("SCAN_PERSISTENCE_FAILED", error instanceof Error ? error.name : "UnknownError");
    }
  }

  return json({
    scanId,
    ...result,
    persistence: saved ? "saved" : "not_configured_or_unavailable"
  });
};
