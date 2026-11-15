import { neon } from "@neondatabase/serverless";
import { analyzeUrl } from "./analyzer";

interface Env {
  DATABASE_URL?: string;
  APP_ENV?: string;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/api/health") {
      return json({ status: "ok", service: "scam-detector-api", environment: env.APP_ENV ?? "unknown" });
    }

    if (request.method !== "POST" || url.pathname !== "/api/scan") {
      return json({ error: "Not found" }, 404);
    }

    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return json({ error: "Content-Type must be application/json." }, 415);
    }

    const declaredLength = Number(request.headers.get("content-length") ?? "0");
    if (declaredLength > 4096) {
      return json({ error: "Request body is too large." }, 413);
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Request body must be valid JSON." }, 400);
    }

    if (!body || typeof body !== "object" || !("url" in body) || typeof (body as {url?: unknown}).url !== "string") {
      return json({ error: "Provide a URL string in the 'url' field." }, 400);
    }

    let result;
    try {
      result = analyzeUrl((body as {url: string}).url);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "URL analysis failed." }, 400);
    }

    const scanId = crypto.randomUUID();
    let saved = false;

    if (env.DATABASE_URL) {
      try {
        const sql = neon(env.DATABASE_URL);
        await sql`INSERT INTO scans (id, input_url, normalized_url, hostname, risk_score, risk_level, created_at)
          VALUES (${scanId}, ${result.inputUrl}, ${result.normalizedUrl}, ${result.hostname}, ${result.score}, ${result.riskLevel}, NOW())`;
        for (const finding of result.findings) {
          await sql`INSERT INTO scan_findings (scan_id, code, title, severity, points, evidence, recommendation)
            VALUES (${scanId}, ${finding.code}, ${finding.title}, ${finding.severity}, ${finding.points}, ${finding.evidence}, ${finding.recommendation})`;
        }
        saved = true;
      } catch {
        // Do not expose database connection details or secrets to clients.
      }
    }

    return json({
      scanId,
      ...result,
      persistence: saved ? "saved" : "not_configured_or_unavailable"
    });
  }
};
