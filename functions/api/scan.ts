import { neon } from "@neondatabase/serverless";
import { analyzeUrl } from "../../src/analyzer";

interface Env {
  DATABASE_URL?: string;
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer"
    }
  });
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > 4096) {
    return json({ error: "Request body is too large." }, 413);
  }

  let rawBody: string;
  try {
    rawBody = await request.text();
  } catch {
    return json({ error: "Could not read request body." }, 400);
  }

  if (new TextEncoder().encode(rawBody).byteLength > 4096) {
    return json({ error: "Request body is too large." }, 413);
  }

  let body: unknown;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: "Request body must be valid JSON." }, 400);
  }

  if (
    !body ||
    typeof body !== "object" ||
    !("url" in body) ||
    typeof (body as { url?: unknown }).url !== "string"
  ) {
    return json({ error: "Provide a URL string in the 'url' field." }, 400);
  }

  let result;
  try {
    result = analyzeUrl((body as { url: string }).url);
  } catch (error) {
    return json(
      { error: error instanceof Error ? error.message : "URL analysis failed." },
      400
    );
  }

  const scanId = crypto.randomUUID();
  let saved = false;

  if (env.DATABASE_URL) {
    try {
      const sql = neon(env.DATABASE_URL);
      await sql`INSERT INTO scans
        (id, input_url, normalized_url, hostname, risk_score, risk_level, created_at)
        VALUES (${scanId}, ${result.inputUrl}, ${result.normalizedUrl},
          ${result.hostname}, ${result.score}, ${result.riskLevel}, NOW())`;

      for (const finding of result.findings) {
        await sql`INSERT INTO scan_findings
          (scan_id, code, title, severity, points, evidence, recommendation)
          VALUES (${scanId}, ${finding.code}, ${finding.title},
            ${finding.severity}, ${finding.points}, ${finding.evidence},
            ${finding.recommendation})`;
      }
      saved = true;
    } catch (error) {
      // Keep credentials and raw database errors out of public responses; retain diagnostics in server logs.
      console.error("DATABASE_SCAN_WRITE_FAILED", error);
    }
  }

  return json({
    scanId,
    ...result,
    persistence: saved ? "saved" : "not_configured_or_unavailable"
  });
};
