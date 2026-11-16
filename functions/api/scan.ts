import { neon } from "@neondatabase/serverless";
import { analyzeUrl } from "../../src/analyzer";
import { lookupThreatIntelligence } from "../../src/threat-intel";
import { investigateDomain } from "../../src/domain-intel";
import { inspectLiveDomain, type TlsData } from "../../src/live-inspection";
import { getAuthenticatedUser } from "../../src/auth";

interface Env {
  DATABASE_URL?: string;
}

const BODY_LIMIT = 4096;
const RATE_WINDOW_SECONDS = 600;
const RATE_LIMIT = 20;
const SIGNAL_LABELS: Record<string, string> = {
  brand_in_name: "A known brand name appears in the domain",
  brand_with_scam_terms: "A brand name is combined with scam-related wording",
  scam_terms: "The domain contains scam-related wording",
  lookalike_of_known_phishing: "The domain resembles a known phishing site",
  shared_name_pattern: "The domain shares a naming pattern with known threats",
  phishing_infrastructure_ip: "The hosting IP is associated with phishing infrastructure",
  high_risk_tld: "The domain uses a higher-risk top-level domain",
  brand_homoglyph: "The domain may imitate a brand using lookalike characters",
  newly_registered: "The domain appears newly registered"
};

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

  if (!env.DATABASE_URL) {
    return json({ error: "Scanner storage and abuse protection are temporarily unavailable." }, 503);
  }

  const scanId = crypto.randomUUID();
  const sql = neon(env.DATABASE_URL);
  let authUser: Awaited<ReturnType<typeof getAuthenticatedUser>> = null;
  try { authUser = await getAuthenticatedUser(sql, request); }
  catch { return json({ error: "Authentication service is temporarily unavailable." }, 503); }
  if ((request.headers.get("Authorization") ?? "").startsWith("Bearer ") && !authUser) {
    return json({ error: "The supplied API key is invalid or revoked." }, 401);
  }

  try {
    if (!(await applyRateLimit(sql, request))) {
      return json(
        { error: "Scan limit reached. Please wait a few minutes before trying again." },
        429,
        { "retry-after": String(RATE_WINDOW_SECONDS) }
      );
    }
  } catch (error) {
    console.error("SCAN_RATE_LIMIT_UNAVAILABLE", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Scanner is temporarily unavailable. Please try again shortly." }, 503);
  }

  let threatIntelligence = {
    status: "unavailable" as "available" | "partial" | "unavailable" | "not_configured",
    matched: false,
    feeds: [] as Array<{ source: string; status: string; lastUpdatedAt: string | null; itemCount: number }>,
    findings: [] as typeof result.findings
  };

  let cachedTls: TlsData | null = null;
  try {
    const cacheRows = await sql`SELECT tls_data FROM domain_tls_cache WHERE hostname = ${result.hostname} AND expires_at > NOW() LIMIT 1`;
    const cachedCandidate = (cacheRows as Array<{tls_data:TlsData}>)[0]?.tls_data ?? null;
    if (cachedCandidate && Array.isArray(cachedCandidate.subjectAltNames) &&
      Object.prototype.hasOwnProperty.call(cachedCandidate, "hostnameMatch")) {
      cachedTls = cachedCandidate;
    }
  } catch (error) {
    console.error("TLS_CACHE_READ_FAILED", error instanceof Error ? error.name : "UnknownError");
  }

  const [localIntelResult, domainIntelResult, liveInspectionResult] = await Promise.allSettled([
    lookupThreatIntelligence(sql, result.normalizedUrl),
    investigateDomain(result.hostname),
    inspectLiveDomain(result.inputUrl, result.hostname, fetch, cachedTls)
  ]);
  if (localIntelResult.status === "fulfilled") {
    threatIntelligence = localIntelResult.value;
  } else {
    console.error("THREAT_INTELLIGENCE_LOOKUP_FAILED",
      localIntelResult.reason instanceof Error ? localIntelResult.reason.name : "UnknownError");
  }
  const domainIntelligence = domainIntelResult.status === "fulfilled"
    ? domainIntelResult.value
    : { status: "unavailable" as const, errorCode: "LOOKUP_FAILED", checkedAt: null, verdict: null, assessment: null,
        infrastructure: null, registration: null, campaign: null, related: [] };

  const liveInspection = liveInspectionResult.status === "fulfilled" ? liveInspectionResult.value : null;
  if (!cachedTls && liveInspection?.tls.status === "available" && liveInspection.tls.data) {
    try {
      await sql`INSERT INTO domain_tls_cache (hostname, tls_data, checked_at, expires_at, updated_at)
        VALUES (${result.hostname}, ${JSON.stringify(liveInspection.tls.data)}::jsonb, NOW(), NOW() + INTERVAL '12 hours', NOW())
        ON CONFLICT (hostname) DO UPDATE SET tls_data = EXCLUDED.tls_data, checked_at = NOW(),
          expires_at = NOW() + INTERVAL '12 hours', updated_at = NOW()`;
    } catch (error) {
      console.error("TLS_CACHE_WRITE_FAILED", error instanceof Error ? error.name : "UnknownError");
    }
  }
  const externalConfirmed = domainIntelligence.status === "available" &&
    domainIntelligence.verdict?.threat === true;
  const findings = [...result.findings, ...threatIntelligence.findings, ...(liveInspection?.findings ?? [])];
  if (externalConfirmed) {
    findings.push({
      code: "PHISHDESTROY_CONFIRMED_THREAT",
      title: "Domain is listed as a confirmed threat",
      severity: "high",
      points: 100,
      evidence: "PhishDestroy lists " +
        (domainIntelligence.verdict?.matchedDomain ?? result.hostname) +
        " as a threat" +
        (domainIntelligence.verdict?.listedSince ? " since " + domainIntelligence.verdict.listedSince : "") +
        (domainIntelligence.verdict?.liveness ? "; last known state: " + domainIntelligence.verdict.liveness : "") + ".",
      recommendation: "Do not visit this website or enter credentials. Verify any claimed organisation through its official website or a separate trusted channel."
    });
  } else if (domainIntelligence.status === "available" &&
      domainIntelligence.assessment && domainIntelligence.assessment.score >= 20) {
    const assessment = domainIntelligence.assessment;
    findings.push({
      code: "PHISHDESTROY_RISK_PATTERN",
      title: "Domain has suspicious threat-pattern signals",
      severity: assessment.risk === "high" ? "high" : assessment.risk === "elevated" ? "medium" : "low",
      points: Math.min(35, Math.max(5, Math.round(assessment.score * 0.35))),
      evidence: "PhishDestroy risk-pattern score: " + assessment.score + "/" + assessment.maxScore + ". Signals: " +
        (assessment.signals.map(signal => SIGNAL_LABELS[signal] ?? signal.replace(/_/g, " ")).join("; ") || "pattern analysis") + ". This is a prediction, not a confirmed blocklist match.",
      recommendation: "Verify the exact domain independently. Do not rely on the sender's message or enter credentials until the destination is confirmed."
    });
  }

  const confirmedThreat = threatIntelligence.matched || externalConfirmed;
  const externalScore = domainIntelligence.status === "available"
    ? Math.round((Number(domainIntelligence.assessment?.score ?? domainIntelligence.verdict?.riskScore ?? 0) /
        Number(domainIntelligence.assessment?.maxScore ?? 100)) * 100)
    : 0;
  const livePoints = (liveInspection?.findings ?? []).reduce((total, finding) => total + finding.points, 0);
  const score = confirmedThreat ? 100 : Math.min(100, Math.max(result.score, Math.min(100, externalScore)) + livePoints);
  const riskLevel = score >= 70 ? "critical" : score >= 40 ? "high" : score >= 20 ? "guarded" : "low";
  let assessmentStatus:
    | "known_threat_detected"
    | "no_known_threat_match"
    | "threat_intel_partial"
    | "threat_intel_unavailable"
    | "insufficient_evidence"
    | "preliminary_signals_detected";

  if (confirmedThreat) assessmentStatus = "known_threat_detected";
  else if (findings.some(finding => finding.points > 0)) assessmentStatus = "preliminary_signals_detected";
  else if (domainIntelligence.status === "available" ||
      threatIntelligence.status === "available") assessmentStatus = "no_known_threat_match";
  else if (threatIntelligence.status === "partial") assessmentStatus = "threat_intel_partial";
  else if (domainIntelligence.status === "rate_limited" ||
      domainIntelligence.status === "unavailable" || threatIntelligence.status === "unavailable") {
    assessmentStatus = "threat_intel_unavailable";
  } else assessmentStatus = "insufficient_evidence";

  const limitations = [...result.limitations];
  if (threatIntelligence.status === "not_configured") {
    limitations.push("Scheduled local threat-intelligence feeds are not configured yet.");
  } else if (threatIntelligence.status === "partial" || threatIntelligence.status === "unavailable") {
    limitations.push("One or more scheduled threat-intelligence feeds are unavailable or stale. A missing match is not conclusive.");
  }
  if (liveInspection) limitations.push(...liveInspection.limitations);
  else limitations.push("Live DNS, certificate, registration and page-content inspection could not be completed.");
  if (domainIntelligence.status === "available") {
    limitations.push("The PhishDestroy provider receives the hostname only; the submitted URL path, query string and fragment are not sent.");
    if (!confirmedThreat && findings.length === 0) {
      limitations.push("No threat listing was found by PhishDestroy at check time. An unlisted domain is not guaranteed safe.");
    }
  } else {
    limitations.push("Live domain intelligence was unavailable or rate-limited (" + (domainIntelligence.errorCode ?? "unknown") + "). This is not a clean verdict.");
  }

  const scanResult = {
    ...result,
    scanId,
    findings,
    score,
    riskLevel,
    assessmentStatus,
    confidence: confirmedThreat ? "high" : domainIntelligence.assessment && domainIntelligence.assessment.score >= 20 ? "moderate" : "limited",
    limitations,
    threatIntelligence,
    domainIntelligence,
    liveInspection
  };

  let saved = false;
  try {
    const storedUrl = redactUrlForStorage(result.inputUrl);
    const findingsJson = JSON.stringify(findings);
    await sql`
      WITH inserted_scan AS (
        INSERT INTO scans
          (id, user_id, input_url, normalized_url, hostname, risk_score, risk_level, created_at)
        VALUES
          (${scanId}, ${authUser?.id ?? null}, ${storedUrl}, ${storedUrl}, ${result.hostname},
           ${score}, ${riskLevel}, NOW())
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

  return json({
    ...scanResult,
    persistence: saved ? "saved" : "not_configured_or_unavailable"
  });
};
