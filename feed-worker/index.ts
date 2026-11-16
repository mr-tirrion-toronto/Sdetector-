import { neon } from "@neondatabase/serverless";

interface Env {
  DATABASE_URL?: string;
  URLHAUS_AUTH_KEY?: string;
  PHISHTANK_APP_KEY?: string;
}

interface Indicator {
  indicator_hash: string;
  source_id: string | null;
  hostname: string;
  threat_type: string;
  target: string | null;
  source_updated_at: string | null;
}

const MAX_FEED_BYTES = 64 * 1024 * 1024;
const BATCH_SIZE = 250;
const INDICATOR_TTL_HOURS = 48;
const USER_AGENT = "ScamDetector/1.0 (defensive phishing and malware URL intelligence; https://scam-detector-a92.pages.dev/)";

export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field.replace(/\r$/, ""));
      if (row.some(value => value.length > 0)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }

  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ""));
    if (row.some(value => value.length > 0)) rows.push(row);
  }
  return rows;
}

export function csvObjects(input: string): Record<string, string>[] {
  const lines = input.split(/\r?\n/);
  const headerIndex = lines.findIndex(line => {
    const trimmed = line.trimStart();
    const candidate = (trimmed.startsWith("#") ? trimmed.slice(1).trimStart() : trimmed).toLowerCase();
    return candidate.startsWith("id,dateadded,url,") || candidate.startsWith("phish_id,url,");
  });
  if (headerIndex < 0) return [];

  const headerLine = lines[headerIndex].trimStart();
  const header = headerLine.startsWith("#") ? headerLine.slice(1).trimStart() : headerLine;
  const dataLines = lines.slice(headerIndex + 1)
    .filter(line => line.trim().length > 0 && !line.trimStart().startsWith("#"));
  const rows = parseCsv([header, ...dataLines].join("\n"));
  if (!rows.length) return [];

  const headers = rows[0].map(value => value.trim().toLowerCase());
  return rows.slice(1).map(values => {
    const item: Record<string, string> = {};
    headers.forEach((name, index) => item[name] = (values[index] ?? "").trim());
    return item;
  });
}
export function canonicalUrl(raw: string): { value: string; hostname: string } | null {
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (!url.hostname || url.hostname.length > 253) return null;
    url.username = "";
    url.password = "";
    url.hash = "";
    return { value: url.toString(), hostname: url.hostname.toLowerCase() };
  } catch {
    return null;
  }
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function readBounded(response: Response, maxBytes = MAX_FEED_BYTES): Promise<string> {
  if (!response.body) throw new Error("EMPTY_FEED_BODY");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let output = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("FEED_TOO_LARGE");
      }
      output += decoder.decode(value, { stream: true });
    }
    output += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  return output;
}

async function setFeedStatus(
  sql: any,
  source: "urlhaus" | "phishtank" | "phishunt",
  status: "ok" | "error" | "not_configured",
  details: { etag?: string | null; itemCount?: number; errorCode?: string; success?: boolean } = {}
): Promise<void> {
  await sql`
    INSERT INTO threat_feed_status
      (source, status, last_checked_at, last_success_at, etag, item_count, error_code)
    VALUES (
      ${source}, ${status}, NOW(),
      CASE WHEN ${Boolean(details.success)} THEN NOW() ELSE NULL END,
      ${details.etag ?? null}, ${details.itemCount ?? 0}, ${details.errorCode ?? null}
    )
    ON CONFLICT (source) DO UPDATE SET
      status = EXCLUDED.status,
      last_checked_at = NOW(),
      last_success_at = CASE WHEN ${Boolean(details.success)}
        THEN NOW() ELSE threat_feed_status.last_success_at END,
      etag = COALESCE(EXCLUDED.etag, threat_feed_status.etag),
      item_count = CASE WHEN ${details.success}
        THEN EXCLUDED.item_count ELSE threat_feed_status.item_count END,
      error_code = EXCLUDED.error_code
  `;
}

async function getFeedState(sql: any, source: "urlhaus" | "phishtank" | "phishunt") {
  const rows = await sql`
    SELECT etag, last_success_at, last_checked_at, item_count
    FROM threat_feed_status WHERE source = ${source}
  `;
  return (rows as unknown as Array<{ etag?: string | null; last_success_at?: string | null; last_checked_at?: string | null; item_count?: number }>)[0];
}

async function upsertIndicators(
  sql: any,
  source: "urlhaus" | "phishtank" | "phishunt",
  indicators: Indicator[]
): Promise<void> {
  for (let offset = 0; offset < indicators.length; offset += BATCH_SIZE) {
    const batch = indicators.slice(offset, offset + BATCH_SIZE);
    const json = JSON.stringify(batch);
    await sql`
      INSERT INTO threat_indicators
        (source, indicator_hash, source_id, hostname, threat_type, target,
         source_updated_at, imported_at, expires_at)
      SELECT
        ${source}, row.indicator_hash, row.source_id, row.hostname,
        row.threat_type, row.target, row.source_updated_at, NOW(),
        NOW() + (${INDICATOR_TTL_HOURS} * INTERVAL '1 hour')
      FROM jsonb_to_recordset(${json}::jsonb) AS row(
        indicator_hash TEXT, source_id TEXT, hostname TEXT, threat_type TEXT,
        target TEXT, source_updated_at TIMESTAMPTZ
      )
      ON CONFLICT (source, indicator_hash) DO UPDATE SET
        source_id = EXCLUDED.source_id,
        hostname = EXCLUDED.hostname,
        threat_type = EXCLUDED.threat_type,
        target = EXCLUDED.target,
        source_updated_at = EXCLUDED.source_updated_at,
        imported_at = NOW(),
        expires_at = NOW() + (${INDICATOR_TTL_HOURS} * INTERVAL '1 hour')
    `;
  }
}

async function makeIndicators(
  source: "urlhaus" | "phishtank",
  records: Record<string, string>[]
): Promise<Indicator[]> {
  const result: Indicator[] = [];
  const seen = new Set<string>();

  for (const record of records) {
    const rawUrl = record.url;
    if (!rawUrl) continue;

    if (source === "urlhaus" && record.url_status && record.url_status.toLowerCase() !== "online") continue;
    if (source === "phishtank" &&
        (record.verified?.toLowerCase() !== "yes" || record.online?.toLowerCase() !== "yes")) continue;

    const canonical = canonicalUrl(rawUrl);
    if (!canonical) continue;
    const indicatorHash = await sha256(canonical.value);
    if (seen.has(indicatorHash)) continue;
    seen.add(indicatorHash);

    result.push({
      indicator_hash: indicatorHash,
      source_id: source === "urlhaus" ? (record.id || null) : (record.phish_id || null),
      hostname: canonical.hostname,
      threat_type: source === "urlhaus" ? (record.threat || "malware") : "phishing",
      target: source === "phishtank" ? (record.target || null) : null,
      source_updated_at: source === "urlhaus"
        ? (record.dateadded || null)
        : (record.verification_time || record.submission_time || null)
    });
  }
  return result;
}

export async function makePhishuntIndicators(input: string): Promise<Indicator[]> {
  const result: Indicator[] = [];
  const seen = new Set<string>();
  for (const line of input.split(/\\r?\\n/)) {
    const value = line.trim();
    if (!value || value.startsWith("#")) continue;
    const canonical = canonicalUrl(value.includes("://") ? value : "https://" + value);
    if (!canonical || !canonical.hostname.includes(".")) continue;
    const hostname = canonical.hostname.toLowerCase().replace(/\\.$/, "");
    if (/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(hostname) ||
        hostname === "localhost" || hostname.endsWith(".local")) continue;
    const indicatorHash = await sha256("domain:" + hostname);
    if (seen.has(indicatorHash)) continue;
    seen.add(indicatorHash);
    result.push({
      indicator_hash: indicatorHash,
      source_id: null,
      hostname,
      threat_type: "phishing_domain",
      target: null,
      source_updated_at: null
    });
  }
  return result;
}

async function syncUrlhaus(sql: any, key?: string): Promise<void> {
  if (!key) {
    await setFeedStatus(sql, "urlhaus", "not_configured", { errorCode: "MISSING_AUTH_KEY" });
    return;
  }
  if (!/^[A-Za-z0-9_-]{12,128}$/.test(key)) {
    await setFeedStatus(sql, "urlhaus", "error", { errorCode: "INVALID_AUTH_KEY_FORMAT" });
    return;
  }

  try {
    const endpoint = "https://urlhaus-api.abuse.ch/v2/files/exports/" +
      encodeURIComponent(key) + "/recent.csv";
    const state = await getFeedState(sql, "urlhaus");
    const response = await fetch(endpoint, {
      headers: { "user-agent": USER_AGENT, "accept": "text/csv", ...(state?.etag ? { "if-none-match": state.etag } : {}) },
      signal: AbortSignal.timeout(25000),
      redirect: "error"
    });
    if (response.status === 304) {
      await setFeedStatus(sql, "urlhaus", "ok", { etag: state?.etag, itemCount: Number(state?.item_count ?? 0), success: true });
      return;
    }
    if (!response.ok) throw new Error("HTTP_" + response.status);

    const etag = response.headers.get("etag");
    const body = await readBounded(response);
    const records = csvObjects(body);
    const indicators = await makeIndicators("urlhaus", records);
    if (!indicators.length) throw new Error("EMPTY_OR_UNRECOGNIZED_FEED");

    await upsertIndicators(sql, "urlhaus", indicators);
    await setFeedStatus(sql, "urlhaus", "ok", {
      etag, itemCount: indicators.length, success: true
    });
  } catch (error) {
    await setFeedStatus(sql, "urlhaus", "error", {
      errorCode: error instanceof Error ? error.message.slice(0, 80) : "UNKNOWN_ERROR"
    });
  }
}

async function syncPhishTank(sql: any, key?: string): Promise<void> {
  if (!key) {
    await setFeedStatus(sql, "phishtank", "not_configured", { errorCode: "MISSING_APP_KEY" });
    return;
  }
  if (!/^[A-Za-z0-9_-]{12,128}$/.test(key)) {
    await setFeedStatus(sql, "phishtank", "error", { errorCode: "INVALID_APP_KEY_FORMAT" });
    return;
  }

  const endpoint = "https://data.phishtank.com/data/" + encodeURIComponent(key) + "/online-valid.csv.gz";
  try {
    const state = await getFeedState(sql, "phishtank");
    const head = await fetch(endpoint, {
      method: "HEAD",
      headers: { "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(12000),
      redirect: "error"
    });

    if (!head.ok) throw new Error("HEAD_HTTP_" + head.status);
    const etag = head.headers.get("etag");
    const lastSuccess = state?.last_success_at ? new Date(state.last_success_at).getTime() : 0;
    const recentlySyncedWithoutEtag = !etag && lastSuccess > 0 && Date.now() - lastSuccess < 60 * 60 * 1000;
    if ((etag && state?.etag === etag && state?.last_success_at) || recentlySyncedWithoutEtag) {
      await setFeedStatus(sql, "phishtank", "ok", { etag: etag ?? state?.etag, itemCount: Number(state?.item_count ?? 0), success: Boolean(etag && state?.etag === etag) });
      return;
    }

    const response = await fetch(endpoint, {
      headers: { "user-agent": USER_AGENT, "accept": "application/gzip" },
      signal: AbortSignal.timeout(30000),
      redirect: "error"
    });
    if (!response.ok) throw new Error("GET_HTTP_" + response.status);

    const compressed = response.body;
    if (!compressed) throw new Error("EMPTY_FEED_BODY");
    const decompressed = compressed.pipeThrough(new DecompressionStream("gzip"));
    const text = await readBounded(new Response(decompressed));
    const records = csvObjects(text);
    const indicators = await makeIndicators("phishtank", records);
    if (!indicators.length) throw new Error("EMPTY_OR_UNRECOGNIZED_FEED");

    await upsertIndicators(sql, "phishtank", indicators);
    await setFeedStatus(sql, "phishtank", "ok", {
      etag: etag ?? response.headers.get("etag"),
      itemCount: indicators.length,
      success: true
    });
  } catch (error) {
    await setFeedStatus(sql, "phishtank", "error", {
      errorCode: error instanceof Error ? error.message.slice(0, 80) : "UNKNOWN_ERROR"
    });
  }
}

async function syncPhishunt(sql: any): Promise<void> {
  const source = "phishunt";
  const endpoint = "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.txt";
  try {
    const state = await getFeedState(sql, source);
    const response = await fetch(endpoint, {
      headers: {
        "user-agent": USER_AGENT,
        "accept": "text/plain",
        ...(state?.etag ? { "if-none-match": state.etag } : {})
      },
      signal: AbortSignal.timeout(20000),
      redirect: "error"
    });
    if (response.status === 304) {
      await setFeedStatus(sql, source, "ok", {
        etag: state?.etag,
        itemCount: Number(state?.item_count ?? 0),
        success: true
      });
      return;
    }
    if (!response.ok) throw new Error("HTTP_" + response.status);
    const body = await readBounded(response, 8 * 1024 * 1024);
    const indicators = await makePhishuntIndicators(body);
    if (!indicators.length) throw new Error("EMPTY_OR_UNRECOGNIZED_FEED");
    await upsertIndicators(sql, source, indicators);
    await setFeedStatus(sql, source, "ok", {
      etag: response.headers.get("etag"),
      itemCount: indicators.length,
      success: true
    });
  } catch (error) {
    await setFeedStatus(sql, source, "error", {
      errorCode: error instanceof Error ? error.message.slice(0, 80) : "UNKNOWN_ERROR"
    });
  }
}

async function runSync(env: Env): Promise<void> {
  if (!env.DATABASE_URL) throw new Error("DATABASE_URL_NOT_CONFIGURED");
  const sql = neon(env.DATABASE_URL);

  await Promise.all([
    syncUrlhaus(sql, env.URLHAUS_AUTH_KEY),
    syncPhishTank(sql, env.PHISHTANK_APP_KEY),
    syncPhishunt(sql)
  ]);

  await sql`DELETE FROM threat_indicators WHERE expires_at < NOW() - INTERVAL '7 days'`;
}

export default {
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runSync(env));
  }
};
