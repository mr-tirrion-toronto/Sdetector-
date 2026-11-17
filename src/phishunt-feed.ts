import { sha256 } from "./auth";

interface Indicator {
  indicator_hash: string;
  source_id: string | null;
  hostname: string;
  threat_type: string;
  target: string | null;
  source_updated_at: string | null;
}

const MAX_FEED_BYTES = 8 * 1024 * 1024;
const BATCH_SIZE = 250;
const INDICATOR_TTL_HOURS = 48;
const USER_AGENT = "ScamDetector/1.0 (defensive phishing intelligence; https://scam-detector-a92.pages.dev/)";

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function readBounded(response: Response): Promise<string> {
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
      if (total > MAX_FEED_BYTES) {
        await reader.cancel();
        throw new Error("FEED_TOO_LARGE");
      }
      output += decoder.decode(value, { stream: true });
    }
    return output + decoder.decode();
  } finally {
    reader.releaseLock();
  }
}

function canonicalHostname(raw: string): string | null {
  try {
    const url = new URL(raw.trim().includes("://") ? raw.trim() : "https://" + raw.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!hostname.includes(".") || hostname.length > 253 || hostname === "localhost" ||
      hostname.endsWith(".local") || hostname.endsWith(".internal") ||
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
    return hostname;
  } catch {
    return null;
  }
}

async function getFeedState(sql: any) {
  const rows = await sql`
    SELECT etag, last_success_at, last_checked_at, item_count
    FROM threat_feed_status WHERE source = 'phishunt'
  `;
  return (rows as Array<{etag?:string|null;last_success_at?:string|null;last_checked_at?:string|null;item_count?:number}>)[0];
}

async function setFeedStatus(
  sql: any,
  status: "ok" | "error",
  details: { etag?: string | null; itemCount?: number; errorCode?: string; success?: boolean } = {}
): Promise<void> {
  await sql`
    INSERT INTO threat_feed_status
      (source, status, last_checked_at, last_success_at, etag, item_count, error_code)
    VALUES (
      'phishunt', ${status}, NOW(),
      CASE WHEN ${Boolean(details.success)} THEN NOW() ELSE NULL END,
      ${details.etag ?? null}, ${details.itemCount ?? 0}, ${details.errorCode ?? null}
    )
    ON CONFLICT (source) DO UPDATE SET
      status = EXCLUDED.status,
      last_checked_at = NOW(),
      last_success_at = CASE WHEN ${Boolean(details.success)}
        THEN NOW() ELSE threat_feed_status.last_success_at END,
      etag = COALESCE(EXCLUDED.etag, threat_feed_status.etag),
      item_count = CASE WHEN ${Boolean(details.success)}
        THEN EXCLUDED.item_count ELSE threat_feed_status.item_count END,
      error_code = EXCLUDED.error_code
  `;
}

async function upsertIndicators(sql: any, indicators: Indicator[]): Promise<void> {
  for (let offset = 0; offset < indicators.length; offset += BATCH_SIZE) {
    const json = JSON.stringify(indicators.slice(offset, offset + BATCH_SIZE));
    await sql`
      INSERT INTO threat_indicators
        (source, indicator_hash, source_id, hostname, threat_type, target,
         source_updated_at, imported_at, expires_at)
      SELECT
        'phishunt', row.indicator_hash, row.source_id, row.hostname,
        row.threat_type, row.target, row.source_updated_at, NOW(),
        NOW() + (${INDICATOR_TTL_HOURS} * INTERVAL '1 hour')
      FROM jsonb_to_recordset(${json}::jsonb) AS row(
        indicator_hash TEXT, source_id TEXT, hostname TEXT, threat_type TEXT,
        target TEXT, source_updated_at TIMESTAMPTZ
      )
      ON CONFLICT (source, indicator_hash) DO UPDATE SET
        hostname = EXCLUDED.hostname,
        threat_type = EXCLUDED.threat_type,
        imported_at = NOW(),
        expires_at = NOW() + (${INDICATOR_TTL_HOURS} * INTERVAL '1 hour')
    `;
  }
}

export async function makePhishuntIndicators(input: string): Promise<Indicator[]> {
  const result: Indicator[] = [];
  const seen = new Set<string>();
  for (const line of input.split(/\r?\n/)) {
    const value = line.trim();
    if (!value || value.startsWith("#")) continue;
    const hostname = canonicalHostname(value);
    if (!hostname) continue;
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

export async function syncPhishuntFeed(sql: any): Promise<void> {
  const endpoint = "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.txt";
  try {
    const state = await getFeedState(sql);
    const response = await fetchWithTimeout(endpoint, {
      headers: {
        "user-agent": USER_AGENT,
        "accept": "text/plain",
        ...(state?.etag ? { "if-none-match": state.etag } : {})
      },
      redirect: "follow"
    }, 20000);
    if (response.status === 304) {
      // The unchanged ETag confirms the complete remote snapshot is still current.
      // Refresh local TTLs so healthy 304 cycles do not let all indicators expire.
      await sql`UPDATE threat_indicators SET imported_at = NOW(), expires_at = NOW() + (${INDICATOR_TTL_HOURS} * INTERVAL '1 hour') WHERE source = 'phishunt'`;
      await setFeedStatus(sql, "ok", {
        etag: state?.etag,
        itemCount: Number(state?.item_count ?? 0),
        success: true
      });
      return;
    }
    if (!response.ok) throw new Error("PHISHUNT_HTTP_" + response.status);
    const body = await readBounded(response);
    const indicators = await makePhishuntIndicators(body);
    if (!indicators.length) throw new Error("EMPTY_OR_UNRECOGNIZED_FEED");
    await upsertIndicators(sql, indicators);
    // A successful full feed response is an authoritative snapshot. Remove entries
    // absent from this snapshot so withdrawn indicators do not remain matchable
    // for the full 48-hour fallback TTL.
    const currentHashes = JSON.stringify(indicators.map(item => ({ indicator_hash: item.indicator_hash })));
    await sql`DELETE FROM threat_indicators
      WHERE source = 'phishunt'
        AND indicator_hash NOT IN (
          SELECT current.indicator_hash
          FROM jsonb_to_recordset(${currentHashes}::jsonb) AS current(indicator_hash TEXT)
        )`;
    await sql`DELETE FROM threat_indicators WHERE expires_at < NOW() - INTERVAL '7 days'`;
    await setFeedStatus(sql, "ok", {
      etag: response.headers.get("etag"),
      itemCount: indicators.length,
      success: true
    });
  } catch (error) {
    await setFeedStatus(sql, "error", {
      errorCode: error instanceof Error ? error.message.slice(0, 80) : "UNKNOWN_ERROR"
    });
  }
}
