import { neon } from "@neondatabase/serverless";
import { syncPhishuntFeed } from "../../../src/phishunt-feed";

interface Env {
  DATABASE_URL?: string;
  FEED_SYNC_SECRET?: string;
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
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
  if (!env.FEED_SYNC_SECRET || !env.DATABASE_URL) {
    return json({ error: "Feed sync is not configured." }, 503);
  }

  const authorization = request.headers.get("Authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!supplied || !constantTimeEqual(supplied, env.FEED_SYNC_SECRET)) {
    return json({ error: "Unauthorized." }, 401);
  }

  if (!(request.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }

  const sql = neon(env.DATABASE_URL);
  try {
    const current = await sql`
      SELECT last_checked_at FROM threat_feed_status WHERE source = 'phishunt' LIMIT 1
    `;
    const lastChecked = (current as Array<{last_checked_at:string|null}>)[0]?.last_checked_at;
    if (lastChecked && Date.now() - new Date(lastChecked).getTime() < 60_000) {
      return json({ error: "Feed sync was recently triggered.", retryAfterSeconds: 60 }, 429);
    }

    await syncPhishuntFeed(sql);
    const rows = await sql`
      SELECT status, last_checked_at, last_success_at, item_count, error_code
      FROM threat_feed_status WHERE source = 'phishunt' LIMIT 1
    `;
    const feed = (rows as Array<{
      status:string;last_checked_at:string|null;last_success_at:string|null;
      item_count:number;error_code:string|null
    }>)[0];

    if (!feed || feed.status !== "ok" || !feed.last_success_at) {
      return json({
        status: feed?.status ?? "unavailable",
        lastCheckedAt: feed?.last_checked_at ?? null,
        errorCode: feed?.error_code ?? "FEED_SYNC_NOT_CONFIRMED"
      }, 502);
    }

    return json({
      status: "ok",
      source: "phishunt",
      lastCheckedAt: feed.last_checked_at,
      lastSuccessAt: feed.last_success_at,
      itemCount: Number(feed.item_count ?? 0)
    });
  } catch (error) {
    console.error("PHISHUNT_SYNC_ENDPOINT_FAILED", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Phishunt feed sync failed." }, 503);
  }
};
