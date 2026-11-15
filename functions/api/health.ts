import { neon } from "@neondatabase/serverless";

interface Env {
  DATABASE_URL?: string;
}

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };

  if (!env.DATABASE_URL) {
    return Response.json(
      { status: "degraded", service: "scam-detector-api", platform: "cloudflare-pages", database: "not_configured" },
      { status: 503, headers }
    );
  }

  try {
    const sql = neon(env.DATABASE_URL);
    await sql`SELECT 1 AS database_check`;
    return Response.json(
      { status: "ok", service: "scam-detector-api", platform: "cloudflare-pages", database: "connected" },
      { headers }
    );
  } catch (error) {
    console.error("DATABASE_HEALTH_CHECK_FAILED", error);
    return Response.json(
      { status: "degraded", service: "scam-detector-api", platform: "cloudflare-pages", database: "unavailable" },
      { status: 503, headers }
    );
  }
};
