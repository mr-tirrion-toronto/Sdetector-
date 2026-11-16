import { neon } from "@neondatabase/serverless";

interface Env { DATABASE_URL?: string }

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const headers = {
    "cache-control": "public, max-age=30, stale-while-revalidate=60",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff"
  };
  if (!env.DATABASE_URL) {
    return Response.json({ error: "Dashboard data is temporarily unavailable." }, { status: 503, headers });
  }
  try {
    const sql = neon(env.DATABASE_URL);
    const [summaryRows, riskRows, trendRows, feedRows] = await Promise.all([
      sql`SELECT COUNT(*)::int AS total_scans,
                 COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS scans_24h,
                 COUNT(DISTINCT hostname)::int AS unique_hosts,
                 COALESCE(ROUND(AVG(risk_score))::int, 0) AS average_score,
                 COUNT(*) FILTER (WHERE risk_level IN ('high','critical'))::int AS elevated_scans
          FROM scans`,
      sql`SELECT risk_level, COUNT(*)::int AS count
          FROM scans GROUP BY risk_level`,
      sql`SELECT TO_CHAR(day, 'Dy') AS day_label,
                 TO_CHAR(day, 'YYYY-MM-DD') AS day,
                 COALESCE(scan_count, 0)::int AS count
          FROM generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day') AS day
          LEFT JOIN (
            SELECT DATE(created_at) AS scan_day, COUNT(*)::int AS scan_count
            FROM scans WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
            GROUP BY DATE(created_at)
          ) daily ON daily.scan_day = DATE(day)
          ORDER BY DATE(day)`,
      sql`SELECT source, status, last_success_at, item_count
          FROM threat_feed_status ORDER BY source`
    ]);
    const summary = (summaryRows as Array<Record<string, unknown>>)[0] ?? {};
    const risk = Object.fromEntries((riskRows as Array<{risk_level:string;count:number}>).map(row => [row.risk_level, Number(row.count)]));
    const trend = (trendRows as Array<{day_label:string;day:string;count:number}>).map(row => ({
      label: row.day_label, date: row.day, count: Number(row.count)
    }));
    const feeds = (feedRows as Array<{source:string;status:string;last_success_at:string|null;item_count:number}>).map(row => ({
      source: row.source, status: row.status, lastSuccessAt: row.last_success_at,
      itemCount: Number(row.item_count)
    }));
    return Response.json({
      generatedAt: new Date().toISOString(),
      summary: {
        totalScans: Number(summary.total_scans ?? 0),
        scans24h: Number(summary.scans_24h ?? 0),
        uniqueHosts: Number(summary.unique_hosts ?? 0),
        averageScore: Number(summary.average_score ?? 0),
        elevatedScans: Number(summary.elevated_scans ?? 0)
      },
      riskDistribution: {
        low: Number(risk.low ?? 0), guarded: Number(risk.guarded ?? 0),
        high: Number(risk.high ?? 0), critical: Number(risk.critical ?? 0)
      },
      dailyActivity: trend,
      threatFeeds: feeds,
      privacy: "Only aggregate statistics are exposed. Scan URLs and report contents are not included."
    }, { headers });
  } catch (error) {
    console.error("DASHBOARD_QUERY_FAILED", error instanceof Error ? error.name : "UnknownError");
    return Response.json({ error: "Dashboard data could not be loaded. Please retry shortly." }, { status: 503, headers });
  }
};
