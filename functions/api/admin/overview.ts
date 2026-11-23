import { neon } from "@neondatabase/serverless";
import { getAuthenticatedUser, json } from "../../../src/auth";

interface Env { DATABASE_URL?: string }

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  if (!env.DATABASE_URL) return json({ error: "Administrator service is unavailable." }, 503);

  try {
    const sql = neon(env.DATABASE_URL);
    const user = await getAuthenticatedUser(sql, request);

    // Administrator access requires a browser session, never an API key.
    if (!user || user.authType !== "session") {
      return json({ error: "Sign in with an administrator account." }, 401);
    }

    const roleRows = await sql`SELECT role FROM public.app_users WHERE id = ${user.id} AND status = 'active' LIMIT 1`;
    const role = (roleRows as Array<{ role: string }>)[0]?.role;
    if (role !== "admin") return json({ error: "Administrator access is required." }, 403);

    const [summaryRows, riskRows, dailyRows, feedRows, latestThreatRows, highRiskRows, findingRows, inventoryRows] = await Promise.all([
      sql`SELECT
        COUNT(*)::int AS total_scans,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS scans_24h,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days')::int AS scans_30d,
        COUNT(DISTINCT hostname)::int AS unique_hosts,
        COUNT(*) FILTER (WHERE risk_level IN ('high','critical'))::int AS high_risk_scans,
        COUNT(*) FILTER (WHERE risk_level = 'critical')::int AS critical_scans,
        COUNT(*) FILTER (WHERE risk_level = 'high')::int AS high_scans
      FROM public.scans`,
      sql`SELECT risk_level, COUNT(*)::int AS count FROM public.scans
          WHERE created_at >= NOW() - INTERVAL '30 days' GROUP BY risk_level`,
      sql`SELECT TO_CHAR(day, 'Dy') AS label, TO_CHAR(day, 'YYYY-MM-DD') AS date,
          COALESCE(daily.count, 0)::int AS count
        FROM generate_series(CURRENT_DATE - INTERVAL '29 days', CURRENT_DATE, INTERVAL '1 day') AS days(day)
        LEFT JOIN (
          SELECT DATE(created_at) AS scan_day, COUNT(*)::int AS count
          FROM public.scans WHERE created_at >= CURRENT_DATE - INTERVAL '29 days'
          GROUP BY DATE(created_at)
        ) daily ON daily.scan_day = DATE(day)
        ORDER BY DATE(day)`,
      sql`SELECT source, status, last_checked_at, last_success_at, item_count, error_code
          FROM public.threat_feed_status ORDER BY source`,
      sql`SELECT source, hostname, threat_type, imported_at, expires_at
          FROM public.threat_indicators WHERE expires_at > NOW()
          ORDER BY imported_at DESC LIMIT 8`,
      sql`SELECT hostname, risk_level, MAX(risk_score)::int AS risk_score,
          MAX(created_at) AS last_seen, COUNT(*)::int AS scan_count
        FROM public.scans WHERE risk_level IN ('high','critical')
        GROUP BY hostname, risk_level ORDER BY MAX(created_at) DESC LIMIT 8`,
      sql`SELECT f.code, f.title, f.severity, COUNT(*)::int AS count
        FROM public.scan_findings f JOIN public.scans s ON s.id = f.scan_id
        WHERE s.created_at >= NOW() - INTERVAL '30 days'
        GROUP BY f.code, f.title, f.severity ORDER BY COUNT(*) DESC LIMIT 10`,
      sql`SELECT
        (SELECT COUNT(*)::int FROM public.app_users WHERE status = 'active') AS users,
        (SELECT COUNT(*)::int FROM public.user_sessions WHERE revoked_at IS NULL AND expires_at > NOW()) AS active_sessions,
        (SELECT COUNT(*)::int FROM public.monitored_domains WHERE enabled = TRUE) AS monitored_domains,
        (SELECT COUNT(DISTINCT hostname)::int FROM public.threat_indicators WHERE expires_at > NOW()) AS threat_hosts,
        (SELECT COUNT(*)::int FROM public.scan_intelligence) AS intelligence_records`
    ]);

    const summary = (summaryRows as Array<Record<string, unknown>>)[0] ?? {};
    const inventory = (inventoryRows as Array<Record<string, unknown>>)[0] ?? {};
    const risk = Object.fromEntries((riskRows as Array<{ risk_level: string; count: number }>).map(row => [row.risk_level, Number(row.count)]));
    const feeds = (feedRows as Array<Record<string, unknown>>).map(row => ({
      source: String(row.source), status: String(row.status),
      lastCheckedAt: row.last_checked_at, lastSuccessAt: row.last_success_at,
      itemCount: Number(row.item_count ?? 0), errorCode: row.error_code ?? null
    }));
    const latestThreats = (latestThreatRows as Array<Record<string, unknown>>).map(row => ({
      source: String(row.source), hostname: String(row.hostname), threatType: String(row.threat_type),
      importedAt: row.imported_at, expiresAt: row.expires_at
    }));
    const highRiskEntities = (highRiskRows as Array<Record<string, unknown>>).map(row => ({
      hostname: String(row.hostname), riskLevel: String(row.risk_level),
      riskScore: Number(row.risk_score), lastSeen: row.last_seen, scanCount: Number(row.scan_count)
    }));
    const topFindings = (findingRows as Array<Record<string, unknown>>).map(row => ({
      code: String(row.code), title: String(row.title), severity: String(row.severity), count: Number(row.count)
    }));

    return json({
      generatedAt: new Date().toISOString(),
      administrator: { id: user.id, email: user.email, role },
      summary: {
        totalScans: Number(summary.total_scans ?? 0), scans24h: Number(summary.scans_24h ?? 0),
        scans30d: Number(summary.scans_30d ?? 0), uniqueHosts: Number(summary.unique_hosts ?? 0),
        highRiskScans: Number(summary.high_risk_scans ?? 0), criticalScans: Number(summary.critical_scans ?? 0),
        highScans: Number(summary.high_scans ?? 0)
      },
      riskDistribution: {
        low: Number(risk.low ?? 0), guarded: Number(risk.guarded ?? 0),
        high: Number(risk.high ?? 0), critical: Number(risk.critical ?? 0)
      },
      dailyActivity: (dailyRows as Array<Record<string, unknown>>).map(row => ({
        label: String(row.label), date: String(row.date), count: Number(row.count)
      })),
      threatFeeds: feeds, latestThreats, highRiskEntities, topFindings,
      inventory: {
        users: Number(inventory.users ?? 0), activeSessions: Number(inventory.active_sessions ?? 0),
        monitoredDomains: Number(inventory.monitored_domains ?? 0),
        threatHosts: Number(inventory.threat_hosts ?? 0),
        intelligenceRecords: Number(inventory.intelligence_records ?? 0)
      },
      capabilities: {
        visitorAnalytics: "not_collected",
        mitreMapping: "not_implemented",
        caseRemediation: "not_implemented",
        slaAndMttr: "not_tracked"
      },
      privacy: "Administrator-only aggregate metrics and threat indicators. Submitted scan URLs and user scan contents are not returned."
    }, 200);
  } catch (error) {
    console.error("ADMIN_OVERVIEW_FAILED", error instanceof Error ? error.name : "UnknownError");
    return json({ error: "Administrator dashboard data could not be loaded." }, 503);
  }
};
