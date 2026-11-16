import type { Finding } from "./analyzer";

export interface ThreatFeedStatus {
  source: "urlhaus" | "phishtank" | "phishunt";
  status: "ok" | "error" | "not_configured";
  last_checked_at: string;
  last_success_at: string | null;
  item_count: number;
  error_code: string | null;
}

export interface ThreatIntelResult {
  status: "available" | "partial" | "unavailable" | "not_configured";
  matched: boolean;
  feeds: Array<{
    source: "urlhaus" | "phishtank";
    status: "ok" | "error" | "not_configured" | "stale";
    lastUpdatedAt: string | null;
    itemCount: number;
  }>;
  findings: Finding[];
}

export async function hashThreatUrl(rawUrl: string): Promise<string> {
  const url = new URL(rawUrl);
  url.username = "";
  url.password = "";
  url.hash = "";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url.toString()));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function hashThreatDomain(hostname: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("domain:" + hostname.toLowerCase().replace(/\\.$/, "")));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function lookupThreatIntelligence(
  sql: any,
  rawUrl: string
): Promise<ThreatIntelResult> {
  const url = new URL(rawUrl);\n  const hash = await hashThreatUrl(rawUrl);\n  const domainHash = await hashThreatDomain(url.hostname);
  const [matches, statuses] = await Promise.all([
    sql`
      SELECT i.source, i.source_id, i.threat_type, i.target,
             i.source_updated_at, s.last_success_at
      FROM threat_indicators i
      LEFT JOIN threat_feed_status s ON s.source = i.source
      WHERE i.indicator_hash = ${hash}
        AND i.expires_at > NOW()
      ORDER BY i.source
    `,
    sql`
      SELECT source, status, last_checked_at, last_success_at, item_count
      FROM threat_feed_status
      ORDER BY source
    `
  ]);

  const now = Date.now();
  const feeds = (statuses as Array<any>).map(feed => {
    const lastSuccess = feed.last_success_at ? new Date(feed.last_success_at).getTime() : null;
    const stale = !lastSuccess || now - lastSuccess > 36 * 60 * 60 * 1000;
    return {
      source: feed.source,
      status: stale && feed.status === "ok" ? "stale" : feed.status,
      lastUpdatedAt: feed.last_success_at ?? null,
      itemCount: Number(feed.item_count ?? 0)
    };
  });

  const configured = feeds.filter(feed => feed.status !== "not_configured");
  const fresh = feeds.filter(feed => feed.status === "ok");
  const status: ThreatIntelResult["status"] =
    configured.length === 0 ? "not_configured" :
    fresh.length === configured.length && fresh.length > 0 ? "available" :
    fresh.length > 0 ? "partial" : "unavailable";

  const findings: Finding[] = (matches as Array<any>).map(match => {
    const isPhish = match.source === "phishtank" || match.source === "phishunt";\n    const sourceName = match.source === "phishunt" ? "Phishunt" : isPhish ? "PhishTank" : "URLhaus";
    return {
      code: isPhish ? "KNOWN_PHISHING_URL" : "KNOWN_MALWARE_URL",
      title: isPhish ? "URL matches a verified PhishTank report" : "URL matches a URLhaus malware indicator",
      severity: "high",
      points: 100,
      evidence: (match.source === "phishunt" ? "Hostname listed in the Phishunt active phishing-domain feed" : isPhish ? "PhishTank verified online phishing URL" : "URLhaus reported malware-distribution URL") +
        (match.source_id ? " (source record " + match.source_id + ")" : "") +
        (match.target ? "; reported target: " + match.target : "") +
        (match.source_updated_at ? "; source timestamp: " + match.source_updated_at : ""),
      recommendation: "Do not visit this URL or enter credentials. Treat it as a known threat and report it through your organisation's security process."
    };
  });

  return { status, matched: findings.length > 0, feeds, findings };
}
