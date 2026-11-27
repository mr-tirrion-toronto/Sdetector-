import type { Finding } from "./analyzer";

export type ExternalThreatSource = "google_safe_browsing" | "urlhaus" | "phishtank" | "virustotal";
export type ProviderState = "ok" | "not_configured" | "unavailable" | "error";

export interface ExternalProviderResult {
  source: ExternalThreatSource;
  status: ProviderState;
  checkedAt: string;
  matched: boolean;
  confirmed: boolean;
  matchCount: number;
  summary: string;
  errorCode: string | null;
}

export interface ExternalThreatIntelResult {
  status: "available" | "partial" | "unavailable" | "not_configured";
  providers: ExternalProviderResult[];
  findings: Finding[];
}

export interface ExternalThreatIntelEnv {
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  URLHAUS_AUTH_KEY?: string;
  PHISHTANK_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const SOURCES: ExternalThreatSource[] = [
  "google_safe_browsing", "urlhaus", "phishtank", "virustotal"
];

function unavailable(source: ExternalThreatSource, status: ProviderState, summary: string, errorCode: string | null = null): ExternalProviderResult {
  return { source, status, checkedAt: new Date().toISOString(), matched: false, confirmed: false, matchCount: 0, summary, errorCode };
}

async function boundedJson(response: Response, maxBytes = 128 * 1024): Promise<any> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error("RESPONSE_TOO_LARGE");
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > maxBytes) throw new Error("RESPONSE_TOO_LARGE");
  return JSON.parse(body);
}

async function request(fetcher: FetchLike, input: RequestInfo | URL, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6500);
  try {
    return await fetcher(input, { ...init, signal: controller.signal, redirect: "error" });
  } finally {
    clearTimeout(timeout);
  }
}

async function googleSafeBrowsing(url: string, key: string, fetcher: FetchLike): Promise<ExternalProviderResult> {
  const endpoint = new URL("https://safebrowsing.googleapis.com/v4/threatMatches:find");
  endpoint.searchParams.set("key", key);
  const response = await request(fetcher, endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      client: { clientId: "scam-detector", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    })
  });
  if (!response.ok) throw new Error("HTTP_" + response.status);
  const payload = await boundedJson(response);
  const matches = Array.isArray(payload.matches) ? payload.matches : [];
  return {
    source: "google_safe_browsing", status: "ok", checkedAt: new Date().toISOString(),
    matched: matches.length > 0, confirmed: matches.length > 0, matchCount: matches.length,
    summary: matches.length ? "Google Safe Browsing reported this URL in a threat category." : "No Google Safe Browsing match was returned for this URL.",
    errorCode: null
  };
}

async function urlhaus(url: string, key: string, fetcher: FetchLike): Promise<ExternalProviderResult> {
  const response = await request(fetcher, "https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: { "auth-key": key, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ url }).toString()
  });
  if (!response.ok) throw new Error("HTTP_" + response.status);
  const payload = await boundedJson(response);
  if (payload.query_status === "no_results") {
    return { source: "urlhaus", status: "ok", checkedAt: new Date().toISOString(), matched: false, confirmed: false, matchCount: 0, summary: "URLhaus returned no matching URL record.", errorCode: null };
  }
  if (payload.query_status !== "ok") throw new Error("PROVIDER_" + String(payload.query_status ?? "UNKNOWN").slice(0, 50));
  return {
    source: "urlhaus", status: "ok", checkedAt: new Date().toISOString(), matched: true, confirmed: true, matchCount: 1,
    summary: "URLhaus lists this URL as a malware-distribution indicator" + (payload.url_status ? " (" + String(payload.url_status).slice(0, 20) + ")." : "."),
    errorCode: null
  };
}

async function phishTank(url: string, key: string, fetcher: FetchLike): Promise<ExternalProviderResult> {
  const response = await request(fetcher, "https://checkurl.phishtank.com/checkurl/", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ url, format: "json", app_key: key }).toString()
  });
  if (!response.ok) throw new Error("HTTP_" + response.status);
  const payload = await boundedJson(response);
  const result = payload?.results;
  const verified = result?.in_database === true && result?.verified === true && result?.valid === true;
  return {
    source: "phishtank", status: "ok", checkedAt: new Date().toISOString(), matched: verified, confirmed: verified, matchCount: verified ? 1 : 0,
    summary: verified ? "PhishTank reports this URL as a verified, online phishing URL." : "No verified, online PhishTank match was returned.",
    errorCode: null
  };
}

function base64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function virusTotal(url: string, key: string, fetcher: FetchLike): Promise<ExternalProviderResult> {
  const response = await request(fetcher, "https://www.virustotal.com/api/v3/urls/" + base64Url(url), {
    method: "GET", headers: { "x-apikey": key, accept: "application/json" }
  });
  if (!response.ok) throw new Error("HTTP_" + response.status);
  const payload = await boundedJson(response);
  const stats = payload?.data?.attributes?.last_analysis_stats;
  if (!stats || typeof stats !== "object") throw new Error("MISSING_ANALYSIS_STATS");
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  const matches = Number.isFinite(malicious) ? malicious : 0;
  const suspiciousCount = Number.isFinite(suspicious) ? suspicious : 0;
  const total = Math.max(0, matches + suspiciousCount);
  return {
    source: "virustotal", status: "ok", checkedAt: new Date().toISOString(), matched: total > 0,
    // VirusTotal aggregates vendor opinions; it is not treated as a single authoritative confirmation.
    confirmed: false, matchCount: total,
    summary: total > 0
      ? "VirusTotal reports " + matches + " malicious and " + suspiciousCount + " suspicious engine verdicts."
      : "VirusTotal returned no malicious or suspicious engine verdicts.",
    errorCode: null
  };
}

export async function lookupExternalThreatIntelligence(
  env: ExternalThreatIntelEnv,
  rawUrl: string,
  fetcher: FetchLike = fetch
): Promise<ExternalThreatIntelResult> {
  const url = new URL(rawUrl);
  // Never forward credentials, query parameters or fragments to third-party reputation providers.
  url.username = "";
  url.password = "";
  url.search = "";
  url.hash = "";
  const providerUrl = url.toString();
  const configured: Array<{ source: ExternalThreatSource; key: string | undefined; run: (key: string) => Promise<ExternalProviderResult> }> = [
    { source: "google_safe_browsing", key: env.GOOGLE_SAFE_BROWSING_API_KEY, run: key => googleSafeBrowsing(providerUrl, key, fetcher) },
    { source: "urlhaus", key: env.URLHAUS_AUTH_KEY, run: key => urlhaus(providerUrl, key, fetcher) },
    { source: "phishtank", key: env.PHISHTANK_API_KEY, run: key => phishTank(providerUrl, key, fetcher) },
    { source: "virustotal", key: env.VIRUSTOTAL_API_KEY, run: key => virusTotal(providerUrl, key, fetcher) }
  ];
  const providers = await Promise.all(configured.map(async item => {
    if (!item.key) return unavailable(item.source, "not_configured", "API credential is not configured.");
    try {
      return await item.run(item.key);
    } catch (error) {
      const code = error instanceof Error ? error.message.slice(0, 80) : "UNKNOWN_ERROR";
      return unavailable(item.source, "unavailable", "Provider lookup did not complete.", code);
    }
  }));

  const findings: Finding[] = providers.filter(provider => provider.matched).map(provider => ({
    code: "EXTERNAL_" + provider.source.toUpperCase(),
    title: provider.confirmed ? "Threat reported by " + provider.source.replace(/_/g, " ") : "Suspicious reputation reported by " + provider.source.replace(/_/g, " "),
    severity: provider.confirmed || provider.matchCount >= 2 ? "high" : "medium",
    points: provider.confirmed ? 100 : provider.matchCount >= 2 ? 25 : 12,
    evidence: provider.summary + " Checked at " + provider.checkedAt + ".",
    recommendation: "Do not enter credentials or payment details. Verify the destination through a trusted, independently sourced channel."
  }));

  const ready = providers.filter(provider => provider.status === "ok");
  const status: ExternalThreatIntelResult["status"] =
    ready.length === 0 ? (providers.every(provider => provider.status === "not_configured") ? "not_configured" : "unavailable") :
    ready.length === SOURCES.length ? "available" : "partial";
  return { status, providers, findings };
}
