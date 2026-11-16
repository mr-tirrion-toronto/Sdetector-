export interface PhishDestroyInvestigation {
  status: "available" | "unavailable" | "rate_limited";
  errorCode: string | null;
  checkedAt: string | null;
  verdict: {
    status: "listed" | "whitelisted" | "not_listed" | "unknown";
    threat: boolean;
    severity: string | null;
    riskScore: number | null;
    matchedDomain: string | null;
    listedSince: string | null;
    active: boolean | null;
    serving: boolean | null;
    liveness: string | null;
    note: string | null;
    appealUrl: string | null;
  } | null;
  assessment: {
    risk: string;
    score: number;
    maxScore: number;
    signals: string[];
  } | null;
  infrastructure: {
    resolvedIps: string[];
    cloudflare: boolean | null;
  } | null;
  registration: {
    created: string | null;
    registrar: string | null;
    ageDays: number | null;
  } | null;
  campaign: {
    brand: string | null;
    total: number | null;
    alive: number | null;
  } | null;
  related: string[];
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
function safeString(value: unknown, max = 180): string | null {
  return typeof value === "string" && value.length > 0 ? value.slice(0, max) : null;
}
function safeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

async function readJsonLimited(response: Response, maxBytes = 64 * 1024): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error("PROVIDER_RESPONSE_TOO_LARGE");
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw new Error("PROVIDER_RESPONSE_TOO_LARGE");
  return JSON.parse(text) as unknown;
}

export async function investigateDomain(
  hostname: string,
  fetcher: FetchLike = fetch
): Promise<PhishDestroyInvestigation> {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || normalized.includes("/") || normalized.includes("@")) {
    return unavailable();
  }
  const parsed = new URL("https://" + normalized);
  if (parsed.hostname !== normalized || !normalized.includes(".")) return unavailable();

  const endpoint = new URL("https://api.destroy.tools/v1/investigate");
  endpoint.searchParams.set("domain", normalized);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6500);
  try {
    const response = await fetcher(endpoint.toString(), {
      method: "GET",
      headers: { accept: "application/json", "user-agent": "ScamDetector/1.0" },
      redirect: "follow",
      signal: controller.signal
    });
    if (response.status === 429) return { ...unavailable("HTTP_429"), status: "rate_limited" };
    if (!response.ok) return unavailable("HTTP_" + response.status);
    const payload = await readJsonLimited(response);
    if (!isRecord(payload) || !isRecord(payload.verdict)) return unavailable();

    const verdict = payload.verdict;
    const assessment = isRecord(payload.assessment) ? payload.assessment : null;
    const infrastructure = isRecord(payload.infrastructure) ? payload.infrastructure : null;
    const registration = isRecord(payload.registration) ? payload.registration : null;
    const campaign = isRecord(payload.campaign) ? payload.campaign : null;
    const related = Array.isArray(payload.related)
      ? payload.related.filter(isRecord).map(item => safeString(item.domain, 253)).filter((value): value is string => Boolean(value)).slice(0, 5)
      : [];

    return {
      status: "available",
      errorCode: null,
      checkedAt: safeString(payload.checked_at, 64),
      verdict: {
        status: verdict.status === "listed" || verdict.status === "whitelisted" || verdict.status === "not_listed"
          ? verdict.status : "unknown",
        threat: verdict.threat === true,
        severity: safeString(verdict.severity, 32),
        riskScore: safeNumber(verdict.risk_score),
        matchedDomain: safeString(verdict.matched_domain, 253),
        listedSince: safeString(verdict.listed_since, 64),
        active: typeof verdict.active === "boolean" ? verdict.active : null,
        serving: typeof verdict.serving === "boolean" ? verdict.serving : null,
        liveness: safeString(verdict.liveness, 32),
        note: safeString(verdict.note, 500),
        appealUrl: safeString(verdict.appeal_url, 500)
      },
      assessment: assessment ? {
        risk: safeString(assessment.risk, 32) ?? "unknown",
        score: Math.max(0, safeNumber(assessment.score) ?? 0),
        maxScore: Math.max(1, safeNumber(assessment.max_score) ?? 100),
        signals: Array.isArray(assessment.signals)
          ? assessment.signals.filter(isRecord).map(signal => safeString(signal.signal, 80)).filter((value): value is string => Boolean(value)).slice(0, 12)
          : []
      } : null,
      infrastructure: infrastructure ? {
        resolvedIps: Array.isArray(infrastructure.resolved_ips)
          ? infrastructure.resolved_ips.filter((value): value is string => typeof value === "string").slice(0, 10)
          : [],
        cloudflare: typeof infrastructure.cloudflare === "boolean" ? infrastructure.cloudflare : null
      } : null,
      registration: registration ? {
        created: safeString(registration.created, 32),
        registrar: safeString(registration.registrar, 180),
        ageDays: safeNumber(registration.age_days)
      } : null,
      campaign: campaign ? {
        brand: safeString(campaign.brand, 120),
        total: safeNumber(campaign.total),
        alive: safeNumber(campaign.alive)
      } : null,
      related
    };
  } catch (error) {
    const code = error instanceof Error
      ? (error.name === "AbortError" ? "PROVIDER_TIMEOUT" : error.name + (error.message ? ":" + error.message.slice(0, 80) : ""))
      : "UNKNOWN_ERROR";
    console.warn("DOMAIN_INTEL_PROVIDER_ERROR", code.slice(0, 120));
    return unavailable(code.slice(0, 120));
  } finally {
    clearTimeout(timeoutId);
  }
}

function unavailable(errorCode = "PROVIDER_UNAVAILABLE"): PhishDestroyInvestigation {
  return {
    status: "unavailable", errorCode, checkedAt: null, verdict: null, assessment: null,
    infrastructure: null, registration: null, campaign: null, related: []
  };
}
