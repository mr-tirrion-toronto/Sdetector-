export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  code: string;
  title: string;
  severity: Severity;
  points: number;
  evidence: string;
  recommendation: string;
}

export interface ScanResult {
  inputUrl: string;
  normalizedUrl: string;
  hostname: string;
  score: number;
  riskLevel: "low" | "guarded" | "high" | "critical";
  assessmentStatus: "insufficient_evidence" | "preliminary_signals_detected";
  confidence: "limited";
  findings: Finding[];
  limitations: string[];
}

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
  "rb.gy", "shorturl.at", "rebrand.ly"
]);

const SUSPICIOUS_TERMS = [
  "login", "verify", "verification", "secure", "account",
  "update", "password", "wallet", "payment", "confirm",
  "signin", "webscr", "recover"
];

function addFinding(findings: Finding[], code: string, title: string, severity: Severity,
  points: number, evidence: string, recommendation: string): void {
  findings.push({ code, title, severity, points, evidence, recommendation });
}

export function analyzeUrl(input: string): ScanResult {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2048) {
    throw new Error("Enter a URL between 1 and 2048 characters.");
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("The supplied value is not a valid absolute URL.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS URLs can be analysed.");
  }
  if (!parsed.hostname) {
    throw new Error("The URL must contain a hostname.");
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const findings: Finding[] = [];

  if (parsed.protocol !== "https:") {
    addFinding(findings, "NO_HTTPS", "Connection is not HTTPS", "medium", 18,
      "The URL uses HTTP rather than HTTPS.", "Avoid entering passwords or personal information on an unencrypted connection.");
  }

  const authority = trimmed.match(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\/([^/?#]*)/);
  const hasUserInfoSyntax = authority?.[1].includes("@") ?? false;
  if (parsed.username || parsed.password || hasUserInfoSyntax) {
    addFinding(findings, "URL_CREDENTIALS_OR_AT", "Potentially deceptive URL syntax", "high", 25,
      "The URL authority contains user-information syntax. This can disguise the actual destination.",
      "Inspect the hostname carefully and do not sign in unless the destination is independently verified.");
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    addFinding(findings, "PUNYCODE_HOST", "Internationalized hostname detected", "medium", 15,
      "The hostname contains a punycode label. This is not automatically malicious, but can be used for lookalike domains.",
      "Compare the displayed domain character by character with the organisation's official domain.");
  }

  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const bracketedIpv6 = hostname.startsWith("[") && hostname.endsWith("]");
  if (ipv4 || bracketedIpv6) {
    addFinding(findings, "IP_LITERAL_HOST", "Website uses an IP address", "medium", 12,
      "The hostname is an IP literal: " + hostname + ".",
      "Confirm through a trusted source why the service is using a direct IP address.");
  }

  const labels = hostname.split(".");
  if (labels.length >= 5) {
    addFinding(findings, "MANY_SUBDOMAINS", "Unusually deep subdomain structure", "low", 8,
      "The hostname contains " + labels.length + " labels.",
      "Focus on the registered domain, not just familiar words in subdomains.");
  }

  if (hostname.length > 50) {
    addFinding(findings, "LONG_HOSTNAME", "Unusually long hostname", "low", 6,
      "The hostname is " + hostname.length + " characters long.",
      "Check for unnecessary words or brand names inserted into the hostname.");
  }

  if (SHORTENERS.has(hostname)) {
    addFinding(findings, "URL_SHORTENER", "URL shortening service detected", "medium", 12,
      "The hostname belongs to a known URL-shortening service; the final destination is not visible in this scan.",
      "Only open the link if you trust the sender and can verify its final destination.");
  }

  const searchable = (parsed.pathname + " " + parsed.search).toLowerCase();
  const matchedTerms = SUSPICIOUS_TERMS.filter(term => searchable.includes(term));
  if (matchedTerms.length >= 2) {
    addFinding(findings, "SENSITIVE_ACTION_TERMS", "Multiple sensitive-action terms in URL", "medium", 12,
      "Matched URL terms: " + matchedTerms.join(", ") + ".",
      "Treat unexpected login, verification or payment links with caution.");
  } else if (matchedTerms.length === 1) {
    addFinding(findings, "SENSITIVE_ACTION_TERM", "Sensitive-action term in URL", "low", 5,
      "Matched URL term: " + matchedTerms[0] + ".",
      "A keyword alone does not prove fraud; verify the sender and domain.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    addFinding(findings, "NONSTANDARD_PORT", "Non-standard web port", "low", 7,
      "The URL specifies port " + parsed.port + ".",
      "Verify that this port is expected for the service.");
  }

  const score = Math.min(100, findings.reduce((sum, finding) => sum + finding.points, 0));
  const riskLevel = score >= 70 ? "critical" : score >= 40 ? "high" : score >= 20 ? "guarded" : "low";

  return {
    inputUrl: trimmed,
    normalizedUrl: parsed.toString(),
    hostname,
    score,
    riskLevel,
    assessmentStatus: findings.length === 0 ? "insufficient_evidence" : "preliminary_signals_detected",
    confidence: "limited",
    findings,
    limitations: [
      "This is a preliminary URL-pattern assessment, not a verdict that a website is safe or fraudulent.",
      "No live website fetch, DNS, domain-age, certificate, redirect-chain or third-party reputation checks are performed yet.",
      "A score of 0 means no configured URL-pattern signals were detected; it does not mean the website is verified safe.",
      "Assessment confidence is limited until independent reputation and live technical evidence are available."
    ]
  };
}
