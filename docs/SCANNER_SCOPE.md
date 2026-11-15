# Scanner Scope and Evidence Model

## Implemented in version 0.2

- Strict URL parsing and HTTP/HTTPS scheme allow-list.
- Explainable URL heuristics for HTTP, authority user-info, punycode, IP literals, deep subdomains, long hostnames, known shorteners, sensitive-action terms and non-standard ports.
- A bounded 0–100 URL-signal score.
- Live domain-reputation lookup against the PhishDestroy public API. Only the normalized hostname is sent; the submitted website is never fetched.
- Primary curated and community-feed matches are distinguished; provider no-match, allowlisted and unavailable states are not treated as safe.
- Zero URL-pattern points are classified as `unknown / insufficient_evidence`, never as verified safe or low risk.
- Streaming 4 KB request-body limit and same-origin browser request check.
- Atomic scan + finding persistence in one SQL statement.
- Stored URL values omit query strings/fragments and redact suspiciously long or email-like path segments.

## Not implemented yet

- DNS record intelligence and domain registration age.
- Live TLS certificate and redirect-chain inspection.
- Static page-content analysis and brand impersonation detection.
- Additional external reputation providers and local threat-feed mirroring.
- Scheduled threat-feed ingestion.
- Rate limiting and authenticated scan-history dashboard.
- Server-generated PDF reports; the current PDF option uses browser print.
- User accounts, team workspaces and public API keys.

## Threat-intelligence source

PhishDestroy Destroylist (MIT) provides primary curated and community phishing/scam domain feeds. Its API is queried at scan time; published feed changes are reflected by the provider's ongoing synchronization. Primary and community matches are shown separately. Its allowlist suppresses false positives only and is not a safety certification. API documentation: https://api.destroy.tools/ . Source repository and MIT license: https://github.com/phishdestroy/destroylist .

## Safety boundary

The scanner does not fetch or execute submitted websites. This avoids turning it into an SSRF-capable proxy. Any future active website inspection must have a separately reviewed SSRF design, DNS rebinding/connection-time controls, private/reserved IP blocking, redirect re-validation, strict deadlines and streaming response limits.

## Threat-intelligence policy

Only integrate a provider after checking its current terms, access method, rate limits, coverage, update frequency and commercial-use conditions. Do not use the OpenPhish Community feed in a product integration without written permission: its current terms restrict use to personal research and prohibit commercial/product-development use. URLhaus focuses on malware distribution URLs, not phishing, and its community API requires an Auth-Key. PhishTank supports exact-URL lookups and requires a descriptive User-Agent; its current Cisco terms must be reviewed before production integration.
