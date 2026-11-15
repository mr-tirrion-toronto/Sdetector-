# Scanner Scope and Evidence Model

## Implemented in version 0.2

- Strict URL parsing and HTTP/HTTPS scheme allow-list.
- Explainable URL heuristics for HTTP, authority user-info, punycode, IP literals, deep subdomains, long hostnames, known shorteners, sensitive-action terms and non-standard ports.
- A bounded 0–100 URL-signal score.
- Zero URL-pattern points are classified as `unknown / insufficient_evidence`, never as verified safe or low risk.
- Streaming 4 KB request-body limit and same-origin browser request check.
- Atomic scan + finding persistence in one SQL statement.
- Stored URL values omit query strings/fragments and redact suspiciously long or email-like path segments.

## Not implemented yet

- DNS record intelligence and domain registration age.
- Live TLS certificate and redirect-chain inspection.
- Static page-content analysis and brand impersonation detection.
- External reputation-provider integration and local threat-feed mirroring.
- Scheduled threat-feed ingestion.
- Rate limiting and authenticated scan-history dashboard.
- Server-generated PDF reports; the current PDF option uses browser print.
- User accounts, team workspaces and public API keys.

## Safety boundary

The scanner does not fetch or execute submitted websites. This avoids turning it into an SSRF-capable proxy. Any future active website inspection must have a separately reviewed SSRF design, DNS rebinding/connection-time controls, private/reserved IP blocking, redirect re-validation, strict deadlines and streaming response limits.

## Threat-intelligence policy

Only integrate a provider after checking its current terms, access method, rate limits, coverage, update frequency and commercial-use conditions. Do not use the OpenPhish Community feed in a product integration without written permission: its current terms restrict use to personal research and prohibit commercial/product-development use. URLhaus focuses on malware distribution URLs, not phishing, and its community API requires an Auth-Key. PhishTank supports exact-URL lookups and requires a descriptive User-Agent; its current Cisco terms must be reviewed before production integration.
