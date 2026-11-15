# Architecture Notes

This document records the intended architecture. It is not a claim that these components are already implemented.

## High-level flow
1. A client submits a URL to an authenticated or rate-limited scan endpoint.
2. The API validates and canonicalizes the URL.
3. A scan orchestrator schedules bounded analysis tasks.
4. Each analyzer returns structured observations with source, timestamp, severity and confidence.
5. The scoring engine combines observations without treating missing data as proof of safety.
6. The result and evidence are stored in Postgres.
7. The client renders the report and can request a PDF export.

## Planned analyzer modules
- URL and hostname parser
- DNS and domain registration intelligence
- TLS certificate inspection
- HTTP response and redirect inspection
- Page-content indicators (static parsing only; never execute untrusted scripts)
- Threat-intelligence provider adapters
- Brand similarity and lookalike-domain checks
- Risk scoring and explanation engine
- PDF report renderer

## Risk scoring
The score should be deterministic, versioned and explainable. Every contributing signal should include a signal identifier, explanation, severity, confidence, evidence source, collection timestamp, signal type and scoring-engine version.

No single missing signal should reduce risk to zero. Conflicting or stale signals must be visible. Verdict thresholds must be calibrated against test data before production use.

## Safe URL fetching / SSRF controls
The scanner is an internet-facing service that fetches attacker-controlled destinations. Before any outbound request:
- Accept only explicitly supported schemes (initially HTTP and HTTPS).
- Reject credentials in URLs, malformed hosts, non-public IP literals and unsupported ports.
- Resolve all A and AAAA records and reject private, loopback, link-local, multicast, reserved or otherwise non-routable addresses.
- Pin the validated destination for the connection where the runtime permits it; do not trust a second uncontrolled DNS lookup.
- Disable automatic redirects. Validate each Location target from scratch, with a small redirect limit.
- Enforce strict timeouts, response byte limits, decompression limits and content-type allowlists.
- Never fetch cloud metadata endpoints or internal service names.
- Run parsing in an isolated, resource-limited environment.
- Do not execute JavaScript, render active content or download arbitrary attachments in the initial scanner.

Cloudflare edge protections are not a substitute for application-level SSRF controls.

## Data protection
- Store credentials only in deployment secrets.
- Use parameterized SQL and least-privilege database roles.
- Minimize retention of raw HTML and personal data.
- Keep user-submitted reports moderated and abuse-resistant.
- Apply per-user and per-IP rate limits.
- Log scan identifiers and operational events without logging secrets or unnecessary personal data.
