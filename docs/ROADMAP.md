# Product Roadmap

## Phase 0 — Project foundation
- [x] Establish repository and project documentation
- [x] Preserve Apache License 2.0
- [x] Add security disclosure guidance
- [x] Confirm Cloudflare Pages and Neon production connectivity
- [x] Add project-specific security engineering skill
- [x] Add CI typecheck and unit tests

## Phase 1 — Reliable preliminary scanner
- [x] Strict URL parsing and URL-pattern checks
- [x] Explainable findings and score bounds
- [x] Distinguish insufficient evidence from verified safety
- [x] Stream-enforced API request body limit
- [x] Per-client API rate limit
- [x] Atomic scan/finding persistence
- [x] Redact sensitive URL components before persistence
- [ ] Add API integration tests for rate limiting and database failure
- [ ] Add paginated server-side scan history and access model

## Phase 2 — Independent technical intelligence
- [ ] Safe DNS A/AAAA inspection through fixed resolver providers
- [ ] RDAP registration metadata with TLD-aware bootstrap and caching
- [ ] TLS certificate and HTTP security metadata from a safe inspection provider
- [ ] Redirect-chain inspection only after connection-time SSRF controls are proven
- [ ] Evidence provenance, source timestamps, expiry and confidence
- [ ] Versioned scoring calibration against labeled benign and malicious datasets

## Phase 3 — Reputation and phishing intelligence
- [ ] Obtain and verify provider permissions and API credentials
- [ ] Integrate approved phishing/malware reputation providers behind server-side adapters
- [ ] Build a scheduled, authenticated feed refresh pipeline with freshness checks and rollback
- [ ] Add feed provenance, last-success timestamps, source status and stale-data warnings
- [ ] Add brand impersonation signals with false-positive controls

## Phase 4 — Investigation workspace
- [ ] Authenticated scan history and authorization model
- [ ] Evidence timeline and scan comparison
- [ ] Server-generated PDF investigation reports
- [ ] Moderated community reports and feedback
- [ ] Watchlists and scheduled re-scans
- [ ] Scam DNA and relationship graph

## Release gates
A feature is not production-ready until it has tests, safe failure behaviour, abuse controls, documented limitations, source attribution, data-retention rules and deployment verification. Risk labels must not claim certainty beyond the evidence available. External intelligence updates must be timestamped and must fail visibly when stale or unavailable.
