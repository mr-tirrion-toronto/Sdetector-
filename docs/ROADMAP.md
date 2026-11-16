# Product Roadmap

## Phase 0 — Foundation
- [x] Repository, documentation and Apache 2.0 license
- [x] Security disclosure guidance and project-specific Copilot security skill
- [x] Cloudflare Pages and Neon connectivity
- [x] CI typecheck, tests and production dependency audit
- [x] Dependabot weekly dependency monitoring

## Phase 1 — Reliable URL scanner
- [x] Strict URL parsing and explainable URL-pattern findings
- [x] Explicit insufficient-evidence and limited-confidence states
- [x] Streaming request-size enforcement and API rate limit
- [x] Atomic scan/finding persistence and sensitive URL redaction
- [x] PDF print and copy-summary actions
- [ ] API integration tests for rate limits and database failures
- [ ] Authenticated, paginated server-side scan history

## Phase 2 — Threat intelligence
- [x] Design scheduled Cloudflare Worker for URLhaus and PhishTank feeds
- [x] Hash-only indicator storage and local exact-match lookup
- [x] Feed freshness and unavailable states in scan responses
- [ ] Apply threat-intelligence migration to production Neon
- [ ] Configure encrypted provider and database secrets
- [ ] Deploy scheduled Worker and verify first successful imports
- [ ] Confirm URLhaus commercial/fair-use entitlement and current PhishTank Cisco terms
- [ ] Add provider integration tests and feed rollback/atomic generation switching

## Phase 3 — Technical website intelligence
- [ ] Safe DNS A/AAAA and DNSSEC signals
- [ ] RDAP registration age with TLD-aware bootstrap
- [ ] TLS certificate and HTTP security metadata
- [ ] Redirect chain inspection only after SSRF controls are tested
- [ ] Static HTML inspection in an isolated, bounded fetch pipeline
- [ ] Brand impersonation and credential-harvesting signals

## Phase 4 — Investigation workspace
- [ ] Authentication and authorization model
- [ ] Server-side scan history, evidence timeline and comparisons
- [ ] Server-generated PDF investigation reports
- [ ] Watchlists and scheduled re-scans
- [ ] Moderated community reports
- [ ] Scam DNA and relationship graph

## Release gates
A feature is not production-ready until tests, safe failure behavior, abuse controls, provenance, timestamps, expiry, data-retention rules and deployment verification are complete. A missing feed match must never be described as a safety guarantee.
