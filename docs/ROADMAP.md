# Product Roadmap

## Phase 0 — Foundation
- [x] Repository, documentation and Apache 2.0 license
- [x] Cloudflare Pages + Pages Functions deployment
- [x] Neon database persistence and health check
- [x] GitHub Actions typecheck and unit tests
- [x] Project-specific security engineering skill
- [x] Correct URL authority user-info detection
- [x] Unknown / insufficient-evidence result state
- [x] Request body limit, URL privacy minimization and atomic persistence
- [x] Dependabot and CodeQL workflows

## Phase 1 — Evidence and API security
- [ ] Configure and validate a licensed phishing-reputation provider
- [ ] Add rate limiting and abuse controls
- [ ] Add scan-history access model and pagination
- [ ] Add audit trail and provider freshness indicators

## Phase 2 — Domain intelligence
- [ ] DNS A/AAAA/MX/NS/CAA intelligence
- [ ] RDAP registration-age checks
- [ ] TLS certificate intelligence
- [ ] Redirect-chain analysis after SSRF safety review

## Phase 3 — Website intelligence
- [ ] Static page-content inspection in a constrained, isolated design
- [ ] Suspicious forms and credential-harvesting indicators
- [ ] Brand impersonation and lookalike-domain analysis

## Phase 4 — Investigation workspace
- [ ] Scan history and comparison
- [ ] Evidence timeline
- [ ] PDF investigation reports
- [ ] Change monitoring and watchlists
- [ ] Scam relationship graph and community reporting

## Release gates

A feature is not production-ready until it has tests, safe failure behaviour, abuse controls, documented limitations, provider/legal review where relevant, and deployment verification. A low or empty score must never imply safety beyond the evidence available.
