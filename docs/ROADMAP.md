# Product Roadmap

## Phase 0 — Project foundation
- [x] Establish repository and project documentation
- [x] Confirm existing Apache License 2.0
- [x] Add security disclosure guidance
- [ ] Confirm database provider and provision development database
- [ ] Confirm runtime/framework and CI checks
- [ ] Add environment-variable template and deployment configuration

## Phase 1 — Reliable scan engine
- [ ] URL canonicalization and validation
- [ ] SSRF-safe DNS resolution and outbound fetch controls
- [ ] TLS certificate and HTTP response inspection
- [ ] Redirect-chain analysis
- [ ] Domain age and DNS intelligence adapters
- [ ] Structured evidence model and unit tests

## Phase 2 — Risk intelligence
- [ ] Versioned, explainable 0–100 scoring model
- [ ] Confidence and data freshness indicators
- [ ] Phishing and impersonation heuristics
- [ ] Reputation provider adapters
- [ ] Safe handling of unknown and conflicting results

## Phase 3 — User experience
- [ ] Responsive investigation dashboard
- [ ] Scan history and comparison
- [ ] Evidence timeline and relationship visualization
- [ ] PDF report generation
- [ ] User feedback and moderated community reports

## Phase 4 — Advanced features
- [ ] Watchlists and scheduled re-scans
- [ ] Change monitoring
- [ ] Scam DNA correlation
- [ ] Brand impersonation radar
- [ ] Investigation graph
- [ ] Public API with authentication, quotas and documentation

## Release gates
A feature is not production-ready until it has tests, safe failure behaviour, abuse controls, documented limitations and deployment verification. Risk labels must not claim certainty beyond the evidence available.
