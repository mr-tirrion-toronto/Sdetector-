# Scam Detector

**Scam Detector** is a live website-risk investigation platform. It combines URL-pattern analysis, domain reputation, DNS, TLS certificate inspection, registration information, public page-content signals and local threat-feed matching.

> **Important:** Scam Detector is a decision-support tool, not a guarantee that a website is safe or malicious. A low score, a missing feed match or an unavailable provider does not prove safety.

## Live capabilities

### URL and domain analysis
- Strict HTTP/HTTPS URL parsing and normalization.
- Signals for deceptive URL syntax, punycode, IP literals, deep subdomains, shorteners, sensitive-action terms and non-standard ports.
- Keyless PhishDestroy investigation for confirmed threat listings, separate risk-pattern predictions, infrastructure, campaign context and related domains when available.
- Explainable findings, risk indicator, recommendations and data-source status.

### Live technical checks
- Public DNS A, AAAA, MX, NS and TXT lookups through Cloudflare DNS-over-HTTPS.
- Live HTTPS certificate and chain validation through Trustico SSL Tools, including subject, issuer, validity, signature/public-key details and chain problems. Successful results are cached for 12 hours because the provider documents a shared 100 requests/hour limit.
- Certificate Transparency issuance history from crt.sh, shown separately from the live certificate check.
- RDAP registration date, registrar and approximate domain age when available.
- Public page-content inspection through Firecrawl keyless scraping for password fields, forms, credential requests, urgent account-pressure wording, prize lures, crypto-wallet secrets and payment-data language. The keyless endpoint is free but rate-limited per source IP.
- Firecrawl receives only the public hostname and path. Query strings, fragments, embedded credentials, browser cookies and authentication headers are not forwarded. Private/reserved DNS targets and non-standard ports are not sent to the provider.
- Redirect reporting compares the final URL reported by Firecrawl with the submitted hostname. It is not a complete network-level redirect trace.

### Accounts and API keys
- Signup, login and logout.
- Salted PBKDF2-SHA256 password hashes and secure HttpOnly session cookies.
- Private per-user scan history.
- Create, list and revoke API keys. The raw key is shown once; only its hash is stored.
- Up to 10 active API keys per account.
- API scan requests can be authenticated using `Authorization: Bearer sd_live_...`.

Open the account workspace at `/account.html`.

### Dashboard and reports
- `/dashboard.html` shows aggregate scan counts, risk distribution, recent activity and threat-feed health without exposing submitted URLs.
- `/report.html` creates a print-ready A4 investigation report with plain-language findings, live evidence, recommendations and limitations.
- Use the browser's Print / Save as PDF action to create the PDF.

## Threat-intelligence feeds

The repository contains a Cloudflare Cron Worker that triggers the protected Pages feed importer every five minutes. The Pages Function uses the existing `DATABASE_URL` secret; the Cron Worker only needs a matching `SYNC_SECRET` and Pages `FEED_SYNC_SECRET`. The feed sources are:
- **Phishunt** — keyless public phishing-domain feed released under CC0 1.0.
- **URLhaus** — optional authenticated integration.
- **PhishTank** — optional authenticated integration.

Indicators are normalized and hashed before storage. Raw feed URLs are not stored. Expired indicators are excluded from matching.

**Deployment state:** the Phishunt importer and protected Pages endpoint are implemented, and the production database schema supports Phishunt. The separate Cron Worker still needs deployment with `SYNC_SECRET`, and Pages needs the matching `FEED_SYNC_SECRET`. No Neon credential needs to be copied to the Worker. Follow [feed-worker/README.md](feed-worker/README.md). Until its first successful sync, the dashboard reports no successful feed sync.

## How to use the scanner
1. Open the public scanner.
2. Paste the URL you want to investigate without visiting it first.
3. Wait for the URL, domain, DNS, TLS, registration, content and threat-intelligence checks.
4. Review each finding and its evidence.
5. Create an account if you want private scan history and API-key management.
6. Print or save the investigation report as PDF.

**Never submit passwords, payment details, one-time codes, recovery phrases or private tokens.** Do not visit a suspicious website just to verify a scan result.

## Technology
- Cloudflare Pages and Pages Functions.
- Neon Postgres.
- TypeScript and the Neon serverless driver.
- Cloudflare Cron Worker for scheduled threat-feed ingestion.
- Browser print-to-PDF reports.

## Security boundaries and known limitations
- The scanner does not execute submitted-site JavaScript or download files. It is not a full malware sandbox.
- TLS details are obtained from the Trustico SSL Tools provider; certificate-transparency history is a separate data source.
- Firecrawl is a third-party content extraction service. Only public hostname/path data is sent to it, and returned HTML is treated as untrusted input.
- Redirect reporting uses the reader's reported final URL, not a complete redirect-by-redirect trace.
- Email verification and password-reset flows are not configured because no email delivery provider is connected.
- Feed auto-refresh is not active until the separate Worker has been deployed with its database secret.
- A 0–100 score is a rule-based/provider risk indicator, not a calibrated probability.

See [Scanner Scope](docs/SCANNER_SCOPE.md), [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md) and [Security Policy](SECURITY.md).

## Responsible use
Use Scam Detector for lawful defensive research, fraud prevention and user protection. Only submit URLs you are authorized to investigate. Do not use the service to probe internal systems, bypass access controls, disrupt websites or collect personal information.

## License
Apache License 2.0. See [LICENSE](LICENSE).

## Security reports
Do not publish exploitable vulnerabilities, credentials or private user data in public issues. Follow [SECURITY.md](SECURITY.md) for responsible disclosure.
