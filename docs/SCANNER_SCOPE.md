# Scanner Scope

## URL analysis
- Strict absolute URL parsing; only HTTP and HTTPS.
- URL-pattern checks for HTTP, deceptive authority syntax, punycode, IP literals, deep subdomains, long hostnames, shorteners, sensitive-action terms and non-standard ports.
- Explainable findings, recommendations and a bounded 0–100 risk indicator.
- A zero score or no-match response is never presented as proof of safety.

## Live domain and website inspection
- **PhishDestroy:** keyless hostname investigation for confirmed listing status, separate pattern predictions, resolved IPs, registration context, campaigns and related domains when available. Only the hostname is sent.
- **DNS:** public A, AAAA, MX, NS and TXT lookups through Cloudflare DNS-over-HTTPS.
- **Live TLS:** Trustico SSL Tools retrieves the current HTTPS certificate and chain, including subject, issuer, validity dates, key details and chain-validation problems. Only the HTTPS hostname is sent. The provider documents a shared unauthenticated limit of 100 requests/hour; successful results are cached in Neon for 12 hours.
- **Certificate Transparency:** crt.sh issuance history is shown separately from the live TLS result.
- **Domain registration:** RDAP registration date, approximate age and registrar are queried for the registrable domain (using the Public Suffix List), not a random subdomain. Certificate Transparency history is similarly filtered to certificates whose DNS names cover the exact hostname.
- **Page content:** Firecrawl keyless scraping inspects public HTML for password fields, forms, one-time-code requests, wallet secrets, urgent account-pressure wording, prize lures and payment-data language. Only the hostname and path are sent; query strings, fragments, embedded credentials, browser cookies and authentication headers are not forwarded. The scanner checks public DNS answers and refuses to send a hostname to the content provider if any returned A/AAAA address is private or reserved. Non-standard ports are not sent. Firecrawl keyless requests are free but rate-limited per source IP and may return HTTP 429 when the daily allowance is exhausted.
- **Redirects:** Firecrawl's reported final URL is compared with the submitted hostname. This is not a complete redirect-by-redirect network trace.
- Provider failures, timeouts and rate limits are shown as unavailable intelligence, never as a clean verdict.

## On-demand multi-source reputation checks
- The scan API can query the official Google Web Risk v1 URL Lookup API, URLhaus URL lookup API, PhishTank Check URL API and VirusTotal v3 URL analysis endpoint.
- Each provider is optional and independently reports `ok`, `not_configured` or `unavailable`; provider failures never become clean verdicts.
- API credentials are server-side Cloudflare Pages secrets only: `GOOGLE_WEB_RISK_API_KEY`, `URLHAUS_AUTH_KEY`, `PHISHTANK_API_KEY`, and `VIRUSTOTAL_PREMIUM_API_KEY`.
- Before any external reputation lookup, URL username/password, query string and fragment are removed. Providers receive only the normalized scheme, hostname and path. This protects common tracking/session query parameters but cannot guarantee that a token embedded in a path is non-sensitive.
- Google Web Risk, URLhaus and verified PhishTank matches are treated as provider-confirmed threat listings. VirusTotal is an aggregation of vendor verdicts and is shown as corroborating reputation, not as a single authoritative confirmation.
- Provider APIs have separate rate limits, eligibility, terms and data-sharing policies. Google Safe Browsing APIs are non-commercial only; Google Web Risk is the appropriate Google service for commercial malicious-URL checks. URLhaus Community API use by for-profit services may require its enhanced commercial API. PhishTank permits commercial use of its Data/API subject to its terms and rate limits. VirusTotal Public API is prohibited in commercial products and services; only a separately licensed VirusTotal Premium key may be configured here. No provider API key is generated or embedded in source code.
- A configured key does not guarantee coverage: provider results may be unavailable, stale, rate-limited, or absent for new threats. Provider status and provenance must be shown separately from local feed status.

## Scheduled threat-intelligence feeds
- A separate Cloudflare Cron Worker runs every five minutes and calls the authenticated Pages feed-sync endpoint. The Pages Function imports the keyless Phishunt CC0 feed using the existing Pages database binding; the Cron Worker does not need a second Neon credential.
- URLhaus and PhishTank importers remain optional integrations and require their own credentials. They are not required for Phishunt.
- Feed rows are normalized and SHA-256 hashed. Raw feed URLs are not stored.
- Scan requests are checked against locally stored indicators; submitted URLs are not sent to URLhaus or PhishTank.
- Results expose provider freshness, match provenance, feed status and clear no-match/unavailable states.
- Indicators expire after 48 hours without a successful refresh; expired records are not used for matching.
- **Activation state:** the importer and protected Pages endpoint are in the repository. The separate Cron Worker still needs deployment with `SYNC_SECRET`, and Pages needs the matching `FEED_SYNC_SECRET`. Until the Worker runs successfully and imports the first snapshot, the dashboard correctly reports that no feed has synced.

## Accounts and API access
- Signup, login and logout endpoints with salted PBKDF2-SHA256 password hashes.
- Secure HttpOnly, Secure, SameSite=Strict session cookies and hashed opaque session tokens.
- Private per-user scan history. Guest scans remain supported and are not retroactively assigned to accounts.
- API keys can be created, listed and revoked. The raw key is displayed only once; only its SHA-256 hash is stored.
- Registration and login have IP-based rate limits. Up to 10 active API keys per account.
- Email verification and self-service password reset are not yet configured because no email delivery provider is connected.

## Dashboard and reports
- `/dashboard.html` exposes aggregate scan counts, risk distribution, seven-day activity and threat-feed health. It does not expose submitted URLs or report contents.
- `/account.html` provides account access, API-key management and private scan history.
- `/report.html` provides a print-ready A4 report with plain-language assessment, findings, live DNS/TLS/domain/content evidence, recommendations and limitations. Users can save it as PDF through the browser print dialog.
- Report data is held in the browser session for the report view; no external PDF service is used.

## Production configuration
- Production Neon migrations 0004 (Phishunt source), 0005 (accounts/API keys) and 0006 (TLS cache) have been applied.
- The Cron Worker only needs the shared `SYNC_SECRET`; Pages keeps the existing `DATABASE_URL`. See `feed-worker/README.md`.
- URLhaus and PhishTank secrets are optional and should only be added if their current terms and eligibility are confirmed.
- Never commit secrets or place them in browser code.

## Provider usage and safety notes
- Phishunt feed data is released under CC0 1.0 according to its public repository.
- PhishDestroy's public API is keyless and has a flood guard that can return HTTP 429. Its Terms of Service still apply.
- Trustico SSL Tools documents no API authentication and a shared 100 requests/hour limit. TLS results are cached for 12 hours.
- Firecrawl is a third-party content extraction service. Only a public hostname/path is forwarded, and returned HTML is treated as untrusted input.
- The scanner does not execute submitted-site JavaScript or download files. It is not a full malware sandbox.
- The 0–100 score is a rule-based/provider risk indicator, not a calibrated probability.

## Remaining boundaries
- Complete redirect-chain capture is not implemented; only the final URL reported by Firecrawl is compared.
- A full browser-isolated malware sandbox, JavaScript behavior analysis and downloaded-file detonation are not implemented.
- The active TLS result is provided by Trustico, while Certificate Transparency history is a separate source. A provider outage or rate limit may leave TLS data unavailable.
- Email verification and password-reset flows require an email provider.
- Server-generated PDF rendering is not implemented; PDF export uses the browser's print-to-PDF flow.

## Safety boundary
The scanner does not directly fetch arbitrary submitted website URLs from the Cloudflare Worker. Public page content is retrieved by the fixed Firecrawl keyless scrape endpoint after public-DNS checks, and TLS checks are performed by a fixed SSL-analysis provider. DNS, RDAP and Certificate Transparency requests go only to fixed provider endpoints. Future direct website fetching would require connection-time destination validation, DNS-rebinding defenses, private/reserved IP blocking, redirect re-validation, strict time/size limits and isolated parsing.
