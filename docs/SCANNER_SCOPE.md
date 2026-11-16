# Scanner Scope

## Implemented URL analysis
- Strict absolute URL parsing; only HTTP/HTTPS.
- URL-pattern checks for HTTP, deceptive authority syntax, punycode, IP literals, deep subdomains, long hostnames, shorteners, sensitive-action terms and non-standard ports.
- Explainable findings, recommendations and bounded 0–100 risk indicator.
- Zero points and no-match responses are never presented as proof of safety.

## Live domain intelligence
- Each scan can query the fixed PhishDestroy `/v1/investigate` API without an API key.
- Only the normalized hostname is sent. URL paths, query strings, fragments, credentials and submitted URL parameters are not sent to this provider.
- The response may include confirmed listing status, a separate pattern-based prediction, DNS-resolved IPs, RDAP registration age/registrar, campaign context and related domains when available.
- Confirmed threat listings are distinguished from predictions and reviewed/whitelisted domains.
- Provider errors, timeouts and rate limits are represented as unavailable intelligence, never as a clean verdict.
- The external provider's risk score is shown as a risk indicator, not a probability.

## Scheduled threat-intelligence feeds
- A separate Cloudflare Worker refreshes keyless Phishunt CC0 phishing-domain data from its public GitHub feed using conditional ETag requests.
- URLhaus and PhishTank importers remain optional integrations; they require their own credentials and are not required for Phishunt.
- Feed rows are normalized and SHA-256 hashed. Raw feed URLs are not stored in the database.
- Scan requests are checked against locally stored indicators; submitted URLs are not sent to URLhaus or PhishTank.
- Results expose provider freshness, match provenance, feed status, and clear no-match/unavailable states.
- Indicators expire after 48 hours without a successful refresh; expired records are not used for matching.

## Dashboard and reports
- `/dashboard.html` exposes aggregate scan counts, risk distribution, seven-day activity and threat-feed health. It does not expose submitted URLs or report contents.
- `/report.html` provides a print-ready A4 report with plain-language verdict, evidence, recommendations and limitations. Users can save it as PDF through the browser print dialog.
- Report data is held in the browser session for the report view; no external PDF service is used.

## Required production configuration
- Apply `migrations/0004_phishunt_feed.sql` to the production Neon database before activating the updated feed Worker.
- Deploy the feed Worker separately from Cloudflare Pages and configure its encrypted `DATABASE_URL` secret (the Pages secret does not automatically transfer to the Worker).
- URLhaus and PhishTank secrets are optional and should only be added if their current terms and eligibility are confirmed.
- Do not commit secrets or place them in browser code.

## Provider usage and legal notes
- Phishunt feed data is released under CC0 1.0 according to its public repository. Review the source and license before changing feeds.
- PhishDestroy's public API documents no API key and no usage quota, with a flood guard that can return HTTP 429. Its Terms of Service still apply.
- URLhaus community exports require an Auth-Key; commercial or for-profit use may require the enhanced commercial API.
- PhishTank's current terms point users to Cisco's current EULA. Confirm applicable terms before using it in a public product.

## Not implemented yet
- Direct TLS certificate inspection, full redirect-chain inspection and live website HTML/content analysis.
- Form/credential-harvesting analysis and browser-isolated page inspection.
- Authenticated multi-user accounts, private per-user investigation history, watchlists and evidence timeline.
- Server-generated PDF rendering; current PDF export uses the browser's print-to-PDF flow.
- Calibrated probability estimates; the 0–100 score is a rule-based/provider risk indicator, not a probability.

## Safety boundary
The scanner does not fetch submitted websites and does not execute third-party page code. It sends only the hostname to the fixed PhishDestroy domain-intelligence endpoint. Scheduled feeds are fetched only from fixed trusted provider endpoints. Any future active inspection of user-submitted websites requires connection-time destination validation, DNS rebinding defenses, private/reserved IP blocking, redirect re-validation, strict time/size limits and isolated parsing.
