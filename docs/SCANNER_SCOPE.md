# Scanner Scope

## Implemented URL analysis
- Strict absolute URL parsing; only HTTP/HTTPS.
- URL-pattern checks for HTTP, deceptive authority syntax, punycode, IP literals, deep subdomains, long hostnames, shorteners, sensitive-action terms and non-standard ports.
- Explainable findings, recommendations and bounded 0–100 heuristic score.
- Zero points are never presented as proof of safety.

## Threat-intelligence integration (code prepared; activation requires provider credentials)
- A separate Cloudflare Worker is configured to refresh URLhaus every five minutes and check PhishTank ETag every five minutes; PhishTank data itself is published hourly.
- URLhaus recent.csv export is ingested from its authenticated v2 export endpoint.
- PhishTank verified-online CSV gzip feed is downloaded only when its ETag changes.
- Feed rows are canonicalized and SHA-256 hashed. Raw feed URLs are not stored in the database.
- Scan requests are checked against locally stored hashes; user-submitted URLs are not sent to either provider.
- Results expose provider freshness, match provenance, feed status, and clear no-match/unavailable states.
- A verified URLhaus or PhishTank match produces a critical known-threat finding.
- Indicator records expire after 48 hours without a successful refresh; expired records are not used for matching.

## Required production configuration
The scheduled feed Worker must be deployed separately from Cloudflare Pages and configured with these encrypted Worker secrets:
- DATABASE_URL — the existing Neon connection string (also add it to this Worker, not just Pages).
- URLHAUS_AUTH_KEY — an abuse.ch authentication key.
- PHISHTANK_APP_KEY — a registered PhishTank application key.

Apply migrations/0003_threat_intelligence.sql to the production Neon database before deploying the new Pages API. Deploy the feed Worker using npm run deploy:feed-worker after its secrets are configured. Do not commit keys or put them in browser code.

## Provider usage and legal notes
- URLhaus community exports require an Auth-Key. Its official API documentation says commercial or for-profit use may require the enhanced commercial API. Confirm that the intended Scam Detector business model is within the community fair-use terms or obtain the appropriate commercial entitlement.
- PhishTank's current terms page points users to Cisco's current EULA; the API documentation requires a registered application key for higher request limits. Confirm the applicable current terms before public product use.
- Do not scrape or redistribute provider data beyond the permissions granted to the account.

## Not implemented yet
- DNS A/AAAA, RDAP registration age, TLS certificate inspection and redirect-chain inspection.
- Live website HTML/content analysis, form/credential-harvesting analysis and brand impersonation.
- Authenticated multi-user investigation history, watchlists, evidence timeline and server-generated PDF reports.
- Calibrated probability estimates; the 0–100 score is a rule-based risk indicator, not a probability.

## Safety boundary
The scanner does not fetch submitted websites and does not execute third-party page code. Threat feeds are fetched only from fixed, trusted provider endpoints by a scheduled Worker. Any future active inspection of user-submitted websites requires connection-time destination validation, DNS rebinding defenses, private/reserved IP blocking, redirect re-validation, strict time/size limits and isolated parsing.
