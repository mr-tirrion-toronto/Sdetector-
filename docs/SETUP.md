# Scam Detector Setup

## Production architecture

- Frontend: Cloudflare Pages static assets in `public/`.
- API: Cloudflare Pages Functions in `functions/api/`.
- Database: Neon PostgreSQL.
- CI/security: GitHub Actions, CodeQL and Dependabot.

Keep production on Cloudflare Pages. Do not create a parallel app or migrate hosting without explicit approval.

## Environment secrets

Configure under Cloudflare Pages > mr-tirrion-scam-detector > Settings > Variables and Secrets > Production:

- `DATABASE_URL`: Neon pooled connection string. Server-side only.
No threat-feed API key is required for the current PhishDestroy API integration. The scanner sends only the normalized hostname to `https://api.destroy.tools/v1/check`. The provider's feed updates are reflected in live scan-time checks. Do not add OpenPhish Community feed without written permission.

After changing production secrets, trigger a new Pages deployment so Functions receive the updated configuration.

## Database migrations

For an existing database, apply migrations in order:
1. `migrations/0001_initial_schema.sql` is the original baseline; fresh installations should use its current schema definition.
2. `migrations/0002_assessment_status.sql` adds explicit evidence status and the `unknown` risk level to an existing database.

Use a direct Neon connection for schema migrations; keep the pooled connection for application queries. Verify schema and a test scan after migration.

## Threat intelligence

No external threat-intelligence feed is currently active in production. The app must not claim live provider coverage until a provider is configured, legally approved, tested and deployed. Provider outage, missing configuration or no match must never be represented as a clean bill of health.

OpenPhish Community feed is not integrated because its current terms prohibit commercial/product-development use without prior written consent. URLhaus covers malware distribution rather than phishing and requires an Auth-Key. PhishTank exact-URL API lookup is a candidate integration; verify current Cisco terms and configure its key before enabling.

## Development

Use Node.js 24.

```sh
npm install
npm run typecheck
npm test
```

Deploy the existing Pages output with `npm run deploy`.
