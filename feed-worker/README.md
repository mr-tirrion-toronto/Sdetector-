# Scheduled Phishunt feed sync

The Cron Worker runs every five minutes and securely calls the Scam Detector Pages Function. The Pages Function performs the import using the existing Pages `DATABASE_URL` secret. The Worker does **not** need a second Neon database credential.

## Architecture

1. Cloudflare Cron Trigger runs `feed-worker/index.ts` every five minutes.
2. The Worker sends a POST request to `/api/internal/feed-sync` with a dedicated bearer secret.
3. The Pages Function validates the secret and imports the keyless Phishunt CC0 feed into Neon.
4. The dashboard reads the same `threat_feed_status` and `threat_indicators` tables used by scans.

## Secrets

- Pages production secret: `FEED_SYNC_SECRET`
- Cron Worker secret: `SYNC_SECRET`

Both values must be identical. Never place either value in Git, frontend code, screenshots or chat. The existing Pages `DATABASE_URL` stays only in Pages and is not copied to the Cron Worker.

If configuring manually, create a long random secret and add it as a production secret in Cloudflare Pages project settings. Then, from the repository root on Windows PowerShell:

```powershell
npm install
npx wrangler login
npx wrangler secret put SYNC_SECRET --config feed-worker/wrangler.toml
npx wrangler deploy --config feed-worker/wrangler.toml
```

When Wrangler asks for `SYNC_SECRET`, paste the same value used for the Pages `FEED_SYNC_SECRET`. Do not put it in `wrangler.toml`.

## Feed sources

- **Phishunt:** keyless public phishing-domain feed released under CC0 1.0. This is the default live feed.
- **URLhaus:** optional authenticated feed; not required for Phishunt.
- **PhishTank:** optional authenticated feed; not required for Phishunt.

Phishunt URLs are normalized to hostnames and SHA-256 hashed. Raw feed URLs are not stored. Indicators expire after 48 hours without a successful refresh; expired indicators are excluded from matching.

## Verify production activation

A successful Worker deployment alone is not enough. Verify all of the following:

- Worker Cron Trigger exists and is enabled for `*/5 * * * *`.
- Cloudflare Worker logs show a successful `phishunt_sync` request with HTTP 200.
- `threat_feed_status` has a `phishunt` row with status `ok`, a recent `last_success_at` and positive `item_count`.
- `threat_indicators` contains unexpired `phishunt` rows.

The dashboard should then show a current Phishunt feed status. A missing match still does not prove a website is safe.
