# Scheduled threat feed worker

This is a separate Cloudflare Worker from the Pages frontend/API. It imports provider feeds into Neon and runs on a five-minute Cron Trigger.

## Production deployment

The production Neon database already has the Phishunt source constraint and account/API-key tables. Do not re-run migrations 0004 or 0005.

The Pages DATABASE_URL secret does not automatically transfer to this separate Worker. Create the Worker's encrypted DATABASE_URL secret using the same Neon connection string already configured for the Pages application.

On Windows PowerShell, run these commands from the repository root:

```powershell
npm install
npx wrangler login
npx wrangler secret put DATABASE_URL --config feed-worker/wrangler.toml
npm run deploy:feed-worker
```

When Wrangler asks for DATABASE_URL, paste the existing Neon connection string into the terminal prompt. Do not paste it into chat, screenshots, source files or wrangler.toml. URLhaus and PhishTank keys are optional. Phishunt is keyless and is the default feed source.

Optional provider secrets can be added later:
```powershell
npx wrangler secret put URLHAUS_AUTH_KEY --config feed-worker/wrangler.toml
npx wrangler secret put PHISHTANK_APP_KEY --config feed-worker/wrangler.toml
```

## Schedule and behavior

- Cron: every five minutes.
- URLhaus: authenticated recent.csv export when configured.
- PhishTank: authenticated online-valid.csv.gz with an HTTP HEAD/ETag check when configured.
- Phishunt: keyless CC0 phishing-domain snapshot from the public GitHub repository. The importer stores hostname hashes only and uses conditional ETag requests.
- Only verified and online PhishTank records and online URLhaus records are imported. Phishunt records are normalized to exact hostnames; raw feed URLs are not stored.
- URLs are normalized and SHA-256 hashed. Raw threat URLs are not written to Neon.
- Indicator TTL is 48 hours; old records are excluded from scans and cleaned up after a seven-day grace period.
- Provider errors are recorded without logging keys or full feed URLs. The previous successful feed timestamp remains visible.

## Operations

After deployment, check Worker Logs in Cloudflare. The Phishunt feed should show status `ok`, a recent `last_success_at`, and a positive `item_count` in `threat_feed_status`. Also verify that `threat_indicators` contains Phishunt rows. A successful deployment alone is not proof that a feed imported successfully.
