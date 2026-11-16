# Scheduled threat feed worker

This is a separate Cloudflare Worker from the Pages frontend/API. It imports provider feeds into Neon and runs on a five-minute Cron Trigger.

## Before deployment
1. Apply migrations/0003_threat_intelligence.sql to the same production Neon database used by Pages.
2. Create the encrypted Worker secret DATABASE_URL. URLhaus and PhishTank keys are optional provider integrations; Phishunt is keyless.
3. Confirm your URLhaus account's community fair-use/commercial entitlement and the current PhishTank/Cisco terms.
4. Deploy with npm run deploy:feed-worker.

Wrangler commands:
```sh
npx wrangler secret put DATABASE_URL --config feed-worker/wrangler.toml
npx wrangler secret put URLHAUS_AUTH_KEY --config feed-worker/wrangler.toml
npx wrangler secret put PHISHTANK_APP_KEY --config feed-worker/wrangler.toml
npm run deploy:feed-worker
```

Secrets must never be added to wrangler.toml, source files, GitHub commits, browser JavaScript or chat messages.

## Schedule and behavior
- Cron: every five minutes.
- URLhaus: authenticated recent.csv export; feed is published on a five-minute cadence.
- PhishTank: authenticated online-valid.csv.gz; an HTTP HEAD/ETag check is performed each run and the data file is downloaded only when it changes. PhishTank says its feed is updated hourly.\n- Phishunt: keyless CC0 phishing-domain snapshot from the public GitHub repository; the importer stores hostname hashes only and uses conditional ETag requests.
- Only verified and online PhishTank records and online URLhaus records are imported. Phishunt records are normalized to exact hostnames; raw feed URLs are not stored.
- URLs are normalized and SHA-256 hashed. Raw threat URLs are not written to Neon.
- Indicator TTL is 48 hours; old records are excluded from scans and cleaned up after a seven-day grace period.
- Provider errors are recorded without logging keys or full feed URLs. The previous successful feed timestamp remains visible.

## Operations
Check Worker Logs in Cloudflare after the first scheduled run. Both feeds should show status ok and a recent last_success_at in threat_feed_status. A successful deployment alone is not proof that a feed imported successfully.
