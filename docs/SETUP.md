# Local Setup

## Requirements

- Node.js 22 or later
- npm
- A Cloudflare account for deployment
- A Neon PostgreSQL project for scan persistence

## 1. Clone the repository

```bash
git clone https://github.com/mr-tirrion-toronto/Sdetector-.git
cd Sdetector-
npm install
```

## 2. Create the Neon database

1. Create a PostgreSQL project in Neon.
2. Open the SQL Editor for that project.
3. Run the complete contents of `migrations/0001_initial_schema.sql`.
4. In the Neon connection details, select the pooled connection string if available.
5. Keep the connection string private. Do not commit it or paste it into source files.

## 3. Configure the Worker secret

For local development, create a `.dev.vars` file in the repository root:

```dotenv
DATABASE_URL=your_private_neon_connection_string
APP_ENV=development
```

The `.dev.vars` file is ignored by Git. Never add the real connection string to `wrangler.toml`.

For a deployed Worker, set the secret through Wrangler:

```bash
npx wrangler secret put DATABASE_URL
```

Paste the connection string only into the secure terminal prompt.

## 4. Verify and run locally

```bash
npm run typecheck
npm test
npm run dev
```

Check the health endpoint at `http://localhost:8787/api/health`.

Submit a scan request:

```bash
curl -X POST http://localhost:8787/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## 5. Deploy

Authenticate with Cloudflare, then run:

```bash
npx wrangler login
npx wrangler deploy
```

Set the `DATABASE_URL` Worker secret before using persistent scan history in production.

## Important current limitation

Version 0.1 performs URL-string heuristics only. It does not connect to or inspect the submitted website. Review `SCANNER_SCOPE.md` before presenting the result as a full website security scan.
