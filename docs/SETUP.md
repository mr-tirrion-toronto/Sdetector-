# Local Setup

## Requirements
- Node.js 22 or later
- npm
- Cloudflare account with Pages access
- Neon PostgreSQL project

## 1. Clone and install

```bash
git clone https://github.com/mr-tirrion-toronto/Sdetector-.git
cd Sdetector-
npm install
```

## 2. Prepare Neon

The database schema is in `migrations/0001_initial_schema.sql`. It will be applied through the connected Neon database integration or Neon SQL Editor. Keep the connection string private.

## 3. Local Pages development

Create a `.dev.vars` file in the repository root:

```dotenv
DATABASE_URL=your_private_neon_connection_string
APP_ENV=development
```

The file is ignored by Git. Never commit credentials.

Run:

```bash
npm run typecheck
npm test
npm run dev
```

The local site is served by Wrangler Pages. Check `/api/health` and submit a URL through the homepage.

## 4. Cloudflare Pages deployment

Create a Pages project named `scam-detector` and connect this GitHub repository.

Recommended build settings:
- Framework preset: None
- Build command: leave empty
- Build output directory: `public`
- Root directory: repository root

In Cloudflare Pages > scam-detector > Settings > Environment variables, add `DATABASE_URL` as an encrypted secret for Production and Preview as needed. Do not put the connection string in source code or `wrangler.toml`.

Alternatively, authenticate with Wrangler and deploy the Pages output:

```bash
npx wrangler login
npm run deploy
```

## Current limitations

Version 0.1 performs URL-string heuristics only. It does not connect to submitted websites, follow redirects, inspect TLS certificates, query domain-age or reputation providers, or parse remote page content. Read `SCANNER_SCOPE.md` before describing it as a full website inspection.
