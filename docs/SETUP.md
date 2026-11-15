# Setup and Deployment

## Requirements
- Node.js 24 or later
- npm
- Cloudflare account with Pages access
- Neon PostgreSQL project

## Repository
GitHub: https://github.com/mr-tirrion-toronto/Sdetector-

## 1. Install locally

```bash
git clone https://github.com/mr-tirrion-toronto/Sdetector-.git
cd Sdetector-
npm install
```

## 2. Neon database

The Neon project contains the initial schema:
- `public.scans`
- `public.scan_findings`

The migration source is `migrations/0001_initial_schema.sql`. Keep the connection string private. For the hosted Pages Function, use the pooled Neon connection URI (the hostname contains `-pooler`).

## 3. Local Pages development

Create a `.dev.vars` file in the repository root:

```dotenv
DATABASE_URL=your_private_pooled_neon_connection_string
APP_ENV=development
```

This file is ignored by Git. Never commit credentials.

Run:

```bash
npm run typecheck
npm test
npm run dev
```

The local site is served by Wrangler Pages. Check `/api/health` and submit a URL through the homepage.

## 4. Cloudflare Pages production

The Cloudflare Pages project has been created:
- Project: `scam-detector`
- Production branch: `main`
- Build command: `npm install --no-audit --no-fund`
- Build output directory: `public`
- Root directory: repository root
- Node.js: `24`

The project is connected to the GitHub repository above. New commits to `main` trigger production deployments.

### Add the Neon secret (required for database persistence)

In the Cloudflare mobile dashboard:
1. Open **Workers & Pages**.
2. Select **scam-detector**.
3. Open **Settings** → **Variables and Secrets**.
4. Under **Production**, choose **Add**.
5. Set the variable name to `DATABASE_URL`.
6. Choose **Secret** / **Encrypt** as the type.
7. Paste the pooled Neon connection string from Neon Console → `scam-detector` → Connect → Connection string.
8. Save and deploy.

Do not use a plaintext variable and do not put the connection string in GitHub, source code, or `wrangler.toml`. Preview deployments are currently disabled, so Production is the only required environment.

## 5. Verify the deployment

After the deployment succeeds, verify:
- `https://scam-detector-a92.pages.dev/`
- `https://scam-detector-a92.pages.dev/api/health`

Submit a test URL and check that the response says `persistence: "saved"`. Then confirm that one row appears in `scans` and its findings appear in `scan_findings`.

## Current implementation limits

Version 0.1 performs URL-string heuristics only. It does not connect to submitted websites, follow redirects, inspect TLS certificates, query domain-age or reputation providers, or parse remote page content. The report action uses the browser's print dialog so users can save the current result as PDF. A low-risk result is not a guarantee of safety.

Read `SCANNER_SCOPE.md` before describing the product as a full website inspection service.
