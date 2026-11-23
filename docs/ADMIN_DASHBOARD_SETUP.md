# Administrator SOC dashboard setup

The private SOC-style console is served at `/admin.html`. It is intentionally not available to ordinary signed-in users or API-key clients.

## What the dashboard currently reports

All displayed operational metrics are queried from the production schema at request time:

- Scan totals, 24-hour and 30-day activity, unique hostnames, and risk distribution.
- High/critical hostnames from recorded scans.
- Unexpired threat-indicator hostnames and feed status.
- Registered users, active sessions, monitored domains, and stored intelligence records.
- Most frequent recorded detection findings.

The dashboard deliberately labels unavailable capabilities instead of fabricating values. Visitor geography/traffic attribution is not collected by the current schema. MITRE ATT&CK mapping, case remediation workflow, SLA targets, and MTTR are not implemented/tracked.

## Required database migration

Before an account can be promoted, apply `migrations/0008_admin_roles.sql` to the Neon production database using the project's normal migration process.

The migration adds `app_users.role`, defaults every existing and future account to `user`, and constrains values to `user` or `admin`. It does not automatically promote any account.

## Promote the verified owner account

After the migration is applied, verify the exact email address of the owner account in Neon. Then run the following SQL with the verified address substituted. Do not commit an email address or credentials into the repository.

```sql
UPDATE public.app_users
SET role = 'admin', updated_at = NOW()
WHERE LOWER(email) = LOWER('REPLACE_WITH_VERIFIED_OWNER_EMAIL')
RETURNING id, email, role;
```

Confirm exactly one intended account is returned with role `admin`. If zero or multiple rows are returned, stop and resolve the identity before proceeding.

To revoke administrator access:

```sql
UPDATE public.app_users
SET role = 'user', updated_at = NOW()
WHERE LOWER(email) = LOWER('VERIFIED_EMAIL');
```

## Authentication and authorization

- The overview endpoint is `GET /api/admin/overview`.
- It requires a valid, unexpired browser session and a database role of `admin`.
- API keys are explicitly not accepted for administrator access.
- Ordinary accounts receive HTTP 403. Missing or expired sessions receive HTTP 401.
- The endpoint returns aggregate scan metrics and indicator hostnames, not submitted scan URLs or personal scan reports.
- The page is not protected by obscurity: authorization is enforced by the API on every request.

## Deployment sequence

1. Review and merge the pull request only after CI passes and the code has been reviewed.
2. Apply the database migration.
3. Promote the verified owner account using the SQL above.
4. Deploy through the existing Cloudflare Pages production workflow.
5. Sign in through the existing account page, then open `/admin.html`.
6. Verify ordinary-user and API-key requests receive 403/401 as expected.

Creating the page and PR does not apply the migration, promote an account, or deploy anything to production.
