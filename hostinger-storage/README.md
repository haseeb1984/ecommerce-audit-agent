# Hostinger Shared Hosting storage bridge

This package is uploaded manually to the same domain as the WordPress marketing
site. Copy the contents of `hostinger-storage/eaa-storage/` to:

```text
public_html/eaa-storage/
```

The Python API remains on its existing runtime. It calls
`https://YOUR-WORDPRESS-DOMAIN/eaa-storage/api/index.php` over HTTPS.

## Folder layout

```text
public_html/eaa-storage/
├── .htaccess
├── config.php                 # create manually; never commit
├── config.example.php
├── api/
│   └── index.php
└── private/
    ├── .htaccess
    ├── reports/               # private PDF objects
    ├── logos/                 # private PNG/JPEG/WebP objects
    ├── nonce-cache.json       # replay protection state
    └── nonce-cache.lock
```

The `private/` directory is intentionally inside the deployed folder only
because the user selected that layout. Apache access is denied by both the
parent and child `.htaccess` files. The PHP endpoint also serves only
allow-listed opaque keys. Do not remove these rules.

## Hostinger setup

1. Upload the package to `public_html/eaa-storage/`.
2. Copy `config.example.php` to `config.php`.
3. Replace the placeholder with a cryptographically random secret of at least
   32 bytes. Use the exact same secret in the API environment variable.
4. Confirm the domain has a valid HTTPS certificate.
5. Configure the FastAPI runtime:

```env
HOSTINGER_STORAGE_BASE_URL=https://YOUR-WORDPRESS-DOMAIN/eaa-storage/api/index.php
HOSTINGER_STORAGE_HMAC_SECRET=THE_SAME_RANDOM_SECRET
REPORT_RETENTION_DAYS=7
```

Do not put the secret in WordPress settings, a public page, or a committed file.

## Security model

- Every bridge operation is a POST signed with HMAC-SHA256.
- Timestamp validation and a locked nonce cache reject stale/replayed requests.
- Storage keys are random 256-bit identifiers, constrained to fixed report/logo
  patterns, and sent in signed headers rather than URL paths.
- Directory listing and direct access to `private/` are denied.
- Uploads are bounded and checked against their expected MIME type and file
  signature. SVG is deliberately not accepted.
- Download and delete operations require a fresh valid signature.
- The API never accepts a caller-supplied filesystem path.

URL encoding is not treated as an authorization control. No permanent public
file URL is generated.

## Verification before enabling

After upload, verify all of the following on the actual Hostinger plan:

- `/eaa-storage/private/reports/` returns 403 or 404.
- `/eaa-storage/private/logos/` returns 403 or 404.
- `/eaa-storage/config.php` returns 403 or 404.
- The API endpoint without signed headers returns 401.
- A signed upload, download, and delete round-trip returns the expected hash
  and byte count.
- Replaying the same signed request returns 401.
- A wrong signature, expired timestamp, path traversal key, unsupported MIME,
  and oversized file are rejected.

This repository package does not deploy itself. Do not enable the application
storage integration until the bridge is uploaded and these checks pass.

## PostgreSQL report migration and retention

The FastAPI code uses the Hostinger bridge for new report PDFs when both
`HOSTINGER_STORAGE_BASE_URL` and `HOSTINGER_STORAGE_HMAC_SECRET` are set.
Until those variables are configured, it retains the legacy PostgreSQL binary
path for backwards-compatible development. Do not consider storage migration
complete while that fallback is active in production.

Before migrating existing reports:

1. Back up Supabase PostgreSQL.
2. Upload the PHP bridge and complete the direct-access, HMAC, replay, and
   upload/download/delete checks above.
3. Apply `migrations/20261121_hostinger_report_storage.sql` to PostgreSQL.
4. Set `HOSTINGER_STORAGE_BASE_URL`, `HOSTINGER_STORAGE_HMAC_SECRET`,
   `REPORT_RETENTION_DAYS=7`, and a strong `CRON_SECRET` in the FastAPI
   runtime.
5. Run the verified migration from the repository root:

```bash
python scripts/migrate_report_pdfs_to_hostinger.py --batch-size 10
```

The migration downloads each uploaded object and verifies its SHA-256 and exact
bytes before setting the PostgreSQL `pdf_bytes` field to NULL. On a failed
batch it rolls back the database transaction and attempts to remove uploaded
objects. Review the final database counts and Hostinger storage before enabling
scheduled cleanup.

The daily Vercel Cron calls
`/api/v1/internal/report-retention/cleanup` at 02:15 UTC. Configure
`CRON_SECRET` in the deployment environment; the endpoint rejects requests
without the matching Bearer token. If the FastAPI runtime is not Vercel, set up
an equivalent daily HTTPS scheduler with the same Authorization header.

Retention is calculated dynamically from each report's original
`created_at` plus the current `REPORT_RETENTION_DAYS`. Changing the setting
therefore affects existing and new reports. Once a PDF has actually been
deleted, increasing retention cannot restore it. The dashboard retains report
history and shows the expiry date and remaining days.
