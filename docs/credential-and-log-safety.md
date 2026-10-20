# Credential and log safety policy

## Non-negotiable rules

1. Secrets belong in local, ignored `.env` files or the deployment platform's encrypted environment-variable/secret store. A real credential must never be committed to source, tests, fixtures, screenshots, issue comments, PR descriptions, or documentation.
2. `.env.example` contains placeholder values only. Never copy production credentials into it.
3. Production credentials are configured in Vercel Project Settings → Environment Variables (or the approved secret manager), not in source files or a deployed `.env` file. Local `.env` is for local development only.
4. Never log credential values, authorization headers, cookies, database URLs, request query strings that may contain keys, raw provider error bodies, or complete exception/request objects that may contain secrets.
5. Never log incoming `X-API-Key`, `X-License-Key`, `Authorization`, `Cookie`, or `Set-Cookie` values. Log a request/correlation ID, route template, status, elapsed time, and a safe error code instead.
6. HTTP client logging must not print complete URLs when credentials can be present in query parameters. Provider errors must be mapped to a safe status/category; do not forward raw provider error text to logs or API responses.
7. Any redaction must be tested against message text, formatting arguments, exception output, query parameters, headers, and nested error strings. Redaction is defense-in-depth, not permission to log secrets.
8. Never disable TLS certificate verification to work around a credential/configuration issue.
9. Rotate any secret suspected of being committed, exposed in logs, or shared in a ticket. Removing it from the latest commit alone does not revoke it.
10. Audit new dependencies and logging middleware whenever a new provider or credential is introduced.

## Environment variable inventory

| Variable | Purpose | Required |
|---|---|---|
| `DATABASE_URL` | PostgreSQL/Supabase connection string | Yes |
| `DATABASE_SSL` | Enforce TLS database connection configuration | Yes in production; default must remain secure |
| `GROQ_API_KEY` | Groq API authentication | Yes |
| `GROQ_MODEL` | Configured model ID; not a credential | Optional |
| `GOOGLE_PAGESPEED_API_KEY` | PageSpeed API authentication | Optional |

Keep the inventory synchronized with the code. New payment, email, OAuth, storage, or analytics credentials must be added as placeholder names only; values are configured through the deployment secret store.

## Safe logging examples

- Good: `logger.warning("PageSpeed request failed; status=%s category=%s", status_code, "provider_error")`
- Bad: logging the full request URL, request/response object, request headers, raw provider response body, database connection string, or an exception whose text contains a credential-bearing URL.

## Release acceptance checks

- Confirm `.env` and `.env.*` are ignored while `.env.example` is tracked.
- Scan the repository history and current tree for live credentials; use secret scanning in CI.
- Add automated redaction tests for API keys, license keys, bearer tokens, passwords, database URLs, and credential-bearing query parameters.
- Exercise failure paths for Groq, PageSpeed, database connection, and authentication. Captured logs must not contain secret values or credential-bearing URLs.
- Confirm Vercel production environment variables are set in the platform and no production secrets are present in source or build artifacts.
- Review platform logs after tests; a clean unit-test log assertion alone does not prove all production logging paths are safe.

## Current implementation note

This policy and the example environment template establish the repository standard. They do not by themselves prove every existing logging path is already redacted. Treat credential-log safety as an open release gate until automated log-capture tests and repository secret scanning pass. No production credentials should be pasted into chat or PRs.
