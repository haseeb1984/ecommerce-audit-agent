# Backend production-readiness checklist

## Why quota reservations exist

The previous request flow held a PostgreSQL `SELECT ... FOR UPDATE` lock while PageSpeed and Groq requests ran. That allowed a slow external request to hold a database lock long enough for a second request to hit the configured database command timeout.

The new flow creates a short-lived quota reservation in a short transaction, commits it, and only then calls external services. The successful audit record and reservation deletion are committed together. Failed audits release their reservation. Reservations expire after 15 minutes so an interrupted invocation cannot block quota indefinitely.

## Required database migration

**Do not deploy the application code until this migration has been applied to the production Supabase PostgreSQL database.**

Run the SQL in `migrations/001_audit_quota_reservations.sql` once. It creates `audit_quota_reservations` and its indexes. The statement is safe to re-run.

## Automated tests

Run:

```bash
pip install -r requirements-dev.txt
pytest -q
```

The test suite uses a dedicated PostgreSQL database. Never point `DATABASE_URL` at production when running tests: the fixture drops and recreates tables.

GitHub Actions runs the tests against an isolated PostgreSQL service on pushes to the main/fix branches and pull requests.

## Deployment gate

Before merging/deploying:

- [ ] GitHub Actions test workflow passes.
- [ ] Apply the quota-reservation migration to production Supabase.
- [ ] Confirm Vercel production environment has `DATABASE_URL`, `GROQ_API_KEY`, and `PAGE_SPEED_API_KEY`.
- [ ] Confirm database TLS remains enabled in production (`DATABASE_SSL` unset or set to `true`).
- [ ] Confirm `GET /health-check` returns database connectivity.
- [ ] Run a production concurrency test using a temporary license with monthly quota 1: two overlapping requests should return exactly one 200 and one 429, and save exactly one audit record.
- [ ] Remove the temporary test license and test audit row after verifying the result.

## Security note

Database TLS certificate verification is enabled by default. `DATABASE_SSL=false` is intended only for local/CI test databases and must not be set in production.
