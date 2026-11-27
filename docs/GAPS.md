# Ecommerce Audit Agent Review Gaps

- Historical verification snapshot records 547 passed / 33 failed; rerun current suite before release.
- Verify SSRF defenses after redirects and DNS resolution on every URL-fetch path.
- Verify tenant isolation at API, database and report-download layers.
- Confirm production migrations, backup/restore and Hostinger database behavior.
- Ensure PDF exports and logs cannot expose credentials or cross-tenant data.


## Additional source-level verification items
- **Legacy test snapshot is historical only:** the 547-pass/33-fail figure belongs to the dated verification snapshot, not a current test run. Re-run the present suite and live integration checks before using it as release evidence.
- **Worker replay/lease state is process-local in places:** the browser worker's seen-request replay cache is an in-memory dictionary with a 5-minute window and 10,000-entry cap. It is not a durable cross-instance replay ledger; confirm deployment topology and whether this protection is sufficient behind multiple replicas.
- **Browser egress defense remains defense-in-depth:** browser worker source explicitly relies on network-layer outbound restrictions to protect against DNS rebinding and browser-process escape. Verify container/network policy in the actual deployment, not just application DNS checks.
- **Bulk scan API depends on two data stores:** operational scan batches/jobs/results live in Hostinger MySQL while licensing/quota/audit-lead records use PostgreSQL. Validate cross-database failure/reconciliation behavior under partial commits and real Hostinger configuration.
- **Worker lease and quota behavior needs operational fault testing:** source has lease heartbeats, quota reservation/release, and idempotent lead lookup; exercise process termination, DB outage, lease expiry, worker restart, and concurrent retries against production-like databases.
- **Customer auth review should cover all account and agency routes:** inspected auth dependency hashes customer session tokens, checks revocation/expiry, and resolves the linked license. Continue route-by-route verification of session ownership, agency role/workspace checks, email-code throttling, cookie attributes, CSRF exposure and token rotation; do not generalize one protected route to every route.
- **Browser evidence retention is intentionally limited:** worker/worker orchestration states that screenshots are not persisted because durable evidence storage is not configured. Confirm this remains the intended product boundary and make report/UI wording consistent.
- **Current source includes a substantial durable scan and account lifecycle implementation:** earlier gap notes should not be read as saying the scan queue, passwordless sessions, agency workspaces or worker lease handling are absent. Remaining work is production fault/tenant/security verification, not treating these implemented features as missing.
