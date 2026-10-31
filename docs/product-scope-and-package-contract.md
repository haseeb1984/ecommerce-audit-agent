# Ecommerce Audit Agent — Product Scope and Package Contract

This document is the implementation baseline for the SaaS product and its public marketing/pricing journey.

## Canonical packages

Only these three package IDs are supported: `starter`, `pro`, and `business`.

| Capability | Starter | Pro | Business |
|---|---:|---:|---:|
| Standard ecommerce audits | Yes | Yes | Yes |
| Monthly audit allowance | 100 | 500 | 2,000 |
| Concurrent audits | 1 | 3 | 10 |
| Conversion Dossier | No | Yes | Yes |
| White-label branding | No | Yes | Yes |
| Agency / multiple-client management | No | No | Yes |
| Direct API access | No | No | Yes |

Package catalogue pricing and Paddle price IDs remain operator-managed; this document does not invent prices.

## White-label scope (Pro and Business)

- Customer-configurable brand name, logo, and primary color.
- Branding applied to customer-facing SaaS surfaces and eligible customer deliverables.
- Branding settings are isolated to the owning customer/workspace.
- Branding entitlement must be enforced by backend APIs, not only hidden in the UI.
- PDF/report branding polish remains part of the final reporting phase, after core SaaS implementation.

## Agency scope (Business only)

- A Business agency account can manage multiple client workspaces.
- Each client workspace owns its own ecommerce website connection, audit history, usage, and settings.
- Agency dashboard provides client-level inventory and audit management.
- Team member invitations and role-based permissions are scoped to the agency and assigned client workspaces.
- Strict tenant isolation is mandatory: a team member or client must never read or mutate another workspace's data without an explicit grant.
- Agency branding is inherited from the Business agency's white-label settings, with client-specific report context kept distinct.
- Agency entitlements and limits must be enforced in backend APIs and billing/usage accounting.
- Starter and Pro remain individual customer plans; their one-license/one-website model is not broadened by agency capabilities.

## Individual customer and WordPress constraints

- An individual customer account is tied to one verified customer email and one license.
- One active WordPress site is allowed per individual license. Replacing it requires disconnecting the existing site first.
- A bulk scan may contain multiple pages, but every URL must belong to the same ecommerce website.
- Multiple devices/sessions for the same customer account are allowed; multiple-license switching is not part of the individual account model.
- Business agency client workspaces are a separately entitled capability and must not be implemented as unrestricted multi-license switching.

## Architecture baseline

- Hostinger MySQL stores operational SaaS/customer data.
- Supabase PostgreSQL stores licensing and audit-engine records.
- Backend APIs are the authorization boundary for package features and tenant ownership.
- Customer portal, admin portal, marketing pricing, checkout, and backend entitlements must use one consistent package contract.
- WordPress integration remains the official plugin under `wordpress-plugin/ecommerce-audit-agent/`; do not resurrect the superseded legacy bridge path.

## Marketing and purchase journey requirements

The public marketing website must show all three packages with their prices, audit allowances, concurrency limits, and included capabilities. It must explain Pro white-label benefits and Business agency capabilities clearly enough for a buyer to choose an appropriate package. Each package must have a purchase call-to-action connected to the existing checkout/subscription flow. Package catalogue values shown publicly must come from the operator-managed catalogue where supported; feature eligibility must come from the canonical entitlement contract. Never advertise a capability that backend enforcement does not provide.

## Delivery order

1. Complete core SaaS account, customer, admin, billing, audit, WordPress, and agency workflows.
2. Complete public marketing/pricing and package purchase journey.
3. Run integrated tests, fix defects, and verify deployment readiness.
4. Refine PDF/report presentation and perform the final audit last.

Do not merge to `main`, deploy, or run production migrations without explicit approval.


## Agency foundation implementation notes

The Business agency foundation is being implemented in Hostinger MySQL, separate from Supabase licensing/audit records.

Current branch additions:
- `AgencyAccount`, `AgencyClientWorkspace`, `AgencyClientWebsite`, `AgencyTeamMember`, `AgencyWorkspaceAccess`, and `AgencyUsageEvent` operational models.
- Additive migration: `migrations/20261101_business_agency_workspaces.sql`.
- Business-only agency provisioning and client workspace list/create/update APIs under `/api/v1/account/agency`.
- Read-only admin inventory at `/api/v1/admin/agencies`.
- Customer portal client workspace controls and admin portal agency inventory.
- Public marketing and pricing entry point at `/` and `/pricing`, using the active package catalogue and the existing Paddle checkout endpoint.

Not yet complete:
- Agency workspace website ownership verification and official WordPress plugin connection.
- Agency team invitation acceptance, authentication, and workspace-scoped authorization.
- Client-specific audit execution/history and shared Business quota/concurrency enforcement.
- Agency-aware branded deliverables and full admin lifecycle controls.
- Actual end-to-end tests and runtime verification.

The Hostinger migration is a repository artifact only. It has not been run against production. Apply it only through the approved deployment/migration process after review and backup.


### Agency team and client audit attribution batch

Additional Business-plan functionality now present on the feature branch:
- Owner-managed team invitation API with 48-hour single-use email token, SMTP delivery, invitation acceptance and revocation.
- Agency role selection (`admin`, `analyst`, `viewer`) and optional client-workspace access grants.
- `PUBLIC_APP_URL` is required to generate HTTPS invitation links; SMTP must also be configured.
- Bulk scan submissions accept an optional `workspace_id`; the API verifies that it belongs to the authenticated Business license's active agency before queueing.
- Durable `scan_batches.workspace_id` stores client attribution; batch idempotency includes the workspace so a request ID cannot be replayed against another client.
- The owner continues to submit scans under the one Business license, so existing licensing quota/concurrency enforcement remains the shared agency allowance. Per-client usage ledger aggregation is not yet connected.
- Customer portal now allows selecting a client workspace for bulk scans and choosing workspace scope when inviting team members.

Still outstanding:
- Full audit report/evidence access, verified WordPress client-site connections, usage aggregation, and team member write actions remain outstanding.
- Agency WordPress connection has an initial owner-issued token/plugin registration and revocation flow; agency plugin audit execution and full client report access remain outstanding.
- Client-specific audit result views and usage aggregation from actual completed jobs.
- Runtime validation of the migration, API routes, browser interactions, and email flow.

- Client workspace selector is now available on the bulk-scan form; submissions carry a workspace ID only when the Business owner selects an active client.
- Scan batches store optional `workspace_id`; personal submissions remain unassigned. The owner can view client-specific batch status/history at `GET /api/v1/account/agency/clients/{workspace_id}/audits`.
- Client audit history currently shows batch/job counts and status, not the complete saved audit report/evidence detail.


### Agency team authentication and least-privilege portal

- Accepted agency teammates can request a 6-digit email OTP and receive an independent 12-hour opaque bearer session; the owner license key is never issued to a team member.
- Team login checks that the agency is active and its owner still has an active Business entitlement.
- Team members can list only active client workspaces explicitly granted to them and read batch status/history only inside those workspaces.
- The owner can revoke a teammate; revocation also revokes that member's active sessions. Sessions can also be ended by the member.
- Dedicated team portal is served at `/agency`; it stores the opaque team session in browser session storage and offers assigned-workspace audit batch history.
- New operational tables are included in the additive agency migration. The migration remains unapplied in production.
- Team member access currently covers assigned-workspace audit batch status/history. It does not yet expose full audit report/evidence, WordPress site connection, client-level quota/usage, or team member write operations.


### Business agency WordPress client-site connection

- The agency owner can issue a one-time 24-hour connection token for an active client workspace.
- The official WordPress plugin has a separate agency-client connection mode. It sends the one-time token from the WordPress server to the SaaS API; it does not share the agency owner's Business license key with the client site.
- Successful registration consumes the one-time token and returns a dedicated per-site credential. The plugin encrypts that credential in its WordPress options and uses it only for agency site status and disconnect operations.
- The agency owner can inspect the connected client website and revoke it from the customer portal. Revocation invalidates the site credential; the client can be reconnected using a newly generated token.
- Agency website rows default to `pending`; a site becomes `active` only after a valid, unexpired owner-issued token is presented by the WordPress plugin.
- This is an owner-authorized plugin connection, not a DNS challenge. The agency owner should issue the token only to the intended client site administrator.
- Plugin-based agency audit execution and full client report/evidence access remain outstanding; the standard single-license WordPress audit flow is unchanged.


### Client-specific audit evidence access

- Business agency owners can retrieve saved structured audit results for one client workspace, including score, findings, check outcomes, coverage and summary JSON.
- Accepted agency teammates can retrieve the same structured evidence only for workspaces explicitly granted to their team identity.
- Both result APIs are workspace-tenant scoped, private/no-store, paginated (maximum 25 result records per request), and do not expose PDF generation/download as part of this implementation batch.
- Agency bulk scan submissions now require an active connected WordPress website for the selected client workspace and reject URLs whose hostname does not match that registered website.
- This closes the gap between a client workspace and its website identity; client audit PDF/report export remains deliberately deferred until the rest of the SaaS product is complete.
