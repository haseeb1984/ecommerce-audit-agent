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

Implementation status:
- Agency client websites are connected through the official WordPress plugin using owner-issued, single-use tokens and dedicated per-site credentials.
- Agency team invitations, OTP authentication, revocable sessions, and workspace-scoped role grants are implemented.
- Client-specific audit submission, history, structured findings/evidence, and shared Business quota/concurrency accounting are implemented for owners and authorized team members.
- Admin agency suspension/reactivation and team-session revocation are implemented.
- Agency-specific PDF export and branded deliverable refinement remain deferred to the final reporting phase.
- Production migrations have not been applied; live integration and release verification remain pending.

The Hostinger migration is a repository artifact only. It has not been run against production. Apply it only through the approved deployment/migration process after review and backup.


### Agency team and client audit attribution batch

Additional Business-plan functionality now present on the feature branch:
- Owner-managed team invitation API with 48-hour single-use email token, SMTP delivery, invitation acceptance and revocation.
- Agency role selection (`admin`, `analyst`, `viewer`) and optional client-workspace access grants.
- `PUBLIC_APP_URL` is required to generate HTTPS invitation links; SMTP must also be configured.
- Bulk scan submissions accept an optional `workspace_id`; the API verifies that it belongs to the authenticated Business license's active agency before queueing.
- Durable `scan_batches.workspace_id` stores client attribution; batch idempotency includes the workspace so a request ID cannot be replayed against another client.
- The owner continues to submit scans under the one Business license, so existing licensing quota/concurrency enforcement remains the shared agency allowance. Completed client-attributed jobs are recorded in the agency usage ledger and aggregated per workspace.
- Customer portal now allows selecting a client workspace for bulk scans and choosing workspace scope when inviting team members.

Completed in the current implementation:
- Verified WordPress client-site connections use owner-issued tokens and dedicated credentials; the official plugin can submit client audits without receiving the agency owner's license key.
- Owners and granted teammates can read workspace-scoped structured audit findings/evidence; the owner and the plugin can queue audits for the connected client site.
- Analyst/Admin workspace grants can submit client audits through the agency team portal; Viewer grants remain read-only.
- Completed client-attributed jobs create idempotent usage events, and the agency usage endpoint reports shared Business allowance, pending/consumed quota, concurrency, and workspace breakdowns.
- Team members can read batch history and saved findings/evidence only for explicitly assigned workspaces.

Remaining release work:
- Agency-specific PDF export and full white-label PDF/report presentation remain deferred to the final reporting phase.
- Run the complete CI suite on the final consolidated commit and verify migration/API/browser/email behavior in an isolated staging environment.
- Production migrations and deployment remain operator-controlled and have not been performed.

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
- Team member access covers assigned-workspace audit batch status/history and structured saved findings/evidence. Analyst/Admin workspace grants can queue client audits; Viewer grants are read-only. Shared quota/usage management and workspace grants remain owner-managed.


### Business agency WordPress client-site connection

- The agency owner can issue a one-time 24-hour connection token for an active client workspace.
- The official WordPress plugin has a separate agency-client connection mode. It sends the one-time token from the WordPress server to the SaaS API; it does not share the agency owner's Business license key with the client site.
- Successful registration consumes the one-time token and returns a dedicated per-site credential. The plugin encrypts that credential in its WordPress options and uses it only for agency site status and disconnect operations.
- The agency owner can inspect the connected client website and revoke it from the customer portal. Revocation invalidates the site credential; the client can be reconnected using a newly generated token.
- Agency website rows default to `pending`; a site becomes `active` only after a valid, unexpired owner-issued token is presented by the WordPress plugin.
- This is an owner-authorized plugin connection, not a DNS challenge. The agency owner should issue the token only to the intended client site administrator.
- Agency WordPress plugin can now queue client page audits using its separate site credential, and the agency portal exposes structured findings/evidence. Agency-specific PDF export remains deferred; the standard single-license WordPress PDF flow is unchanged.


### Client-specific audit evidence access

- Business agency owners can retrieve saved structured audit results for one client workspace, including score, findings, check outcomes, coverage and summary JSON.
- Accepted agency teammates can retrieve the same structured evidence only for workspaces explicitly granted to their team identity.
- Both result APIs are workspace-tenant scoped, private/no-store, paginated (maximum 25 result records per request), and do not expose PDF generation/download as part of this implementation batch.
- Agency bulk scan submissions now require an active connected WordPress website for the selected client workspace and reject URLs whose hostname does not match that registered website.
- This closes the gap between a client workspace and its website identity; client audit PDF/report export remains deliberately deferred until the rest of the SaaS product is complete.


### Business agency shared usage and quota reporting

- A successful client-attributed scan completion now creates an idempotent `AgencyUsageEvent` in the same Hostinger transaction as the completed job and existing customer usage event.
- The event is attributed to the agency, client workspace, current calendar-month quota period and job reference; retries cannot double-count the same completed job.
- `GET /api/v1/account/agency/usage` returns the operator-managed monthly allowance, account-wide consumed/pending quota, remaining allowance, concurrent audit limit/current active reservations, and completed audit counts by client workspace.
- The agency dashboard displays this shared usage summary. Personal and agency audits continue to consume the same Business license quota and concurrency limit; no separate client quota is created.


### Standard-license single-site enforcement

- Bulk scan enqueue now checks existing Hostinger customer website bindings and active WordPress registrations while holding the per-license batch sequence lock.
- A standard customer license can submit multiple pages only when every URL belongs to one hostname. The first accepted audit binds an otherwise-unbound license; later submissions to a different hostname are rejected.
- If a standard license has conflicting historical host bindings, the queue fails closed rather than silently granting multi-site access.
- Business agency submissions are handled separately: the selected workspace must have an active owner-authorized WordPress connection, and every submitted URL hostname must match that connected client website.


### Agency WordPress plugin audit queue

- The official plugin's agency-client mode now includes a client-page audit form. It submits through `POST /api/v1/integrations/wordpress/agency/sites/audits` using the dedicated site credential, never the agency owner's license key.
- The API checks the active agency/site credential, current non-expired Business license, active client workspace, HTTPS scheme and exact connected website hostname before enqueueing.
- Jobs are queued with the selected workspace ID and use the same Business license quota/concurrency controls as other audits. Completion records the structured result and idempotent per-client usage event.
- The agency plugin mode reports that the job was queued and directs users to the SaaS dashboard for progress and findings; it does not generate a separate client PDF in this phase.


### Agency admin lifecycle and integration verification

- The admin agency inventory now includes suspend/reactivate controls.
- Suspending an agency revokes all active agency team sessions and consumes outstanding team login challenges. Reactivation restores agency eligibility but teammates must authenticate again.
- The WordPress agency audit submission endpoint is registered in `scan_api.py` and is included through the application router. It authenticates the per-site credential, checks the Business subscription, restricts every submitted URL to the connected client hostname over HTTPS, and queues the batch under the owner license and client workspace.
- Regression tests were added for agency usage ledger idempotency, missing/revoked WordPress credentials, cross-client domain rejection, successful workspace-scoped queue submission, and admin suspension session revocation.
- Customer portal guidance now reflects the implemented agency workflow and links team members to the separate `/agency` portal.
- CI was observed for the latest changes, but GitHub reported a failed job with no executed steps (`steps: []`). This is runner/job initialization failure evidence, not a test assertion result; source remains unverified by CI.

- Agency owners can now update and remove individual workspace grants for existing active team members from the customer portal; each selected workspace grant has its own Viewer/Analyst/Admin role.
- Platform suspension is enforced across owner-side agency provisioning, team management, client listing, and client updates, in addition to blocking team-member sessions and WordPress site-token access. Reactivation does not silently restore previously revoked team sessions.
- Added regression coverage for removing one workspace grant and ensuring a suspended agency cannot list its client workspaces.

- Agency invitation acceptance now re-checks the agency's active state and current Business subscription before activating a teammate; naive MySQL expiry timestamps are normalized to UTC before comparison.
- Owner-side workspace access grants can be individually added, role-updated, or removed. Admin suspension blocks owner management endpoints as well as team and WordPress access.
