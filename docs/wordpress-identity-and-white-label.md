# WordPress identity linking, plan entitlements, and white-label settings

## Customer-to-site linking

The customer portal can issue a one-time WordPress link token. The token is returned only to the authenticated SaaS account, stored as a SHA-256 digest, expires after ten minutes, and is single-use. A WordPress site administrator redeems it from the plugin settings page. The backend records the canonical HTTPS site home URL and the administrator's WordPress user ID, login, and email.

Customers can list and unlink their own site connections from the SaaS portal. The plugin requires a signed-in WordPress user and the configured site capability; site linking and unlinking require the WordPress manage_options capability and a nonce. The plugin sends the SaaS credential server-side only.

## Customer account identity

A normalized, verified checkout email identifies exactly one SaaS customer account and one license. Customer sessions may exist on multiple devices, but they all remain attached to that single license; the portal does not offer license listing or switching. The checkout API requires the customer email and blocks a known existing account before creating a Paddle transaction. The declared checkout email is carried in transaction metadata and compared with Paddle’s verified customer email at webhook time. A provider-side mismatch is recorded as `checkout_email_mismatch`; a race or second transaction that reaches the webhook for an existing email is recorded as `duplicate_account_blocked`. Neither path creates or emails a second license key. Subscription lifecycle updates and renewals continue to update the existing license through its original subscription linkage.

The `software_licenses.account_email` field is the canonical identity, protected by a case-insensitive unique database index. Passwordless login resolves that field; legacy payment-event lookup is allowed only when all matching events identify exactly one license. Ambiguous historical duplicates fail closed rather than selecting whichever payment event happens to be newest. The migration deliberately stops with an actionable error when it finds duplicate email-to-license mappings. Run the read-only `scripts/report_duplicate_customer_emails.sql` report first, then reconcile those records without silently discarding billing, audit, API-key, WordPress-link, or usage history before the unique index can be installed.

## Plan entitlements

plan_features.py is the canonical display and authorization feature map:

- Starter: standard audits.
- Agency / Pro: standard audits and conversion dossier.
- Whitelabel / Enterprise / legacy Business: standard audits, conversion dossier, white-label branding, and direct API access.
- Supported package IDs are `starter`, `agency`, `pro`, `agency_pro`, `whitelabel`, `white_label`, `enterprise`, and legacy `business`.
- The admin package API and UI reject unmapped tier IDs so operators cannot accidentally sell a package whose features are all disabled.
- Blank or unknown plan identifiers fail closed.

The backend enforces standard-audit, conversion-dossier, white-label, and direct API access before quota reservation, provider calls, or key creation. Existing direct API keys stop authorizing audit API calls after a downgrade to a plan without direct API access; the customer account surface remains available for key revocation and billing recovery. Customer and WordPress interfaces use the same feature metadata for visibility, but UI hiding is not treated as authorization.

## White-label settings

Eligible accounts can save a brand name, optional HTTPS logo URL, and six-digit primary color. Settings are isolated by license. The API validates the values and never fetches the logo URL. Branding metadata is available to the customer portal and WordPress bridge; it does not yet re-skin existing PDF reports, which remain reserved for the final reporting phase.

## Database rollout

Apply migrations in order after the core SaaS schema:

1. 20261029_white_label_branding.sql
2. 20261030_customer_passwordless_auth.sql
3. 20261030_paddle_billing_period.sql
4. 20261030_customer_identity_wordpress_linking.sql
5. Run `scripts/report_duplicate_customer_emails.sql` and reconcile any returned rows without discarding linked history.
6. 20261031_single_customer_license_identity.sql

For a new database, the core schema also includes the account-session, white-label, and WordPress identity tables. The migrations are idempotent for their create/index operations. Run python scripts/check_production_readiness.py against the intended staging schema after migration; it is read-only and does not apply schema changes.

## WordPress installation

Install the wordpress/ai-ecommerce-audit-bridge directory as a plugin, configure the HTTPS SaaS API base URL and the license/API credential in Settings, and place the [ai_ecommerce_audit_dashboard] shortcode on a page restricted to the intended signed-in customer audience. The site administrator then redeems the one-time link code. The bridge displays live plan features and quota, enables audit submission only when standard-audit entitlement and quota are confirmed, and offers branding controls only when the plan is entitled.

## Verification boundary

CI validates the PHP syntax and static bridge contracts, backend ownership/one-time-token/entitlement behavior, and dependency security. A real WordPress installation, Paddle sandbox journey, staging database migration, and live customer-site acceptance still require staging credentials and explicit release approval.