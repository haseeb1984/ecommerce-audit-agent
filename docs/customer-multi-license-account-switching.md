# Customer account identity (supersedes multi-license switching)

The former multi-license listing and switching behavior is retired. A normalized verified checkout email identifies one customer account and one license. Customer sessions may be active on multiple devices, but every session for that email remains bound to the same license.

## Retired API

- `GET /api/v1/account/licenses` is no longer registered.
- `POST /api/v1/account/licenses/switch` is no longer registered.
- The customer portal no longer displays a linked-license selector.

## Current identity behavior

- The checkout API requires an email and rejects an email that already owns or is historically linked to an account before creating a new Paddle transaction.
- The webhook compares the declared checkout email with Paddle's customer email and refuses to provision when they differ.
- A duplicate purchase event is retained as `duplicate_account_blocked`; it does not create or email another license.
- Passwordless login resolves one canonical account or accepts a legacy email only when payment history maps it to exactly one license. Ambiguous legacy mappings fail closed.
- Subscription renewals and lifecycle updates continue to reconcile against the original subscription/license relationship.
- Multiple device sessions are supported and can be revoked individually or together; this does not imply multiple licenses per email.

See `docs/wordpress-identity-and-white-label.md` and migration `20261031_single_customer_license_identity.sql` for the rollout and legacy-data safety rules.
