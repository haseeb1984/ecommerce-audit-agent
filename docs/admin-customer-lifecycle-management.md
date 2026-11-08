# Admin customer lifecycle management

## Account-level directory
The operator console exposes a paginated customer directory grouped by normalized verified checkout email. Search is case-insensitive and returns license counts, active/inactive entitlement counts, and most recent billing activity. Customer identity is derived from payment provisioning records rather than an arbitrary email supplied by an unauthenticated visitor.

## Account detail
The detail endpoint returns the selected customer's linked license entitlements, browser-session metadata, bounded billing lifecycle events, and internal support notes. It never returns license keys, API key secrets, bearer tokens, token digests, or provider credentials.

## Account actions
Account-wide suspend, reactivate, and revoke-all-sessions operations require the operator to enter the exact customer email as confirmation and supply a reason. Each action is recorded in the existing administrator action log with affected license IDs, count, and reason. Suspend/reactivate affects all licenses linked to that verified checkout email. Revoke sessions invalidates all active browser sessions across those licenses.

These operations do not cancel, pause, or modify Paddle subscriptions. Subscription state remains provider-owned and is reflected through existing webhook reconciliation. Operators must use the billing provider workflow for actual subscription cancellation or changes.

## Internal support notes
Operators can append bounded internal support notes to a customer identity. Notes are append-only through this interface, visible in account detail, and never exposed to customer endpoints. The note itself is stored in the dedicated notes table; the administrator action log records the note ID, not its contents.

## Rollout
Apply `migrations/20261031_admin_customer_lifecycle.sql` before deploying this revision. All endpoints require the configured `ADMIN_API_KEY` and return private, non-cacheable customer data.

## Paddle subscription cancellation

The account detail view exposes a confirmed cancellation request for linked Paddle subscriptions. The operator must re-enter the exact subscription ID and provide a reason. The default action schedules cancellation at the next billing period; the API also supports an explicitly requested immediate cancellation. The backend calls Paddle with server-side credentials, verifies the returned subscription ID, and writes an administrator action record. It does not directly mutate local license entitlements. The verified Paddle subscription webhook remains authoritative for local subscription and access state.


## Customer detail sublist pagination

Browser sessions, linked WordPress installations, and internal support notes have independent offset/limit pagination. Each endpoint sublist defaults to 50 rows, accepts a maximum of 100 rows per request, and returns its own total and `has_more` metadata. The operator console exposes a separate Load more control for each list. Session ordering uses creation time plus the session primary key for deterministic pagination; session token hashes are never returned.

Billing lifecycle events use the independent cross-database pagination described below; the former 200-event sample limit has been removed.



## Cross-database billing event pagination

The customer detail billing history now has independent offset/limit pagination (default 50, maximum 100) and returns total/has-more metadata. The count merges sorted unique event-ID streams from Hostinger mirrors and PostgreSQL legacy events in constant application memory. Page candidates are fetched from both stores up to the requested offset plus page size, canonical PostgreSQL rows take precedence for duplicate event IDs, and the merged candidates are ordered by update timestamp and event ID. Legacy PostgreSQL events are matched by the normalized account email in addition to the currently visible license IDs so later license pages do not hide older billing history. The operator console exposes a separate Load more control for billing events.
