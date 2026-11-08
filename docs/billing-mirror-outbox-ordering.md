# Billing mirror outbox ordering

The PostgreSQL billing mirror worker claims one pending event at a time. Claim
ordering is scoped to the canonical `PaymentWebhookEvent.license_id`, not to
email address, Paddle customer ID, or subscription text.

For a license, only its oldest pending outbox event is eligible. Ordering uses
`BillingMirrorSyncOutbox.created_at` and then `event_id` as a deterministic
tie-breaker. An earlier event remains an ordering barrier while it is deferred
for retry, even when its next retry time is in the future. This prevents a
later event from overwriting a newer Hostinger projection before the earlier
canonical event has been mirrored.

The claim's correlated pending-event lookup is supported by the
`ix_billing_mirror_sync_pending_order` index on `(status, created_at, event_id)`.
The index is declared in ORM metadata and in the idempotent
`migrations/20261106_billing_mirror_sync_outbox.sql` migration; the production
readiness CLI will report it as missing until that migration is applied.

Different licenses remain independently claimable. Claims use
`FOR UPDATE OF billing_mirror_sync_outbox SKIP LOCKED`; the source
`PaymentWebhookEvent` is then locked separately before its canonical state is
copied to Hostinger. Missing or unlinked source events remain claimable so the
existing discard path can remove orphaned outbox rows instead of blocking a
license queue forever.

This is an application-level ordering guarantee for the retry worker. It does
not replace webhook idempotency, canonical event locking, or the independent
customer lifecycle/email-identity outboxes. Regression coverage is in
`tests/test_billing_mirror_outbox_order.py`.

No live database was queried or modified by this change. CI/staging acceptance
is still required before treating the worker as production-verified.
