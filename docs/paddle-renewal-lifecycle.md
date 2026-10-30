# Paddle Renewal and Subscription Lifecycle

## Source of truth

A completed Paddle transaction confirms that a payment completed. It does not, by itself, prove that a subscription was resumed or activated. Subscription access transitions are driven by verified `subscription.updated` webhooks.

## Renewal behavior

For a recurring `transaction.completed` event linked to an existing subscription, the backend:

- Reuses the existing license instead of provisioning a second license or sending another license key.
- Reconciles the configured plan and monthly audit allowance.
- Updates `billing_period_ends_at` when Paddle supplies a valid billing-period end.
- Preserves the current access state. In particular, a paid transaction does not reactivate a subscription Paddle has paused.

## Lifecycle behavior

- `paused`: access is disabled.
- `active` / `trialing`: a verified subscription update may restore access after a pause, subject to license expiry.
- `past_due`: access follows the existing retry/dunning policy and is not revoked solely because of this status.
- `canceled` / `cancelled`: cancellation remains sticky; a later payment event cannot restore access.

Billing period end remains distinct from the license expiry timestamp. A renewal updates billing metadata but does not override the provider's lifecycle state.

## Regression coverage

The backend test suite covers a purchase followed by a paused subscription and a successful renewal. It verifies that the billing period is updated while the license remains inactive.