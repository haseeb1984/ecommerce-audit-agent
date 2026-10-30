# Customer account recovery and verified email changes

## Existing-account recovery

Customer account recovery uses the passwordless email sign-in flow:

1. The customer requests a code using the checkout email at `POST /api/v1/account/auth/request-code`.
2. The API returns the same accepted response whether or not an account exists.
3. A linked customer receives a six-digit one-time code by SMTP.
4. Codes expire after ten minutes, allow at most five verification attempts, and are single-use.
5. A successful verification issues a 30-day opaque bearer session. The raw token is returned once and only its SHA-256 digest is stored.

The existing rate limits are one request per minute and five requests per hour per email. `ACCOUNT_AUTH_SECRET` must contain at least 32 characters. SMTP must be configured for delivery.

## Change a verified account email

The customer must already be signed in with a verified bearer session.

- `POST /api/v1/account/auth/email-change/request-code` with `{"new_email":"new@example.com"}` sends a verification code to the proposed address.
- The response includes an opaque `challenge_id`; the code is never returned by the API.
- `POST /api/v1/account/auth/email-change/verify-code` with `{"challenge_id":"...","code":"123456"}` completes the change.
- The code expires after ten minutes, is single-use, and allows at most five attempts.
- Email-change challenges are limited to one request per minute and five per hour for the existing email.
- The new address cannot take over licenses already linked to another customer identity. Collision checks run both when issuing and consuming the challenge.
- Until successful verification, the existing email and access remain unchanged.
- On success, the checkout-email identity on all payment provisioning records for the existing verified email is updated atomically, pending sign-in codes are invalidated, the current browser session is retained under the new email, and other active sessions are revoked.
- Paddle customer records and billing-provider login identity are not modified; this is the SaaS customer account identity used by license linking and passwordless sign-in.

The customer portal exposes the workflow in Account profile. The verification code is delivered only to the proposed new address.

## Database rollout

Apply `migrations/20261031_customer_email_change.sql` before deploying this revision. The migration creates the durable challenge table and its lookup, rate-limit, expiry, and license indexes.

## Recovery when the old mailbox is inaccessible

The product does not permit an unauthenticated email takeover or an operator-free change based only on a claimed address. If the customer cannot access the existing mailbox to sign in, support must verify ownership through the organization's approved support procedure before an administrator performs an account recovery action. No unverified email change is performed by these endpoints.
