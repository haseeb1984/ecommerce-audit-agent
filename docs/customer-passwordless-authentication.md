# Customer passwordless authentication

Customer accounts can sign in using the email address associated with a completed Paddle purchase.

## Sign-in lifecycle

1. The customer submits their checkout email to `POST /api/v1/account/auth/request-code`.
2. The API returns a generic accepted response for both known and unknown addresses. Known accounts receive a six-digit code by SMTP.
3. Codes expire after ten minutes, are single-use, and are limited to five verification attempts. A newer code invalidates older outstanding challenges.
4. Resend requests are limited to one per minute and five per hour per email address.
5. Successful verification issues an opaque 30-day bearer session. Only the SHA-256 digest of the session token is stored.
6. `POST /api/v1/account/auth/logout` revokes the current session. `POST /api/v1/account/auth/logout-all` revokes every active session for the license.

The customer portal keeps the bearer token in page memory only. It is not written to localStorage, sessionStorage, cookies, or URLs. Closing/reloading the page requires signing in again.

## Configuration and migration

- Set `ACCOUNT_AUTH_SECRET` to a unique random secret of at least 32 characters.
- Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, and the optional SMTP credentials/TLS mode.
- Apply `migrations/20261030_customer_passwordless_auth.sql` before deploying the new application version.
- The core SaaS baseline schema also includes the two authentication tables.

## Compatibility

Existing `X-License-Key` and `X-API-Key` authentication remains supported for integrations and legacy customer portal access. Customer bearer sessions are accepted by account self-service routes and the authenticated audit/report API.

## Account recovery

A customer who loses a browser session can request a fresh code at the original verified checkout email address. If a device is lost or suspected compromised, sign in on a trusted device and use the revoke-all-sessions action. Account email changes remain managed through the billing identity process and are not self-service in this phase.
