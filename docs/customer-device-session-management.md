# Customer device session management

## Scope

Passwordless customers can review recent browser sessions and revoke an individual device without signing out every other device.

- `GET /api/v1/account/auth/sessions` returns at most 100 sessions for the authenticated verified checkout email.
- `DELETE /api/v1/account/auth/sessions/{session_id}` revokes one session belonging to that verified email.
- Responses expose only a random public session identifier and safe timestamps/status. Bearer tokens and token digests are never returned.
- A session belonging to another verified email is indistinguishable from a missing session (404).
- Revoking the current session immediately clears the portal's in-memory credentials.
- Existing sign-out-current-session and sign-out-all-devices flows remain supported.

## Schema rollout

Apply `migrations/20261030_customer_passwordless_auth.sql` before enabling the feature. It adds a random public `session_id` to existing rows, then enforces uniqueness and non-nullability. Fresh installs receive the column from `migrations/2026-10-28-core-saas-schema.sql`.

The read-only production readiness check now requires the account challenge/session columns and the unique session identifier index.

## Security boundaries

The public session identifier is not an authentication credential. All operations still require the current valid bearer session and enforce exact verified-email ownership. Session listing is bounded to 100 newest records and private/no-store response headers are applied. No device fingerprinting or IP/geolocation tracking is introduced.

## Verification

PostgreSQL-backed API tests cover session listing, current-session marking, token/digest privacy, single-device revocation, and isolation from another email. CI verification is required before this phase is considered complete.
