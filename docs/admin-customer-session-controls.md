# Administrator customer-session controls

The operator console exposes session metadata for a selected license account under its customer history panel.

- `GET /api/v1/admin/clients/{license_id}/sessions` lists up to 100 sessions with email, status, creation time, last-seen time, expiry, and revocation time.
- `POST /api/v1/admin/clients/{license_id}/sessions/revoke-all` revokes every unrevoked session for that license and requires an operator reason.
- Both routes require the `X-Admin-Key` header and return private/no-store responses.
- The API never returns bearer tokens or token digests.
- Revocation is recorded in the SaaS admin action log as `client.sessions_revoked`, including the count and operator-supplied reason.
- Customers must complete email verification again to establish a new browser session after revocation.

Use this control for lost-device reports, suspected credential exposure, or customer support security requests. It does not revoke the customer's license key or API integration keys; those remain separate controls.
