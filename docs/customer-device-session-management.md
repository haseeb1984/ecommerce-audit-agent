# Customer device session management

Customers authenticated through passwordless email sign-in can view active browser/device sessions associated with the same verified checkout email and revoke individual other devices.

- GET /api/v1/account/auth/sessions returns bounded, non-secret session metadata.
- DELETE /api/v1/account/auth/sessions/{session_id} revokes one other active device for the same verified email.
- The current device cannot be revoked through the per-device action; use current sign-out or sign out all devices.
- Public session IDs are opaque and separate from SHA-256 bearer token digests. User-agent metadata is bounded to 500 characters and is display-only.
- Legacy sessions are assigned public IDs by the migration. No bearer token or token digest is returned to the browser.
- Apply migrations/20261031_customer_device_sessions.sql before deploying this change.
