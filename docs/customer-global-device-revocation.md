# Customer-wide device revocation

Customer authentication is based on a normalized verified checkout email that identifies one SaaS account and one license. A customer may have multiple browser/device sessions, but those sessions all remain attached to that same license; there is no customer license-switching flow.

The customer device list and individual-device revoke endpoint are scoped to the verified email identity. The revoke-all endpoint follows the same boundary:

- The request must carry a valid active customer bearer session.
- The server resolves the session's verified email from the stored token digest; it does not trust an email supplied by the browser.
- Every active session for that email is revoked.
- Sessions belonging to other email identities are not affected.
- The response is private and non-cacheable.

This preserves account-wide device revocation without treating multiple devices as multiple customer accounts or licenses.
