# Customer-wide device revocation

Customer authentication is based on a verified checkout email. A single email may own multiple purchased licenses, and browser sessions can be switched between those linked licenses.

The customer device list and individual-device revoke endpoint are scoped to the verified email identity. The revoke-all endpoint follows the same boundary:

- The request must carry a valid active customer bearer session.
- The server resolves the session's verified email from the stored token digest; it does not trust an email supplied by the browser.
- Every active session for that email is revoked, including sessions whose currently selected license differs from the request's selected license.
- Sessions belonging to other email identities are not affected.
- The response is private and non-cacheable.

This prevents the account-wide revoke-all action from leaving other devices signed in merely because those sessions were created while another linked license was selected.