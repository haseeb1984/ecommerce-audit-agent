# Customer multi-license account switching

A passwordless customer browser session is bound to the verified checkout email and has one currently selected license.

## API

- `GET /api/v1/account/licenses` lists license records associated with the session email through provisioned payment webhook records. The response includes safe display metadata and the currently selected license ID.
- `POST /api/v1/account/licenses/switch` accepts `{"license_id": 123}` and changes the selected license on the current browser session only.
- Both endpoints require a valid customer bearer session. Legacy license/API-key credentials cannot enumerate or switch linked licenses.
- The switch operation checks the target license against the exact normalized verified email on the session before changing the session's license ID.
- Responses are private/no-store. The API does not expose license keys, API secrets, payment identifiers, or session digests.

## Portal behavior

The customer portal shows a linked-license selector only after passwordless email sign-in. Selecting another license refreshes report history, usage, activity, API keys, billing history, and profile data for the newly selected license. Existing license-key and API-key access remains a single-license legacy flow.

## Identity boundary

This release uses the verified checkout email as the account grouping key; it does not introduce a separate customer master identity record or merge licenses with different checkout email addresses. Changing billing email is not an account-linking operation. A future customer identity phase can introduce verified email change and explicit account-linking workflows with additional proof and audit controls.
