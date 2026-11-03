# Admin customer identity search

The administrator client directory supports searching by client display name, package tier, license ID, and verified checkout email.

The checkout email is sourced from the most recently updated payment webhook event linked to each license. It is exposed only through the admin-key-protected overview response and is not added to customer-facing license APIs.

The admin portal displays the email as a separate column and includes it in the existing search field. Search remains bounded by the existing page size/offset controls and applies the same status and exact-tier filters.

A license without a linked payment webhook event has no verified checkout email in the directory. This does not infer identity from an unverified profile field or allow operators to link customer identities across unrelated checkout emails.
