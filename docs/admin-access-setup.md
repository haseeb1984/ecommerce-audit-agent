# Securely configure production admin access

The admin API intentionally returns HTTP 503 when `ADMIN_API_KEY` is absent. Do not remove the authentication check, use a public fallback key, or commit the key to Git.

## Configure the production secret

1. Open the Vercel dashboard and select the `ecommerce-audit-agent` project.
2. Open **Settings → Environment Variables**.
3. Add `ADMIN_API_KEY` with a newly generated, high-entropy secret. Set its environment to **Production** only unless a separate preview key is intentionally required.
4. Save the setting and redeploy the latest `main` deployment so the serverless function receives the new environment.
5. Keep the secret in your password manager or approved secret manager. Do not put it in GitHub files, issue comments, chat, screenshots, shell history, deployment logs, or client-side HTML/JavaScript.
6. Open `https://ecommerce-audit-agent.vercel.app/admin`, enter the key in the operator-only field, and load the admin data. The browser should send it as `X-Admin-Key`; it must not be embedded in the page source or stored in local storage.
7. Confirm `GET /api/v1/admin/packages` returns HTTP 200 only when the correct key is supplied, and returns 403 for a wrong key. Without the environment variable it should continue to return 503.
8. If the key is exposed or access changes, rotate it in Vercel and redeploy.

## Generate a key locally

Generate the secret on a trusted local machine; never ask a chat assistant or paste the generated value into a ticket.

Python:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

PowerShell:

```powershell
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

Use only one generated value. Store it securely, then paste it directly into Vercel's environment-variable value field.

## Safe acceptance checks

- [ ] `ADMIN_API_KEY` is configured in the Vercel **Production** environment.
- [ ] A fresh production deployment has completed successfully.
- [ ] Admin APIs return 200 with the correct key and 403 with a wrong key.
- [ ] Admin APIs return 503 if the key is not configured in a non-production test environment.
- [ ] No secret appears in the dashboard source, Git, logs, or test output.
- [ ] Review package settings and recent operation events before making any billing changes.

This guide does not change production environment variables or apply database migrations. Those actions remain operator-controlled.
