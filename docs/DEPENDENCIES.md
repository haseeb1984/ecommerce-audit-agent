# Dependency Map

## Python runtime

- Root application runtime inputs: requirements.in.
- Root pinned/hash-locked runtime: requirements.txt.
- Development/test inputs: requirements-dev.in.
- Development/test pinned/hash-locked dependencies: requirements-dev.txt.
- Browser worker runtime: browser-worker/requirements.txt (FastAPI, Uvicorn and Playwright).
- CI installs the lock files with pip --require-hashes, runs pip-audit, and compiles Python sources.

## Other runtime components

- API entrypoint: main:app; Vercel configuration is in vercel.json.
- WordPress customer plugin: wordpress-plugin/ecommerce-audit-agent/.
- Public marketing theme: wordpress-theme/ecommerce-audit-agent/; PHP syntax is linted in CI. No separate Composer/npm build is required by the theme source.
- Hostinger private storage bridge: hostinger-storage/eaa-storage/.

## Maintenance rules

- Change source dependency inputs first, then regenerate the pinned/hash-locked manifests using the repository's documented compile workflow.
- Do not hand-edit compiled lock files or introduce unpinned runtime dependencies.
- Keep browser-worker dependencies separately pinned; do not assume the root application environment is its runtime.
- The current working branch does not contain an active pyproject.toml; do not document it as the API entrypoint configuration.
- Never commit credentials, SMTP passwords, database URLs, API keys or signing secrets.
