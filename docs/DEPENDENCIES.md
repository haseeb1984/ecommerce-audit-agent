# Dependency Map

- Runtime Python dependencies: `requirements.txt`, generated from `requirements.in`.
- Development dependencies: `requirements-dev.txt`, generated from `requirements-dev.in`.
- Browser worker dependencies: `browser-worker/requirements.txt` (FastAPI, Uvicorn, Playwright).
- Project entrypoint metadata: `pyproject.toml` (`main:app`).
- Keep generated lock files synchronized by editing source input manifests and re-running the documented pip-compile workflow; do not hand-edit compiled pins.
