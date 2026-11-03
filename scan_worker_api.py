"""Authenticated Vercel cron entry point for the durable scan worker."""
import hmac
import os

from fastapi import APIRouter, Header, HTTPException, Query

from scan_worker import process_scan_queue

router = APIRouter()


@router.get("/api/v1/internal/scan-worker", include_in_schema=False)
async def run_legacy_scan_worker(
    authorization: str | None = Header(default=None),
):
    """Backward-compatible one-job scheduler endpoint for existing deployments."""
    expected_tokens = [
        value for value in (
            os.getenv("CRON_SECRET", "").strip(),
            os.getenv("SCAN_WORKER_TOKEN", "").strip(),
            os.getenv("SCAN_WORKER_SECRET", "").strip(),
        ) if value
    ]
    supplied = authorization or ""
    if not expected_tokens:
        raise HTTPException(status_code=503, detail="Scan worker is not configured.")
    if not any(hmac.compare_digest(supplied, f"Bearer {token}") for token in expected_tokens):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    try:
        return await process_scan_queue(max_jobs=1)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Scan worker database is unavailable.") from None


@router.get("/internal/scan-worker/run")
async def run_scan_worker(
    max_jobs: int = Query(10, ge=1, le=10),
    authorization: str | None = Header(default=None),
):
    # Vercel Cron sends Authorization: Bearer <CRON_SECRET> automatically.
    # SCAN_WORKER_TOKEN remains supported for controlled non-Vercel invocations.
    expected_tokens = [
        value for value in (
            os.getenv("CRON_SECRET", "").strip(),
            os.getenv("SCAN_WORKER_TOKEN", "").strip(),
        ) if value
    ]
    if not expected_tokens:
        raise HTTPException(status_code=503, detail="Scan worker is not configured.")
    supplied = authorization or ""
    if not any(hmac.compare_digest(supplied, f"Bearer {token}") for token in expected_tokens):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    try:
        return await process_scan_queue(max_jobs=max_jobs)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Scan worker database is unavailable.") from None
