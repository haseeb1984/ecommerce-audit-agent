"""Authenticated Vercel cron entry point for the durable scan worker."""
import hmac
import os

from fastapi import APIRouter, Header, HTTPException, Query

from scan_worker import process_scan_queue

router = APIRouter()


@router.post("/internal/scan-worker/run")
async def run_scan_worker(
    max_jobs: int = Query(5, ge=1, le=10),
    authorization: str | None = Header(default=None),
):
    expected = os.getenv("SCAN_WORKER_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Scan worker is not configured.")
    supplied = authorization or ""
    if not hmac.compare_digest(supplied, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    try:
        return await process_scan_queue(max_jobs=max_jobs)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Scan worker database is unavailable.") from None
