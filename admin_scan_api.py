"""Admin-only read-only diagnostics for the durable website scan queue."""
import hmac
import os
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hostinger_database import get_hostinger_db
from hostinger_models import ScanBatch, WebsiteScanJob
from models import SoftwareLicense

router = APIRouter()


def _require_scan_admin(request: Request) -> None:
    expected = os.getenv("ADMIN_API_KEY", "").strip()
    supplied = request.headers.get("x-admin-key", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Admin access is not configured.")
    if not supplied:
        raise HTTPException(status_code=401, detail="Admin authentication required.")
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Admin authentication failed.")


@router.get("/api/v1/admin/scan-operations")
async def admin_scan_operations(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Return bounded queue counts and failed-job references; never mutate queue state."""
    _require_scan_admin(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"

    status_rows = (await db.execute(
        select(WebsiteScanJob.status, func.count(WebsiteScanJob.id))
        .group_by(WebsiteScanJob.status)
    )).all()
    counts = {str(status): int(count or 0) for status, count in status_rows}
    batch_total = int((await db.execute(
        select(func.count(ScanBatch.id))
    )).scalar_one() or 0)

    failed = (await db.execute(
        select(WebsiteScanJob)
        .where(WebsiteScanJob.status == "failed")
        .order_by(WebsiteScanJob.completed_at.desc(), WebsiteScanJob.created_at.desc())
        .limit(50)
    )).scalars().all()
    license_keys = {job.license_key for job in failed}
    license_ids = {}
    if license_keys:
        license_ids = {
            key: license_id for license_id, key in (await db.execute(
                select(SoftwareLicense.id, SoftwareLicense.license_key)
                .where(SoftwareLicense.license_key.in_(license_keys))
            )).all()
        }

    return {
        "counts": {
            "batches_total": batch_total,
            "jobs_queued": counts.get("queued", 0),
            "jobs_processing": counts.get("processing", 0),
            "jobs_retry_wait": counts.get("retry_wait", 0),
            "jobs_failed": counts.get("failed", 0),
            "jobs_completed": counts.get("completed", 0),
            "jobs_cancelled": counts.get("cancelled", 0),
        },
        "failed_jobs": [{
            "job_id": job.id,
            "batch_id": job.batch_id,
            "license_id": license_ids.get(job.license_key),
            "host": urlsplit(job.target_url).hostname or "unknown host",
            "attempt_count": job.attempt_count,
            "max_attempts": job.max_attempts,
            "error_code": job.last_error_code,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        } for job in failed],
        "failed_jobs_limit": 50,
    }
