"""Admin-only read-only diagnostics for the durable website scan queue."""
import hmac
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_db
from hostinger_database import get_hostinger_db
from hostinger_models import ScanBatch, WebsiteScanJob, CustomerEmailIdentitySyncOutbox
from models import SoftwareLicense, CustomerLifecycleSyncOutbox, BillingMirrorSyncOutbox
from scan_queue import retry_failed_scan_job

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
    failed_limit: int = Query(25, ge=1, le=100),
    failed_offset: int = Query(0, ge=0, le=1000000),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return bounded queue counts and failed-job references; never mutate queue state."""
    _require_scan_admin(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"

    status_rows = (await operational_db.execute(
        select(WebsiteScanJob.status, func.count(WebsiteScanJob.id))
        .group_by(WebsiteScanJob.status)
    )).all()
    counts = {str(status): int(count or 0) for status, count in status_rows}
    batch_total = int((await operational_db.execute(
        select(func.count(ScanBatch.id))
    )).scalar_one() or 0)

    async def outbox_summary(session: AsyncSession, model) -> dict:
        status_rows = (await session.execute(
            select(model.status, func.count()).group_by(model.status)
        )).all()
        status_counts = {str(status): int(count or 0) for status, count in status_rows}
        pending = int(status_counts.get("pending", 0))
        due = int((await session.execute(
            select(func.count()).select_from(model).where(
                model.status == "pending",
                model.next_attempt_at <= datetime.now(timezone.utc),
            )
        )).scalar_one() or 0)
        oldest_pending = await session.scalar(
            select(func.min(model.created_at)).where(model.status == "pending")
        )
        return {
            "pending": pending,
            "due": due,
            "completed": int(status_counts.get("completed", 0)),
            "oldest_pending_at": oldest_pending.isoformat() if oldest_pending else None,
        }

    reconciliation_outboxes = {
        "customer_lifecycle": await outbox_summary(db, CustomerLifecycleSyncOutbox),
        "billing_mirror": await outbox_summary(db, BillingMirrorSyncOutbox),
        "customer_email_identity": await outbox_summary(operational_db, CustomerEmailIdentitySyncOutbox),
    }

    failed_query = select(WebsiteScanJob).where(WebsiteScanJob.status == "failed")
    failed_total = int((await operational_db.execute(
        select(func.count(WebsiteScanJob.id)).where(WebsiteScanJob.status == "failed")
    )).scalar_one() or 0)
    failed = (await operational_db.execute(
        failed_query
        .order_by(WebsiteScanJob.completed_at.desc(), WebsiteScanJob.created_at.desc(), WebsiteScanJob.id.desc())
        .offset(failed_offset)
        .limit(failed_limit)
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
        "reconciliation_outboxes": reconciliation_outboxes,
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
        "failed_jobs_total": failed_total,
        "failed_jobs_limit": failed_limit,
        "failed_jobs_offset": failed_offset,
        "failed_jobs_has_more": failed_offset + len(failed) < failed_total,
    }


@router.post("/api/v1/admin/scan-operations/jobs/{job_id}/retry")
async def admin_retry_failed_scan_job(
    job_id: str,
    request: Request,
    response: Response,
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Explicitly requeue one failed job without reopening cancelled batches."""
    _require_scan_admin(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"

    job = await operational_db.scalar(
        select(WebsiteScanJob).where(WebsiteScanJob.id == job_id)
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job was not found.")

    result = await retry_failed_scan_job(
        operational_db,
        job_id=job_id,
        license_key=job.license_key,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan job or owning batch was not found.")
    if result.get("status") != "retry_wait":
        raise HTTPException(
            status_code=409,
            detail="Only failed jobs in non-cancelled failed batches can be retried.",
        )
    return {
        "status": "accepted",
        "job_id": result["job_id"],
        "batch_id": result["batch_id"],
        "next_attempt_at": result["next_attempt_at"].isoformat()
        if result.get("next_attempt_at") else None,
    }
