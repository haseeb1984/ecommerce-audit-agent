"""Durable Hostinger scan queue operations.

Jobs are claimed under a row lock and protected by an owner-bound lease. All
state transitions are conditional on the current lease owner so an expired
worker cannot overwrite the result of a replacement worker.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select, update

from hostinger_models import ScanJob


LEASE_SECONDS = 600
DEFAULT_MAX_ATTEMPTS = 5


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def claim_next_scan_job(db, *, worker_id: str):
    """Atomically claim the oldest due job or recover one whose lease expired."""
    now = _utcnow()
    eligible = or_(
        and_(
            ScanJob.status.in_(("queued", "retry")),
            ScanJob.available_at <= now,
        ),
        and_(
            ScanJob.status == "processing",
            ScanJob.lease_expires_at.is_not(None),
            ScanJob.lease_expires_at <= now,
        ),
    )
    job = (await db.execute(
        select(ScanJob)
        .where(eligible)
        .order_by(ScanJob.created_at.asc(), ScanJob.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )).scalar_one_or_none()
    if job is None:
        return None
    job.status = "processing"
    job.lease_owner = worker_id[:80]
    job.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
    job.attempts = int(job.attempts or 0) + 1
    job.updated_at = now
    await db.commit()
    await db.refresh(job)
    return job


async def renew_scan_job_lease(db, *, job_id: str, worker_id: str) -> bool:
    """Extend a lease only while the caller still owns an unexpired claim."""
    now = _utcnow()
    result = await db.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == "processing",
            ScanJob.lease_owner == worker_id,
            ScanJob.lease_expires_at > now,
        )
        .values(
            lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
            updated_at=now,
        )
    )
    await db.commit()
    return bool(result.rowcount)


async def complete_scan_job(
    db,
    *,
    job_id: str,
    worker_id: str,
    result_reference: str,
    quota_committed: bool,
) -> bool:
    """Complete a job only for its active lease owner."""
    now = _utcnow()
    result = await db.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == "processing",
            ScanJob.lease_owner == worker_id,
            ScanJob.lease_expires_at > now,
        )
        .values(
            status="completed",
            result_reference=result_reference,
            quota_committed=bool(quota_committed),
            completed_at=now,
            updated_at=now,
            lease_owner=None,
            lease_expires_at=None,
            error_code=None,
        )
    )
    await db.commit()
    return bool(result.rowcount)


async def fail_or_retry_scan_job(
    db,
    *,
    job_id: str,
    worker_id: str,
    error_code: str,
    retry_delay_seconds: int = 60,
    retryable: bool = True,
) -> str:
    """Schedule bounded retry or terminal failure without accepting stale workers."""
    now = _utcnow()
    job = (await db.execute(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.status == "processing",
            ScanJob.lease_owner == worker_id,
        ).with_for_update()
    )).scalar_one_or_none()
    if job is None:
        await db.rollback()
        return "lease_lost"
    terminal = (not retryable) or (
        int(job.attempts or 0) >= min(10, max(1, int(job.max_attempts or DEFAULT_MAX_ATTEMPTS)))
    )
    job.status = "failed" if terminal else "retry"
    job.error_code = (error_code or "WORKER_ERROR")[:120]
    job.available_at = now + timedelta(seconds=min(86400, max(1, int(retry_delay_seconds))))
    job.updated_at = now
    job.lease_owner = None
    job.lease_expires_at = None
    await db.commit()
    return "failed" if terminal else "retry_scheduled"


async def defer_scan_job(
    db,
    *,
    job_id: str,
    worker_id: str,
    delay_seconds: int = 30,
) -> bool:
    """Release a claimed job back to the queue without consuming a failure retry."""
    now = _utcnow()
    result = await db.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == "processing",
            ScanJob.lease_owner == worker_id,
        )
        .values(
            status="queued",
            available_at=now + timedelta(seconds=min(3600, max(1, int(delay_seconds)))),
            updated_at=now,
            lease_owner=None,
            lease_expires_at=None,
            error_code=None,
        )
    )
    await db.commit()
    return bool(result.rowcount)
