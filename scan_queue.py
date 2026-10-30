"""Durable Hostinger-backed website scan queue.

The caller must validate public URLs and authorize the package/license before
calling enqueue_scan_request. This module owns operational persistence only;
license/quota decisions remain with the Supabase licensing boundary.
"""
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hostinger_models import (
    CustomerUsageEvent,
    CustomerWebsite,
    ScanBatch,
    WebsiteScanJob,
)


def _utcnow():
    return datetime.now(timezone.utc)


def _stable_idempotency_key(license_key: str, request_id: str, normalized_url: str) -> str:
    raw = "\0".join((license_key, request_id, normalized_url)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def enqueue_scan_request(
    db: AsyncSession,
    *,
    license_key: str,
    package_tier: str,
    urls: Iterable[str],
    request_id: str,
    requested_by: str | None = None,
    batch_size: int = 10,
    max_attempts: int = 3,
) -> dict:
    """Persist a bulk request as sequential batches and idempotent URL jobs.

    URLs must already be normalized and SSRF-validated by the API boundary.
    batch_size is intentionally restricted to the agreed 10/11 URL grouping.
    """
    if batch_size not in (10, 11):
        raise ValueError("Scan batch size must be 10 or 11.")
    if not license_key or not request_id:
        raise ValueError("License key and request ID are required.")

    normalized_urls = list(dict.fromkeys(
        str(url).strip() for url in urls if str(url).strip()
    ))
    if not normalized_urls:
        raise ValueError("At least one website URL is required.")

    now = _utcnow()
    existing_max = await db.scalar(
        select(func.max(ScanBatch.batch_number)).where(
            ScanBatch.license_key == license_key
        )
    )
    first_batch_number = int(existing_max or 0) + 1
    created_batches = []
    created_jobs = []
    already_queued = []

    try:
        for offset in range(0, len(normalized_urls), batch_size):
            chunk = normalized_urls[offset:offset + batch_size]
            batch = ScanBatch(
                id=uuid.uuid4().hex,
                license_key=license_key,
                requested_by=requested_by,
                package_tier=package_tier,
                batch_number=first_batch_number + len(created_batches),
                batch_size=batch_size,
                total_urls=len(chunk),
                queued_count=0,
                status="queued",
                available_at=now,
                created_at=now,
            )
            db.add(batch)
            await db.flush()

            for target_url in chunk:
                host = target_url.split("/", 3)[2].split("@")[-1].split(":")[0].lower()
                website = await db.scalar(
                    select(CustomerWebsite).where(
                        CustomerWebsite.license_key == license_key,
                        CustomerWebsite.normalized_url == target_url,
                    )
                )
                if website is None:
                    website = CustomerWebsite(
                        id=uuid.uuid4().hex,
                        license_key=license_key,
                        submitted_by=requested_by,
                        url=target_url,
                        normalized_url=target_url,
                        host=host,
                        status="active",
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(website)
                    await db.flush()

                idem = _stable_idempotency_key(license_key, request_id, target_url)
                prior = await db.scalar(
                    select(WebsiteScanJob).where(
                        WebsiteScanJob.idempotency_key == idem
                    )
                )
                if prior is not None:
                    already_queued.append(prior.id)
                    continue

                job = WebsiteScanJob(
                    id=uuid.uuid4().hex,
                    batch_id=batch.id,
                    license_key=license_key,
                    website_id=website.id,
                    target_url=target_url,
                    status="queued",
                    idempotency_key=idem,
                    attempt_count=0,
                    max_attempts=max_attempts,
                    next_attempt_at=now,
                    quota_reserved=False,
                    quota_consumed=False,
                    created_at=now,
                )
                db.add(job)
                created_jobs.append(job.id)
                batch.queued_count += 1

            if batch.queued_count == 0:
                batch.status = "completed"
                batch.completed_at = now
            created_batches.append(batch.id)

        await db.commit()
    except Exception:
        await db.rollback()
        raise

    return {
        "request_id": request_id,
        "batch_ids": created_batches,
        "job_ids": created_jobs,
        "existing_job_ids": already_queued,
        "submitted_urls": len(normalized_urls),
        "new_jobs": len(created_jobs),
        "batch_size": batch_size,
        "batch_count": len(created_batches),
    }


async def claim_next_scan_job(
    db: AsyncSession,
    *,
    worker_id: str,
    lease_seconds: int = 900,
) -> WebsiteScanJob | None:
    """Claim one URL from the oldest unfinished batch for its license."""
    now = _utcnow()
    stale_before = now - timedelta(seconds=lease_seconds)
    try:
        # Expired worker leases return to the retryable queue without losing history.
        await db.execute(
            update(WebsiteScanJob)
            .where(
                WebsiteScanJob.status == "processing",
                WebsiteScanJob.locked_at < stale_before,
                WebsiteScanJob.attempt_count < WebsiteScanJob.max_attempts,
            )
            .values(
                status="retry_wait",
                next_attempt_at=now,
                locked_at=None,
                locked_by=None,
                last_error_code="WORKER_LEASE_EXPIRED",
            )
        )
        earliest_batch = (
            select(func.min(ScanBatch.batch_number))
            .where(
                ScanBatch.license_key == WebsiteScanJob.license_key,
                ScanBatch.status.notin_(("completed", "failed", "cancelled")),
            )
            .correlate(WebsiteScanJob)
            .scalar_subquery()
        )
        job = await db.scalar(
            select(WebsiteScanJob)
            .join(ScanBatch, ScanBatch.id == WebsiteScanJob.batch_id)
            .where(
                WebsiteScanJob.status.in_(("queued", "retry_wait")),
                WebsiteScanJob.next_attempt_at <= now,
                ScanBatch.status.in_(("queued", "processing")),
                ScanBatch.batch_number == earliest_batch,
            )
            .order_by(ScanBatch.created_at, WebsiteScanJob.created_at, WebsiteScanJob.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            await db.commit()
            return None

        job.status = "processing"
        job.attempt_count += 1
        job.started_at = job.started_at or now
        job.locked_at = now
        job.locked_by = worker_id[:128]
        batch = await db.get(ScanBatch, job.batch_id)
        if batch is not None:
            batch.status = "processing"
            batch.started_at = batch.started_at or now
            batch.queued_count = max(0, batch.queued_count - 1)
            batch.processing_count += 1
        await db.commit()
        await db.refresh(job)
        return job
    except Exception:
        await db.rollback()
        raise


async def complete_scan_job(
    db: AsyncSession,
    *,
    job_id: str,
    worker_id: str,
    result_reference: str | None = None,
) -> bool:
    """Mark a claimed job complete and record quota usage exactly once."""
    now = _utcnow()
    try:
        job = await db.scalar(
            select(WebsiteScanJob)
            .where(
                WebsiteScanJob.id == job_id,
                WebsiteScanJob.status == "processing",
                WebsiteScanJob.locked_by == worker_id[:128],
            )
            .with_for_update()
        )
        if job is None:
            await db.rollback()
            return False

        job.status = "completed"
        job.result_reference = result_reference
        job.completed_at = now
        job.locked_at = None
        job.locked_by = None
        job.quota_consumed = True

        batch = await db.get(ScanBatch, job.batch_id)
        if batch is not None:
            batch.processing_count = max(0, batch.processing_count - 1)
            batch.completed_count += 1
            if batch.completed_count + batch.failed_count >= batch.total_urls:
                batch.status = "completed" if batch.failed_count == 0 else "failed"
                batch.completed_at = now

        usage_key = f"scan-complete:{job.id}"
        existing_event = await db.scalar(
            select(CustomerUsageEvent.id).where(
                CustomerUsageEvent.event_key == usage_key
            )
        )
        if existing_event is None:
            db.add(CustomerUsageEvent(
                license_key=job.license_key,
                job_id=job.id,
                event_key=usage_key,
                event_type="scan_completed",
                quantity=1,
                package_tier=batch.package_tier if batch else "unknown",
                details_json=json.dumps({"batch_id": job.batch_id}),
                created_at=now,
            ))
        await db.commit()
        return True
    except Exception:
        await db.rollback()
        raise


async def fail_or_retry_scan_job(
    db: AsyncSession,
    *,
    job_id: str,
    worker_id: str,
    error_code: str,
    retry_delay_seconds: int = 60,
) -> str:
    """Persist a bounded retry or terminal failure; never silently drops a job."""
    now = _utcnow()
    safe_error = "".join(ch for ch in error_code.upper() if ch.isalnum() or ch in "_-")[:80] or "SCAN_FAILED"
    try:
        job = await db.scalar(
            select(WebsiteScanJob)
            .where(
                WebsiteScanJob.id == job_id,
                WebsiteScanJob.status == "processing",
                WebsiteScanJob.locked_by == worker_id[:128],
            )
            .with_for_update()
        )
        if job is None:
            await db.rollback()
            return "not_owned"

        batch = await db.get(ScanBatch, job.batch_id)
        if batch is not None:
            batch.processing_count = max(0, batch.processing_count - 1)

        job.last_error_code = safe_error
        job.locked_at = None
        job.locked_by = None
        if job.attempt_count < job.max_attempts:
            job.status = "retry_wait"
            job.next_attempt_at = now + timedelta(
                seconds=max(1, min(retry_delay_seconds, 3600))
            )
            if batch is not None:
                batch.queued_count += 1
                batch.status = "queued"
            outcome = "retry_wait"
        else:
            job.status = "failed"
            job.completed_at = now
            if batch is not None:
                batch.failed_count += 1
                if batch.completed_count + batch.failed_count >= batch.total_urls:
                    batch.status = "failed"
                    batch.completed_at = now
            outcome = "failed"

        await db.commit()
        return outcome
    except Exception:
        await db.rollback()
        raise
