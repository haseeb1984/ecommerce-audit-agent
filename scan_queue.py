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
from urllib.parse import urlsplit

from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from hostinger_models import (
    CustomerUsageEvent,
    CustomerWebsite,
    ScanBatch,
    WebsiteScanJob,
    AgencyAccount,
    AgencyUsageEvent,
    WordPressInstallation,
)


def _utcnow():
    return datetime.now(timezone.utc)


def _validate_standard_license_site_binding(registered_hosts: Iterable[str], submitted_urls: Iterable[str]) -> None:
    """Keep ordinary customer licenses bound to one store; agency workspaces are exempt."""
    existing = {str(host).strip().lower().rstrip(".") for host in registered_hosts if host}
    submitted = set()
    for value in submitted_urls:
        parsed = urlsplit(str(value))
        host = parsed.hostname
        if not host:
            raise ValueError("Every audit URL must include a valid website hostname.")
        submitted.add(host.encode("idna").decode("ascii").lower().rstrip("."))
    if len(submitted) != 1:
        raise ValueError("A standard customer license can audit pages from one ecommerce website only.")
    if len(existing) > 1:
        raise ValueError("This standard customer license has multiple historical website bindings. Contact support before submitting more audits.")
    if existing and not submitted.issubset(existing):
        raise ValueError("This standard customer license is already bound to a different ecommerce website.")


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
    workspace_id: str | None = None,
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
    request_hash = hashlib.sha256(
        ((workspace_id or "") + "\\n" + "\\n".join(normalized_urls)).encode("utf-8")
    ).hexdigest()
    # Acquire the per-license sequence lock before checking idempotency. This
    # serializes the check-and-create operation, so concurrent retries with the
    # same request_id cannot both observe an empty request and enqueue duplicates.
    try:
        await db.execute(text("""
            INSERT IGNORE INTO scan_batch_sequences (license_key, next_batch_number)
            SELECT :license_key, COALESCE(MAX(batch_number), 0) + 1
            FROM scan_batches WHERE license_key = :license_key
        """), {"license_key": license_key})
        sequence = (await db.execute(text("""
            SELECT next_batch_number FROM scan_batch_sequences
            WHERE license_key = :license_key FOR UPDATE
        """), {"license_key": license_key})).scalar_one()

        existing_batches = (await db.execute(
            select(ScanBatch).where(
                ScanBatch.license_key == license_key,
                ScanBatch.request_id == request_id,
            ).order_by(ScanBatch.batch_number)
        )).scalars().all()
        if existing_batches:
            if any(
                batch.request_hash != request_hash or batch.batch_size != batch_size
                or batch.workspace_id != workspace_id
                for batch in existing_batches
            ):
                raise ValueError(
                    "This request ID has already been used for a different URL list or batch size."
                )
            existing_ids = [batch.id for batch in existing_batches]
            existing_jobs = (await db.execute(
                select(WebsiteScanJob.id).where(WebsiteScanJob.batch_id.in_(existing_ids))
            )).scalars().all()
            await db.commit()  # Release the sequence lock before returning the replay.
            return {
                "request_id": request_id,
                "batch_ids": existing_ids,
                "job_ids": [],
                "existing_job_ids": list(existing_jobs),
                "submitted_urls": len(normalized_urls),
                "new_jobs": 0,
                "batch_size": batch_size,
                "batch_count": len(existing_ids),
                "idempotent_replay": True,
            }

        if workspace_id is None:
            registered_hosts = (await db.execute(
                select(CustomerWebsite.host).join(
                    WebsiteScanJob, WebsiteScanJob.website_id == CustomerWebsite.id
                ).join(
                    ScanBatch, ScanBatch.id == WebsiteScanJob.batch_id
                ).where(
                    CustomerWebsite.license_key == license_key,
                    ScanBatch.workspace_id.is_(None),
                ).distinct()
            )).scalars().all()
            registered_hosts.extend((await db.execute(
                select(WordPressInstallation.site_host).where(
                    WordPressInstallation.license_key == license_key,
                    WordPressInstallation.status == "active",
                )
            )).scalars().all())
            _validate_standard_license_site_binding(registered_hosts, normalized_urls)

        # Allocate the contiguous range only after the locked replay check.
        first_batch_number = int(sequence)
        batch_count = (len(normalized_urls) + batch_size - 1) // batch_size
        await db.execute(text("""
            UPDATE scan_batch_sequences
            SET next_batch_number = :next_number
            WHERE license_key = :license_key
        """), {"license_key": license_key, "next_number": first_batch_number + batch_count})
    except Exception:
        await db.rollback()
        raise
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
                request_id=request_id,
                workspace_id=workspace_id,
                request_hash=request_hash,
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
                if website is not None and website.status != "active":
                    website.status = "active"
                    website.updated_at = now
                if website is None:
                    website = CustomerWebsite(
                        id=uuid.uuid4().hex,
                        license_key=license_key,
                        submitted_by=requested_by,
                        url=target_url,
                        normalized_url=target_url,
                        normalized_url_hash=hashlib.sha256(target_url.encode("utf-8")).hexdigest(),
                        host=host,
                        status="active",
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(website)
                    await db.flush()

                idem = _stable_idempotency_key(license_key, request_id, target_url)
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
        # Reconcile expired leases and batch counters atomically before claiming more work.
        expired_jobs = (await db.execute(
            select(WebsiteScanJob)
            .where(
                WebsiteScanJob.status == "processing",
                WebsiteScanJob.locked_at < stale_before,
            )
            .with_for_update()
        )).scalars().all()
        for expired in expired_jobs:
            batch = await db.scalar(
                select(ScanBatch).where(ScanBatch.id == expired.batch_id).with_for_update()
            )
            if batch is not None:
                batch.processing_count = max(0, batch.processing_count - 1)
            expired.locked_at = None
            expired.locked_by = None
            expired.last_error_code = "WORKER_LEASE_EXPIRED"
            if batch is not None and batch.status == "cancel_requested":
                expired.status = "failed"
                expired.completed_at = now
                batch.failed_count += 1
                if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                    batch.status = "cancelled"
                    batch.completed_at = now
            elif expired.attempt_count < expired.max_attempts:
                expired.status = "retry_wait"
                expired.next_attempt_at = now
                if batch is not None:
                    batch.queued_count += 1
                    batch.status = "queued"
            else:
                expired.status = "failed"
                expired.completed_at = now
                if batch is not None:
                    batch.failed_count += 1
                    if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                        batch.status = "failed" if batch.cancelled_count == 0 else "cancelled"
                        batch.completed_at = now
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
        batch = await db.scalar(
            select(ScanBatch).where(ScanBatch.id == job.batch_id).with_for_update()
        )
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
    quota_committed: bool = False,
) -> bool:
    """Mark a claimed job complete and record quota usage exactly once."""
    if not quota_committed:
        raise ValueError("A scan can only complete after the licensing service confirms quota consumption.")
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

        batch = await db.scalar(
            select(ScanBatch).where(ScanBatch.id == job.batch_id).with_for_update()
        )
        if batch is not None:
            batch.processing_count = max(0, batch.processing_count - 1)
            batch.completed_count += 1
            if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                batch.status = (
                    "cancelled" if batch.cancelled_count
                    else ("completed" if batch.failed_count == 0 else "failed")
                )
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
        if batch is not None and batch.workspace_id:
            agency = await db.scalar(select(AgencyAccount).where(
                AgencyAccount.owner_license_key == job.license_key
            ))
            if agency is not None:
                agency_usage_reference = f"scan-complete:{job.id}"
                agency_usage_exists = await db.scalar(select(AgencyUsageEvent.id).where(
                    AgencyUsageEvent.agency_id == agency.id,
                    AgencyUsageEvent.source_reference == agency_usage_reference,
                ))
                if agency_usage_exists is None:
                    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    if month_start.month == 12:
                        period_end = month_start.replace(year=month_start.year + 1, month=1)
                    else:
                        period_end = month_start.replace(month=month_start.month + 1)
                    db.add(AgencyUsageEvent(
                        id=uuid.uuid4().hex,
                        agency_id=agency.id,
                        workspace_id=batch.workspace_id,
                        event_type="audit_completed",
                        quantity=1,
                        period_start=month_start,
                        period_end=period_end,
                        source_reference=agency_usage_reference,
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

        batch = await db.scalar(
            select(ScanBatch).where(ScanBatch.id == job.batch_id).with_for_update()
        )
        if batch is not None:
            batch.processing_count = max(0, batch.processing_count - 1)

        job.last_error_code = safe_error
        job.locked_at = None
        job.locked_by = None
        if batch is not None and batch.status == "cancel_requested":
            job.status = "failed"
            job.completed_at = now
            batch.failed_count += 1
            if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                batch.status = "cancelled"
                batch.completed_at = now
            outcome = "failed"
        elif job.attempt_count < job.max_attempts:
            job.status = "retry_wait"
            backoff = max(1, min(retry_delay_seconds * (2 ** max(0, job.attempt_count - 1)), 3600))
            job.next_attempt_at = now + timedelta(seconds=backoff)
            if batch is not None:
                batch.queued_count += 1
                batch.status = "queued"
            outcome = "retry_wait"
        else:
            job.status = "failed"
            job.completed_at = now
            if batch is not None:
                batch.failed_count += 1
                if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                    batch.status = "failed" if batch.cancelled_count == 0 else "cancelled"
                    batch.completed_at = now
            outcome = "failed"

        await db.commit()
        return outcome
    except Exception:
        await db.rollback()
        raise


async def defer_scan_job(
    db: AsyncSession,
    *,
    job_id: str,
    worker_id: str,
    delay_seconds: int = 30,
) -> bool:
    """Return a claimed job to the queue when package concurrency is temporarily full."""
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
        batch = await db.scalar(
            select(ScanBatch).where(ScanBatch.id == job.batch_id).with_for_update()
        )
        job.attempt_count = max(0, job.attempt_count - 1)
        job.locked_at = None
        job.locked_by = None
        if batch is not None:
            batch.processing_count = max(0, batch.processing_count - 1)
        if batch is not None and batch.status == "cancel_requested":
            job.status = "failed"
            job.completed_at = now
            job.last_error_code = "CANCELLED_DURING_CONCURRENCY_WAIT"
            batch.failed_count += 1
            if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
                batch.status = "cancelled"
                batch.completed_at = now
        else:
            job.status = "retry_wait"
            job.next_attempt_at = now + timedelta(seconds=max(5, min(delay_seconds, 300)))
            job.last_error_code = "PACKAGE_CONCURRENCY_WAIT"
            if batch is not None:
                batch.queued_count += 1
                batch.status = "queued"
        await db.commit()
        return True
    except Exception:
        await db.rollback()
        raise


async def cancel_scan_batch(
    db: AsyncSession,
    *,
    batch_id: str,
    license_key: str,
) -> dict | None:
    """Cancel work not yet claimed; allow in-flight scans to finish safely.

    Processing jobs are deliberately not force-killed: their external audit and
    licensing reservation may already be in progress. The batch remains
    cancel_requested until those jobs reach a terminal state.
    """
    now = _utcnow()
    try:
        # Match the worker's lock order (job first, then batch) to avoid
        # deadlocks when a cancellation races with a claim or completion.
        batch = await db.scalar(
            select(ScanBatch).where(
                ScanBatch.id == batch_id,
                ScanBatch.license_key == license_key,
            )
        )
        if batch is None:
            await db.rollback()
            return None

        pending = (await db.execute(
            select(WebsiteScanJob).where(
                WebsiteScanJob.batch_id == batch_id,
                WebsiteScanJob.license_key == license_key,
                WebsiteScanJob.status.in_(("queued", "retry_wait")),
            ).order_by(WebsiteScanJob.created_at, WebsiteScanJob.id)
            .with_for_update()
        )).scalars().all()

        # Re-read and lock the batch only after pending job locks are held.
        batch = await db.scalar(
            select(ScanBatch).where(
                ScanBatch.id == batch_id,
                ScanBatch.license_key == license_key,
            ).with_for_update()
        )
        if batch is None:
            await db.rollback()
            return None
        if batch.status in ("completed", "failed", "cancelled"):
            await db.commit()
            return {
                "batch_id": batch.id,
                "status": batch.status,
                "cancelled_jobs": 0,
                "in_flight_jobs": 0,
            }
        for job in pending:
            job.status = "cancelled"
            job.completed_at = now
            job.last_error_code = "CANCELLED_BY_CUSTOMER"
        cancelled_now = len(pending)
        batch.queued_count = max(0, batch.queued_count - cancelled_now)
        batch.cancelled_count = (batch.cancelled_count or 0) + cancelled_now
        in_flight = int((await db.execute(
            select(func.count(WebsiteScanJob.id)).where(
                WebsiteScanJob.batch_id == batch.id,
                WebsiteScanJob.status == "processing",
            )
        )).scalar_one() or 0)
        if batch.completed_count + batch.failed_count + batch.cancelled_count >= batch.total_urls:
            batch.status = "cancelled"
            batch.completed_at = now
        else:
            batch.status = "cancel_requested"
        await db.commit()
        return {
            "batch_id": batch.id,
            "status": batch.status,
            "cancelled_jobs": cancelled_now,
            "in_flight_jobs": in_flight,
        }
    except Exception:
        await db.rollback()
        raise


async def retry_failed_scan_job(
    db: AsyncSession,
    *,
    job_id: str,
    license_key: str,
) -> dict | None:
    """Requeue one terminally failed job at the customer's explicit request.

    A cancelled/cancel-requested batch is never reopened. The original job ID and
    idempotency key are retained so quota consumption remains idempotent.
    """
    now = _utcnow()
    try:
        job = await db.scalar(
            select(WebsiteScanJob)
            .where(
                WebsiteScanJob.id == job_id,
                WebsiteScanJob.license_key == license_key,
            )
            .with_for_update()
        )
        if job is None:
            await db.rollback()
            return None
        if job.status != "failed":
            await db.rollback()
            return {"job_id": job.id, "status": "not_retryable"}

        batch = await db.scalar(
            select(ScanBatch)
            .where(
                ScanBatch.id == job.batch_id,
                ScanBatch.license_key == license_key,
            )
            .with_for_update()
        )
        if batch is None:
            await db.rollback()
            return None
        if batch.status != "failed" or batch.cancelled_count:
            await db.rollback()
            return {"job_id": job.id, "status": "not_retryable"}

        job.status = "retry_wait"
        job.attempt_count = 0
        job.next_attempt_at = now
        job.locked_at = None
        job.locked_by = None
        job.last_error_code = None
        job.result_reference = None
        job.completed_at = None
        batch.failed_count = max(0, int(batch.failed_count or 0) - 1)
        batch.queued_count = int(batch.queued_count or 0) + 1
        batch.status = "queued"
        batch.completed_at = None
        batch.available_at = now
        await db.commit()
        return {
            "job_id": job.id,
            "batch_id": batch.id,
            "status": "retry_wait",
            "next_attempt_at": job.next_attempt_at,
        }
    except Exception:
        await db.rollback()
        raise


async def renew_scan_job_lease(
    db: AsyncSession,
    *,
    job_id: str,
    worker_id: str,
) -> bool:
    """Extend an active worker lease only while the caller still owns the job."""
    now = _utcnow()
    try:
        result = await db.execute(
            update(WebsiteScanJob)
            .where(
                WebsiteScanJob.id == job_id,
                WebsiteScanJob.status == "processing",
                WebsiteScanJob.locked_by == worker_id[:128],
            )
            .values(locked_at=now)
        )
        await db.commit()
        return bool(result.rowcount)
    except Exception:
        await db.rollback()
        raise
