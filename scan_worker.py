"""Worker that executes persisted Hostinger scan jobs through the audit engine."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, func, or_, select, update

from database import AsyncSessionLocal
from models import AuditLead, CustomerLifecycleSyncOutbox, PaymentWebhookEvent, SoftwareLicense
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import run_phase_one_checks
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks
from coverage_manifest import build_coverage_manifest
from unavailable_checks import append_unavailable_check_outcomes
from hostinger_database import HostingerAsyncSessionLocal
from hostinger_models import CustomerAccount, CustomerEmailChangeChallenge, CustomerEmailIdentitySyncOutbox, CustomerLoginChallenge, CustomerSession, WebsiteScanResult
from scan_queue import (
    claim_next_scan_job,
    complete_scan_job,
    fail_or_retry_scan_job,
    defer_scan_job,
    renew_scan_job_lease,
)
from ecommerce_agent import UniversalEcommerceAgent

logger = logging.getLogger("scan_worker")


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


async def _execute_audit(target_url: str) -> dict:
    """Run the same evidence-based checker families used by the synchronous audit."""
    result = await run_phase_one_checks(target_url)
    modules = {
        "core_homepage_discovery": "completed",
        "pagespeed": "unavailable",
        "bounded_crawl": "not_started",
        "conversion_paid_traffic": "not_started",
    }
    metrics = None
    try:
        agent = UniversalEcommerceAgent()
        metrics = await agent.run_audit(target_url)
        modules["pagespeed"] = "completed"
    except Exception as exc:
        modules["pagespeed"] = "error"
        result.limitations.append(
            f"PageSpeed metrics were unavailable for this run ({type(exc).__name__}); no performance score is inferred."
        )

    try:
        crawl_findings, crawl_pages, crawl_limitations = await run_bounded_site_crawl(
            target_url, outcome_records=result.check_outcomes
        )
        result.findings.extend(crawl_findings)
        result.pages_checked = list(dict.fromkeys([*result.pages_checked, *crawl_pages]))
        result.limitations.extend(crawl_limitations)
        modules["bounded_crawl"] = "completed" if crawl_pages else "unavailable"
    except Exception as exc:
        modules["bounded_crawl"] = "error"
        result.limitations.append(
            f"Bounded same-origin crawl was unavailable ({type(exc).__name__}); no crawl pass is inferred."
        )

    try:
        conversion_findings, conversion_pages, conversion_limitations = await run_conversion_paid_traffic_checks(target_url)
        result.findings.extend(conversion_findings)
        result.pages_checked = list(dict.fromkeys([*result.pages_checked, *conversion_pages]))
        result.limitations.extend(conversion_limitations)
        modules["conversion_paid_traffic"] = "completed"
    except Exception as exc:
        modules["conversion_paid_traffic"] = "error"
        result.limitations.append(
            f"Conversion and paid-traffic checks were unavailable ({type(exc).__name__}); no checkout or attribution outcome is inferred."
        )

    append_unavailable_check_outcomes(result)
    coverage = build_coverage_manifest(
        target_url=target_url,
        pages_checked=result.pages_checked,
        findings=result.findings,
        limitations=result.limitations,
        check_outcomes=result.check_outcomes,
        run_context={"modules": modules},
    )
    finding_data = [item.dict() for item in result.findings]
    outcome_data = [item.dict() for item in result.check_outcomes]
    # Do not label a PageSpeed mobile score as a composite audit score.
    score = None
    summary = {
        "checked_at_utc": result.checked_at_utc,
        "pages_checked": result.pages_checked,
        "limitations": result.limitations,
        "modules": modules,
        "pagespeed": metrics.dict(exclude={"screenshot_data_uri"}) if metrics is not None else None,
    }
    return {
        "findings": finding_data,
        "check_outcomes": outcome_data,
        "coverage": coverage,
        "summary": summary,
        "overall_score": score,
    }


async def process_one_scan(worker_id: str) -> dict:
    if HostingerAsyncSessionLocal is None:
        raise RuntimeError("Hostinger operational database is not configured.")
    async with HostingerAsyncSessionLocal() as operational_db:
        job = await claim_next_scan_job(operational_db, worker_id=worker_id)
        if job is None:
            return {"status": "idle"}
        job_id = job.id
        license_key = job.license_key
        website_id = job.website_id
        target_url = job.target_url

    lease_unconfirmed = asyncio.Event()

    async def _heartbeat():
        while True:
            await asyncio.sleep(240)
            try:
                async with HostingerAsyncSessionLocal() as heartbeat_db:
                    owned = await renew_scan_job_lease(
                        heartbeat_db, job_id=job_id, worker_id=worker_id,
                    )
                if not owned:
                    logger.warning("Scan worker lease ownership lost (job_id=%s)", job_id)
                    lease_unconfirmed.set()
                    return
            except Exception as heartbeat_error:
                # If ownership cannot be renewed or confirmed, stop doing billable work.
                # The stale-lease reconciler will safely recover the job after its lease expires.
                logger.warning(
                    "Scan worker heartbeat failed (job_id=%s, error_type=%s)",
                    job_id, type(heartbeat_error).__name__,
                )
                lease_unconfirmed.set()
                return

    heartbeat_task = asyncio.create_task(_heartbeat())
    reservation_id = None
    try:
        async with AsyncSessionLocal() as licensing_db:
            license_obj = await licensing_db.scalar(
                select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)
            )
            if license_obj is None:
                raise HTTPException(status_code=403, detail="LICENSE_NOT_FOUND")
            expiry = license_obj.expires_at
            if expiry is not None and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if not license_obj.is_active or (expiry is not None and expiry <= datetime.now(timezone.utc)):
                raise HTTPException(status_code=403, detail="LICENSE_INACTIVE_OR_EXPIRED")
            existing_lead = await licensing_db.scalar(
                select(AuditLead).where(AuditLead.source_job_id == job_id)
            )
            if existing_lead is None:
                reservation_id, reserved_at = await reserve_audit_slot(licensing_db, license_obj.id)
            else:
                reserved_at = existing_lead.created_at or datetime.now(timezone.utc)

        audit_task = asyncio.create_task(_execute_audit(target_url))
        lease_check_task = asyncio.create_task(lease_unconfirmed.wait())
        done, _ = await asyncio.wait(
            {audit_task, lease_check_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if lease_check_task in done and lease_unconfirmed.is_set():
            audit_task.cancel()
            await asyncio.gather(audit_task, return_exceptions=True)
            raise RuntimeError("SCAN_JOB_LEASE_UNCONFIRMED")
        lease_check_task.cancel()
        await asyncio.gather(lease_check_task, return_exceptions=True)
        result = audit_task.result()
        if lease_unconfirmed.is_set():
            raise RuntimeError("SCAN_JOB_LEASE_UNCONFIRMED")

        # Persist the successful quota consumption in Supabase exactly once per scan job.
        async with AsyncSessionLocal() as licensing_db:
            existing_lead = await licensing_db.scalar(
                select(AuditLead).where(AuditLead.source_job_id == job_id)
            )
            if existing_lead is None:
                lead = AuditLead(
                    license_id=license_obj.id,
                    domain=target_url.split("/")[2],
                    mobile_score=result["overall_score"],
                    speed_index_sec=(result["summary"].get("pagespeed") or {}).get("speed_index_sec"),
                    source_channel="bulk_scan",
                    source_job_id=job_id,
                    created_at=reserved_at,
                )
                licensing_db.add(lead)
                if reservation_id is not None:
                    from sqlalchemy import delete
                    from models import AuditQuotaReservation
                    await licensing_db.execute(
                        delete(AuditQuotaReservation).where(AuditQuotaReservation.id == reservation_id)
                    )
                await licensing_db.commit()
                reservation_id = None

        async with HostingerAsyncSessionLocal() as operational_db:
            stored = await operational_db.scalar(
                select(WebsiteScanResult).where(WebsiteScanResult.job_id == job_id)
            )
            if stored is None:
                stored = WebsiteScanResult(
                    id=uuid.uuid4().hex,
                    job_id=job_id,
                    license_key=license_key,
                    website_id=website_id,
                    target_url=target_url,
                    status="completed",
                    overall_score=result["overall_score"],
                    finding_count=len(result["findings"]),
                    findings_json=_json(result["findings"]),
                    check_outcomes_json=_json(result["check_outcomes"]),
                    coverage_json=_json(result["coverage"]),
                    summary_json=_json(result["summary"]),
                    created_at=datetime.now(timezone.utc),
                )
                operational_db.add(stored)
            else:
                stored.status = "completed"
                stored.overall_score = result["overall_score"]
                stored.finding_count = len(result["findings"])
                stored.findings_json = _json(result["findings"])
                stored.check_outcomes_json = _json(result["check_outcomes"])
                stored.coverage_json = _json(result["coverage"])
                stored.summary_json = _json(result["summary"])
            await operational_db.commit()
            completed = await complete_scan_job(
                operational_db,
                job_id=job_id,
                worker_id=worker_id,
                result_reference=stored.id,
                quota_committed=True,
            )
            if not completed:
                raise RuntimeError("SCAN_JOB_LEASE_LOST")
        return {"status": "completed", "job_id": job_id, "finding_count": len(result["findings"])}
    except RuntimeError as exc:
        if str(exc) == "SCAN_JOB_LEASE_UNCONFIRMED":
            if reservation_id is not None:
                async with AsyncSessionLocal() as licensing_db:
                    await release_audit_reservation(licensing_db, reservation_id)
            return {"status": "lease_unconfirmed", "job_id": job_id}
        if reservation_id is not None:
            async with AsyncSessionLocal() as licensing_db:
                await release_audit_reservation(licensing_db, reservation_id)
        logger.warning("Bulk scan worker failed (job_id=%s, error_type=%s)", job_id, type(exc).__name__)
        async with HostingerAsyncSessionLocal() as operational_db:
            outcome = await fail_or_retry_scan_job(
                operational_db, job_id=job_id, worker_id=worker_id,
                error_code=type(exc).__name__.upper(), retry_delay_seconds=60,
            )
        return {"status": outcome, "job_id": job_id, "error_code": type(exc).__name__.upper()}
    except HTTPException as exc:
        if reservation_id is not None:
            async with AsyncSessionLocal() as licensing_db:
                await release_audit_reservation(licensing_db, reservation_id)
        if exc.status_code == 429 and str(exc.detail).startswith("Concurrent audit limit"):
            async with HostingerAsyncSessionLocal() as operational_db:
                deferred = await defer_scan_job(
                    operational_db, job_id=job_id, worker_id=worker_id, delay_seconds=30,
                )
            return {"status": "deferred" if deferred else "lease_lost", "job_id": job_id, "reason": "package_concurrency"}
        error_code = "QUOTA_OR_LICENSE_BLOCKED" if exc.status_code in (402, 403, 429) else "AUDIT_REJECTED"
        async with HostingerAsyncSessionLocal() as operational_db:
            outcome = await fail_or_retry_scan_job(
                operational_db, job_id=job_id, worker_id=worker_id,
                error_code=error_code, retry_delay_seconds=300,
            )
        return {"status": outcome, "job_id": job_id, "error_code": error_code}
    except Exception as exc:
        if reservation_id is not None:
            async with AsyncSessionLocal() as licensing_db:
                await release_audit_reservation(licensing_db, reservation_id)
        logger.warning("Bulk scan worker failed (job_id=%s, error_type=%s)", job_id, type(exc).__name__)
        async with HostingerAsyncSessionLocal() as operational_db:
            outcome = await fail_or_retry_scan_job(
                operational_db, job_id=job_id, worker_id=worker_id,
                error_code=type(exc).__name__.upper(), retry_delay_seconds=60,
            )
        return {"status": outcome, "job_id": job_id, "error_code": type(exc).__name__.upper()}
    finally:
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)


async def reconcile_customer_lifecycle_outbox(*, batch_size: int = 50) -> dict:
    """Apply canonical PostgreSQL admin lifecycle actions to Hostinger operational records."""
    if batch_size < 1 or batch_size > 200:
        raise ValueError("batch_size must be between 1 and 200.")
    now = datetime.now(timezone.utc)
    counts = {"processed": 0, "deferred": 0}
    async with AsyncSessionLocal() as licensing_db:
        for _ in range(batch_size):
            event = (await licensing_db.execute(
                select(CustomerLifecycleSyncOutbox)
                .where(
                    CustomerLifecycleSyncOutbox.status == "pending",
                    CustomerLifecycleSyncOutbox.next_attempt_at <= now,
                )
                .order_by(CustomerLifecycleSyncOutbox.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )).scalar_one_or_none()
            if event is None:
                break
            event_id = event.id
            license_key = event.license_key
            action = event.action
            try:
                async with HostingerAsyncSessionLocal() as operational_db:
                    if action in {"suspend", "reactivate"}:
                        await operational_db.execute(update(CustomerAccount).where(
                            CustomerAccount.license_key == license_key
                        ).values(
                            status="suspended" if action == "suspend" else "active",
                            updated_at=datetime.now(timezone.utc),
                        ))
                    if action in {"suspend", "revoke_sessions"}:
                        await operational_db.execute(update(CustomerSession).where(
                            CustomerSession.license_key == license_key,
                            CustomerSession.revoked_at.is_(None),
                        ).values(revoked_at=datetime.now(timezone.utc)))
                    await operational_db.commit()
                event.status = "completed"
                event.processed_at = datetime.now(timezone.utc)
                event.last_error = None
                await licensing_db.commit()
                counts["processed"] += 1
            except Exception as exc:
                await licensing_db.rollback()
                retry_event = await licensing_db.get(CustomerLifecycleSyncOutbox, event_id)
                if retry_event is not None:
                    retry_event.attempts = int(retry_event.attempts or 0) + 1
                    retry_event.last_error = type(exc).__name__[:120]
                    delay = min(3600, 30 * (2 ** min(retry_event.attempts, 7)))
                    retry_event.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    await licensing_db.commit()
                counts["deferred"] += 1
                logger.warning(
                    "Customer lifecycle sync deferred (event_id=%s, error_type=%s)",
                    event_id, type(exc).__name__,
                )
    return counts


async def reconcile_customer_email_identity_outbox(*, batch_size: int = 50) -> dict:
    """Retry verified email changes into PostgreSQL billing records idempotently."""
    if batch_size < 1 or batch_size > 200:
        raise ValueError("batch_size must be between 1 and 200.")
    now = datetime.now(timezone.utc)
    counts = {"processed": 0, "deferred": 0}
    async with HostingerAsyncSessionLocal() as operational_db:
        for _ in range(batch_size):
            event = (await operational_db.execute(
                select(CustomerEmailIdentitySyncOutbox)
                .where(
                    CustomerEmailIdentitySyncOutbox.status == "pending",
                    CustomerEmailIdentitySyncOutbox.next_attempt_at <= now,
                )
                .order_by(CustomerEmailIdentitySyncOutbox.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )).scalar_one_or_none()
            if event is None:
                break
            event_id = event.id
            try:
                # Reapplying the same recipient update is safe if PostgreSQL committed
                # but the Hostinger acknowledgement was interrupted.
                async with AsyncSessionLocal() as licensing_db:
                    await licensing_db.execute(update(PaymentWebhookEvent).where(
                        func.lower(PaymentWebhookEvent.recipient_email) == event.old_email,
                    ).values(recipient_email=event.new_email))
                    await licensing_db.commit()
                event.status = "completed"
                event.processed_at = datetime.now(timezone.utc)
                event.last_error = None
                await operational_db.commit()
                counts["processed"] += 1
            except Exception as exc:
                await operational_db.rollback()
                # Re-read after rollback; the row lock is released and a retry is
                # scheduled with capped exponential backoff.
                retry_event = await operational_db.get(CustomerEmailIdentitySyncOutbox, event_id)
                if retry_event is not None:
                    retry_event.attempts = int(retry_event.attempts or 0) + 1
                    retry_event.last_error = type(exc).__name__[:120]
                    delay = min(3600, 30 * (2 ** min(retry_event.attempts, 7)))
                    retry_event.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    await operational_db.commit()
                counts["deferred"] += 1
                logger.warning(
                    "Customer email identity sync deferred (event_id=%s, error_type=%s)",
                    event_id, type(exc).__name__,
                )
    return counts


async def cleanup_expired_customer_auth_records(*, batch_size: int = 500) -> dict:
    """Bounded retention cleanup for authentication records and completed sync events."""
    if batch_size < 1 or batch_size > 2000:
        raise ValueError("batch_size must be between 1 and 2000.")
    now = datetime.now(timezone.utc)
    outbox_retention_cutoff = now - timedelta(days=90)
    challenge_expiry_cutoff = now - timedelta(days=7)
    challenge_retention_cutoff = now - timedelta(days=30)
    session_retention_cutoff = now - timedelta(days=30)
    counts = {"login_challenges_deleted": 0, "email_change_challenges_deleted": 0, "sessions_deleted": 0, "email_identity_outbox_deleted": 0}
    async with HostingerAsyncSessionLocal() as operational_db:
        try:
            cleanup_targets = (
                (CustomerLoginChallenge, CustomerLoginChallenge.id, or_(CustomerLoginChallenge.expires_at < challenge_expiry_cutoff, CustomerLoginChallenge.consumed_at < challenge_retention_cutoff), "login_challenges_deleted"),
                (CustomerEmailChangeChallenge, CustomerEmailChangeChallenge.id, or_(CustomerEmailChangeChallenge.expires_at < challenge_expiry_cutoff, CustomerEmailChangeChallenge.consumed_at < challenge_retention_cutoff), "email_change_challenges_deleted"),
                (CustomerSession, CustomerSession.token_hash, or_(CustomerSession.expires_at < session_retention_cutoff, CustomerSession.revoked_at < session_retention_cutoff), "sessions_deleted"),
                (CustomerEmailIdentitySyncOutbox, CustomerEmailIdentitySyncOutbox.id, (CustomerEmailIdentitySyncOutbox.status == "completed") & (CustomerEmailIdentitySyncOutbox.processed_at < outbox_retention_cutoff), "email_identity_outbox_deleted"),
            )
            for model, key_column, condition, count_key in cleanup_targets:
                identifiers = list((await operational_db.execute(select(key_column).where(condition).order_by(key_column).limit(batch_size))).scalars().all())
                if identifiers:
                    result = await operational_db.execute(delete(model).where(key_column.in_(identifiers)))
                    counts[count_key] = max(0, int(result.rowcount or 0))
            await operational_db.commit()
        except Exception:
            await operational_db.rollback()
            raise
    return counts

async def process_scan_queue(*, max_jobs: int = 1, worker_id: str | None = None) -> dict:
    if max_jobs < 1 or max_jobs > 10:
        raise ValueError("max_jobs must be between 1 and 10.")
    worker_id = worker_id or f"vercel-{uuid.uuid4().hex[:24]}"
    import asyncio

    lifecycle_sync = {"status": "completed", "processed": 0, "deferred": 0}
    try:
        lifecycle_sync.update(await reconcile_customer_lifecycle_outbox())
    except Exception as exc:
        lifecycle_sync = {"status": "deferred", "error_type": type(exc).__name__}
        logger.warning("Customer lifecycle reconciliation failed (error_type=%s)", type(exc).__name__)

    identity_sync = {"status": "completed", "processed": 0, "deferred": 0}
    try:
        identity_sync.update(await reconcile_customer_email_identity_outbox())
    except Exception as exc:
        identity_sync = {"status": "deferred", "error_type": type(exc).__name__}
        logger.warning("Customer email identity reconciliation failed (error_type=%s)", type(exc).__name__)

    cleanup = {"status": "completed"}
    try:
        cleanup.update(await cleanup_expired_customer_auth_records())
    except Exception as exc:
        # Authentication housekeeping must not take the scan queue offline.
        cleanup = {"status": "deferred", "error_type": type(exc).__name__}
        logger.warning("Customer authentication retention cleanup failed (error_type=%s)", type(exc).__name__)

    async def _run_slot(slot: int):
        return await process_one_scan(f"{worker_id}-{slot}")

    outcomes = await asyncio.gather(*(_run_slot(slot) for slot in range(max_jobs)))
    active = [item for item in outcomes if item["status"] != "idle"]
    return {
        "worker_id": worker_id,
        "authentication_cleanup": cleanup,
        "customer_email_identity_sync": identity_sync,
        "customer_lifecycle_sync": lifecycle_sync,
        "claimed_slots": len(active),
        "processed": sum(1 for item in active if item["status"] == "completed"),
        "outcomes": active,
    }
