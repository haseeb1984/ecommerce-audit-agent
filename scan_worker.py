"""Worker that executes persisted Hostinger scan jobs through the audit engine."""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select

from database import AsyncSessionLocal
from models import AuditLead, SoftwareLicense
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import run_phase_one_checks
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks
from coverage_manifest import build_coverage_manifest
from unavailable_checks import append_unavailable_check_outcomes
from hostinger_database import HostingerAsyncSessionLocal
from hostinger_models import WebsiteScanResult
from scan_queue import (
    claim_next_scan_job,
    complete_scan_job,
    fail_or_retry_scan_job,
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
        executed_categories=["technical_seo", "crawlability", "conversion_paid_traffic"],
        run_context={"modules": modules},
    )
    finding_data = [item.dict() for item in result.findings]
    outcome_data = [item.dict() for item in result.check_outcomes]
    score = metrics.mobile_score if metrics is not None else None
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
        attempt = job.attempt_count

    reservation_id = None
    try:
        async with AsyncSessionLocal() as licensing_db:
            license_obj = await licensing_db.scalar(
                select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)
            )
            if license_obj is None:
                raise HTTPException(status_code=403, detail="LICENSE_NOT_FOUND")
            existing_lead = await licensing_db.scalar(
                select(AuditLead).where(AuditLead.source_job_id == job_id)
            )
            if existing_lead is None:
                reservation_id, reserved_at = await reserve_audit_slot(licensing_db, license_obj.id)
            else:
                reserved_at = existing_lead.created_at or datetime.now(timezone.utc)

        result = await _execute_audit(target_url)

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
    except HTTPException as exc:
        if reservation_id is not None:
            async with AsyncSessionLocal() as licensing_db:
                await release_audit_reservation(licensing_db, reservation_id)
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


async def process_scan_queue(*, max_jobs: int = 1, worker_id: str | None = None) -> dict:
    if max_jobs < 1 or max_jobs > 10:
        raise ValueError("max_jobs must be between 1 and 10.")
    worker_id = worker_id or f"vercel-{uuid.uuid4().hex[:24]}"
    outcomes = []
    for _ in range(max_jobs):
        outcome = await process_one_scan(worker_id)
        outcomes.append(outcome)
        if outcome["status"] == "idle":
            break
    return {
        "worker_id": worker_id,
        "processed": sum(1 for item in outcomes if item["status"] == "completed"),
        "outcomes": outcomes,
    }
