"""Customer API for durable Hostinger-backed bulk scan submissions."""
import json
import hashlib
from typing import Literal
from datetime import datetime, timezone
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import verify_license_or_api_key
from hostinger_database import get_hostinger_db
from database import get_async_db
from hostinger_models import ScanBatch, WebsiteScanJob, WebsiteScanResult, CustomerWebsite, AgencyAccount, AgencyClientWorkspace, AgencyClientWebsite
from models import SoftwareLicense
from plan_features import plan_features
from scan_queue import enqueue_scan_request, cancel_scan_batch, retry_failed_scan_job
from ecommerce_agent import UniversalEcommerceAgent

router = APIRouter()
_url_normalizer = UniversalEcommerceAgent()


class AgencyWordPressAuditRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=1000)
    request_id: str = Field(..., min_length=8, max_length=128)


class BulkScanSubmission(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=1000)
    request_id: str = Field(..., min_length=8, max_length=128)
    batch_size: Literal[10, 11] = 10
    workspace_id: str | None = Field(default=None, min_length=1, max_length=64)

class CustomerWebsiteUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=160)


def _normalize_bulk_target(value: str) -> str:
    raw = value.strip()
    if not raw or "?" in raw or "#" in raw:
        raise ValueError("Submit a public website URL without query strings or fragments.")
    parsed = urlsplit(raw if "://" in raw else "https://" + raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Each entry must be a valid HTTP or HTTPS website URL.")
    if parsed.username or parsed.password:
        raise ValueError("Website URLs must not contain embedded credentials.")
    return _url_normalizer._normalize_audit_target(raw)


def _validate_single_site_submission(urls: list[str]) -> None:
    """Require every page in one customer's bulk request to belong to one store."""
    hosts = {urlsplit(url).hostname.lower() for url in urls if urlsplit(url).hostname}
    if len(hosts) != 1:
        raise ValueError("All URLs in one scan submission must belong to the same ecommerce website.")


@router.post("/api/v1/scan-batches", status_code=202)
async def submit_scan_batches(
    payload: BulkScanSubmission,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Accept up to 1,000 URLs and persist 10/11-URL batches in Hostinger."""
    if not plan_features(license_obj.tier)["standard_audits"]:
        raise HTTPException(status_code=403, detail="Website audits are not included in this package.")

    normalized = []
    invalid = []
    for index, value in enumerate(payload.urls):
        try:
            normalized.append(_normalize_bulk_target(value))
        except (ValueError, TypeError):
            invalid.append(index)

    if invalid:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "One or more website URLs are invalid.",
                "invalid_url_indexes": invalid[:100],
                "invalid_count": len(invalid),
            },
        )
    try:
        _validate_single_site_submission(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    workspace_id = None
    if payload.workspace_id:
        if not plan_features(license_obj.tier)["agency_management"]:
            raise HTTPException(status_code=403, detail="Client workspace audits are available on the Business plan.")
        # Serialize workspace submissions with agency suspension and WordPress
        # connection lifecycle changes using the shared agency -> workspace -> site lock order.
        agency = await db.scalar(select(AgencyAccount).where(
            AgencyAccount.owner_license_key == license_obj.license_key,
            AgencyAccount.status == "active",
        ).with_for_update())
        if agency is None:
            raise HTTPException(status_code=404, detail="Business agency workspace was not found.")
        workspace = await db.scalar(select(AgencyClientWorkspace).where(
            AgencyClientWorkspace.id == payload.workspace_id,
            AgencyClientWorkspace.agency_id == agency.id,
            AgencyClientWorkspace.status == "active",
        ).with_for_update())
        if workspace is None:
            raise HTTPException(status_code=404, detail="Client workspace was not found in this agency.")
        client_site = await db.scalar(select(AgencyClientWebsite).where(
            AgencyClientWebsite.agency_id == agency.id,
            AgencyClientWebsite.workspace_id == workspace.id,
            AgencyClientWebsite.status == "active",
        ).with_for_update())
        if client_site is None:
            raise HTTPException(status_code=409, detail="Connect and verify this client's WordPress website before assigning audits to the workspace.")
        submitted_host = (urlsplit(normalized[0]).hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if submitted_host != client_site.site_host:
            raise HTTPException(status_code=422, detail="Every client audit URL must belong to the WordPress website connected to the selected workspace.")
        workspace_id = workspace.id

    try:
        result = await enqueue_scan_request(
            db,
            license_key=license_obj.license_key,
            package_tier=license_obj.tier,
            urls=normalized,
            request_id=payload.request_id,
            workspace_id=workspace_id,
            batch_size=payload.batch_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Hostinger operational database is unavailable.") from exc
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "accepted",
        "message": "Website URLs have been added to the persistent scan queue.",
        **result,
    }


@router.post("/api/v1/integrations/wordpress/agency/sites/audits", status_code=202)
async def queue_agency_wordpress_site_audit(
    payload: AgencyWordPressAuditRequest,
    request: Request,
    response: Response,
    licensing_db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Queue scans using the connected agency site credential, never the owner's key at WordPress."""
    raw_token = (request.headers.get("x-agency-site-token") or "").strip()
    if len(raw_token) < 32 or len(raw_token) > 200:
        raise HTTPException(status_code=401, detail="Agency site authentication is required.")
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    # Resolve the tenant without a row lock, then serialize the lifecycle check
    # in the same agency -> workspace -> site order used by agency connection flows.
    candidate = await operational_db.scalar(select(AgencyClientWebsite).where(
        AgencyClientWebsite.site_token_hash == token_hash,
        AgencyClientWebsite.status == "active",
    ))
    if candidate is None:
        raise HTTPException(status_code=404, detail="Agency WordPress connection is no longer active.")
    agency = await operational_db.scalar(select(AgencyAccount).where(
        AgencyAccount.id == candidate.agency_id,
        AgencyAccount.status == "active",
    ).with_for_update())
    workspace = await operational_db.scalar(select(AgencyClientWorkspace).where(
        AgencyClientWorkspace.id == candidate.workspace_id,
        AgencyClientWorkspace.agency_id == candidate.agency_id,
        AgencyClientWorkspace.status == "active",
    ).with_for_update())
    site = await operational_db.scalar(select(AgencyClientWebsite).where(
        AgencyClientWebsite.id == candidate.id,
        AgencyClientWebsite.agency_id == candidate.agency_id,
        AgencyClientWebsite.workspace_id == candidate.workspace_id,
        AgencyClientWebsite.site_token_hash == token_hash,
        AgencyClientWebsite.status == "active",
    ).with_for_update())
    if site is None:
        raise HTTPException(status_code=404, detail="Agency WordPress connection is no longer active.")
    owner_license = await licensing_db.scalar(select(SoftwareLicense).where(
        SoftwareLicense.license_key == agency.owner_license_key
    )) if agency else None
    owner_expiry = owner_license.expires_at if owner_license is not None else None
    if owner_expiry is not None and owner_expiry.tzinfo is None:
        owner_expiry = owner_expiry.replace(tzinfo=timezone.utc)
    if (agency is None or workspace is None or owner_license is None or not owner_license.is_active
            or (owner_expiry is not None and owner_expiry <= datetime.now(timezone.utc))):
        raise HTTPException(status_code=403, detail="Agency Business subscription or client workspace is inactive or expired.")
    entitlements = plan_features(owner_license.tier)
    if not entitlements["agency_management"] or not entitlements["standard_audits"]:
        raise HTTPException(status_code=403, detail="The agency Business package does not include website audits.")
    normalized = []
    invalid_indexes = []
    for index, raw_url in enumerate(payload.urls):
        try:
            target = _normalize_bulk_target(raw_url)
            parsed = urlsplit(target)
            host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            if parsed.scheme.lower() != "https" or host != site.site_host:
                raise ValueError("Audit URLs must use HTTPS and belong to this connected client website.")
            normalized.append(target)
        except (ValueError, TypeError, UnicodeError):
            invalid_indexes.append(index)
    if invalid_indexes:
        raise HTTPException(status_code=422, detail={
            "message": "One or more URLs do not belong to the connected client website.",
            "invalid_url_indexes": invalid_indexes[:100],
            "invalid_count": len(invalid_indexes),
        })
    try:
        _validate_single_site_submission(normalized)
        result = await enqueue_scan_request(
            operational_db,
            license_key=owner_license.license_key,
            package_tier=owner_license.tier,
            urls=normalized,
            request_id=payload.request_id,
            requested_by=site.admin_email,
            workspace_id=workspace.id,
            batch_size=10,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Agency scan queue is temporarily unavailable.") from exc
    site.last_seen_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "accepted", "workspace_id": workspace.id, "workspace_name": workspace.display_name,
            "site_id": site.id, "message": "Client website audit URLs have been queued under the shared Business allowance.",
            **result}


@router.get("/api/v1/scan-batches")
async def list_scan_batches(
    response: Response,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    batches = (await db.execute(
        select(ScanBatch)
        .where(ScanBatch.license_key == license_obj.license_key)
        .order_by(ScanBatch.created_at.desc(), ScanBatch.batch_number.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    return {
        "items": [
            {
                "id": item.id,
                "workspace_id": item.workspace_id,
                "request_id": item.request_id,
                "package_tier": item.package_tier,
                "batch_number": item.batch_number,
                "batch_size": item.batch_size,
                "total_urls": item.total_urls,
                "queued": item.queued_count,
                "processing": item.processing_count,
                "completed": item.completed_count,
                "failed": item.failed_count,
                "cancelled": item.cancelled_count,
                "status": item.status,
                "created_at": item.created_at,
                "started_at": item.started_at,
                "completed_at": item.completed_at,
            }
            for item in batches
        ],
        "limit": limit,
        "offset": offset,
    }


@router.post("/api/v1/scan-batches/{batch_id}/cancel")
async def cancel_customer_scan_batch(
    batch_id: str,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Cancel queued URLs in a customer's batch without interrupting in-flight work."""
    result = await cancel_scan_batch(
        db, batch_id=batch_id, license_key=license_obj.license_key,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan batch not found.")
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "message": (
            "Queued URLs were cancelled. Already-running scans will finish safely."
            if result["in_flight_jobs"]
            else "The scan batch cancellation has been recorded."
        ),
        **result,
    }


@router.post("/api/v1/scan-jobs/{job_id}/retry")
async def retry_customer_scan_job(
    job_id: str,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Retry one failed job without resubmitting the original URL or batch."""
    result = await retry_failed_scan_job(
        db, job_id=job_id, license_key=license_obj.license_key,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    if result.get("status") == "not_retryable":
        raise HTTPException(
            status_code=409,
            detail="Only failed jobs in a failed, non-cancelled batch can be retried.",
        )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "message": "The failed website scan has been returned to the queue.",
        **result,
    }


@router.get("/api/v1/scan-batches/{batch_id}")
async def get_scan_batch(
    response: Response,
    batch_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    batch = await db.scalar(select(ScanBatch).where(
        ScanBatch.id == batch_id,
        ScanBatch.license_key == license_obj.license_key,
    ))
    if batch is None:
        raise HTTPException(status_code=404, detail="Scan batch not found.")

    jobs = (await db.execute(
        select(WebsiteScanJob)
        .where(
            WebsiteScanJob.batch_id == batch.id,
            WebsiteScanJob.license_key == license_obj.license_key,
        )
        .order_by(WebsiteScanJob.created_at, WebsiteScanJob.id)
    )).scalars().all()

    return {
        "id": batch.id,
        "request_id": batch.request_id,
        "batch_number": batch.batch_number,
        "package_tier": batch.package_tier,
        "status": batch.status,
        "total_urls": batch.total_urls,
        "queued": batch.queued_count,
        "processing": batch.processing_count,
        "completed": batch.completed_count,
        "failed": batch.failed_count,
        "cancelled": batch.cancelled_count,
        "jobs": [
            {
                "id": job.id,
                "website_id": job.website_id,
                "url": job.target_url,
                "status": job.status,
                "attempts": job.attempt_count,
                "max_attempts": job.max_attempts,
                "last_error_code": job.last_error_code,
                "result_reference": job.result_reference,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
            }
            for job in jobs
        ],
    }


@router.get("/api/v1/scan-history")
async def list_scan_history(
    response: Response,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    rows = (await db.execute(
        select(WebsiteScanResult)
        .where(WebsiteScanResult.license_key == license_obj.license_key)
        .order_by(WebsiteScanResult.created_at.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "job_id": row.job_id,
                "website_id": row.website_id,
                "url": row.target_url,
                "status": row.status,
                "overall_score": row.overall_score,
                "finding_count": row.finding_count,
                "created_at": row.created_at,
                "summary": json.loads(row.summary_json or "{}"),
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/v1/scan-jobs/{job_id}/result")
async def get_scan_job_result(
    response: Response,
    job_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    job = await db.scalar(select(WebsiteScanJob).where(
        WebsiteScanJob.id == job_id,
        WebsiteScanJob.license_key == license_obj.license_key,
    ))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    result = await db.scalar(select(WebsiteScanResult).where(
        WebsiteScanResult.job_id == job.id,
        WebsiteScanResult.license_key == license_obj.license_key,
    ))
    if result is None:
        raise HTTPException(status_code=404, detail="Scan result is not available yet.")
    return {
        "id": result.id,
        "job_id": result.job_id,
        "website_id": result.website_id,
        "url": result.target_url,
        "status": result.status,
        "overall_score": result.overall_score,
        "finding_count": result.finding_count,
        "findings": json.loads(result.findings_json or "[]"),
        "check_outcomes": json.loads(result.check_outcomes_json or "[]"),
        "coverage": json.loads(result.coverage_json or "{}"),
        "summary": json.loads(result.summary_json or "{}"),
        "created_at": result.created_at,
    }


@router.get("/api/v1/websites")
async def list_customer_websites(
    response: Response,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """List the authenticated customer's persistent website inventory."""
    from sqlalchemy import func
    total = int((await db.execute(select(func.count(CustomerWebsite.id)).where(
        CustomerWebsite.license_key == license_obj.license_key
    ))).scalar_one() or 0)
    websites = (await db.execute(
        select(CustomerWebsite)
        .where(CustomerWebsite.license_key == license_obj.license_key)
        .order_by(CustomerWebsite.created_at.desc(), CustomerWebsite.id.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "items": [{
            "id": site.id,
            "url": site.url,
            "host": site.host,
            "label": site.label,
            "status": site.status,
            "created_at": site.created_at,
            "updated_at": site.updated_at,
        } for site in websites],
        "page": {
            "limit": limit,
            "offset": offset,
            "total": total,
            "has_more": offset + len(websites) < total,
        },
    }


@router.patch("/api/v1/websites/{website_id}")
async def update_customer_website(
    website_id: str,
    payload: CustomerWebsiteUpdate,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Update customer-controlled website metadata without changing its URL identity."""
    changes = payload.dict(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide a website label to update.")
    website = await db.scalar(select(CustomerWebsite).where(
        CustomerWebsite.id == website_id,
        CustomerWebsite.license_key == license_obj.license_key,
    ).with_for_update())
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found.")
    if "label" in changes:
        label = changes["label"]
        website.label = label.strip() or None if isinstance(label, str) else None
    await db.commit()
    await db.refresh(website)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "id": website.id,
        "url": website.url,
        "host": website.host,
        "label": website.label,
        "status": website.status,
        "updated_at": website.updated_at,
    }


@router.delete("/api/v1/websites/{website_id}")
async def archive_customer_website(
    website_id: str,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Archive a website from inventory while preserving its audit and scan history."""
    website = await db.scalar(select(CustomerWebsite).where(
        CustomerWebsite.id == website_id,
        CustomerWebsite.license_key == license_obj.license_key,
    ).with_for_update())
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found.")
    website.status = "archived"
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"id": website.id, "status": website.status, "message": "Website archived; scan history is preserved."}


@router.get("/api/v1/websites/{website_id}")
async def get_customer_website(
    website_id: str,
    response: Response,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Return a customer's website and a bounded page of its scan-job history."""
    from sqlalchemy import func
    website = await db.scalar(select(CustomerWebsite).where(
        CustomerWebsite.id == website_id,
        CustomerWebsite.license_key == license_obj.license_key,
    ))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found.")
    history_scope = (
        WebsiteScanJob.website_id == website.id,
        WebsiteScanJob.license_key == license_obj.license_key,
    )
    total_history = int((await db.execute(
        select(func.count(WebsiteScanJob.id)).where(*history_scope)
    )).scalar_one() or 0)
    jobs = (await db.execute(
        select(WebsiteScanJob)
        .where(*history_scope)
        .order_by(WebsiteScanJob.created_at.desc(), WebsiteScanJob.id.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "id": website.id,
        "url": website.url,
        "host": website.host,
        "label": website.label,
        "status": website.status,
        "created_at": website.created_at,
        "updated_at": website.updated_at,
        "scan_history": [{
            "job_id": job.id,
            "batch_id": job.batch_id,
            "status": job.status,
            "attempts": job.attempt_count,
            "last_error_code": job.last_error_code,
            "created_at": job.created_at,
            "completed_at": job.completed_at,
            "result_reference": job.result_reference,
        } for job in jobs],
        "history_page": {
            "limit": limit,
            "offset": offset,
            "total": total_history,
            "has_more": offset + len(jobs) < total_history,
        },
    }
