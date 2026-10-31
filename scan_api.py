"""Customer API for durable Hostinger-backed bulk scan submissions."""
import json
from typing import Literal
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import verify_license_or_api_key
from hostinger_database import get_hostinger_db
from hostinger_models import ScanBatch, WebsiteScanJob, WebsiteScanResult, CustomerWebsite
from models import SoftwareLicense
from plan_features import plan_features
from scan_queue import enqueue_scan_request, cancel_scan_batch
from ecommerce_agent import UniversalEcommerceAgent

router = APIRouter()
_url_normalizer = UniversalEcommerceAgent()


class BulkScanSubmission(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=1000)
    request_id: str = Field(..., min_length=8, max_length=128)
    batch_size: Literal[10, 11] = 10

class CustomerWebsiteUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=160)



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


@router.post("/api/v1/scan-batches", status_code=202)
async def submit_scan_batches(
    payload: BulkScanSubmission,
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
        result = await enqueue_scan_request(
            db,
            license_key=license_obj.license_key,
            package_tier=license_obj.tier,
            urls=normalized,
            request_id=payload.request_id,
            batch_size=payload.batch_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Hostinger operational database is unavailable.") from exc
    return {
        "status": "accepted",
        "message": "Website URLs have been added to the persistent scan queue.",
        **result,
    }


@router.get("/api/v1/scan-batches")
async def list_scan_batches(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
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
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Cancel queued URLs in a customer's batch without interrupting in-flight work."""
    result = await cancel_scan_batch(
        db, batch_id=batch_id, license_key=license_obj.license_key,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan batch not found.")
    return {
        "message": (
            "Queued URLs were cancelled. Already-running scans will finish safely."
            if result["in_flight_jobs"]
            else "The scan batch cancellation has been recorded."
        ),
        **result,
    }


@router.get("/api/v1/scan-batches/{batch_id}")
async def get_scan_batch(
    batch_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
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
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
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
    job_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
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
    return {"id": website.id, "status": website.status, "message": "Website archived; scan history is preserved."}


@router.patch("/api/v1/websites/{website_id}")
async def update_customer_website(
    website_id: str,
    payload: CustomerWebsiteUpdate,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Update customer-controlled website metadata without changing URL identity."""
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
        website.label = (label.strip() or None) if isinstance(label, str) else None
    await db.commit()
    await db.refresh(website)
    return {
        "id": website.id, "url": website.url, "host": website.host,
        "label": website.label, "status": website.status,
        "updated_at": website.updated_at,
    }


@router.delete("/api/v1/websites/{website_id}")
async def archive_customer_website(
    website_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Archive inventory while preserving the website's scan and audit history."""
    website = await db.scalar(select(CustomerWebsite).where(
        CustomerWebsite.id == website_id,
        CustomerWebsite.license_key == license_obj.license_key,
    ).with_for_update())
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found.")
    website.status = "archived"
    await db.commit()
    return {"id": website.id, "status": website.status,
            "message": "Website archived; scan history is preserved."}


@router.get("/api/v1/websites/{website_id}")
async def get_customer_website(
    website_id: str,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_hostinger_db),
):
    """Return one customer's website record and its scan-job history."""
    website = await db.scalar(select(CustomerWebsite).where(
        CustomerWebsite.id == website_id,
        CustomerWebsite.license_key == license_obj.license_key,
    ))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found.")
    jobs = (await db.execute(
        select(WebsiteScanJob)
        .where(
            WebsiteScanJob.website_id == website.id,
            WebsiteScanJob.license_key == license_obj.license_key,
        )
        .order_by(WebsiteScanJob.created_at.desc())
        .limit(100)
    )).scalars().all()
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
    }
