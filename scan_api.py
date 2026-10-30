"""Customer API for durable Hostinger-backed bulk scan submissions."""
from datetime import timezone
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import verify_license_or_api_key
from hostinger_database import get_hostinger_db
from hostinger_models import ScanBatch, WebsiteScanJob
from models import SoftwareLicense
from plan_features import plan_features
from scan_queue import enqueue_scan_request
from ecommerce_agent import UniversalEcommerceAgent

router = APIRouter()
_url_normalizer = UniversalEcommerceAgent()


class BulkScanSubmission(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=1000)
    request_id: str = Field(..., min_length=8, max_length=128)
    batch_size: Literal[10, 11] = 10


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
