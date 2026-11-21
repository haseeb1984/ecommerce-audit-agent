"""Safely migrate legacy PostgreSQL report PDFs to the Hostinger private bridge.

Run only after applying migrations/20261121_hostinger_report_storage.sql and
verifying the deployed PHP bridge. Each object is uploaded and downloaded with
a SHA-256 verification before its PostgreSQL binary is nulled.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from database import AsyncSessionLocal
from models import AuditReport
from hostinger_storage import (
    HostingerStorageError,
    delete_file,
    download_file,
    storage_configured,
    upload_report,
)

logger = logging.getLogger("migrate_report_storage")


async def _cleanup_unreferenced_uploads(uploaded_keys: list[str]) -> None:
    """Delete only uploads confirmed unreferenced after a fresh database read.

    A commit can succeed on PostgreSQL while its acknowledgement is lost. If
    that happens, deleting every uploaded object in the exception handler would
    leave committed report rows pointing at missing files. If the verification
    read itself fails, preserve the objects; an orphan is safer than data loss.
    """
    if not uploaded_keys:
        return

    try:
        async with AsyncSessionLocal() as verification_db:
            result = await verification_db.execute(
                select(AuditReport.storage_key).where(
                    AuditReport.storage_key.in_(uploaded_keys)
                )
            )
            referenced_keys = {key for key in result.scalars().all() if key}
    except Exception as verification_error:
        logger.error(
            "Upload cleanup deferred because report references could not be verified (error_type=%s)",
            type(verification_error).__name__,
        )
        return

    for key in uploaded_keys:
        if key in referenced_keys:
            continue
        try:
            await asyncio.to_thread(delete_file, key)
        except Exception as cleanup_error:
            logger.error("Orphan cleanup failed (error_type=%s)", type(cleanup_error).__name__)


async def migrate(batch_size: int) -> tuple[int, int]:
    if not storage_configured():
        raise RuntimeError("Configure HOSTINGER_STORAGE_BASE_URL and HOSTINGER_STORAGE_HMAC_SECRET first.")

    retention_raw = os.getenv("REPORT_RETENTION_DAYS", "7").strip()
    try:
        retention_days = int(retention_raw)
    except ValueError:
        raise RuntimeError("REPORT_RETENTION_DAYS must be an integer.") from None
    if not 1 <= retention_days <= 3650:
        raise RuntimeError("REPORT_RETENTION_DAYS must be between 1 and 3650.")
    retention_cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    migrated = 0
    skipped_or_failed = 0
    async with AsyncSessionLocal() as db:
        while True:
            rows = (await db.execute(
                select(AuditReport)
                .where(
                    AuditReport.pdf_bytes.is_not(None),
                    AuditReport.storage_key.is_(None),
                    AuditReport.pdf_deleted_at.is_(None),
                    AuditReport.created_at > retention_cutoff,
                )
                .order_by(AuditReport.id.asc())
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )).scalars().all()
            if not rows:
                break

            uploaded_keys: list[str] = []
            try:
                for report in rows:
                    payload = bytes(report.pdf_bytes or b"")
                    if not payload.startswith(b"%PDF-"):
                        logger.error("Report row rejected: stored payload is not a PDF.")
                        raise RuntimeError("A legacy report payload failed PDF signature validation.")

                    receipt = await asyncio.to_thread(upload_report, payload)
                    uploaded_keys.append(receipt.storage_key)
                    verified = await asyncio.to_thread(
                        download_file, receipt.storage_key, receipt.sha256
                    )
                    if verified != payload:
                        raise HostingerStorageError("Uploaded report did not match the source payload.")

                    # Only clear the PostgreSQL binary after the remote object has
                    # been downloaded and its exact contents have been verified.
                    report.storage_key = receipt.storage_key
                    report.pdf_sha256 = receipt.sha256
                    report.pdf_byte_size = receipt.byte_size
                    report.pdf_bytes = None

                await db.commit()
                migrated += len(rows)
            except Exception:
                await db.rollback()
                # A failed COMMIT acknowledgement is ambiguous: PostgreSQL may
                # already have committed. Re-read references before deleting any
                # remote object; if the read fails, preserve uploads for recovery.
                await _cleanup_unreferenced_uploads(uploaded_keys)
                skipped_or_failed += len(rows)
                raise

    return migrated, skipped_or_failed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be between 1 and 100")
    logging.basicConfig(level=logging.INFO)
    migrated, failed = asyncio.run(migrate(args.batch_size))
    print(f"Verified and migrated report PDFs: {migrated}; failed/skipped: {failed}")


if __name__ == "__main__":
    main()
