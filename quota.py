from datetime import datetime, timedelta, timezone
import os

from fastapi import HTTPException, status
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLead, AuditQuotaReservation, SoftwareLicense


RESERVATION_TTL = timedelta(minutes=15)


def _month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def reserve_audit_slot(db: AsyncSession, license_id: int) -> tuple[int, datetime]:
    """Atomically reserve one monthly slot, then release the DB lock before slow API calls.

    The license row lock serializes only the short reservation transaction. The committed
    reservation counts against quota while PageSpeed/Groq work happens without a DB lock.
    """
    now = datetime.now(timezone.utc)
    month_start = _month_start(now)

    try:
        result = await db.execute(
            select(SoftwareLicense)
            .where(SoftwareLicense.id == license_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        license_obj = result.scalar_one_or_none()

        if (
            license_obj is None
            or not license_obj.is_active
            or (license_obj.expires_at and license_obj.expires_at < now)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="License is invalid, expired, or revoked.",
            )

        await db.execute(
            delete(AuditQuotaReservation).where(
                AuditQuotaReservation.license_id == license_id,
                AuditQuotaReservation.expires_at <= now,
            )
        )

        successful_count = (
            await db.execute(
                select(func.count(AuditLead.id)).where(
                    AuditLead.license_id == license_id,
                    AuditLead.created_at >= month_start,
                )
            )
        ).scalar_one()

        pending_count = (
            await db.execute(
                select(func.count(AuditQuotaReservation.id)).where(
                    AuditQuotaReservation.license_id == license_id,
                    AuditQuotaReservation.created_at >= month_start,
                    AuditQuotaReservation.expires_at > now,
                )
            )
        ).scalar_one()

        # Prefer the operator-managed package limit; fall back to environment configuration
        # when no package record exists for this tier.
        tier_key = str(license_obj.tier or "starter").strip().lower()
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS saas_plan_packages (
                tier VARCHAR(50) PRIMARY KEY,
                label VARCHAR(100) NOT NULL,
                monthly_audit_allowance INTEGER NOT NULL CHECK (monthly_audit_allowance BETWEEN 1 AND 10000000),
                max_concurrent_audits INTEGER NOT NULL CHECK (max_concurrent_audits BETWEEN 1 AND 10000),
                paddle_price_id VARCHAR(100),
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        package_result = await db.execute(text("""
            SELECT max_concurrent_audits FROM saas_plan_packages WHERE tier=:tier
        """), {"tier": tier_key})
        package_limit = package_result.scalar_one_or_none()
        concurrency_limit = int(package_limit) if package_limit is not None else None
        if concurrency_limit is None:
            tier_env = tier_key.upper()
            raw_concurrency_limit = os.getenv(f"LICENSE_MAX_CONCURRENT_AUDITS_{tier_env}", "").strip()
            if raw_concurrency_limit:
                try:
                    concurrency_limit = int(raw_concurrency_limit)
                except ValueError as exc:
                    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                        detail="Audit concurrency configuration is invalid.") from exc
                if concurrency_limit < 1:
                    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                        detail="Audit concurrency configuration is invalid.")
        if concurrency_limit is not None:
            active_count = (await db.execute(select(func.count(AuditQuotaReservation.id)).where(
                AuditQuotaReservation.license_id == license_id,
                AuditQuotaReservation.expires_at > now,
            ))).scalar_one()
            if active_count >= concurrency_limit:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Concurrent audit limit of {concurrency_limit} reached for tier '{license_obj.tier}'.")

        if successful_count + pending_count >= license_obj.max_monthly_audits:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Monthly audit quota of {license_obj.max_monthly_audits} "
                    f"exceeded for tier '{license_obj.tier}'."
                ),
            )

        reservation = AuditQuotaReservation(
            license_id=license_id,
            created_at=now,
            expires_at=now + RESERVATION_TTL,
        )
        db.add(reservation)
        await db.flush()
        reservation_id = reservation.id
        reserved_at = reservation.created_at
        await db.commit()
        return reservation_id, reserved_at
    except Exception:
        await db.rollback()
        raise


async def release_audit_reservation(db: AsyncSession, reservation_id: int) -> None:
    """Release a failed audit's quota reservation; safe to call after a rollback."""
    try:
        await db.execute(
            delete(AuditQuotaReservation).where(AuditQuotaReservation.id == reservation_id)
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
