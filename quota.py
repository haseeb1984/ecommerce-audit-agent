from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import delete, func, select
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

        # Expired reservations no longer count against quota; delete them opportunistically.
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
