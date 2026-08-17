import hashlib
from datetime import datetime, timezone
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi.security import APIKeyHeader
from database import get_async_db
from models import SoftwareLicense, APIKey, AuditLead

#API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
#LICENSE_HEADER = APIKeyHeader(name="X-License-Key", auto_error=False)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False, description="Enter your API Key")
LICENSE_HEADER = APIKeyHeader(name="X-License-Key", auto_error=False, description="Enter your Software License Key")




async def verify_license_or_api_key(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    db: AsyncSession = Depends(get_async_db)
) -> SoftwareLicense:
    
    if not api_key and not license_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key' or 'X-License-Key' header."
        )

    stmt = None
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stmt = (
            select(SoftwareLicense)
            .join(APIKey)
            .where(APIKey.api_key_hash == key_hash, SoftwareLicense.is_active == True)
        )
    elif license_key:
        stmt = select(SoftwareLicense).where(
            SoftwareLicense.license_key == license_key,
            SoftwareLicense.is_active == True
        )

    result = await db.execute(stmt)
    license_obj = result.scalar_one_or_none()

    if not license_obj:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked license key / API key."
        )

    # Validate License Expiration
    if license_obj.expires_at and license_obj.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="License expired. Renewal required."
        )

    # Validate Usage Quotas (Current Month)
    first_day_of_month = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    count_stmt = select(func.count(AuditLead.id)).where(
        AuditLead.license_id == license_obj.id,
        AuditLead.created_at >= first_day_of_month
    )
    usage_count = (await db.execute(count_stmt)).scalar() or 0

    if usage_count >= license_obj.max_monthly_audits:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Monthly audit quota of {license_obj.max_monthly_audits} exceeded for tier '{license_obj.tier}'."
        )

    return license_obj
