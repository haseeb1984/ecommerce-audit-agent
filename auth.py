import hashlib
from datetime import datetime, timezone

from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_async_db
from models import SoftwareLicense, APIKey

# Define explicit scheme_names to prevent Swagger UI schema collisions
API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    scheme_name="APIKeyAuth",
    auto_error=False,
    description="SaaS Client API Key"
)

LICENSE_HEADER = APIKeyHeader(
    name="X-License-Key",
    scheme_name="LicenseKeyAuth",
    auto_error=False,
    description="Software License Key"
)


async def verify_license_or_api_key(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    db: AsyncSession = Depends(get_async_db)
) -> SoftwareLicense:
    """Authenticate a caller without holding a database lock during audit work."""

    if not api_key and not license_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key' or 'X-License-Key' header."
        )

    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stmt = (
            select(SoftwareLicense)
            .join(APIKey)
            .where(APIKey.api_key_hash == key_hash, SoftwareLicense.is_active.is_(True))
        )
    else:
        stmt = select(SoftwareLicense).where(
            SoftwareLicense.license_key == license_key,
            SoftwareLicense.is_active.is_(True)
        )

    result = await db.execute(stmt)
    license_obj = result.scalar_one_or_none()

    if not license_obj:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked license key / API key."
        )

    if license_obj.expires_at and license_obj.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="License expired. Renewal required."
        )

    return license_obj
