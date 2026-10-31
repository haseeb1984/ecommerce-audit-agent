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

CUSTOMER_SESSION_HEADER = APIKeyHeader(
    name="X-Customer-Session",
    scheme_name="CustomerSessionAuth",
    auto_error=False,
    description="Short-lived customer portal session token"
)


async def _customer_session_license_key(token: str) -> str:
    """Resolve a hashed, unrevoked Hostinger session token to its owning license."""
    from hostinger_database import HostingerAsyncSessionLocal
    from hostinger_models import CustomerSession

    if HostingerAsyncSessionLocal is None:
        raise HTTPException(status_code=503, detail="Customer session authentication is not configured.")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    async with HostingerAsyncSessionLocal() as operational_db:
        session = await operational_db.scalar(
            select(CustomerSession).where(CustomerSession.token_hash == token_hash)
        )
    if session is None or session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Customer session is invalid or has been revoked.")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Customer session has expired. Sign in again.")
    return session.license_key


async def verify_license_or_api_key(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    customer_session: str = Security(CUSTOMER_SESSION_HEADER),
    db: AsyncSession = Depends(get_async_db)
) -> SoftwareLicense:
    """Authenticate a caller without holding a database lock during audit work."""

    if customer_session and (api_key or license_key):
        raise HTTPException(status_code=400, detail="Provide only one authentication method.")
    if not api_key and not license_key and not customer_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key', 'X-License-Key', or 'X-Customer-Session' header."
        )

    if customer_session:
        resolved_license_key = await _customer_session_license_key(customer_session)
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == resolved_license_key)
    elif api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        # Resolve the account first, including expired/inactive accounts, so
        # entitlement state can return the correct renewal response instead of
        # misclassifying a known expired customer as invalid credentials.
        stmt = (
            select(SoftwareLicense)
            .join(APIKey)
            .where(APIKey.api_key_hash == key_hash)
        )
    else:
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)

    result = await db.execute(stmt)
    license_obj = result.scalar_one_or_none()

    if not license_obj:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked license key / API key."
        )

    expires_at = license_obj.expires_at
    if expires_at:
        # SQLite and older schemas may return a naive datetime even though the
        # production column is timezone-aware. Treat legacy naive values as UTC
        # so authentication does not crash with a naive/aware comparison error.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="License expired. Renewal required."
            )

    if not license_obj.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License is inactive. Contact the account owner or renew service."
        )

    return license_obj


async def verify_account_credentials_for_key_revocation(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    customer_session: str = Security(CUSTOMER_SESSION_HEADER),
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Authenticate account ownership for key revocation, even after expiry.

    This narrowly scoped dependency intentionally does not grant audit access:
    it only resolves the account for the customer API-key revoke endpoint. An
    inactive or expired account may still need to invalidate a compromised key.
    """
    if customer_session and (api_key or license_key):
        raise HTTPException(status_code=400, detail="Provide only one authentication method.")
    if not api_key and not license_key and not customer_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key', 'X-License-Key', or 'X-Customer-Session' header.",
        )

    if customer_session:
        resolved_license_key = await _customer_session_license_key(customer_session)
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == resolved_license_key)
    elif api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stmt = (
            select(SoftwareLicense)
            .join(APIKey)
            .where(APIKey.api_key_hash == key_hash)
        )
    else:
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)

    result = await db.execute(stmt)
    license_obj = result.scalar_one_or_none()
    if license_obj is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid account credentials.",
        )
    return license_obj


async def verify_account_credentials_for_billing(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    customer_session: str = Security(CUSTOMER_SESSION_HEADER),
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Authenticate account ownership for billing history/portal, including expired accounts.

    This dependency only resolves the account for billing self-service routes; it does
    not grant audit, report, or quota access. Revoked API keys remain invalid because
    lookup requires a currently stored key hash.
    """
    if customer_session and (api_key or license_key):
        raise HTTPException(status_code=400, detail="Provide only one authentication method.")
    if not api_key and not license_key and not customer_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key', 'X-License-Key', or 'X-Customer-Session' header.",
        )

    if customer_session:
        resolved_license_key = await _customer_session_license_key(customer_session)
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == resolved_license_key)
    elif api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stmt = select(SoftwareLicense).join(APIKey).where(APIKey.api_key_hash == key_hash)
    else:
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)

    result = await db.execute(stmt)
    license_obj = result.scalar_one_or_none()
    if license_obj is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid account credentials.",
        )
    return license_obj
