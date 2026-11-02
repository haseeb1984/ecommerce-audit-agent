import hashlib
from datetime import datetime, timezone

from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_async_db
from models import SoftwareLicense, APIKey
from hostinger_database import HostingerAsyncSessionLocal
from hostinger_models import CustomerSession

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

CUSTOMER_BEARER = HTTPBearer(auto_error=False, scheme_name="CustomerSessionAuth")


async def verify_license_or_api_key(
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    credentials: HTTPAuthorizationCredentials | None = Depends(CUSTOMER_BEARER),
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Authenticate a caller without holding a database lock during audit work."""

    if credentials is not None:
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        if HostingerAsyncSessionLocal is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Customer session storage is unavailable.")
        async with HostingerAsyncSessionLocal() as operational_db:
            session = (await operational_db.execute(select(CustomerSession).where(
                CustomerSession.token_hash == token_hash
            ))).scalar_one_or_none()
            if session is not None:
                session.last_seen_at = datetime.now(timezone.utc)
                await operational_db.commit()
        now = datetime.now(timezone.utc)
        if session is None or session.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session is invalid or revoked.")
        session_expiry = session.expires_at
        if session_expiry.tzinfo is None:
            session_expiry = session_expiry.replace(tzinfo=timezone.utc)
        if session_expiry <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session has expired.")
        license_obj = (await db.execute(select(SoftwareLicense).where(
            SoftwareLicense.license_key == session.license_key
        ))).scalar_one_or_none()
        if license_obj is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer account is unavailable.")
    elif not api_key and not license_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key' or 'X-License-Key' header."
        )

    elif api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        # Resolve the account first, including expired/inactive accounts, so
        # entitlement state can return the correct renewal response instead of
        # misclassifying a known expired customer as invalid credentials.
        stmt = select(SoftwareLicense).join(APIKey).where(APIKey.api_key_hash == key_hash)
        result = await db.execute(stmt)
        license_obj = result.scalar_one_or_none()
    else:
        result = await db.execute(select(SoftwareLicense).where(SoftwareLicense.license_key == license_key))
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
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Authenticate account ownership for key revocation, even after expiry.

    This narrowly scoped dependency intentionally does not grant audit access:
    it only resolves the account for the customer API-key revoke endpoint. An
    inactive or expired account may still need to invalidate a compromised key.
    """
    if not api_key and not license_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key' or 'X-License-Key' header.",
        )

    if api_key:
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
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Authenticate account ownership for billing history/portal, including expired accounts.

    This dependency only resolves the account for billing self-service routes; it does
    not grant audit, report, or quota access. Revoked API keys remain invalid because
    lookup requires a currently stored key hash.
    """
    if not api_key and not license_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Provide 'X-API-Key' or 'X-License-Key' header.",
        )

    if api_key:
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



async def verify_customer_account(
    credentials: HTTPAuthorizationCredentials | None = Depends(CUSTOMER_BEARER),
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Resolve a customer account using a Hostinger-backed session or legacy key."""
    if credentials is not None:
        if credentials.scheme.lower() != "bearer" or not credentials.credentials:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid customer session.")
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        if HostingerAsyncSessionLocal is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Customer session storage is unavailable.")
        async with HostingerAsyncSessionLocal() as operational_db:
            session = (await operational_db.execute(
                select(CustomerSession).where(CustomerSession.token_hash == token_hash)
            )).scalar_one_or_none()
            if session is not None:
                session.last_seen_at = datetime.now(timezone.utc)
                await operational_db.commit()
        now = datetime.now(timezone.utc)
        if session is None or session.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session is invalid or revoked.")
        expiry = session.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session has expired. Sign in again.")
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.license_key == session.license_key)
        )).scalar_one_or_none()
        if license_obj is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer account is unavailable.")
        if not license_obj.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customer account is suspended or inactive.")
        return license_obj

    # Backward compatibility for existing license-key and API-key customers.
    if not api_key and not license_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in with your verified email or provide an existing account key.")
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stmt = select(SoftwareLicense).join(APIKey).where(APIKey.api_key_hash == key_hash)
    else:
        stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)
    license_obj = (await db.execute(stmt)).scalar_one_or_none()
    if license_obj is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid account credentials.")
    if not license_obj.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customer account is suspended or inactive.")
    return license_obj



async def verify_customer_account_for_management(
    credentials: HTTPAuthorizationCredentials | None = Depends(CUSTOMER_BEARER),
    api_key: str = Security(API_KEY_HEADER),
    license_key: str = Security(LICENSE_HEADER),
    db: AsyncSession = Depends(get_async_db),
) -> SoftwareLicense:
    """Resolve account ownership for billing/key management while permitting expired accounts.

    Suspended non-expired licenses remain forbidden. This dependency grants no audit,
    scan, report, or other paid-feature access; callers must enforce their own action
    policy after account ownership is established.
    """
    if credentials is not None:
        if credentials.scheme.lower() != "bearer" or not credentials.credentials:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid customer session.")
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        if HostingerAsyncSessionLocal is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Customer session storage is unavailable.")
        async with HostingerAsyncSessionLocal() as operational_db:
            session = (await operational_db.execute(
                select(CustomerSession).where(CustomerSession.token_hash == token_hash)
            )).scalar_one_or_none()
            if session is not None:
                session.last_seen_at = datetime.now(timezone.utc)
                await operational_db.commit()
        now = datetime.now(timezone.utc)
        if session is None or session.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session is invalid or revoked.")
        expiry = session.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer session has expired. Sign in again.")
        license_obj = await db.scalar(
            select(SoftwareLicense).where(SoftwareLicense.license_key == session.license_key)
        )
    else:
        if not api_key and not license_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sign in with your verified email or provide an existing account key.")
        if api_key:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            stmt = select(SoftwareLicense).join(APIKey).where(APIKey.api_key_hash == key_hash)
        else:
            stmt = select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)
        license_obj = await db.scalar(stmt)

    if license_obj is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid account credentials.")
    now = datetime.now(timezone.utc)
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    is_expired = expires_at is not None and expires_at <= now
    if not license_obj.is_active and not is_expired:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customer account is suspended or inactive.")
    return license_obj
