"""License-scoped, one-time WordPress identity linking for standard customer accounts."""
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import verify_customer_account
from database import get_async_db
from hostinger_database import get_hostinger_db
from hostinger_models import CustomerAccount, CustomerBillingEvent, WordPressInstallation, WordPressSiteLinkChallenge
from models import PaymentWebhookEvent, SoftwareLicense

router = APIRouter()


class WordPressLinkClaim(BaseModel):
    token: str = Field(..., min_length=32, max_length=128)
    site_url: str = Field(..., min_length=8, max_length=2048)
    wp_user_id: int = Field(..., ge=1, le=2147483647)
    wp_user_login: str = Field(..., min_length=1, max_length=60)
    wp_user_email: str = Field(..., min_length=3, max_length=254)
    plugin_version: str = Field(default="", max_length=30)
    wordpress_version: str = Field(default="", max_length=30)
    woocommerce_version: str = Field(default="", max_length=30)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _normalize_site_url(value: str) -> tuple[str, str]:
    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="WordPress site URL is malformed.") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="WordPress site URL must be a valid HTTPS URL.")
    if parsed.query or parsed.fragment or len(parsed.hostname) > 253:
        raise HTTPException(status_code=422, detail="WordPress site URL contains unsupported components.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise HTTPException(status_code=422, detail="WordPress site hostname is invalid.") from exc
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
        raise HTTPException(status_code=422, detail="WordPress site hostname is invalid.")
    if port not in (None, 443):
        raise HTTPException(status_code=422, detail="WordPress site URL must use the standard HTTPS port.")
    path = parsed.path.rstrip("/")
    canonical = f"https://{host}{path}/" if path else f"https://{host}/"
    return canonical, host


def _valid_email(value: str) -> str:
    email = value.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="WordPress user email is invalid.")
    return email


def _license_is_current(license_obj) -> bool:
    if license_obj is None or not bool(license_obj.is_active):
        return False
    expiry = license_obj.expires_at
    if expiry is None:
        return True
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > datetime.now(timezone.utc)


@router.post("/api/v1/account/wordpress-link/challenges", status_code=201)
async def create_wordpress_link_challenge(
    response: Response,
    license_obj=Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Issue a short-lived single-use token for the authenticated license."""
    now = datetime.now(timezone.utc)
    if not _license_is_current(license_obj):
        raise HTTPException(status_code=403, detail="An active, non-expired license is required to link a WordPress site.")
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    recent = int((await operational_db.execute(
        select(func.count(WordPressSiteLinkChallenge.id)).where(
            WordPressSiteLinkChallenge.license_key == license_obj.license_key,
            WordPressSiteLinkChallenge.created_at >= now - timedelta(hours=1),
        )
    )).scalar_one() or 0)
    if recent >= 5:
        raise HTTPException(status_code=429, detail="Too many WordPress link codes were requested. Try again later.")
    outstanding = (await operational_db.execute(
        select(WordPressSiteLinkChallenge).where(
            WordPressSiteLinkChallenge.license_key == license_obj.license_key,
            WordPressSiteLinkChallenge.consumed_at.is_(None),
            WordPressSiteLinkChallenge.expires_at > now,
        ).with_for_update()
    )).scalars().all()
    for item in outstanding:
        item.consumed_at = now
    token = secrets.token_urlsafe(32)
    challenge = WordPressSiteLinkChallenge(
        id=secrets.token_urlsafe(24),
        license_key=license_obj.license_key,
        token_hash=_token_digest(token),
        expires_at=now + timedelta(minutes=10),
        consumed_at=None,
        created_at=now,
    )
    operational_db.add(challenge)
    await operational_db.commit()
    return {"token": token, "expires_at": challenge.expires_at.isoformat(), "expires_in_seconds": 600}


@router.post("/api/v1/integrations/wordpress/sites/claim", status_code=201)
async def claim_wordpress_site_identity(
    payload: WordPressLinkClaim,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Consume a license-bound token and bind the current WordPress administrator identity."""
    now = datetime.now(timezone.utc)
    site_url, site_host = _normalize_site_url(payload.site_url)
    wp_login = payload.wp_user_login.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,60}", wp_login):
        raise HTTPException(status_code=422, detail="WordPress user login contains unsupported characters.")
    wp_email = _valid_email(payload.wp_user_email)
    token_hash = _token_digest(payload.token)
    challenge = await operational_db.scalar(
        select(WordPressSiteLinkChallenge).where(
            WordPressSiteLinkChallenge.token_hash == token_hash,
            WordPressSiteLinkChallenge.consumed_at.is_(None),
        ).with_for_update()
    )
    if challenge is None:
        raise HTTPException(status_code=400, detail="WordPress link code is invalid or has already been used.")
    expires_at = challenge.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=410, detail="WordPress link code has expired. Generate a new code.")

    license_obj = await db.scalar(
        select(SoftwareLicense).where(
            SoftwareLicense.license_key == challenge.license_key
        ).with_for_update()
    )
    if license_obj is None or not bool(license_obj.is_active):
        raise HTTPException(status_code=403, detail="The linked SaaS license is not active.")
    license_expiry = license_obj.expires_at
    if license_expiry is not None:
        if license_expiry.tzinfo is None:
            license_expiry = license_expiry.replace(tzinfo=timezone.utc)
        if license_expiry <= now:
            raise HTTPException(status_code=403, detail="The linked SaaS license has expired.")

    customer_account = await operational_db.scalar(
        select(CustomerAccount).where(CustomerAccount.license_key == challenge.license_key)
    )
    customer_email = customer_account.email if customer_account is not None else None
    if not customer_email:
        customer_email = await operational_db.scalar(
            select(CustomerBillingEvent.recipient_email).where(
                CustomerBillingEvent.license_key == challenge.license_key
            ).order_by(CustomerBillingEvent.updated_at.desc()).limit(1)
        )
    if not customer_email:
        customer_email = await db.scalar(
            select(PaymentWebhookEvent.recipient_email).where(
                PaymentWebhookEvent.license_id == license_obj.id,
                PaymentWebhookEvent.recipient_email.is_not(None),
            ).order_by(PaymentWebhookEvent.updated_at.desc()).limit(1)
        )

    existing = await operational_db.scalar(
        select(WordPressInstallation).where(
            WordPressInstallation.license_key == challenge.license_key,
            WordPressInstallation.site_host == site_host,
        ).with_for_update()
    )
    active_count = int((await operational_db.execute(
        select(func.count(WordPressInstallation.id)).where(
            WordPressInstallation.license_key == challenge.license_key,
            WordPressInstallation.status == "active",
        )
    )).scalar_one() or 0)
    if active_count >= 1 and (existing is None or existing.status != "active"):
        raise HTTPException(
            status_code=409,
            detail="This license already has a connected WordPress site. Disconnect it before connecting another site.",
        )

    if existing is None:
        existing = WordPressInstallation(
            id=secrets.token_urlsafe(24),
            license_key=challenge.license_key,
            site_url=site_url,
            site_host=site_host,
            admin_email=wp_email,
            customer_email=customer_email.strip().lower() if customer_email else None,
            plugin_version=payload.plugin_version.strip() or "unknown",
            wordpress_version=payload.wordpress_version.strip() or None,
            woocommerce_version=payload.woocommerce_version.strip() or None,
            status="active",
            created_at=now,
            last_seen_at=now,
        )
        operational_db.add(existing)
    else:
        existing.site_url = site_url
        existing.admin_email = wp_email
        existing.customer_email = customer_email.strip().lower() if customer_email else existing.customer_email
        existing.plugin_version = payload.plugin_version.strip() or existing.plugin_version
        existing.wordpress_version = payload.wordpress_version.strip() or existing.wordpress_version
        existing.woocommerce_version = payload.woocommerce_version.strip() or existing.woocommerce_version
        existing.wordpress_user_id = payload.wp_user_id
        existing.wordpress_user_login = wp_login
        existing.status = "active"
        existing.disconnected_at = None
        existing.last_seen_at = now

    if existing is not None:
        existing.wordpress_user_id = payload.wp_user_id
        existing.wordpress_user_login = wp_login
    challenge.consumed_at = now
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "connected",
        "site_id": existing.id,
        "site_url": existing.site_url,
        "wordpress_user_id": existing.wordpress_user_id,
        "wordpress_user_login": existing.wordpress_user_login,
        "license": {"id": license_obj.id, "client_name": license_obj.client_name, "tier": license_obj.tier},
    }
