"""Acceptance tests for the current Hostinger-backed WordPress identity flow."""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

import main
from database import AsyncSessionLocal
from hostinger_models import CustomerAccount, WordPressInstallation, WordPressSiteLinkChallenge
from models import SoftwareLicense


async def seed_customer(license_key: str):
    async with AsyncSessionLocal() as db:
        license_obj = SoftwareLicense(
            license_key=license_key,
            client_name="WordPress Identity Test",
            tier="pro",
            max_monthly_audits=25,
            is_active=True,
            expires_at=None,
        )
        db.add(license_obj)
        await db.commit()
        await db.refresh(license_obj)

    async with main.HostingerAsyncSessionLocal() as operational_db:
        operational_db.add(CustomerAccount(
            id=f"account-{license_key}",
            license_key=license_key,
            email="owner@example.test",
            display_name="WordPress Identity Test",
            status="active",
        ))
        await operational_db.commit()
    return license_obj.id


async def issue_link_code(client, license_key: str):
    response = await client.post(
        "/api/v1/account/wordpress-link/challenges",
        headers={"X-License-Key": license_key},
    )
    assert response.status_code == 201, response.text
    return response.json()["token"]


def claim_payload(token: str, site_url: str = "https://shop.example.test/"):
    return {
        "token": token,
        "site_url": site_url,
        "wp_user_id": 17,
        "wp_user_login": "store_admin",
        "wp_user_email": "wp-admin@example.test",
        "plugin_version": "1.1.0",
        "wordpress_version": "6.8",
        "woocommerce_version": "9.9",
    }


@pytest.mark.asyncio
async def test_wordpress_link_challenge_rate_limit_is_per_license_and_hour(client):
    license_key = "wordpress-challenge-rate-limit"
    await seed_customer(license_key)

    issued = []
    for _ in range(5):
        issued.append(await issue_link_code(client, license_key))
    assert len(set(issued)) == 5

    limited = await client.post(
        "/api/v1/account/wordpress-link/challenges",
        headers={"X-License-Key": license_key},
    )
    assert limited.status_code == 429
    assert "Too many WordPress link codes" in limited.json()["detail"]

    async with main.HostingerAsyncSessionLocal() as operational_db:
        rows = (await operational_db.execute(
            select(WordPressSiteLinkChallenge).where(
                WordPressSiteLinkChallenge.license_key == license_key
            )
        )).scalars().all()
        assert len(rows) == 5


@pytest.mark.asyncio
async def test_parallel_wordpress_link_challenge_requests_leave_only_latest_token_valid(client):
    license_key = "wordpress-parallel-challenge-issuance"
    await seed_customer(license_key)

    responses = await asyncio.gather(*[
        client.post(
            "/api/v1/account/wordpress-link/challenges",
            headers={"X-License-Key": license_key},
        )
        for _ in range(3)
    ])
    assert all(response.status_code == 201 for response in responses), [
        response.text for response in responses
    ]

    async with main.HostingerAsyncSessionLocal() as operational_db:
        rows = (await operational_db.execute(
            select(WordPressSiteLinkChallenge).where(
                WordPressSiteLinkChallenge.license_key == license_key
            )
        )).scalars().all()
        assert len(rows) == 3
        outstanding = [
            row for row in rows
            if row.consumed_at is None
        ]
        assert len(outstanding) == 1
        assert sum(row.consumed_at is not None for row in rows) == 2


@pytest.mark.asyncio
async def test_wordpress_identity_claim_persists_owner_and_wp_user_and_token_is_single_use(client):
    license_key = "wordpress-identity-acceptance"
    await seed_customer(license_key)

    token = await issue_link_code(client, license_key)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    async with main.HostingerAsyncSessionLocal() as operational_db:
        challenge = await operational_db.scalar(select(WordPressSiteLinkChallenge))
        assert challenge is not None
        assert challenge.token_hash == token_hash
        assert challenge.token_hash != token
        assert challenge.consumed_at is None
        expires_at = challenge.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        remaining = expires_at - datetime.now(timezone.utc)
        assert timedelta(minutes=9) < remaining <= timedelta(minutes=10, seconds=2)

    claimed = await client.post(
        "/api/v1/integrations/wordpress/sites/claim",
        json=claim_payload(token, "https://Shop.Example.test/store/"),
    )
    assert claimed.status_code == 201, claimed.text
    body = claimed.json()
    assert body["status"] == "connected"
    assert body["site_url"] == "https://shop.example.test/store/"
    assert body["wordpress_user_id"] == 17
    assert body["wordpress_user_login"] == "store_admin"

    async with main.HostingerAsyncSessionLocal() as operational_db:
        site = await operational_db.scalar(select(WordPressInstallation).where(
            WordPressInstallation.id == body["site_id"]
        ))
        challenge = await operational_db.scalar(select(WordPressSiteLinkChallenge).where(
            WordPressSiteLinkChallenge.token_hash == token_hash
        ))
        assert site is not None
        assert site.license_key == license_key
        assert site.customer_email == "owner@example.test"
        assert site.admin_email == "wp-admin@example.test"
        assert site.wordpress_user_id == 17
        assert site.wordpress_user_login == "store_admin"
        assert site.status == "active"
        assert challenge.consumed_at is not None

    replay = await client.post(
        "/api/v1/integrations/wordpress/sites/claim",
        json=claim_payload(token, "https://shop.example.test/store/"),
    )
    assert replay.status_code == 400
    assert "invalid or has already been used" in replay.json()["detail"]


@pytest.mark.asyncio
async def test_wordpress_identity_claim_rejects_expired_token_and_marks_it_consumed(client):
    license_key = "wordpress-identity-expired"
    await seed_customer(license_key)
    token = "expired-wordpress-link-token-0123456789"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    async with main.HostingerAsyncSessionLocal() as operational_db:
        operational_db.add(WordPressSiteLinkChallenge(
            id="expired-wordpress-challenge",
            license_key=license_key,
            token_hash=token_hash,
            expires_at=now - timedelta(minutes=1),
            consumed_at=None,
            created_at=now - timedelta(minutes=11),
        ))
        await operational_db.commit()

    response = await client.post(
        "/api/v1/integrations/wordpress/sites/claim",
        json=claim_payload(token),
    )
    assert response.status_code == 410, response.text
    assert "expired" in response.json()["detail"].lower()

    async with main.HostingerAsyncSessionLocal() as operational_db:
        challenge = await operational_db.scalar(select(WordPressSiteLinkChallenge).where(
            WordPressSiteLinkChallenge.token_hash == token_hash
        ))
        assert challenge is not None
        assert challenge.consumed_at is not None
        assert await operational_db.scalar(select(WordPressInstallation.id)) is None


@pytest.mark.asyncio
async def test_wordpress_identity_claim_enforces_one_active_site_per_license(client):
    license_key = "wordpress-identity-one-site"
    await seed_customer(license_key)

    first_token = await issue_link_code(client, license_key)
    first = await client.post(
        "/api/v1/integrations/wordpress/sites/claim",
        json=claim_payload(first_token, "https://first.example.test/"),
    )
    assert first.status_code == 201, first.text

    second_token = await issue_link_code(client, license_key)
    second = await client.post(
        "/api/v1/integrations/wordpress/sites/claim",
        json=claim_payload(second_token, "https://second.example.test/"),
    )
    assert second.status_code == 409
    assert "already has a connected WordPress site" in second.json()["detail"]

    async with main.HostingerAsyncSessionLocal() as operational_db:
        sites = (await operational_db.execute(select(WordPressInstallation).where(
            WordPressInstallation.license_key == license_key,
        ))).scalars().all()
        second_challenge = await operational_db.scalar(select(WordPressSiteLinkChallenge).where(
            WordPressSiteLinkChallenge.token_hash == hashlib.sha256(second_token.encode()).hexdigest()
        ))
        assert len(sites) == 1
        assert sites[0].site_host == "first.example.test"
        # A capacity conflict does not burn the one-time token; the owner may
        # disconnect the existing site and retry before this token expires.
        assert second_challenge is not None
        assert second_challenge.consumed_at is None
