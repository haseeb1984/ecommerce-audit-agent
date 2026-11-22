from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from auth import _license_is_expired


def test_license_expiry_detects_past_aware_timestamp():
    license_obj = SimpleNamespace(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert _license_is_expired(license_obj)


def test_license_expiry_detects_past_naive_timestamp_as_utc():
    license_obj = SimpleNamespace(expires_at=datetime.utcnow() - timedelta(seconds=1))
    assert _license_is_expired(license_obj)


def test_license_expiry_accepts_future_and_missing_expiry():
    assert not _license_is_expired(SimpleNamespace(expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
    assert not _license_is_expired(SimpleNamespace(expires_at=None))


def test_usage_access_keeps_expired_customer_management_path():
    from auth import verify_customer_account_for_usage

    expired_account = SimpleNamespace(
        tier="business",
        is_active=True,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    assert verify_customer_account_for_usage(expired_account, "") is expired_account


def test_usage_access_preserves_direct_api_plan_restriction():
    import pytest
    from fastapi import HTTPException
    from auth import verify_customer_account_for_usage

    starter_account = SimpleNamespace(tier="starter")
    with pytest.raises(HTTPException) as exc_info:
        verify_customer_account_for_usage(starter_account, "present-api-key")
    assert exc_info.value.status_code == 403

    business_account = SimpleNamespace(tier="business")
    assert verify_customer_account_for_usage(business_account, "present-api-key") is business_account
