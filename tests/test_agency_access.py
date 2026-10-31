from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from main import _license_is_current


def test_current_business_license_is_accepted():
    license_obj = SimpleNamespace(is_active=True, expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert _license_is_current(license_obj) is True


def test_expired_business_license_is_rejected():
    license_obj = SimpleNamespace(is_active=True, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert _license_is_current(license_obj) is False


def test_inactive_business_license_is_rejected():
    license_obj = SimpleNamespace(is_active=False, expires_at=None)
    assert _license_is_current(license_obj) is False


def test_license_without_expiry_is_current_when_active():
    license_obj = SimpleNamespace(is_active=True, expires_at=None)
    assert _license_is_current(license_obj) is True
