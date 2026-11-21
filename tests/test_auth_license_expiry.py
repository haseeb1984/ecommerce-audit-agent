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
