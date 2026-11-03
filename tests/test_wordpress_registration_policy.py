import pytest
from fastapi import HTTPException

from main import _ensure_wordpress_site_capacity


def test_first_wordpress_site_can_be_connected():
    _ensure_wordpress_site_capacity(active_count=0, existing_is_active=False)


def test_same_active_wordpress_site_can_refresh_registration():
    _ensure_wordpress_site_capacity(active_count=1, existing_is_active=True)


def test_disconnected_site_can_be_reactivated_when_no_other_site_is_active():
    _ensure_wordpress_site_capacity(active_count=0, existing_is_active=False)


def test_second_active_wordpress_site_is_rejected():
    with pytest.raises(HTTPException) as exc:
        _ensure_wordpress_site_capacity(active_count=1, existing_is_active=False)
    assert exc.value.status_code == 409
    assert "Disconnect it before connecting another site" in exc.value.detail
