import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from auth import get_customer_session_credentials


def test_customer_session_auth_accepts_legacy_header_as_bearer_credentials():
    credentials = get_customer_session_credentials(
        credentials=None,
        customer_session="opaque-session-token",
    )
    assert credentials is not None
    assert credentials.scheme == "Bearer"
    assert credentials.credentials == "opaque-session-token"


def test_customer_session_auth_preserves_bearer_credentials():
    original = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="opaque-session-token",
    )
    credentials = get_customer_session_credentials(
        credentials=original,
        customer_session=None,
    )
    assert credentials is original


def test_customer_session_auth_rejects_mixed_bearer_and_legacy_header():
    original = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="bearer-token",
    )
    with pytest.raises(HTTPException) as raised:
        get_customer_session_credentials(
            credentials=original,
            customer_session="header-token",
        )
    assert raised.value.status_code == 400


def test_customer_auth_legacy_routes_remain_registered():
    import main

    paths = set(main.app.openapi()["paths"])
    assert {
        "/api/v1/account/login",
        "/api/v1/account/login/verify",
        "/api/v1/account/logout",
        "/api/v1/account/sessions",
        "/api/v1/account/sessions/{session_id}",
        "/api/v1/account/sessions/revoke-others",
        "/api/v1/account/email-change",
        "/api/v1/account/email-change/confirm",
    } <= paths


def test_customer_session_revoke_others_keeps_current_session():
    import inspect
    import main

    endpoint = next(
        route.endpoint for route in main.app.routes
        if getattr(route, "path", None) == "/api/v1/account/sessions/revoke-others"
    )
    source = inspect.getsource(endpoint)
    assert "CustomerSession.token_hash != digest" in source
    assert "CustomerSession.email == current.email" in source
    assert "revoked_count" in source


def test_customer_portal_exposes_safe_other_device_signout_controls():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    assert 'id="logoutOtherSessions"' in portal
    assert '"/api/v1/account/sessions/revoke-others"' in portal
    assert "This browser will remain signed in." in portal
    assert '$("logoutOtherSessions").disabled = !connected || !sessionToken' in portal
    assert '$("logoutAllSessions").disabled = !connected || !sessionToken' in portal


def test_customer_passwordless_login_responses_cannot_overwrite_a_newer_account_session():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    request_start = portal.index('$("requestLoginCode").addEventListener')
    verify_start = portal.index('$("verifyLoginCode").addEventListener')
    connect_start = portal.index('$("connect").addEventListener', verify_start)
    request_handler = portal[request_start:verify_start]
    verify_handler = portal[verify_start:connect_start]

    assert "const loginAttemptVersion = accountSessionVersion;" in request_handler
    assert "if (loginAttemptVersion !== accountSessionVersion) return;" in request_handler
    assert "if (loginAttemptVersion === accountSessionVersion) button.disabled = false;" in request_handler
    assert "const loginAttemptVersion = accountSessionVersion;" in verify_handler
    stale_guard = verify_handler.index("if (loginAttemptVersion !== accountSessionVersion) return;")
    token_install = verify_handler.index('sessionToken = String(data.access_token || "");')
    assert stale_guard < token_install
    assert "if (loginAttemptVersion !== accountSessionVersion) return;" in verify_handler
    assert "if (loginAttemptVersion === accountSessionVersion) {" in verify_handler
    assert "if (loginAttemptVersion === accountSessionVersion) button.disabled = false;" in verify_handler
