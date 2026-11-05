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


def test_customer_portal_keeps_passwordless_session_actions_enabled():
    from pathlib import Path

    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    assert 'if (!sessionToken) { setStatus("loginStatus", "Sign in with your customer email to manage device sessions."' in portal
    assert 'finally { button.disabled = !sessionToken; }' in portal
    assert 'finally { button.disabled = !credential && !sessionToken; }' in portal
    assert 'finally { button.disabled = !credential; }' in portal  # WordPress identity-link action still requires a license credential.
