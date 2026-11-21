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
    assert "CustomerSession.email == email" in source
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


def test_customer_portal_keeps_passwordless_session_actions_enabled():
    from pathlib import Path

    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    assert 'finally { button.disabled = !credential && !sessionToken; }' in portal
    logout_all = portal[portal.index('$("logoutAllSessions").addEventListener("click"'):portal.index('$("disconnectAccount").addEventListener("click"')]
    assert 'if (!sessionToken) { setStatus("loginStatus", "Sign in with your customer email to manage device sessions."' in logout_all
    assert 'if (operationSessionVersion === accountSessionVersion) button.disabled = !sessionToken;' in logout_all
    wordpress_link = portal[portal.index('$("generateWordPressLinkCode").addEventListener("click"'):portal.index('$("copyWordPressLinkCode").addEventListener("click"')]
    assert 'finally {\n      if (operationSessionVersion === accountSessionVersion) button.disabled = !credential;' in wordpress_link


def test_customer_portal_profile_update_accepts_verified_bearer_sessions():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    handler_start = portal.index('$("saveProfile").addEventListener')
    handler_end = portal.index('$("openBillingPortal").addEventListener', handler_start)
    handler = portal[handler_start:handler_end]

    assert 'if (!credential && !sessionToken)' in handler
    assert 'api("/api/v1/account/profile"' in handler
    assert 'button.disabled = !credential && !sessionToken;' in handler


def test_customer_management_actions_accept_verified_bearer_sessions():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    assert '$("createApiKey").disabled = (!credential && !sessionToken) || !apiKeyCreationAllowed || atLimit;' in portal

    key_start = portal.index("async function createApiKey()")
    key_end = portal.index("async function loadDeviceSessions()", key_start)
    key_handler = portal[key_start:key_end]
    assert 'if (!credential && !sessionToken)' in key_handler
    assert 'api("/api/v1/account/api-keys"' in key_handler

    billing_start = portal.index('$("openBillingPortal").addEventListener')
    billing_end = portal.index('$("loadMoreBillingHistory").addEventListener', billing_start)
    billing_handler = portal[billing_start:billing_end]
    assert 'if (!credential && !sessionToken)' in billing_handler
    assert 'api("/api/v1/account/billing-portal"' in billing_handler


def test_wordpress_identity_link_accepts_verified_customer_session_authentication():
    from pathlib import Path
    import inspect
    import wordpress_identity_api

    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    controls = portal[portal.index("function setAccountControls"):portal.index("setAccountControls(false)")]
    assert '"generateWordPressLinkCode"' in controls
    assert 'const authHeaders = () => sessionToken ? {Authorization: "Bearer " + sessionToken}' in portal

    endpoint = inspect.getsource(wordpress_identity_api.create_wordpress_link_challenge)
    assert "Depends(verify_customer_account)" in endpoint

def test_customer_session_revocation_actions_have_request_time_cutoffs():
    import inspect
    import main

    revoke_others = inspect.getsource(main.revoke_other_customer_sessions)
    logout_all = inspect.getsource(main.logout_all_account_sessions)

    assert "CustomerSession.revoked_at.is_(None)" in revoke_others
    assert "CustomerSession.revoked_at.is_(None)" in logout_all
    assert "_lock_customer_login_email" in revoke_others
    assert "_lock_customer_login_email" in logout_all
    assert "CustomerSession.created_at <= now" not in revoke_others
    assert "CustomerSession.created_at <= now" not in logout_all

