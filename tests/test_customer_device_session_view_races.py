"""Regression tests for customer device-session UI race protection."""

from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "customer_portal.html"


def _portal():
    return PORTAL.read_text(encoding="utf-8")


def _device_loader(source):
    start = source.index("  async function loadDeviceSessions() {")
    end = source.index("  async function loadWordPressSites()", start)
    return source[start:end]


def test_device_session_refreshes_only_render_the_latest_response():
    loader = _device_loader(_portal())
    assert "const requestId = ++deviceSessionsRequestId;" in loader
    assert "const requestSessionVersion = accountSessionVersion;" in loader
    assert "if (requestId !== deviceSessionsRequestId || requestSessionVersion !== accountSessionVersion) return;" in loader


def test_device_session_view_is_cleared_and_inflight_refreshes_invalidated_on_disconnect():
    source = _portal()
    start = source.index("  function clearAccountView() {")
    end = source.index('  $("requestLoginCode").addEventListener', start)
    clear = source[start:end]
    assert "deviceSessionsRequestId += 1;" in clear
    assert '$("deviceSessions").replaceChildren();' in clear
    assert "Connect with email sign-in to view active devices." in clear


def test_device_revocation_does_not_update_a_new_account_session():
    loader = _device_loader(_portal())
    assert "const actionSessionVersion = accountSessionVersion;" in loader
    assert "if (actionSessionVersion !== accountSessionVersion) return;" in loader
    assert "if (actionSessionVersion === accountSessionVersion)" in loader


def test_device_list_does_not_expose_old_session_when_email_signin_is_unavailable():
    loader = _device_loader(_portal())
    assert 'if (!sessionToken) {' in loader
    assert 'Email sign-in is required to manage devices.' in loader


def _handler(source, start_marker, end_marker):
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def test_revoke_other_sessions_guards_refresh_status_and_button_state():
    source = _portal()
    handler = _handler(source, '  $("logoutOtherSessions").addEventListener', '  $("logoutAllSessions").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert handler.count("if (operationSessionVersion !== accountSessionVersion) return;") == 2
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler
    assert "if (operationSessionVersion === accountSessionVersion) button.disabled" in handler


def test_logout_all_sessions_only_clears_the_account_that_authorized_the_request():
    source = _portal()
    handler = _handler(source, '  $("logoutAllSessions").addEventListener', '  $("disconnectAccount").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "accountSessionVersion += 1;" in handler
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler


def test_email_change_request_does_not_publish_old_challenge_after_account_switch():
    source = _portal()
    handler = _handler(source, '  $("requestEmailChange").addEventListener', '  $("verifyEmailChange").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion)" in handler


def test_email_change_verification_guards_the_post_change_refresh_and_status():
    source = _portal()
    handler = _handler(source, '  $("verifyEmailChange").addEventListener', '  $("generateWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "const updatedSessionVersion = accountSessionVersion;" in handler
    assert "if (updatedSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion)" in handler


def test_wordpress_one_time_code_is_never_rendered_into_a_different_account_view():
    source = _portal()
    handler = _handler(source, '  $("generateWordPressLinkCode").addEventListener', '  $("copyWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler


def test_copy_wordpress_code_does_not_update_status_after_account_switch():
    source = _portal()
    handler = _handler(source, '  $("copyWordPressLinkCode").addEventListener', '  $("hideWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert handler.count("if (operationSessionVersion === accountSessionVersion) setStatus") == 2
