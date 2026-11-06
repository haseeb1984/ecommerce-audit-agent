from pathlib import Path


def test_customer_api_key_list_ignores_out_of_order_refresh_responses():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("  async function loadApiKeys()")
    end = portal.index("  function renderApiKeys()", start)
    source = portal[start:end]

    assert "const requestVersion = ++apiKeyRequestVersion;" in source
    assert "const sessionVersion = accountSessionVersion;" in source
    assert "if (requestVersion !== apiKeyRequestVersion || sessionVersion !== accountSessionVersion) return;" in source
    assert "requestVersion === apiKeyRequestVersion && sessionVersion === accountSessionVersion" in source


def test_customer_account_clear_invalidates_pending_api_key_list_requests():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("  function clearAccountView()")
    end = portal.index('  $("requestLoginCode")', start)
    source = portal[start:end]

    assert "apiKeyRequestVersion += 1;" in source
    assert "apiKeyRows = []; renderApiKeys();" in source


def test_customer_api_key_revoke_and_refresh_feedback_are_session_guarded():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("  function renderApiKeys()")
    end = portal.index("  async function createApiKey()", start)
    source = portal[start:end]

    assert "const operationSessionVersion = accountSessionVersion;" in source
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in source
    assert 'if (operationSessionVersion === accountSessionVersion) setStatus("apiKeyStatus", "API key revoked.", "success");' in source

    refresh_start = portal.index('  $("refreshApiKeys").addEventListener')
    refresh_end = portal.index('  $("copyApiKey").addEventListener', refresh_start)
    refresh_source = portal[refresh_start:refresh_end]
    assert "const operationSessionVersion = accountSessionVersion;" in refresh_source
    assert 'if (operationSessionVersion === accountSessionVersion) setStatus("apiKeyStatus", "API key list refreshed.", "success");' in refresh_source


def test_customer_api_key_clipboard_feedback_cannot_cross_account_switch():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index('  $("copyApiKey").addEventListener')
    end = portal.index('  $("hideApiKey").addEventListener', start)
    source = portal[start:end]

    assert "const operationSessionVersion = accountSessionVersion;" in source
    assert "const keyToCopy = newlyCreatedApiKey;" in source
    assert "if (operationSessionVersion === accountSessionVersion)" in source
