from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "admin_portal.html"


def _section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_scan_operations_refresh_ignores_stale_session_and_older_page_requests():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "scanOperationsRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++scanOperationsRequestVersion;" in loader
    assert "requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion" in loader
    assert loader.index("requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion") < loader.index('const c=d.counts||{}')
    assert "if(requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion)return;" in loader


def test_admin_logout_invalidates_inflight_scan_operations_refresh():
    source = PORTAL.read_text(encoding="utf-8")
    clear = _section(source, "function clearAdminData", '$("createClientApiKey")')

    assert "scanOperationsRequestVersion++" in clear


def test_sync_outbox_retry_uses_session_guarded_admin_post():
    source = PORTAL.read_text(encoding="utf-8")
    retry = _section(source, "async function retrySyncOutbox", '$("retryLifecycleOutbox")')

    assert "const requestSessionVersion=adminSessionVersion" in retry
    assert 'await adminPost("/api/v1/admin/sync-outboxes/retry?"+query.toString())' in retry
    assert "if(requestSessionVersion!==adminSessionVersion)return;" in retry
    assert "finally{if(requestSessionVersion===adminSessionVersion)button.disabled=!key}" in retry


def test_failed_scan_job_retry_cannot_update_or_alert_in_a_new_admin_session():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "const actionSessionVersion=adminSessionVersion;" in loader
    assert "await adminPost(" in loader
    assert "if(actionSessionVersion!==adminSessionVersion)return;" in loader
    assert "if(actionSessionVersion===adminSessionVersion){alert(" in loader
