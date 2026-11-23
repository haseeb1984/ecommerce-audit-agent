from pathlib import Path
import inspect

import main


def test_admin_api_key_revocation_locks_license_then_key_before_audit():
    source = inspect.getsource(main.admin_revoke_client_api_key)

    auth = source.index("_require_admin_key(request)")
    license_lock = source.index("SoftwareLicense.id == license_id")
    key_lock = source.index("APIKey.id == key_id")
    delete_key = source.index("delete(APIKey)")
    audit = source.index('_write_admin_log(db, "client.api_key_revoked"')
    commit = source.index("await db.commit()")

    assert auth < license_lock < key_lock < delete_key < audit < commit
    assert ".with_for_update()" in source[license_lock:key_lock]
    assert ".with_for_update()" in source[key_lock:delete_key]
    assert '"api_key_hash"' not in source[audit:commit]
    assert '"key_prefix": prefix' in source[audit:commit]


def test_admin_api_key_inventory_ignores_stale_client_and_session_responses():
    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadClientApiKeys(")
    end = portal.index("async function loadClientSessions(", start)
    source = portal[start:end]

    assert "const requestVersion=++clientApiKeyRequestVersion" in source
    assert "sessionVersion=adminSessionVersion" in source
    assert "if(expectedDetailVersion!==clientDetailVersion||currentHistoryId!==id)return;" in source
    assert "requestVersion!==clientApiKeyRequestVersion" in source
    assert "sessionVersion!==adminSessionVersion" in source
    assert "currentHistoryId!==id)return;" in source
    assert "currentHistoryId=id;" not in source


def test_admin_api_key_revoke_and_clipboard_feedback_are_selection_guarded():
    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadClientApiKeys(id,expectedDetailVersion=clientDetailVersion)")
    end = portal.index("async function loadClientSessions(id,expectedDetailVersion=clientDetailVersion)", start)
    source = portal[start:end]

    assert "const operationSessionVersion=adminSessionVersion;" in source
    assert "operationSessionVersion!==adminSessionVersion||currentHistoryId!==id" in source
    assert "operationSessionVersion===adminSessionVersion&&currentHistoryId===id" in source

    copy_start = portal.index('$("copyClientApiKey").addEventListener')
    copy_end = portal.index('$("hideClientApiKey").addEventListener', copy_start)
    copy_source = portal[copy_start:copy_end]
    assert "const operationSessionVersion=adminSessionVersion" in copy_source
    assert "operationClientId=currentHistoryId" in copy_source
    assert "operationClientId===currentHistoryId" in copy_source


def test_admin_disconnect_invalidates_in_flight_api_key_inventory_requests():
    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    start = portal.index("function clearAdminData(")
    source = portal[start:start + 3000]

    assert "adminSessionVersion+=1;" in source
    assert "clientApiKeyRequestVersion+=1;" in source
