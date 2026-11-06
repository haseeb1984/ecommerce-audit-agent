"""Consolidated regression coverage for agency and customer lifecycle integration."""
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import main



def test_admin_agency_status_transition_is_audited_after_commit():
    source = inspect.getsource(main.admin_update_business_agency)
    assert 'previous_status = agency.status' in source
    assert 'await operational_db.commit()' in source
    assert 'await _write_admin_log(' in source
    assert source.index('await operational_db.commit()') < source.index('await _write_admin_log(')
    assert '"agency_status_changed"' in source
    assert '"previous_status": previous_status' in source
    assert '"new_status": agency.status' in source
    assert 'if previous_status != agency.status:' in source


def test_admin_client_update_commits_before_writing_audit_and_returns_private_response():
    source = inspect.getsource(main.admin_update_client)
    assert 'previous_values = {' in source
    assert 'current_values = {' in source
    assert '"previous": previous_values' in source
    assert '"updated": current_values' in source
    assert source.index('await db.commit()') < source.index('await _write_admin_log(')
    assert 'response.headers["Cache-Control"] = "no-store, private"' in source
    assert 'response.headers["Pragma"] = "no-cache"' in source


def test_agency_workspace_grant_mutations_follow_agency_member_workspace_lock_order():
    import inspect
    import main

    grant_source = inspect.getsource(main.set_business_agency_team_workspace_access)
    remove_source = inspect.getsource(main.remove_business_agency_team_workspace_access)

    grant_agency = grant_source.index("AgencyAccount.owner_license_key")
    grant_member = grant_source.index("AgencyTeamMember.id == member_id")
    grant_workspace = grant_source.index("AgencyClientWorkspace.id == workspace_id")
    grant_access = grant_source.index("AgencyWorkspaceAccess.agency_id == agency.id")
    assert grant_agency < grant_member < grant_workspace < grant_access
    assert ".with_for_update()" in grant_source[grant_agency:grant_member]
    assert ".with_for_update()" in grant_source[grant_member:grant_workspace]
    assert ".with_for_update()" in grant_source[grant_workspace:grant_access]

    remove_agency = remove_source.index("AgencyAccount.owner_license_key")
    remove_member = remove_source.index("AgencyTeamMember.id == member_id")
    remove_access = remove_source.index("AgencyWorkspaceAccess.agency_id == agency.id")
    assert remove_agency < remove_member < remove_access
    assert ".with_for_update()" in remove_source[remove_agency:remove_member]
    assert ".with_for_update()" in remove_source[remove_member:remove_access]
    assert 'AgencyTeamMember.status == "active"' in remove_source[remove_member:remove_access]
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
    start = portal.index("async function loadClientApiKeys(id)")
    end = portal.index("async function loadClientSessions(id)", start)
    source = portal[start:end]

    assert "const requestVersion=++clientApiKeyRequestVersion" in source
    assert "const sessionVersion=adminSessionVersion" in source
    assert "if(currentHistoryId!==id)return;" in source
    assert "requestVersion!==clientApiKeyRequestVersion" in source
    assert "sessionVersion!==adminSessionVersion" in source
    assert "currentHistoryId!==id)return;" in source
    assert "currentHistoryId=id;" not in source


def test_admin_api_key_revoke_and_clipboard_feedback_are_selection_guarded():
    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadClientApiKeys(id)")
    end = portal.index("async function loadClientSessions(id)", start)
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
    end = portal.index('$("connect").addEventListener', start)
    source = portal[start:end]

    assert "adminSessionVersion+=1;" in source
    assert "clientApiKeyRequestVersion+=1;" in source


def test_agency_workspace_create_and_update_lock_agency_before_workspace():
    import inspect
    import main

    create_source = inspect.getsource(main.create_business_agency_client)
    update_source = inspect.getsource(main.update_business_agency_client)
    suspend_source = inspect.getsource(main.admin_update_business_agency)

    create_agency_lock = create_source.index("AgencyAccount.owner_license_key")
    create_insert = create_source.index("operational_db.add(item)")
    assert create_agency_lock < create_insert
    assert ".with_for_update()" in create_source[create_agency_lock:create_insert]
    assert 'agency.status != "active"' in create_source[create_agency_lock:create_insert]

    update_agency_lock = update_source.index("AgencyAccount.owner_license_key")
    update_workspace_lock = update_source.index("AgencyClientWorkspace.id == workspace_id")
    update_commit = update_source.index("await operational_db.commit()")
    assert update_agency_lock < update_workspace_lock < update_commit
    assert ".with_for_update()" in update_source[update_agency_lock:update_workspace_lock]
    assert ".with_for_update()" in update_source[update_workspace_lock:update_commit]
    assert 'agency.status != "active"' in update_source[update_agency_lock:update_workspace_lock]

    suspend_agency_lock = suspend_source.index("AgencyAccount.id == agency_id")
    assert ".with_for_update()" in suspend_source[suspend_agency_lock:]


@pytest.mark.asyncio
async def test_agency_workspace_creation_rejects_suspended_agency_before_insert(monkeypatch):
    import main
    from fastapi import HTTPException, Response
    from main import AgencyClientWorkspaceCreate, create_business_agency_client

    class OperationalSession:
        def __init__(self):
            self.added = []
            self.committed = False
            self.statement = None

        async def scalar(self, statement):
            self.statement = statement
            return SimpleNamespace(id="agency-1", status="suspended")

        def add(self, item):
            self.added.append(item)

        async def commit(self):
            self.committed = True

    operational = OperationalSession()
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    with pytest.raises(HTTPException) as error:
        await create_business_agency_client(
            AgencyClientWorkspaceCreate(display_name="New Client"),
            Response(),
            license_obj=SimpleNamespace(license_key="business-license", tier="business"),
            operational_db=operational,
        )

    assert error.value.status_code == 409
    assert operational.added == []
    assert operational.committed is False
    assert operational.statement._for_update_arg is not None
import inspect


def test_customer_api_key_revocation_uses_license_then_key_lock_order():
    import main

    source = inspect.getsource(main.revoke_account_api_key)
    auth_dependency = source.index("verify_customer_account_for_management")
    license_lock = source.index("SoftwareLicense.id == license_obj.id")
    key_lock = source.index("APIKey.id == key_id")
    delete_key = source.index("delete(APIKey)")
    commit = source.index("await db.commit()")

    assert auth_dependency < license_lock < key_lock < delete_key < commit
    assert ".with_for_update()" in source[license_lock:key_lock]
    assert ".with_for_update()" in source[key_lock:delete_key]
    assert "APIKey.license_id == client.id" in source[key_lock:delete_key]


def test_customer_api_key_revocation_is_tenant_scoped_and_rolls_back_missing_key():
    import inspect
    import main

    source = inspect.getsource(main.revoke_account_api_key)
    key_lookup = source.index("select(APIKey)")
    missing_key = source.index("if item is None:")
    delete_key = source.index("delete(APIKey)")

    assert "APIKey.id == key_id" in source[key_lookup:missing_key]
    assert "APIKey.license_id == client.id" in source[key_lookup:missing_key]
    assert "await db.rollback()" in source[missing_key:delete_key]
    assert 'detail="API key not found for this account."' in source[missing_key:delete_key]
"""Regression tests for defensive customer usage-history metadata decoding."""

import inspect
import json

import main


def test_usage_endpoint_uses_safe_decoder_for_persisted_history():
    source = inspect.getsource(main.get_account_usage)

    assert '"details": _load_customer_usage_details(item.details_json)' in source
    assert '"details": json.loads(item.details_json or "{}")' not in source


def test_usage_details_invalid_json_does_not_break_usage_response():
    details = main._load_customer_usage_details("{not-json")

    assert details == {
        "_warning": "Stored usage details were invalid and have been omitted."
    }


def test_usage_details_non_object_payload_is_omitted():
    details = main._load_customer_usage_details(json.dumps(["unexpected", "list"]))

    assert details == {
        "_warning": "Stored usage details were not an object and have been omitted."
    }


def test_usage_details_redact_credentials_and_bound_nested_values():
    details = main._load_customer_usage_details(json.dumps({
        "job_id": "job-123",
        "api_key": "must-not-leak",
        "nested": {"authorization": "Bearer must-not-leak-either"},
        "large_list": list(range(150)),
    }))

    assert details["job_id"] == "job-123"
    assert details["api_key"] == "[REDACTED]"
    assert details["nested"]["authorization"] == "[REDACTED]"
    assert len(details["large_list"]) == 100
    assert "must-not-leak" not in repr(details)
"""Regression tests for customer usage-history visibility and safe rendering."""

from pathlib import Path


def test_customer_portal_renders_usage_events_from_account_usage_response():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'id="usageHistoryHeading">Usage history' in portal
    assert 'renderUsageHistory(usage.history);' in portal
    assert 'String(item.event_type || "Usage event")' in portal
    assert '"Quantity: " + (Number.isFinite(Number(item.quantity))' in portal
    assert 'metadata.textContent = serialized ? serialized.slice(0, 1200)' in portal


def test_customer_usage_history_uses_text_nodes_and_clears_on_account_switch():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'title.textContent = String(item.event_type || "Usage event")' in portal
    assert 'metadata.textContent = serialized ? serialized.slice(0, 1200)' in portal
    assert 'metadata.innerHTML' not in portal
    assert 'renderUsageHistory([]);' in portal
    assert 'Connect your account to view usage history.' in portal