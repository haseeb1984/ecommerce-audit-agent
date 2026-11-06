"""Regression coverage for agency lifecycle, WordPress and customer session compatibility."""
import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import pytest
from starlette.requests import Request
import main

class _ScalarsResult:
    def __init__(self, items): self.items = items
    def scalars(self): return SimpleNamespace(all=lambda: self.items)




class _GenericOutboxRetryDB:
    def __init__(self, items):
        self.items = items
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _ScalarsResult(self.items)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_admin_generic_sync_retry_supports_billing_mirror_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/sync-outboxes/retry",
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"queue=billing_mirror",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })
    now = datetime.now(timezone.utc)
    items = [
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 1, tzinfo=timezone.utc)),
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 2, tzinfo=timezone.utc)),
    ]
    db = _GenericOutboxRetryDB(items)
    logs = []

    async def write_log(*args, **kwargs):
        logs.append((args, kwargs))

    monkeypatch.setattr(main, "_write_admin_log", write_log)

    result = await main.admin_retry_sync_outbox(
        request=request, queue="billing_mirror", limit=2, db=db
    )

    assert result["queue"] == "billing_mirror"
    assert result["status"] == "queued"
    assert result["queued"] == 2
    assert result["next_worker_cycle"] is True
    assert all(item.next_attempt_at == datetime.fromisoformat(result["checked_at"]) for item in items)
    assert db.committed is True
    assert len(logs) == 1
    assert logs[0][0][1] == "sync_outbox.retry_queued"
    assert logs[0][0][2] == "billing_mirror"
            request=_admin_request(), queue="unknown_queue", limit=10, db=db


class AgencyArchiveSession:
    def __init__(self, agency, workspace, site, challenges):
        self.rows = [agency, workspace, site]
        self.challenges = challenges
        self.committed = False

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def execute(self, _statement):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.challenges))

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_archiving_agency_workspace_revokes_plugin_credential_and_pending_tokens(monkeypatch):
    import main
    from fastapi import Response
    from main import AgencyClientWorkspaceUpdate, update_business_agency_client

    agency = SimpleNamespace(id="agency-archive", status="active", owner_license_key="business-license")
    workspace = SimpleNamespace(
        id="workspace-archive", agency_id=agency.id, display_name="Client",
        external_reference=None, status="active", updated_at=None,
    )
    site = SimpleNamespace(
        agency_id=agency.id, workspace_id=workspace.id, status="active",
        site_token_hash="hashed-live-site-token", disconnected_at=None,
    )
    challenges = [
        SimpleNamespace(agency_id=agency.id, workspace_id=workspace.id, consumed_at=None),
        SimpleNamespace(agency_id=agency.id, workspace_id=workspace.id, consumed_at=None),
    ]
    db = AgencyArchiveSession(agency, workspace, site, challenges)
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await update_business_agency_client(
        workspace.id, AgencyClientWorkspaceUpdate(status="archived"), Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=db,
    )

    assert result["status"] == "archived"
    assert result["connection_revoked"] is True
    assert site.status == "disconnected"
    assert site.site_token_hash is None
    assert site.disconnected_at is not None
    assert all(challenge.consumed_at is not None for challenge in challenges)
    assert db.committed


@pytest.mark.asyncio
async def test_archiving_workspace_without_connections_is_safe(monkeypatch):
    import main
    from fastapi import Response
    from main import AgencyClientWorkspaceUpdate, update_business_agency_client

    agency = SimpleNamespace(id="agency-empty", status="active", owner_license_key="business-license")
    workspace = SimpleNamespace(
        id="workspace-empty", agency_id=agency.id, display_name="Empty",
        external_reference=None, status="active", updated_at=None,
    )
    db = AgencyArchiveSession(agency, workspace, None, [])
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await update_business_agency_client(
        workspace.id, AgencyClientWorkspaceUpdate(status="archived"), Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=db,
    )

    assert result["status"] == "archived"
    assert result["connection_revoked"] is False
    assert db.committed


def test_customer_portal_explains_wordpress_revocation_after_archiving():
    from pathlib import Path

    portal = Path(__file__).resolve().parents[1] / "customer_portal.html"
    source = portal.read_text(encoding="utf-8")
    assert "updated.connection_revoked" in source
    assert "WordPress credential and unused connection codes were revoked" in source
    assert "reconnect the site after reactivation" in source



def test_admin_wordpress_link_inventory_exposes_bounded_connection_health_without_secrets():
    source = inspect.getsource(main.admin_list_client_wordpress_links)

    assert 'now = datetime.now(timezone.utc)' in source
    assert '"connection_health"' in source
    assert '"not_connected"' in source
    assert '"stale"' in source
    assert '"healthy"' in source
    assert 'timedelta(days=7)' in source
    assert '"token_hash"' not in source
    assert '"token_digest"' not in source
    assert '"license_key":' not in source


def test_admin_wordpress_connection_health_is_visible_in_operator_console():
    from pathlib import Path

    portal = Path(__file__).resolve().parents[1] / "admin_portal.html"
    source = portal.read_text(encoding="utf-8")

    assert 'item.connection_health' in source
    assert 'staleHeartbeat' in source
    assert 'Connection health ' in source
    assert 'No recent plugin heartbeat.' in source
from pathlib import Path



def test_agency_wordpress_connection_ui_supports_health_refresh_and_token_replacement():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadAgencyDashboard")
    end = portal.index("async function loadAgencyClientAuditResults", start)
    section = portal[start:end]

    assert 'refreshWebsite.textContent = "Refresh connection status";' in section
    assert 'website.connection_health === "healthy"' in section
    assert 'website.connection_health === "stale"' in section
    assert 'connectWebsite.textContent = "Generate replacement token";' in section
    assert 'window.confirm("Generate a replacement token?' in section
    assert 'Generating another token invalidates this one.' in section
    assert 'refreshWebsiteStatus();' in section



def test_agency_portal_otp_attempts_ignore_stale_responses():
    portal = Path("agency_portal.html").read_text(encoding="utf-8")
    start = portal.index("(() => {")
    script = portal[start:portal.index("</script>", start)]

    assert "let authAttemptVersion = 0;" in script
    assert "const attemptVersion=++authAttemptVersion;" in script
    assert "if(attemptVersion!==authAttemptVersion)return;" in script
    assert 'if(actionVersion===sessionVersion&&attemptVersion===authAttemptVersion)$("loginStatus").textContent=error.message;' in script
    assert 'if(actionVersion===sessionVersion&&attemptVersion===authAttemptVersion)button.disabled=false;' in script
    assert "authAttemptVersion += 1;" in script
    assert 'if(!result.access_token)throw new Error("The server did not return an agency session.");' in script



def test_customer_portal_keeps_passwordless_session_actions_enabled():
    from pathlib import Path

    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    assert 'finally { button.disabled = !credential && !sessionToken; }' in portal
    logout_all = portal[portal.index('$("logoutAllSessions").addEventListener("click"'):portal.index('$("disconnectAccount").addEventListener("click"')]
    assert 'if (!sessionToken) { setStatus("loginStatus", "Sign in with your customer email to manage device sessions."' in logout_all
    assert 'if (operationSessionVersion === accountSessionVersion) button.disabled = !sessionToken;' in logout_all
    # WordPress identity-link challenge generation remains license/API-key credential gated.
    wordpress_link = portal[portal.index('$("generateWordPressLinkCode").addEventListener("click"'):portal.index('$("copyWordPressLinkCode").addEventListener("click"')]
    assert 'if (operationSessionVersion === accountSessionVersion) button.disabled = !credential;' in wordpress_link




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


def test_customer_portal_agency_workspace_rename_and_archive_confirmation():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    assert 'rename.textContent = "Rename client"' in portal
    assert "body: JSON.stringify({display_name: displayName})" in portal
    assert "Client workspace name cannot be blank." in portal
    assert "if (!window.confirm(confirmation)) return;" in portal
    assert "Existing audit history is retained." in portal


def test_admin_client_detail_panels_ignore_stale_client_responses():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text()
    assert "clientDetailVersion=0" in portal
    assert "const detailVersion=++clientDetailVersion;currentHistoryId=id;" in portal
    assert "if(detailVersion!==clientDetailVersion||currentHistoryId!==id)return;" in portal
    assert "loadClientSessions(id,detailVersion)" in portal
    assert "loadClientWordPressLinks(id,detailVersion)" in portal
    assert "loadClientApiKeys(id,detailVersion)" in portal
    assert "clientDetailVersion+=1;currentHistoryId=null;" in portal



def test_agency_portal_exposes_agency_role_editor_and_preserves_workspace_overrides():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")

    assert 'agencyRoleLabel.textContent = "Agency default role"' in portal
    assert 'method:"PUT"' in portal
    assert '"/api/v1/account/agency/team/" + encodeURIComponent(item.id)' in portal
    assert "Custom workspace roles were preserved." in portal


def test_agency_member_role_api_updates_default_role_without_overwriting_custom_grants():
    import inspect
    import main

    assert "/api/v1/account/agency/team/{member_id}" in main.app.openapi()["paths"]
    source = inspect.getsource(main.update_business_agency_team_member_role)
    assert "AgencyAccount.owner_license_key == license_obj.license_key" in source
    assert "AgencyTeamMember.agency_id == agency.id" in source
    assert "AgencyTeamMember.status == \"active\"" in source
    assert "AgencyWorkspaceAccess.role == previous_role" in source
    assert ".values(role=payload.role)" in source
    assert "AgencyWorkspaceAccess.role == previous_role" in source