from hostinger_models import AgencyAccount, AgencyClientWorkspace, AgencyClientWebsite, AgencyTeamMember, AgencyWorkspaceAccess, AgencyUsageEvent


def test_business_agency_tables_are_registered():
    expected = {"agency_accounts", "agency_client_workspaces", "agency_client_websites", "agency_team_members", "agency_workspace_access", "agency_usage_events"}
    actual = {AgencyAccount.__tablename__, AgencyClientWorkspace.__tablename__, AgencyClientWebsite.__tablename__, AgencyTeamMember.__tablename__, AgencyWorkspaceAccess.__tablename__, AgencyUsageEvent.__tablename__}
    assert actual == expected


def test_bulk_scan_payload_accepts_optional_agency_workspace():
    from scan_api import BulkScanSubmission

    personal = BulkScanSubmission(urls=["https://shop.example/"], request_id="request-12345678")
    agency = BulkScanSubmission(
        urls=["https://shop.example/"],
        request_id="request-abcdefgh",
        workspace_id="agency-client-workspace",
    )
    assert personal.workspace_id is None
    assert agency.workspace_id == "agency-client-workspace"
