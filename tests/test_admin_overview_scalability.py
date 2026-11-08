import inspect

import main


def test_admin_overview_aggregates_only_current_page_licenses():
    source = inspect.getsource(main.admin_overview)

    assert "visible_license_ids = [item.id for item in licenses]" in source
    assert source.count("AuditLead.license_id.in_(visible_license_ids)") == 2
    assert "AuditReport.license_id.in_(visible_license_ids)" in source
    assert "AuditQuotaReservation.license_id.in_(visible_license_ids)" in source
    assert "if visible_license_ids:" in source


def test_admin_overview_fetches_only_one_latest_contact_per_visible_license():
    source = inspect.getsource(main.admin_overview)

    assert "sql_func.row_number().over(" in source
    assert "partition_by=CustomerBillingEvent.license_key" in source
    assert "ranked_contact_rows.c.contact_rank == 1" in source
    assert "partition_by=PaymentWebhookEvent.license_id" in source
    assert "ranked_legacy_contacts.c.contact_rank == 1" in source
    assert "CustomerBillingEvent.license_key.in_(visible_license_keys)" in source
    assert "PaymentWebhookEvent.license_id.in_(missing_contact_ids)" in source
