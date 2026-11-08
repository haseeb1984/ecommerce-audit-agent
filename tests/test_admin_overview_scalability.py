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



def test_admin_overview_email_search_streams_operational_license_keys_in_bounded_batches():
    source = inspect.getsource(main.admin_overview)
    start = source.index("normalized_search = search.strip()")
    end = source.index("count_query = select(sql_func.count(SoftwareLicense.id))", start)
    search_block = source[start:end]

    assert "CREATE TEMP TABLE admin_overview_search_license_keys" in search_block
    assert "operational_db.stream(operational_identity_query)" in search_block
    assert "identity_values.fetchmany(500)" in search_block
    assert "await identity_stream.close()" in search_block
    assert "union(" in search_block
    assert "matching_license_keys = set(" not in search_block
    assert "matching_license_ids = set(" not in search_block
    assert ".scalars().all()" not in search_block


def test_admin_overview_drops_search_identity_temp_table_after_count_and_page_queries():
    source = inspect.getsource(main.admin_overview)
    page_query = source.index("licenses = (await db.execute(")
    cleanup = source.index("if search_identity_table_created:", page_query)
    summary = source.index("total_clients =", cleanup)
    assert page_query < cleanup < summary
    assert "await db.commit()" in source[cleanup:summary]
