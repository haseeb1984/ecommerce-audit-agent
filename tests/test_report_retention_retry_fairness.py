from pathlib import Path
import inspect

import main
from hostinger_models import CustomerBrandingLogoCleanup, CustomerReportFile


def test_report_retention_cleanup_records_failed_attempt_before_storage_delete():
    source = inspect.getsource(main.cleanup_expired_report_pdfs)
    attempt = source.index("report_file.cleanup_last_attempt_at = now")
    delete = source.index("await asyncio.to_thread(delete_file, report_file.storage_key)")
    failure = source.index("except HostingerStorageError as exc:", delete)
    assert attempt < delete < failure
    assert "report_file.cleanup_attempts = int(report_file.cleanup_attempts or 0) + 1" in source


def test_report_retention_cleanup_orders_report_retries_fairly():
    source = inspect.getsource(main.cleanup_expired_report_pdfs)
    report_query = source[source.index("select(CustomerReportFile)"):source.index("hostinger_deleted = 0")]
    assert "CustomerReportFile.cleanup_last_attempt_at.asc().nullsfirst()" in report_query
    assert "CustomerReportFile.expires_at.asc()" in report_query


def test_report_retention_cleanup_orders_logo_retries_by_last_attempt():
    source = inspect.getsource(main.cleanup_expired_report_pdfs)
    logo_query = source[source.index("select(CustomerBrandingLogoCleanup)"):source.index("logo_deleted = 0")]
    assert "CustomerBrandingLogoCleanup.last_attempt_at.asc().nullsfirst()" in logo_query
    assert "cleanup.last_attempt_at = now" in source


def test_customer_report_file_model_has_persisted_cleanup_retry_state():
    assert CustomerReportFile.__table__.c.cleanup_attempts.default.arg == 0
    assert CustomerReportFile.__table__.c.cleanup_last_attempt_at.nullable is True


def test_logo_cleanup_model_retains_last_attempt_marker():
    assert CustomerBrandingLogoCleanup.__table__.c.last_attempt_at.nullable is True
