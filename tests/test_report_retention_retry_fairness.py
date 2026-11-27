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
    assert "case((customerreportfile.cleanup_last_attempt_at.is_(none), 0), else_=1)" in report_query.lower()
    assert "CustomerReportFile.cleanup_last_attempt_at.asc()" in report_query
    assert "CustomerReportFile.expires_at.asc()" in report_query


def test_report_retention_cleanup_orders_logo_retries_by_last_attempt():
    source = inspect.getsource(main.cleanup_expired_report_pdfs)
    logo_query = source[source.index("select(CustomerBrandingLogoCleanup)"):source.index("logo_deleted = 0")]
    assert "case((customerbrandinglogocleanup.last_attempt_at.is_(none), 0), else_=1)" in logo_query.lower()
    assert "CustomerBrandingLogoCleanup.last_attempt_at.asc()" in logo_query
    assert "cleanup.last_attempt_at = now" in source


def test_customer_report_file_model_has_persisted_cleanup_retry_state():
    assert CustomerReportFile.__table__.c.cleanup_attempts.default.arg == 0
    assert CustomerReportFile.__table__.c.cleanup_last_attempt_at.nullable is True


def test_logo_cleanup_model_retains_last_attempt_marker():
    assert CustomerBrandingLogoCleanup.__table__.c.last_attempt_at.nullable is True


def test_legacy_report_retention_cleanup_records_attempts_and_rotates_failures():
    source = inspect.getsource(main.cleanup_expired_report_pdfs)
    legacy_start = source.index("select(AuditReport)")
    legacy_end = source.index("\n    deleted = 0", legacy_start)
    legacy_query = source[legacy_start:legacy_end]
    assert "case((AuditReport.pdf_cleanup_last_attempt_at.is_(None), 0), else_=1)" in legacy_query
    assert "AuditReport.pdf_cleanup_last_attempt_at.asc()" in legacy_query
    assert "report.pdf_cleanup_attempts = int(report.pdf_cleanup_attempts or 0) + 1" in source
    assert "report.pdf_cleanup_last_attempt_at = now" in source


def test_audit_report_model_has_persisted_cleanup_retry_state():
    from models import AuditReport
    assert AuditReport.__table__.c.pdf_cleanup_attempts.default.arg == 0
    assert AuditReport.__table__.c.pdf_cleanup_last_attempt_at.nullable is True
