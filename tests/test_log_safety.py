import logging

from log_safety import CredentialRedactionFilter, redact_secrets


def test_redacts_query_tokens_headers_and_database_passwords():
    sample = (
        "request https://example.test/path?key=pagespeed-secret&token=oauth-secret "
        "Authorization: Bearer bearer-secret "
        "postgresql://audit-user:database-secret@db.example.test/audit"
    )
    redacted = redact_secrets(sample)
    for secret in ("pagespeed-secret", "oauth-secret", "bearer-secret", "database-secret"):
        assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_filter_redacts_formatted_message(caplog):
    logger = logging.getLogger("test.credentials")
    logger.addFilter(CredentialRedactionFilter())
    try:
        with caplog.at_level(logging.ERROR, logger="test.credentials"):
            logger.error("provider failed for token=%s", "sensitive-token-value")
        assert "sensitive-token-value" not in caplog.text
        assert "[REDACTED]" in caplog.text
    finally:
        logger.removeFilter(CredentialRedactionFilter())


def test_filter_redacts_exception_trace(caplog):
    logger = logging.getLogger("test.credentials.exception")
    logger.addFilter(CredentialRedactionFilter())
    try:
        with caplog.at_level(logging.ERROR, logger="test.credentials.exception"):
            try:
                raise RuntimeError("provider URL contained ?key=exception-secret")
            except RuntimeError:
                logger.exception("upstream request failed")
        assert "exception-secret" not in caplog.text
        assert "[REDACTED]" in caplog.text
    finally:
        logger.filters.clear()
