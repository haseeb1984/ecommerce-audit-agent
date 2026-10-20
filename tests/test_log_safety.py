import logging

from log_safety import CredentialRedactionFilter, redact_secrets


def test_redacts_query_tokens_headers_json_and_database_passwords():
    sample = (
        'request https://example.test/path?key=pagespeed-secret&token=oauth-secret '
        'Authorization: Bearer bearer-secret '
        'payload={"client_secret": "json-secret", "GROQ_API_KEY":"groq-secret"} '
        'postgresql://audit-user:database-secret@db.example.test/audit'
    )
    redacted = redact_secrets(sample)
    for secret in ("pagespeed-secret", "oauth-secret", "bearer-secret", "json-secret", "groq-secret", "database-secret"):
        assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_filter_redacts_formatted_message(caplog):
    logger = logging.getLogger("test.credentials")
    redaction_filter = CredentialRedactionFilter()
    logger.addFilter(redaction_filter)
    try:
        with caplog.at_level(logging.ERROR, logger="test.credentials"):
            logger.error("provider failed for token=%s", "sensitive-token-value")
        assert "sensitive-token-value" not in caplog.text
        assert "[REDACTED]" in caplog.text
    finally:
        logger.removeFilter(redaction_filter)


def test_filter_redacts_exception_trace(caplog):
    logger = logging.getLogger("test.credentials.exception")
    redaction_filter = CredentialRedactionFilter()
    logger.addFilter(redaction_filter)
    try:
        with caplog.at_level(logging.ERROR, logger="test.credentials.exception"):
            try:
                raise RuntimeError('provider URL contained ?key="exception-secret"')
            except RuntimeError:
                logger.exception("upstream request failed")
        assert "exception-secret" not in caplog.text
        assert "[REDACTED]" in caplog.text
    finally:
        logger.removeFilter(redaction_filter)


def test_filter_redacts_stack_info_field():
    record = logging.LogRecord(
        name="test.credentials.stack",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="request failed",
        args=(),
        exc_info=None,
    )
    record.stack_info = 'Stack (most recent call last): URL had ?token="stack-secret-value"'
    assert CredentialRedactionFilter().filter(record)
    assert "stack-secret-value" not in record.stack_info
    assert "[REDACTED]" in record.stack_info
