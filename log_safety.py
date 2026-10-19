"""Best-effort redaction of credential-shaped values in application logs.

Do not log raw requests, headers, provider bodies, or secret-bearing URLs even
with this filter installed. Redaction is defense-in-depth, not a substitute
for safe logging practices.
"""
from __future__ import annotations

import logging
import re
import traceback


_PATTERNS = [
    # Authorization header values and bearer tokens.
    re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"),
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+"),
    # Credential-bearing query parameters and key/value text.
    re.compile(
        r"(?i)([?&;\s](?:api[_-]?key|key|token|access[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|secret|password|passwd|license[_-]?key|"
        r"groq_api_key|google_pagespeed_api_key)=)[^&#\s,;]+"
    ),
    # Database connection URLs with embedded user/password.
    re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)"),
]


def redact_secrets(value: str) -> str:
    """Redact common credential patterns from a string."""
    result = value
    for pattern in _PATTERNS:
        result = pattern.sub(r"\1[REDACTED]\2" if pattern.groups == 2 else r"\1[REDACTED]", result)
    return result


class CredentialRedactionFilter(logging.Filter):
    """Redact formatted log messages and exception text before handlers emit them."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = "[log message formatting failed]"
        record.msg = redact_secrets(message)
        record.args = ()

        if record.exc_info:
            try:
                formatted = "".join(traceback.format_exception(*record.exc_info))
                record.exc_text = redact_secrets(formatted)
            except Exception:
                record.exc_text = "[exception details suppressed]"
            # Avoid handlers formatting the original exception again.
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_secrets(record.exc_text)
        return True
