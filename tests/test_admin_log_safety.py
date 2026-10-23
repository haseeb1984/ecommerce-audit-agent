"""Tests for defense-in-depth sanitization of persistent admin activity logs."""
import main


def test_admin_log_sanitizer_redacts_sensitive_keys_and_assignments():
    safe = main._sanitize_admin_log_value({
        "client": "Acme Store",
        "license_key": "license-secret-value",
        "nested": {
            "api_key": "api-secret-value",
            "note": "authorization: Bearer bearer-secret-value",
        },
    })

    assert safe["client"] == "Acme Store"
    assert safe["license_key"] == "[REDACTED]"
    assert safe["nested"]["api_key"] == "[REDACTED]"
    assert "api-secret-value" not in repr(safe)
    assert "bearer-secret-value" not in repr(safe)


def test_admin_log_sanitizer_bounds_depth_collections_and_strings():
    nested = {"level": {"level": {"level": {"level": {"level": {"level": "hidden"}}}}}}
    safe = main._sanitize_admin_log_value({
        "nested": nested,
        "items": list(range(150)),
        "message": "x" * 3000,
    })

    assert "[nested value omitted]" in repr(safe)
    assert len(safe["items"]) == 100
    assert len(safe["message"]) <= 2000
