"""Regression tests for defensive customer usage-history metadata decoding."""

import json

import main


def test_usage_details_invalid_json_does_not_break_usage_response():
    details = main._load_customer_usage_details("{not-json")

    assert details == {
        "_warning": "Stored usage details were invalid and have been omitted."
    }


def test_usage_details_non_object_payload_is_omitted():
    details = main._load_customer_usage_details(json.dumps(["unexpected", "list"]))

    assert details == {
        "_warning": "Stored usage details were not an object and have been omitted."
    }


def test_usage_details_redact_credentials_and_bound_nested_values():
    details = main._load_customer_usage_details(json.dumps({
        "job_id": "job-123",
        "api_key": "must-not-leak",
        "nested": {"authorization": "Bearer must-not-leak-either"},
        "large_list": list(range(150)),
    }))

    assert details["job_id"] == "job-123"
    assert details["api_key"] == "[REDACTED]"
    assert details["nested"]["authorization"] == "[REDACTED]"
    assert len(details["large_list"]) == 100
    assert "must-not-leak" not in repr(details)
