from types import SimpleNamespace

from coverage_manifest import build_coverage_manifest


def test_coverage_manifest_never_counts_absent_categories_as_passes():
    findings = [
        SimpleNamespace(category="technical_seo", status="verified"),
        SimpleNamespace(category="security_dependency", status="not_tested"),
        SimpleNamespace(category="indexing", status="not_tested"),
    ]
    manifest = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=["https://shop.example/", "https://shop.example/"],
        findings=findings,
        limitations=["Search Console was not queried."],
    )

    assert manifest["required_categories"] == 28
    assert manifest["pages_checked_count"] == 1
    assert manifest["categories_with_recorded_findings"] == 3
    assert manifest["categories_not_proven"] == 25
    assert manifest["category_signal_coverage_pct"] == 10.7
    assert manifest["coverage_level"] == "category_signal_coverage_not_individual_check_coverage"
    assert {item["category"] for item in manifest["not_proven_categories"]} >= {
        "pixel_analytics", "backlink_competitor", "content_quality"
    }
    assert "not a pass" not in manifest["important_note"].lower()


def test_not_tested_finding_is_observed_but_never_described_as_pass():
    manifest = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=[],
        findings=[SimpleNamespace(category="indexing", status="not_tested")],
        limitations=[],
    )
    row = next(item for item in manifest["observed_categories"] if item["category"] == "indexing")
    assert row["status"] == "recorded"
    assert row["findings_in_category"] == 1
    assert "does not prove" in manifest["important_note"]



def test_coverage_manifest_records_each_observation_without_url_query_secrets():
    finding = SimpleNamespace(
        category="technical_seo",
        title="Canonical target",
        status="manual_review_required",
        severity="medium",
        source_url="https://shop.example/product?session=private#details",
    )
    first = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=["https://shop.example/"],
        findings=[finding],
        limitations=[],
    )
    second = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=["https://shop.example/"],
        findings=[finding],
        limitations=[],
    )
    observation = first["recorded_observations"][0]
    assert observation["check_id"] == second["recorded_observations"][0]["check_id"]
    assert observation["status"] == "manual_review_required"
    assert observation["source_url"] == "https://shop.example/product"
    assert "session" not in observation["source_url"]
    assert first["recorded_observations_count"] == 1



def test_completed_checker_group_without_findings_is_not_marked_unproven_or_as_a_pass():
    manifest = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=["https://shop.example/"],
        findings=[
            SimpleNamespace(category="technical_seo", status="verified"),
        ],
        limitations=["Google Search Console is not connected."],
        executed_categories=["performance", "accessibility"],
    )

    performance = next(
        item for item in manifest["checked_without_findings_categories"]
        if item["category"] == "performance"
    )
    accessibility = next(
        item for item in manifest["checked_without_findings_categories"]
        if item["category"] == "accessibility"
    )
    assert performance["status"] == "checked_no_findings"
    assert performance["checker_group_executed"] is True
    assert accessibility["status"] == "checked_no_findings"
    # ARIA is a separate category and is not inferred from the general
    # accessibility checker unless its own checker group is explicitly executed.
    assert "aria" in {
        item["category"] for item in manifest["not_proven_categories"]
    }
    assert "indexing" in {
        item["category"] for item in manifest["not_proven_categories"]
    }
    assert manifest["categories_checked"] == 3
    assert manifest["categories_checked_without_findings"] == 2
    assert manifest["category_execution_coverage_pct"] > manifest["category_signal_coverage_pct"]



def test_coverage_manifest_includes_bounded_reproducibility_context():
    finding = SimpleNamespace(
        category="technical_seo",
        title="Title check",
        status="verified",
        severity="low",
        source_url="https://shop.example/?private=token",
    )
    outcome = SimpleNamespace(
        check_id="seo.title",
        outcome="pass",
        page_url="https://shop.example/",
    )
    manifest = build_coverage_manifest(
        target_url="https://shop.example/?secret=removed",
        pages_checked=["https://shop.example/", "https://shop.example/?session=private"],
        findings=[finding],
        limitations=["Rendered browser was not available."],
        check_outcomes=[outcome],
        run_context={
            "started_at_utc": "2026-10-27T10:00:00+00:00",
            "completed_at_utc": "2026-10-27T10:01:00+00:00",
            "target_scope": "Public unauthenticated audit.",
            "user_agent": "EcommerceAuditBot/1.0",
            "limits": {"max_crawl_pages": 12, "max_response_bytes": 1000000, "unsafe": "ignore"},
            "measurement_context": {"performance": "lab only", "private_token": {"should": "not leak"}},
        },
    )

    context = manifest["audit_run_context"]
    assert manifest["schema_version"] == 4
    assert context["started_at_utc"] == "2026-10-27T10:00:00+00:00"
    assert context["completed_at_utc"] == "2026-10-27T10:01:00+00:00"
    assert context["limits"] == {"max_crawl_pages": 12, "max_response_bytes": 1000000}
    assert context["check_ids_recorded"] == ["seo.title"]
    assert context["check_outcome_state_counts"] == {"pass": 1}
    assert context["limitations_count"] == 1
    assert "private_token" not in context["measurement_context"]
    assert manifest["target_url"] == "https://shop.example/"
    assert manifest["pages_checked_count"] == 1



def test_coverage_manifest_preserves_only_known_module_lifecycle_states():
    manifest = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=[],
        findings=[],
        limitations=[],
        run_context={
            "module_statuses": {
                "pagespeed": "unavailable",
                "bounded_crawl": "error",
                "unsafe_state": "pretend_success",
                "nested": {"state": "completed"},
            },
        },
    )

    assert manifest["audit_run_context"]["module_statuses"] == {
        "pagespeed": "unavailable",
        "bounded_crawl": "error",
    }


def test_recorded_observation_keeps_bounded_finding_contract():
    finding = SimpleNamespace(
        category="technical_seo", title="Canonical target", status="verified",
        severity="medium", source_url="https://shop.example/page?token=secret",
        explanation="Canonical points to the preferred URL.",
        recommendation="Review the canonical target.",
        verification_steps=["Open the page source."],
        standard_references=["https://developers.google.com/search/docs"],
    )
    manifest = build_coverage_manifest(
        target_url="https://shop.example/", pages_checked=[], findings=[finding], limitations=[]
    )
    row = manifest["recorded_observations"][0]
    assert row["finding_id"].startswith("F-")
    assert row["check_id"] == row["finding_id"]
    assert row["source_url"] == "https://shop.example/page"
    assert row["explanation"] == "Canonical points to the preferred URL."
    assert row["verification_steps"] == ["Open the page source."]
    assert row["standard_references"] == ["https://developers.google.com/search/docs"]


def test_recorded_observation_redacts_credentials_from_text_fields():
    finding = SimpleNamespace(
        category="security_headers",
        title="Header review",
        status="manual_review_required",
        severity="medium",
        source_url="https://shop.example/",
        evidence="Authorization: Bearer abc.def.ghi api_key=secret123 and https://shop.example/path?token=hidden",
        explanation="Review the response without exposing secret=private-value.",
    )
    manifest = build_coverage_manifest(
        target_url="https://shop.example/", pages_checked=[], findings=[finding], limitations=[]
    )
    row = manifest["recorded_observations"][0]
    assert "abc.def.ghi" not in row["evidence"]
    assert "secret123" not in row["evidence"]
    assert "token=hidden" not in row["evidence"]
    assert "private-value" not in row["explanation"]
    assert "[REDACTED]" in row["evidence"]
