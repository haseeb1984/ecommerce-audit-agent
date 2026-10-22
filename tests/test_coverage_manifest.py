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
    assert manifest["categories_with_observed_evidence"] == 3
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
    assert row["status"] == "observed"
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
