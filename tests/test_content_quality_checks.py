from content_quality_checks import inspect_content_quality


def _long_content(words=120):
    return "<main><h1>Product information</h1><p>" + " ".join(f"distinctiveword{i}" for i in range(words)) + "</p></main>"


def test_low_visible_text_volume_is_manual_review_not_a_quality_verdict():
    findings, outcomes, fingerprint = inspect_content_quality(
        "<html><body><main><p>Only a few visible words.</p></main></body></html>",
        "https://shop.example/product/",
    )

    assert any(item.title == "Low visible-text volume needs editorial review" for item in findings)
    assert all(item.status == "manual_review_required" for item in findings)
    volume = next(item for item in outcomes if item.check_id == "content.visible_text_volume")
    assert volume.outcome == "warning"
    assert "5 visible word(s)" in volume.evidence
    assert "Only a few visible words" not in volume.evidence
    assert fingerprint is None


def test_visible_text_extraction_ignores_navigation_script_style_and_footer():
    html = (
        "<nav>" + " ".join(f"navword{i}" for i in range(150)) + "</nav>"
        "<script>" + " ".join(f"scriptword{i}" for i in range(150)) + "</script>"
        "<style>" + " ".join(f"styleword{i}" for i in range(150)) + "</style>"
        "<main><p>Short product summary.</p></main>"
        "<footer>" + " ".join(f"footerword{i}" for i in range(150)) + "</footer>"
    )
    findings, outcomes, fingerprint = inspect_content_quality(html, "https://shop.example/")

    assert any(item.title == "Low visible-text volume needs editorial review" for item in findings)
    assert next(item for item in outcomes if item.check_id == "content.visible_text_volume").outcome == "warning"
    assert fingerprint is None


def test_sufficient_visible_text_passes_volume_heuristic_without_claiming_quality():
    findings, outcomes, fingerprint = inspect_content_quality(
        _long_content(), "https://shop.example/category/",
    )

    assert not any(item.title == "Low visible-text volume needs editorial review" for item in findings)
    assert next(item for item in outcomes if item.check_id == "content.visible_text_volume").outcome == "pass"
    assert "does not establish content quality" in next(
        item for item in outcomes if item.check_id == "content.visible_text_volume"
    ).evidence
    assert fingerprint


def test_exact_duplicate_visible_text_is_flagged_for_manual_review_without_reproducing_content():
    first_findings, _, fingerprint = inspect_content_quality(
        _long_content(), "https://shop.example/category/a/",
    )
    second_findings, outcomes, _ = inspect_content_quality(
        _long_content(), "https://shop.example/category/b/",
        prior_fingerprints={fingerprint: "https://shop.example/category/a/"},
    )

    duplicate = next(item for item in second_findings if item.title == "Exact duplicate visible content across sampled pages")
    outcome = next(item for item in outcomes if item.check_id == "content.exact_duplicate_copy")
    assert duplicate.status == "manual_review_required"
    assert duplicate.severity == "low"
    assert "https://shop.example/category/a/" in duplicate.evidence
    assert "distinctiveword" not in duplicate.evidence
    assert outcome.outcome == "warning"
    assert not any(item.title == "Exact duplicate visible content across sampled pages" for item in first_findings)


def test_bounded_crawler_integrates_content_quality_outcomes():
    from pathlib import Path
    import inspect
    from crawl_checks import run_bounded_site_crawl

    source = inspect.getsource(run_bounded_site_crawl)
    assert "content_fingerprints: dict[str, str] = {}" in source
    assert "inspect_content_quality(" in source
    assert "outcome_records.extend(content_outcomes)" in source
    assert (Path(__file__).resolve().parents[1] / "content_quality_checks.py").exists()
