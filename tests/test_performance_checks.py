import pytest

from performance_checks import inspect_static_performance_signals


def test_missing_image_dimensions_are_a_review_signal_not_a_cwv_claim():
    findings = inspect_static_performance_signals(
        '<img src="/hero.webp"><img src="/logo.svg" width="100" height="30">',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "Images lack explicit width or height attributes")
    assert finding.status == "manual_review_required"
    assert "1 of 2" in finding.evidence
    assert "layout shifts" in finding.explanation.lower()
    assert "PageSpeed Insights" in " ".join(finding.verification_steps)


def test_many_scripts_styles_and_large_inline_blocks_are_flagged_for_review():
    html = (
        "".join(f'<script src="/app-{i}.js"></script>' for i in range(11))
        + "".join(f'<link rel="stylesheet" href="/style-{i}.css">' for i in range(6))
        + "<script>" + ("x" * 50_001) + "</script>"
        + "<style>" + ("a{}" * 17_000) + "</style>"
    )
    findings = inspect_static_performance_signals(html, "https://shop.example/")
    titles = {f.title for f in findings}
    assert "Many external script elements need review" in titles
    assert "Many stylesheet links need review" in titles
    assert "Large inline JavaScript block needs review" in titles
    assert "Large inline CSS block needs review" in titles
    assert all(f.status == "manual_review_required" for f in findings)


def test_normal_resource_counts_do_not_create_findings():
    findings = inspect_static_performance_signals(
        '<img src="/hero.webp" width="1200" height="600">'
        '<script src="/app.js"></script><link rel="stylesheet" href="/site.css">',
        "https://shop.example/",
    )
    assert findings == []
