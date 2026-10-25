from datetime import datetime, timezone

from audit_checks import AuditFinding, _finding


def test_finding_factory_records_reproducibility_metadata():
    finding = _finding(
        category="technical_seo",
        title="Canonical URL needs review",
        status="verified",
        severity="medium",
        evidence="Observed a canonical link in the fetched HTML.",
        explanation="The canonical declaration is a public source signal.",
        recommendation="Compare the declared canonical URL with the intended indexable URL.",
        steps=["Fetch the page source again.", "Compare canonical URL and final response URL."],
        source_url="https://shop.example/products/item",
    )

    assert finding.finding_id.startswith("F-")
    assert datetime.fromisoformat(finding.observed_at_utc).tzinfo is not None
    assert finding.test_method
    assert finding.evidence_confidence in {"limited", "moderate"}
    assert "https://developers.google.com/search/docs/crawling-indexing" in finding.standard_references
    assert finding.source_url == "https://shop.example/products/item"


def test_finding_contract_defaults_are_explicit_for_manual_findings():
    finding = AuditFinding(
        category="conversion_paid_traffic",
        title="Checkout outcome not verified",
        status="not_tested",
        severity="info",
        evidence="No authorized checkout session was available.",
        explanation="Static public HTML does not establish successful checkout.",
        recommendation="Verify the flow in an authorized test environment.",
        verification_steps=["Use a test account and test payment mode."],
        source_url="https://shop.example/checkout",
    )

    assert finding.finding_id.startswith("F-")
    assert datetime.fromisoformat(finding.observed_at_utc).tzinfo is not None
    assert finding.test_method == "Not specified by the individual checker"
    assert finding.evidence_confidence == "limited"
    assert finding.standard_references == []
    assert finding.estimated_effort == "Not applicable until an actionable issue is confirmed"
