import browser_audit_service


def test_navigation_timing_evidence_is_explicitly_not_core_web_vitals():
    evidence = browser_audit_service._format_navigation_timing(
        {"responseStart": 125.4, "domContentLoadedEventEnd": 480.2, "loadEventEnd": 710.8},
        {"count": 14, "transfer_bytes": 245760},
    )
    assert "responseStart=125ms" in evidence
    assert "domContentLoadedEventEnd=480ms" in evidence
    assert "resource entries: 14" in evidence
    assert "245760" in evidence
    assert "not field Core Web Vitals" in evidence


def test_navigation_timing_evidence_handles_unavailable_entries():
    evidence = browser_audit_service._format_navigation_timing({}, {})
    assert "timing fields unavailable" in evidence
    assert "resource entries: 0" in evidence
