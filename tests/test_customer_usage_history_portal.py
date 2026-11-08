"""Regression tests for customer usage-history visibility and safe rendering."""

from pathlib import Path


def test_customer_portal_renders_usage_events_from_account_usage_response():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'id="usageHistoryHeading">Usage history' in portal
    assert 'renderUsageHistory(usage.history);' in portal
    assert 'String(item.event_type || "Usage event")' in portal
    assert '"Quantity: " + (Number.isFinite(Number(item.quantity))' in portal
    assert 'metadata.textContent = serialized ? serialized.slice(0, 1200)' in portal


def test_customer_usage_history_uses_text_nodes_and_clears_on_account_switch():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'title.textContent = String(item.event_type || "Usage event")' in portal
    assert 'metadata.textContent = serialized ? serialized.slice(0, 1200)' in portal
    assert 'metadata.innerHTML' not in portal
    assert 'renderUsageHistory([]);' in portal
    assert 'Connect your account to view usage history.' in portal



def test_customer_bulk_scan_reuses_request_id_until_success_or_payload_change():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("async function submitBulkScans()")
    end = portal.index('$("submitBulkScans").addEventListener', start)
    source = portal[start:end]

    assert "pendingBulkScanFingerprint" in source
    assert "pendingBulkScanRequestId" in source
    assert "JSON.stringify({urls,batch_size:batchSize,workspace_id:workspaceId})" in source
    assert "request_id:pendingBulkScanRequestId" in source
    assert 'pendingBulkScanFingerprint="";' in source
    assert 'pendingBulkScanRequestId="";' in source


def test_customer_account_switch_clears_pending_bulk_scan_idempotency_key():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("function clearAccountView()")
    end = portal.index("\n  }", start)
    source = portal[start:end]

    assert 'pendingBulkScanFingerprint = "";' in source
    assert 'pendingBulkScanRequestId = "";' in source
