from pathlib import Path


def test_customer_scan_history_uses_server_pagination_and_loads_older_batches():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'const scanBatchPageSize = 100;' in portal
    assert 'offset = append ? scanBatchOffset : 0' in portal
    assert 'loadScanBatches({append: true})' in portal
    assert 'Load older scan batches' in portal
    assert 'scanBatchOffset = offset + items.length' in portal


def test_customer_scan_history_refresh_starts_from_latest_page():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'async function loadScanBatches({append = false} = {})' in portal
    assert 'if (!append) {' in portal
    assert 'container.replaceChildren();' in portal
