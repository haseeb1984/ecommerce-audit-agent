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



def test_customer_scan_batch_cancel_requires_confirmation_and_handles_errors():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'window.confirm("Request cancellation for this scan batch?' in portal
    assert 'cancel.textContent = "Requesting cancellation…"' in portal
    assert 'cancel.disabled = false;' in portal
    assert 'setStatus("bulkScanStatus", error.message || "Batch cancellation could not be recorded.", "error")' in portal
    assert "In-progress jobs may finish before the batch settles." in portal


def test_customer_scan_batch_detail_action_reports_load_errors():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()

    assert 'view.textContent = "Loading URLs…"' in portal
    assert 'Batch details could not be loaded.' in portal
    assert 'view.disabled = false;' in portal



def test_customer_website_inventory_requests_are_scoped_to_account_session():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("async function loadWebsites")
    end = portal.index("const scanBatchPageSize", start)
    source = portal[start:end]

    assert "const requestSessionVersion = accountSessionVersion;" in source
    assert "websiteLoadingSessionVersion === requestSessionVersion" in source
    assert "const requestVersion = ++websiteRequestVersion;" in source
    assert "requestVersion !== websiteRequestVersion || requestSessionVersion !== accountSessionVersion" in source
    assert "requestVersion === websiteRequestVersion && requestSessionVersion === accountSessionVersion" in source


def test_customer_website_inventory_clear_invalidates_in_flight_requests():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("function clearAccountView")
    end = portal.index('$("requestLoginCode").addEventListener', start)
    source = portal[start:end]

    assert "websiteRequestVersion += 1;" in source
    assert "websitesLoading = false;" in source
    assert 'websiteOffset = 0;' in source
    assert 'websiteHasMore = false;' in source
    assert '$("loadMoreWebsites").hidden = true;' in source
