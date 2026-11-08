"""HTTP-level acceptance tests for the authenticated scan worker route."""

import pytest

import scan_worker_api


@pytest.mark.asyncio
async def test_scan_worker_http_route_authenticates_and_processes_requested_batch(
    client, monkeypatch
):
    monkeypatch.setenv("CRON_SECRET", "http-worker-cron-secret")
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)
    calls = []

    async def fake_process_scan_queue(*, max_jobs):
        calls.append(max_jobs)
        return {"claimed_slots": max_jobs, "processed": max_jobs}

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", fake_process_scan_queue)

    response = await client.get(
        "/internal/scan-worker/run?max_jobs=4",
        headers={"Authorization": "Bearer http-worker-cron-secret"},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"claimed_slots": 4, "processed": 4}
    assert calls == [4]


@pytest.mark.asyncio
@pytest.mark.parametrize("max_jobs", [0, 11])
async def test_scan_worker_http_route_rejects_out_of_range_batch_sizes(
    client, monkeypatch, max_jobs
):
    monkeypatch.setenv("CRON_SECRET", "http-worker-cron-secret")
    calls = []

    async def fake_process_scan_queue(*, max_jobs):
        calls.append(max_jobs)
        return {"processed": max_jobs}

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", fake_process_scan_queue)

    response = await client.get(
        f"/internal/scan-worker/run?max_jobs={max_jobs}",
        headers={"Authorization": "Bearer http-worker-cron-secret"},
    )

    assert response.status_code == 422
    assert calls == []


@pytest.mark.asyncio
async def test_scan_worker_http_route_rejects_missing_and_invalid_bearer_tokens(
    client, monkeypatch
):
    monkeypatch.setenv("CRON_SECRET", "http-worker-cron-secret")
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)

    missing = await client.get("/internal/scan-worker/run?max_jobs=1")
    invalid = await client.get(
        "/internal/scan-worker/run?max_jobs=1",
        headers={"Authorization": "Bearer wrong-token"},
    )

    assert missing.status_code == 401
    assert invalid.status_code == 401


@pytest.mark.asyncio
async def test_scan_worker_http_route_fails_closed_when_no_secret_is_configured(
    client, monkeypatch
):
    monkeypatch.delenv("CRON_SECRET", raising=False)
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)

    response = await client.get(
        "/internal/scan-worker/run?max_jobs=1",
        headers={"Authorization": "Bearer anything"},
    )

    assert response.status_code == 503



@pytest.mark.asyncio
async def test_scan_worker_http_route_returns_retryable_503_for_sqlalchemy_failures(
    client, monkeypatch
):
    from sqlalchemy.exc import SQLAlchemyError

    monkeypatch.setenv("CRON_SECRET", "http-worker-cron-secret")

    async def unavailable(*, max_jobs):
        raise SQLAlchemyError("private database connection details")

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", unavailable)
    response = await client.get(
        "/internal/scan-worker/run?max_jobs=2",
        headers={"Authorization": "Bearer http-worker-cron-secret"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Scan worker database is unavailable."}
    assert "private database connection details" not in response.text


@pytest.mark.asyncio
async def test_legacy_scan_worker_route_returns_retryable_503_for_sqlalchemy_failures(
    client, monkeypatch
):
    from sqlalchemy.exc import SQLAlchemyError

    monkeypatch.setenv("SCAN_WORKER_SECRET", "legacy-worker-secret")

    async def unavailable(*, max_jobs):
        raise SQLAlchemyError("private database connection details")

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", unavailable)
    response = await client.get(
        "/api/v1/internal/scan-worker",
        headers={"Authorization": "Bearer legacy-worker-secret"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Scan worker database is unavailable."}
    assert "private database connection details" not in response.text
