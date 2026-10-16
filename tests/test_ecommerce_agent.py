import pytest

import ecommerce_agent
from ecommerce_agent import UniversalEcommerceAgent


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.is_error = status_code >= 400

    def json(self):
        return self._payload


class FakeAsyncClient:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, *args, **kwargs):
        return self.response


def make_agent(monkeypatch, response):
    monkeypatch.setattr(
        ecommerce_agent.httpx,
        "AsyncClient",
        lambda timeout: FakeAsyncClient(response),
    )
    agent = UniversalEcommerceAgent.__new__(UniversalEcommerceAgent)
    agent.pagespeed_key = "test-pagespeed-key"
    return agent


@pytest.mark.asyncio
async def test_pagespeed_http_error_is_reported_without_using_invalid_metrics(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            status_code=403,
            payload={"error": {"message": "API key is invalid"}},
        ),
    )

    with pytest.raises(RuntimeError, match="HTTP 403"):
        await agent.run_audit("shop.example")


@pytest.mark.asyncio
async def test_missing_lighthouse_report_is_rejected(monkeypatch):
    agent = make_agent(monkeypatch, FakeResponse(payload={"status": "OK"}))

    with pytest.raises(RuntimeError, match="did not contain a Lighthouse report"):
        await agent.run_audit("shop.example")


@pytest.mark.asyncio
async def test_valid_pagespeed_report_converts_metrics(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            payload={
                "lighthouseResult": {
                    "categories": {"performance": {"score": 0.876}},
                    "audits": {"speed-index": {"numericValue": 1234}},
                }
            }
        ),
    )

    result = await agent.run_audit("https://shop.example/")
    assert result.domain == "shop.example"
    assert result.mobile_score == 88
    assert result.speed_index_sec == 1.23
    assert result.is_slow is False


@pytest.mark.asyncio
async def test_out_of_range_pagespeed_metrics_are_rejected(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            payload={
                "lighthouseResult": {
                    "categories": {"performance": {"score": 1.2}},
                    "audits": {"speed-index": {"numericValue": 1000}},
                }
            }
        ),
    )

    with pytest.raises(RuntimeError, match="out-of-range"):
        await agent.run_audit("shop.example")
