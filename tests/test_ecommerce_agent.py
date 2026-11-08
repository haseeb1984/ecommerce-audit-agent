import pytest

import ecommerce_agent


def test_httpx_request_logging_does_not_emit_info_level_urls():
    # PageSpeed credentials are query parameters, so HTTPX INFO request logs are unsafe.
    assert ecommerce_agent.logging.getLogger("httpx").getEffectiveLevel() >= ecommerce_agent.logging.WARNING

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
async def test_pagespeed_http_error_is_reported_without_logging_target_or_provider_body(monkeypatch, caplog):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            status_code=403,
            payload={"error": {"message": "API key is invalid"}},
        ),
    )

    with pytest.raises(RuntimeError, match="HTTP 403"):
        await agent.run_audit("shop.example?token=synthetic-secret")

    assert "synthetic-secret" not in caplog.text
    assert "shop.example" not in caplog.text
    assert "API key is invalid" not in caplog.text


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
                "loadingExperience": {
                    "id": "https://shop.example/",
                    "overall_category": "AVERAGE",
                    "metrics": {
                        "LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 2400, "category": "AVERAGE"},
                        "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"percentile": 12, "category": "GOOD"},
                        "INTERACTION_TO_NEXT_PAINT": {"percentile": 180, "category": "GOOD"},
                    }
                },
                "originLoadingExperience": {
                    "id": "https://shop.example",
                    "overall_category": "GOOD",
                    "metrics": {
                        "LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 1900, "category": "GOOD"}
                    }
                },
                "lighthouseResult": {
                    "lighthouseVersion": "12.8.0",
                    "fetchTime": "2026-10-25T10:00:00.000Z",
                    "finalDisplayedUrl": "https://shop.example/",
                    "configSettings": {"formFactor": "mobile"},
                    "categories": {"performance": {"score": 0.876}},
                    "audits": {
                        "speed-index": {"numericValue": 1234},
                        "largest-contentful-paint": {"numericValue": 2400},
                        "cumulative-layout-shift": {"numericValue": 0.12},
                        "total-blocking-time": {"numericValue": 125},
                        "server-response-time": {"numericValue": 350},
                    },
                }
            }
        ),
    )

    result = await agent.run_audit("https://shop.example/")
    assert result.domain == "shop.example"
    assert result.mobile_score == 88
    assert result.speed_index_sec == 1.23
    assert result.lcp_sec == 2.4
    assert result.cls_score == 0.12
    assert result.tbt_ms == 125
    assert result.ttfb_ms == 350
    assert result.field_metrics["url:LARGEST_CONTENTFUL_PAINT_MS"]["percentile"] == 2400
    assert result.field_metrics["url:INTERACTION_TO_NEXT_PAINT"]["category"] == "GOOD"
    assert result.field_metrics["url:CUMULATIVE_LAYOUT_SHIFT_SCORE"]["normalized_value"] == 0.012
    assert result.field_metrics["origin:LARGEST_CONTENTFUL_PAINT_MS"]["percentile"] == 1900
    assert result.field_data_context["origin_overall_category"] == "GOOD"
    assert result.lighthouse_version == "12.8.0"
    assert result.form_factor == "mobile"
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


def test_pagespeed_key_prefers_current_environment_name_and_supports_legacy_fallback(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "synthetic-groq-key")
    monkeypatch.setattr(ecommerce_agent, "AsyncGroq", lambda api_key: object())
    monkeypatch.setenv("PAGE_SPEED_API_KEY", "current-pagespeed-key")
    monkeypatch.setenv("GOOGLE_PAGESPEED_API_KEY", "legacy-pagespeed-key")
    assert UniversalEcommerceAgent().pagespeed_key == "current-pagespeed-key"

    monkeypatch.delenv("PAGE_SPEED_API_KEY")
    assert UniversalEcommerceAgent().pagespeed_key == "legacy-pagespeed-key"



@pytest.mark.asyncio
async def test_pagespeed_rejects_non_finite_remote_metrics(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            payload={
                "lighthouseResult": {
                    "categories": {"performance": {"score": 0.8}},
                    "audits": {"speed-index": {"numericValue": float("inf")}},
                }
            }
        ),
    )

    with pytest.raises(RuntimeError, match="out-of-range"):
        await agent.run_audit("shop.example")



@pytest.mark.asyncio
async def test_pagespeed_field_urls_drop_query_secrets_and_categories_are_allowlisted(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(
            payload={
                "loadingExperience": {
                    "id": "https://shop.example/product?token=field-secret#section",
                    "overall_category": "UNRECOGNIZED",
                    "metrics": {
                        "INTERACTION_TO_NEXT_PAINT": {"percentile": 180, "category": "UNTRUSTED CATEGORY"},
                    },
                },
                "lighthouseResult": {
                    "categories": {"performance": {"score": 0.8}},
                    "audits": {"speed-index": {"numericValue": 1000}},
                    "finalDisplayedUrl": "https://shop.example/product?session=final-secret#top",
                },
            }
        ),
    )

    result = await agent.run_audit("shop.example")
    assert result.field_data_context["url_data_id"] == "https://shop.example/product"
    assert "url_overall_category" not in result.field_data_context
    assert result.field_metrics["url:INTERACTION_TO_NEXT_PAINT"]["category"] is None
    assert result.final_url == "https://shop.example/product"
    assert "field-secret" not in str(result.model_dump())
    assert "final-secret" not in str(result.model_dump())


@pytest.mark.asyncio
async def test_pagespeed_accepts_documented_field_data_categories(monkeypatch):
    agent = make_agent(
        monkeypatch,
        FakeResponse(payload={
            "loadingExperience": {
                "id": "https://shop.example/",
                "overall_category": "FAST",
                "metrics": {
                    "INTERACTION_TO_NEXT_PAINT": {"percentile": 180, "category": "NEEDS_IMPROVEMENT"},
                },
            },
            "lighthouseResult": {
                "categories": {"performance": {"score": 0.8}},
                "audits": {"speed-index": {"numericValue": 1000}},
            },
        }),
    )
    result = await agent.run_audit("shop.example")
    assert result.field_data_context["url_overall_category"] == "FAST"
    assert result.field_metrics["url:INTERACTION_TO_NEXT_PAINT"]["category"] == "NEEDS_IMPROVEMENT"



@pytest.mark.asyncio
async def test_generated_outreach_rejects_unsupported_revenue_and_quantified_claims():
    import json
    from types import SimpleNamespace

    class FakeCompletions:
        async def create(self, **kwargs):
            self.kwargs = kwargs
            content = json.dumps({
                "revenue_leak_hypothesis": "The store is losing thousands in revenue.",
                "email_subject": "Stop burning ad budget",
                "email_body": "Your score is costing you sales and could lift conversions by 20%. Would you like a 90-second Loom?",
            })
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    completions = FakeCompletions()
    agent = UniversalEcommerceAgent.__new__(UniversalEcommerceAgent)
    agent.groq_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    audit = ecommerce_agent.StoreAuditMetrics(
        domain="shop.example", mobile_score=62, speed_index_sec=3.4, is_slow=True
    )
    contact = ecommerce_agent.ContactInfo(email="owner@example.com")

    pitch = await agent._request_pitch("test-model", audit, contact)

    assert "62/100" in pitch.revenue_leak_hypothesis
    assert "3.40 seconds" in pitch.revenue_leak_hypothesis
    assert "business impact is unknown" in pitch.revenue_leak_hypothesis
    assert "burning ad budget" not in pitch.email_subject.lower()
    assert "20%" not in pitch.email_body
    assert "do not establish a business outcome" in pitch.email_body
    system_prompt = completions.kwargs["messages"][0]["content"]
    assert "Do not mention revenue, sales, conversions, ad budgets, ROI" in system_prompt


@pytest.mark.asyncio
async def test_grounded_generated_outreach_preserves_safe_copy():
    import json
    from types import SimpleNamespace

    class FakeCompletions:
        async def create(self, **kwargs):
            content = json.dumps({
                "revenue_leak_hypothesis": "A revenue opportunity may exist.",
                "email_subject": "A performance observation for your store",
                "email_body": "I reviewed your mobile PageSpeed score of 62/100 and Speed Index of 3.40 seconds. These are lab observations from the tested page. Would you be open to a 90-second Loom walking through them?",
            })
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    agent = UniversalEcommerceAgent.__new__(UniversalEcommerceAgent)
    agent.groq_client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    audit = ecommerce_agent.StoreAuditMetrics(
        domain="shop.example", mobile_score=62, speed_index_sec=3.4, is_slow=True
    )
    pitch = await agent._request_pitch("test-model", audit, ecommerce_agent.ContactInfo(email="owner@example.com"))

    assert "business impact is unknown" in pitch.revenue_leak_hypothesis
    assert pitch.email_subject == "A performance observation for your store"
    assert "score of 62/100" in pitch.email_body
