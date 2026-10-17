import json
from types import SimpleNamespace

import pytest

from ecommerce_agent import (
    ContactInfo,
    StoreAuditMetrics,
    UniversalEcommerceAgent,
)


class GroqError(Exception):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


class FakeCompletions:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs["model"])
        result = self.responses[kwargs["model"]]
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=json.dumps(result))
                )
            ]
        )


class FakeModels:
    def __init__(self, model_ids):
        self.model_ids = model_ids

    async def list(self):
        return SimpleNamespace(
            data=[SimpleNamespace(id=model_id, active=True) for model_id in self.model_ids]
        )


def make_agent(responses, model_ids):
    agent = UniversalEcommerceAgent.__new__(UniversalEcommerceAgent)
    agent.model = "retired-model"
    agent.groq_client = SimpleNamespace(
        chat=SimpleNamespace(completions=FakeCompletions(responses)),
        models=FakeModels(model_ids),
    )
    return agent


@pytest.fixture
def audit_and_contact():
    return (
        StoreAuditMetrics(
            domain="shop.example",
            mobile_score=72,
            speed_index_sec=2.4,
            is_slow=False,
        ),
        ContactInfo(first_name="Store Owner", email="owner@example.com"),
    )


@pytest.mark.asyncio
async def test_recovers_to_available_model_that_passes_json_validation(audit_and_contact):
    audit, contact = audit_and_contact
    valid_pitch = {
        "revenue_leak_hypothesis": "Slow mobile performance may reduce conversions.",
        "email_subject": "A quick mobile performance idea",
        "email_body": "I noticed your mobile score. It may affect conversions. Would a short video help?",
    }
    agent = make_agent(
        {
            "retired-model": GroqError("model not found", 404),
            "openai/gpt-oss-20b": valid_pitch,
        },
        [
            "whisper-large-v3",
            "meta-llama/llama-prompt-guard-2-22m",
            "openai/gpt-oss-20b",
        ],
    )

    result = await agent.generate_pitch(audit, contact)

    assert result.email_subject == valid_pitch["email_subject"]
    assert agent.model == "openai/gpt-oss-20b"
    assert agent.groq_client.chat.completions.calls == [
        "retired-model",
        "openai/gpt-oss-20b",
    ]


@pytest.mark.asyncio
async def test_does_not_switch_models_for_rate_limit(audit_and_contact):
    audit, contact = audit_and_contact
    agent = make_agent(
        {"retired-model": GroqError("rate limit exceeded", 429)},
        ["openai/gpt-oss-20b"],
    )

    with pytest.raises(GroqError, match="rate limit"):
        await agent.generate_pitch(audit, contact)

    assert agent.model == "retired-model"
    assert agent.groq_client.chat.completions.calls == ["retired-model"]


@pytest.mark.asyncio
async def test_fails_explicitly_when_no_candidate_passes_validation(audit_and_contact):
    audit, contact = audit_and_contact
    agent = make_agent(
        {
            "retired-model": GroqError("model not found", 404),
            "openai/gpt-oss-20b": ValueError("unsupported JSON response format"),
        },
        ["openai/gpt-oss-20b"],
    )

    with pytest.raises(RuntimeError, match="no listed alternative passed"):
        await agent.generate_pitch(audit, contact)
