import hashlib
import hmac
import json
import time

import pytest
from fastapi import HTTPException

import main


class _ContactRequest:
    def __init__(self, body, headers):
        self._body = body
        self.headers = headers

    async def body(self):
        return self._body


def _signed_contact_request(payload, secret):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"\n" + body,
        hashlib.sha256,
    ).hexdigest()
    return _ContactRequest(
        body,
        {"x-eaa-timestamp": timestamp, "x-eaa-signature": signature},
    )


@pytest.mark.asyncio
async def test_public_contact_endpoint_sends_branded_html_and_reply_to(monkeypatch):
    secret = "a-long-random-contact-secret"
    monkeypatch.setenv("EAA_CONTACT_FORM_SECRET", secret)
    monkeypatch.setenv("EAA_CONTACT_TO_EMAIL", "support@example.com")
    monkeypatch.setenv("SMTP_FROM", "mailer@example.com")
    payload_data = {
        "name": "Store Owner",
        "email": "owner@example.net",
        "subject": "Audit question",
        "message": "I would like to understand the audit report.",
    }
    payload = main.PublicContactRequest(**payload_data)
    request = _signed_contact_request(payload_data, secret)
    sent = []

    def capture(message):
        sent.append(message)

    monkeypatch.setattr(main, "_send_email_message", capture)
    result = await main.submit_public_contact(payload, request)

    assert result == {"status": "sent"}
    assert len(sent) == 1
    message = sent[0]
    assert message["To"] == "support@example.com"
    assert message["Reply-To"] == "owner@example.net"
    assert message["From"] == "Ecommerce Audit Agent <mailer@example.com>"
    assert message.get_content_type() == "multipart/alternative"
    assert "Ecommerce Audit Agent" in message.get_body(preferencelist=("html",)).get_content()


@pytest.mark.asyncio
async def test_public_contact_endpoint_rejects_invalid_signature(monkeypatch):
    monkeypatch.setenv("EAA_CONTACT_FORM_SECRET", "expected-secret")
    monkeypatch.setenv("EAA_CONTACT_TO_EMAIL", "support@example.com")
    payload_data = {
        "name": "Store Owner",
        "email": "owner@example.net",
        "subject": "Audit question",
        "message": "I would like to understand the audit report.",
    }
    payload = main.PublicContactRequest(**payload_data)
    request = _signed_contact_request(payload_data, "wrong-secret")

    with pytest.raises(HTTPException) as raised:
        await main.submit_public_contact(payload, request)

    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_public_contact_endpoint_requires_delivery_configuration(monkeypatch):
    monkeypatch.delenv("EAA_CONTACT_FORM_SECRET", raising=False)
    monkeypatch.delenv("EAA_CONTACT_TO_EMAIL", raising=False)
    payload = main.PublicContactRequest(
        name="Store Owner",
        email="owner@example.net",
        subject="Audit question",
        message="I would like to understand the audit report.",
    )
    request = _ContactRequest(b"{}", {})

    with pytest.raises(HTTPException) as raised:
        await main.submit_public_contact(payload, request)

    assert raised.value.status_code == 503
