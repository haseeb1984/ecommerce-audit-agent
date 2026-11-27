from email.message import EmailMessage

import pytest

import email_service


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.sent = []
        self.logged_in = None
        self.started_tls = False
        self.ehlo_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self):
        self.ehlo_calls += 1

    def starttls(self):
        self.started_tls = True

    def login(self, username, password):
        self.logged_in = (username, password)

    def send_message(self, message):
        self.sent.append(message)


def configure(monkeypatch, mode="starttls"):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer")
    monkeypatch.setenv("SMTP_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("SMTP_FROM", "noreply@example.test")
    monkeypatch.setenv("SMTP_TLS_MODE", mode)


def test_smtp_configuration_status_does_not_expose_secrets():
    env = {
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": "587",
        "SMTP_USERNAME": "mailer",
        "SMTP_PASSWORD": "hidden",
        "SMTP_FROM": "noreply@example.test",
        "SMTP_TLS_MODE": "starttls",
    }
    status = email_service.smtp_configuration_status(env)
    assert status == {"configured": True, "issues": []}
    assert "hidden" not in repr(status)


def test_smtp_configuration_status_reports_invalid_auth_pair():
    status = email_service.smtp_configuration_status({
        "SMTP_HOST": "smtp.example.test",
        "SMTP_FROM": "noreply@example.test",
        "SMTP_USERNAME": "mailer",
        "SMTP_TLS_MODE": "starttls",
    })
    assert status["configured"] is False
    assert "SMTP_USERNAME and SMTP_PASSWORD must both be set or both be empty" in status["issues"]


def test_send_email_uses_one_shared_starttls_transport(monkeypatch):
    configure(monkeypatch)
    fake = FakeSMTP()
    monkeypatch.setattr(email_service.smtplib, "SMTP", lambda *a, **kw: fake)
    message = EmailMessage()
    message["To"] = "customer@example.test"
    message["Subject"] = "Test"
    message.set_content("Hello")

    email_service.send_email(message)

    assert fake.started_tls is True
    assert fake.ehlo_calls == 2
    assert fake.logged_in == ("mailer", "not-a-real-secret")
    assert fake.sent == [message]
    assert message["From"] == "noreply@example.test"


def test_send_email_uses_shared_ssl_transport(monkeypatch):
    configure(monkeypatch, mode="ssl")
    fake = FakeSMTP()
    monkeypatch.setattr(email_service.smtplib, "SMTP_SSL", lambda *a, **kw: fake)
    message = EmailMessage()
    message["To"] = "customer@example.test"
    message["Subject"] = "Test"
    message.set_content("Hello")

    email_service.send_email(message)

    assert fake.started_tls is False
    assert fake.logged_in == ("mailer", "not-a-real-secret")
    assert fake.sent == [message]


def test_send_email_rejects_missing_configuration(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_FROM", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        email_service.send_email(EmailMessage())
