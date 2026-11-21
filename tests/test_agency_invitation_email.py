def test_agency_invitation_email_uses_real_line_breaks(monkeypatch):
    import main

    sent_messages = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == "smtp.example.test"
            assert port == 587
            assert timeout == 15

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def ehlo(self):
            return None

        def starttls(self):
            return None

        def send_message(self, message):
            sent_messages.append(message)

    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_FROM", "noreply@example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_TLS_MODE", "starttls")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://app.example.test")
    monkeypatch.setattr(main.smtplib, "SMTP", FakeSMTP)

    main._send_agency_invitation_email(
        "teammate@example.test",
        "single-use-token",
        "owner@example.test",
        "analyst",
    )

    assert len(sent_messages) == 1
    body = sent_messages[0].get_content()
    assert "owner@example.test invited you to join their agency as analyst.\n\n" in body
    assert "Accept this invitation within 48 hours: https://app.example.test/app?agency_invitation=single-use-token\n\n" in body
    assert "\\n" not in body
