"""Centralized platform SMTP transport.

All platform email workflows construct their own message content, then hand
an EmailMessage to this module for configuration, TLS, authentication and send.
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Mapping


SMTP_TIMEOUT_SECONDS = 15


def _smtp_environment(environ: Mapping[str, str] | None = None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def smtp_configuration_status(environ: Mapping[str, str] | None = None) -> dict:
    """Describe SMTP readiness without returning configured values or secrets."""
    env = _smtp_environment(environ)
    issues: list[str] = []
    if not env.get("SMTP_HOST", "").strip():
        issues.append("SMTP_HOST missing")
    if not env.get("SMTP_FROM", "").strip():
        issues.append("SMTP_FROM missing")
    try:
        port = int(env.get("SMTP_PORT", "587").strip())
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        issues.append("SMTP_PORT must be an integer from 1 to 65535")
    mode = env.get("SMTP_TLS_MODE", "starttls").strip().lower()
    if mode not in {"starttls", "ssl"}:
        issues.append("SMTP_TLS_MODE must be starttls or ssl")
    username = env.get("SMTP_USERNAME", "").strip()
    password = env.get("SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        issues.append("SMTP_USERNAME and SMTP_PASSWORD must both be set or both be empty")
    return {"configured": not issues, "issues": issues}


def configured_smtp_port(environ: Mapping[str, str] | None = None) -> int:
    """Validate the single platform SMTP port setting."""
    raw_port = _smtp_environment(environ).get("SMTP_PORT", "587").strip()
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("SMTP port configuration is invalid") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP port configuration is invalid")
    return port


def send_email(message: EmailMessage) -> None:
    """Send one prepared message using the platform's sole SMTP configuration."""
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured")

    port = configured_smtp_port()
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    mode = os.getenv("SMTP_TLS_MODE", "starttls").strip().lower()
    if mode not in {"starttls", "ssl"}:
        raise RuntimeError("Unsupported SMTP TLS mode")
    if not message.get("From"):
        message["From"] = sender

    if mode == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
        return

    with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        if username:
            server.login(username, password)
        server.send_message(message)
