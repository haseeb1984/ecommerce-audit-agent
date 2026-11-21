"""Authenticated client for the Hostinger Shared Hosting PHP storage bridge.

The bridge URL and HMAC secret are deployment configuration. Storage keys are
opaque random identifiers and are sent in signed headers, never URL paths.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


_REPORT_KEY_RE = re.compile(r"^reports/[a-f0-9]{64}\.pdf$")
_LOGO_KEY_RE = re.compile(r"^logos/[a-f0-9]{64}\.(?:png|jpg|webp)$")
_ALLOWED_UPLOADS = {
    "report": ("application/pdf", ".pdf", 25 * 1024 * 1024),
    "logo_png": ("image/png", ".png", 5 * 1024 * 1024),
    "logo_jpeg": ("image/jpeg", ".jpg", 5 * 1024 * 1024),
    "logo_webp": ("image/webp", ".webp", 5 * 1024 * 1024),
}


class HostingerStorageError(RuntimeError):
    """Storage bridge request failed or returned an invalid response."""


@dataclass(frozen=True)
class StorageReceipt:
    storage_key: str
    sha256: str
    byte_size: int
    mime_type: str


def _storage_config() -> tuple[str, bytes]:
    base_url = os.getenv("HOSTINGER_STORAGE_BASE_URL", "").strip().rstrip("/")
    secret = os.getenv("HOSTINGER_STORAGE_HMAC_SECRET", "")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise HostingerStorageError("HOSTINGER_STORAGE_BASE_URL must be an HTTPS URL.")
    if parsed.query or parsed.fragment:
        raise HostingerStorageError("HOSTINGER_STORAGE_BASE_URL cannot contain a query or fragment.")
    if len(secret.encode("utf-8")) < 32:
        raise HostingerStorageError("HOSTINGER_STORAGE_HMAC_SECRET must contain at least 32 bytes.")
    return base_url, secret.encode("utf-8")


def _validate_key(storage_key: str) -> None:
    if not (_REPORT_KEY_RE.fullmatch(storage_key) or _LOGO_KEY_RE.fullmatch(storage_key)):
        raise HostingerStorageError("Invalid storage key.")


def _canonical_request(timestamp: str, nonce: str, operation: str,
                       storage_key: str, mime_type: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join((
        "POST", timestamp, nonce, operation, storage_key, mime_type, body_hash
    )).encode("utf-8")


def _request(operation: str, storage_key: str, body: bytes = b"",
             mime_type: str = "application/octet-stream") -> bytes:
    base_url, secret = _storage_config()
    _validate_key(storage_key)
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(24)
    signature = hmac.new(
        secret,
        _canonical_request(timestamp, nonce, operation, storage_key, mime_type, body),
        hashlib.sha256,
    ).hexdigest()
    request = Request(
        base_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": mime_type,
            "Accept": "application/json, application/octet-stream",
            "X-EAA-Timestamp": timestamp,
            "X-EAA-Nonce": nonce,
            "X-EAA-Operation": operation,
            "X-EAA-Storage-Key": storage_key,
            "X-EAA-Mime": mime_type,
            "X-EAA-Signature": signature,
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return response.read()
    except HTTPError as exc:
        # Do not include response URLs, headers, or request credentials in logs.
        detail = "storage bridge rejected the request"
        try:
            payload = json.loads(exc.read(4096).decode("utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                detail = payload["error"][:160]
        except Exception:
            pass
        raise HostingerStorageError(f"Hostinger storage {operation} failed: {detail}") from None
    except (URLError, TimeoutError, OSError):
        raise HostingerStorageError(f"Hostinger storage {operation} is unavailable.") from None


def upload_report(pdf_bytes: bytes) -> StorageReceipt:
    return _upload("report", pdf_bytes)


def upload_logo(image_bytes: bytes, mime_type: str) -> StorageReceipt:
    kind_by_mime = {
        "image/png": "logo_png",
        "image/jpeg": "logo_jpeg",
        "image/webp": "logo_webp",
    }
    kind = kind_by_mime.get(mime_type)
    if not kind:
        raise HostingerStorageError("Logo must be PNG, JPEG, or WebP.")
    return _upload(kind, image_bytes)


def _upload(kind: str, content: bytes) -> StorageReceipt:
    config = _ALLOWED_UPLOADS.get(kind)
    if config is None:
        raise HostingerStorageError("Unsupported upload type.")
    mime_type, extension, max_size = config
    if not isinstance(content, bytes) or not content or len(content) > max_size:
        raise HostingerStorageError("Upload is empty or exceeds the allowed size.")
    if kind == "report" and not content.startswith(b"%PDF-"):
        raise HostingerStorageError("Report payload is not a PDF.")
    if kind == "logo_png" and not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise HostingerStorageError("Logo payload is not a valid PNG.")
    if kind == "logo_jpeg" and not content.startswith(b"\xff\xd8\xff"):
        raise HostingerStorageError("Logo payload is not a valid JPEG.")
    if kind == "logo_webp" and not (content.startswith(b"RIFF") and content[8:12] == b"WEBP"):
        raise HostingerStorageError("Logo payload is not a valid WebP image.")
    folder = "reports" if kind == "report" else "logos"
    storage_key = f"{folder}/{secrets.token_hex(32)}{extension}"
    response = _request("upload", storage_key, content, mime_type)
    try:
        payload = json.loads(response.decode("utf-8"))
        expected_hash = hashlib.sha256(content).hexdigest()
        if (payload.get("storage_key") != storage_key
                or payload.get("sha256") != expected_hash
                or int(payload.get("byte_size", -1)) != len(content)):
            raise ValueError("receipt mismatch")
    except Exception:
        # A successful HTTP response without an exact integrity receipt is not success.
        raise HostingerStorageError("Hostinger storage returned an invalid upload receipt.") from None
    return StorageReceipt(storage_key, expected_hash, len(content), mime_type)


def download_file(storage_key: str, expected_sha256: str | None = None) -> bytes:
    content = _request("download", storage_key)
    if expected_sha256:
        actual = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual, expected_sha256):
            raise HostingerStorageError("Stored file integrity check failed.")
    return content


def delete_file(storage_key: str) -> None:
    response = _request("delete", storage_key)
    try:
        payload = json.loads(response.decode("utf-8"))
        if payload.get("deleted") is not True:
            raise ValueError("delete not confirmed")
    except Exception:
        raise HostingerStorageError("Hostinger storage did not confirm file deletion.") from None
