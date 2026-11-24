import hashlib
import io
import json
from unittest.mock import patch

import pytest

import hostinger_storage as storage


def test_storage_config_requires_exact_https_bridge_endpoint(monkeypatch):
    monkeypatch.setenv(
        "HOSTINGER_STORAGE_BASE_URL",
        "https://storage.example.com/eaa-storage/api/index.php",
    )
    monkeypatch.setenv("HOSTINGER_STORAGE_HMAC_SECRET", "s" * 32)
    assert storage._storage_config()[0] == (
        "https://storage.example.com/eaa-storage/api/index.php"
    )

    for invalid_url in (
        "https://storage.example.com/",
        "https://storage.example.com/other/index.php",
        "https://:443/eaa-storage/api/index.php",
        "https://storage.example.com:70000/eaa-storage/api/index.php",
    ):
        monkeypatch.setenv("HOSTINGER_STORAGE_BASE_URL", invalid_url)
        with pytest.raises(storage.HostingerStorageError):
            storage._storage_config()


def test_storage_keys_are_opaque_and_allow_listed():
    storage._validate_key("reports/" + "a" * 64 + ".pdf")
    storage._validate_key("logos/" + "b" * 64 + ".png")
    for invalid in (
        "../reports/" + "a" * 64 + ".pdf",
        "reports/customer-123/report.pdf",
        "logos/" + "c" * 64 + ".svg",
        "reports/" + "A" * 64 + ".pdf",
    ):
        with pytest.raises(storage.HostingerStorageError):
            storage._validate_key(invalid)


def test_post_signature_canonicalization_is_stable():
    body = b"%PDF-test"
    canonical = storage._canonical_request(
        "1760000000", "a" * 48, "upload", "reports/" + "b" * 64 + ".pdf",
        "application/pdf", body,
    )
    expected = "\n".join((
        "POST", "1760000000", "a" * 48, "upload",
        "reports/" + "b" * 64 + ".pdf", "application/pdf",
        hashlib.sha256(body).hexdigest(),
    )).encode("utf-8")
    assert canonical == expected


def test_upload_report_requires_pdf_signature_and_verifies_receipt():
    payload = b"%PDF-1.7 test"
    digest = hashlib.sha256(payload).hexdigest()

    def fake_request(operation, key, body, mime_type):
        assert operation == "upload"
        assert body == payload
        assert mime_type == "application/pdf"
        return json.dumps({
            "storage_key": key,
            "sha256": digest,
            "byte_size": len(payload),
        }).encode("utf-8")

    with patch.object(storage, "_request", side_effect=fake_request):
        receipt = storage.upload_report(payload)

    assert receipt.storage_key.startswith("reports/")
    assert receipt.storage_key.endswith(".pdf")
    assert receipt.sha256 == digest
    assert receipt.byte_size == len(payload)


def test_upload_report_rejects_non_pdf():
    with pytest.raises(storage.HostingerStorageError):
        storage.upload_report(b"not a pdf")


def test_download_checks_sha256():
    payload = b"%PDF-1.7 test"
    digest = hashlib.sha256(payload).hexdigest()
    with patch.object(storage, "_request", return_value=payload):
        assert storage.download_file("reports/" + "d" * 64 + ".pdf", digest) == payload
    with patch.object(storage, "_request", return_value=b"tampered"):
        with pytest.raises(storage.HostingerStorageError):
            storage.download_file("reports/" + "d" * 64 + ".pdf", digest)



def test_storage_http_client_refuses_redirects():
    from urllib.request import Request

    handler = storage._NoRedirectHandler()
    request = Request("https://storage.example/eaa-storage/api/index.php")
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "https://attacker.example/collect"
    ) is None


def test_storage_http_response_reads_are_bounded():
    response = io.BytesIO(b"x" * 1025)
    response.headers = {}
    with pytest.raises(storage.HostingerStorageError, match="exceeds the allowed size"):
        storage._read_limited_response(response, 1024)


def test_storage_http_response_rejects_oversized_content_length_before_read():
    response = io.BytesIO(b"")
    response.headers = {"Content-Length": "2048"}
    with pytest.raises(storage.HostingerStorageError, match="exceeds the allowed size"):
        storage._read_limited_response(response, 1024)



def test_invalid_upload_receipt_triggers_private_object_cleanup():
    operations = []

    def fake_request(operation, storage_key, body=b"", mime_type="application/octet-stream"):
        operations.append(operation)
        if operation == "upload":
            return b"{}"
        return b'{"deleted":true}'

    with patch.object(storage, "_request", side_effect=fake_request):
        with pytest.raises(storage.HostingerStorageError, match="invalid upload receipt"):
            storage.upload_report(b"%PDF-1.7 test")

    assert operations == ["upload", "delete"]


def test_ambiguous_upload_failure_attempts_idempotent_cleanup():
    operations = []

    def fake_request(operation, storage_key, body=b"", mime_type="application/octet-stream"):
        operations.append(operation)
        if operation == "upload":
            raise storage.HostingerStorageError("simulated network timeout")
        return b'{"deleted":true}'

    with patch.object(storage, "_request", side_effect=fake_request):
        with pytest.raises(storage.HostingerStorageError, match="simulated network timeout"):
            storage.upload_report(b"%PDF-1.7 test")

    assert operations == ["upload", "delete"]


@pytest.mark.asyncio
async def test_migration_cleanup_preserves_objects_referenced_after_ambiguous_commit(monkeypatch):
    from contextlib import asynccontextmanager
    from scripts import migrate_report_pdfs_to_hostinger as migration

    referenced = "reports/" + "a" * 64 + ".pdf"
    orphaned = "reports/" + "b" * 64 + ".pdf"
    deleted = []

    class Result:
        def scalars(self):
            return self

        def all(self):
            return [referenced]

    class VerificationSession:
        async def execute(self, statement):
            return Result()

    @asynccontextmanager
    async def session_factory():
        yield VerificationSession()

    monkeypatch.setattr(migration, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(migration, "delete_file", lambda key: deleted.append(key))
    await migration._cleanup_unreferenced_uploads([referenced, orphaned])

    assert deleted == [orphaned]


@pytest.mark.asyncio
async def test_migration_cleanup_preserves_all_objects_when_reference_check_fails(monkeypatch):
    from contextlib import asynccontextmanager
    from scripts import migrate_report_pdfs_to_hostinger as migration

    keys = ["reports/" + "c" * 64 + ".pdf"]
    deleted = []

    @asynccontextmanager
    async def session_factory():
        raise RuntimeError("database unavailable")
        yield  # pragma: no cover

    monkeypatch.setattr(migration, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(migration, "delete_file", lambda key: deleted.append(key))
    await migration._cleanup_unreferenced_uploads(keys)

    assert deleted == []

@pytest.mark.asyncio
async def test_pdf_migration_uses_owner_managed_hostinger_retention_over_environment(monkeypatch):
    from contextlib import asynccontextmanager
    from scripts import migrate_report_pdfs_to_hostinger as migration

    class Result:
        def scalar_one_or_none(self):
            return "30"

    class OperationalSession:
        async def execute(self, statement):
            return Result()

    @asynccontextmanager
    async def session_factory():
        yield OperationalSession()

    monkeypatch.setattr(migration, "HostingerAsyncSessionLocal", session_factory)
    monkeypatch.setenv("REPORT_RETENTION_DAYS", "7")

    assert await migration._effective_retention_days() == 30


@pytest.mark.asyncio
async def test_pdf_migration_uses_environment_default_only_when_no_owner_setting(monkeypatch):
    from contextlib import asynccontextmanager
    from scripts import migrate_report_pdfs_to_hostinger as migration

    class Result:
        def scalar_one_or_none(self):
            return None

    class OperationalSession:
        async def execute(self, statement):
            return Result()

    @asynccontextmanager
    async def session_factory():
        yield OperationalSession()

    monkeypatch.setattr(migration, "HostingerAsyncSessionLocal", session_factory)
    monkeypatch.setenv("REPORT_RETENTION_DAYS", "14")

    assert await migration._effective_retention_days() == 14


@pytest.mark.asyncio
async def test_pdf_migration_requires_hostinger_database_for_authoritative_retention(monkeypatch):
    from scripts import migrate_report_pdfs_to_hostinger as migration

    monkeypatch.setattr(migration, "HostingerAsyncSessionLocal", None)

    with pytest.raises(RuntimeError, match="HOSTINGER_DATABASE_URL"):
        await migration._effective_retention_days()


@pytest.mark.asyncio
async def test_pdf_migration_rejects_invalid_owner_managed_retention(monkeypatch):
    from contextlib import asynccontextmanager
    from scripts import migrate_report_pdfs_to_hostinger as migration

    class Result:
        def scalar_one_or_none(self):
            return "0"

    class OperationalSession:
        async def execute(self, statement):
            return Result()

    @asynccontextmanager
    async def session_factory():
        yield OperationalSession()

    monkeypatch.setattr(migration, "HostingerAsyncSessionLocal", session_factory)

    with pytest.raises(RuntimeError, match="between 1 and 3650"):
        await migration._effective_retention_days()
