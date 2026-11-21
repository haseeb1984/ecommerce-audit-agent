import hashlib
import json
from unittest.mock import patch

import pytest

import hostinger_storage as storage


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
