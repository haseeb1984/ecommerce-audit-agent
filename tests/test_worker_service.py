"""Configuration contract for the managed durable scan worker."""

import pytest

from worker_service import _bounded_int


def test_worker_configuration_uses_safe_defaults(monkeypatch):
    monkeypatch.delenv("SCAN_WORKER_MAX_JOBS", raising=False)
    monkeypatch.delenv("SCAN_WORKER_POLL_SECONDS", raising=False)

    assert _bounded_int("SCAN_WORKER_MAX_JOBS", 1, 1, 10) == 1
    assert _bounded_int("SCAN_WORKER_POLL_SECONDS", 5, 1, 300) == 5


@pytest.mark.parametrize(
    ("name", "raw", "minimum", "maximum"),
    [
        ("SCAN_WORKER_MAX_JOBS", "10", 1, 10),
        ("SCAN_WORKER_POLL_SECONDS", "300", 1, 300),
    ],
)
def test_worker_configuration_accepts_upper_bounds(monkeypatch, name, raw, minimum, maximum):
    monkeypatch.setenv(name, raw)
    assert _bounded_int(name, minimum, minimum, maximum) == maximum


@pytest.mark.parametrize(
    ("name", "raw", "minimum", "maximum"),
    [
        ("SCAN_WORKER_MAX_JOBS", "0", 1, 10),
        ("SCAN_WORKER_MAX_JOBS", "11", 1, 10),
        ("SCAN_WORKER_POLL_SECONDS", "0", 1, 300),
        ("SCAN_WORKER_POLL_SECONDS", "301", 1, 300),
        ("SCAN_WORKER_POLL_SECONDS", "fast", 1, 300),
    ],
)
def test_worker_configuration_rejects_invalid_values(monkeypatch, name, raw, minimum, maximum):
    monkeypatch.setenv(name, raw)
    with pytest.raises(RuntimeError):
        _bounded_int(name, 5, minimum, maximum)
