"""Exercise the operational migration CLI's preflight ordering without databases."""

import sys

import pytest

from scripts import migrate_operational_data_to_hostinger as migration


def test_apply_aborts_before_writes_when_read_only_preflight_has_blockers(monkeypatch):
    calls = []

    async def fake_migrate(apply_changes=False, verify_only=False):
        calls.append((apply_changes, verify_only))
        return False

    monkeypatch.setattr(migration, "migrate", fake_migrate)
    monkeypatch.setattr(sys, "argv", ["migrate_operational_data_to_hostinger.py", "--apply"])

    with pytest.raises(SystemExit) as exc:
        migration.main()

    assert exc.value.code == 1
    assert calls == [(False, False)]


def test_apply_runs_write_pass_only_after_successful_read_only_preflight(monkeypatch):
    calls = []

    async def fake_migrate(apply_changes=False, verify_only=False):
        calls.append((apply_changes, verify_only))
        return True

    monkeypatch.setattr(migration, "migrate", fake_migrate)
    monkeypatch.setattr(sys, "argv", ["migrate_operational_data_to_hostinger.py", "--apply"])

    migration.main()

    assert calls == [(False, False), (True, False)]


@pytest.mark.parametrize(
    ("argv", "expected_verify_only"),
    [
        (["migrate_operational_data_to_hostinger.py"], False),
        (["migrate_operational_data_to_hostinger.py", "--verify"], True),
    ],
)
def test_dry_run_and_verify_each_execute_one_read_only_pass(
    monkeypatch, argv, expected_verify_only
):
    calls = []

    async def fake_migrate(apply_changes=False, verify_only=False):
        calls.append((apply_changes, verify_only))
        return True

    monkeypatch.setattr(migration, "migrate", fake_migrate)
    monkeypatch.setattr(sys, "argv", argv)

    migration.main()

    assert calls == [(False, expected_verify_only)]
