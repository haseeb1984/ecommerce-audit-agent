"""Regression tests for the read-only production readiness CLI."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_production_readiness.py"


def test_missing_database_url_fails_with_actionable_message() -> None:
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 2
    assert "FAIL database_url: DATABASE_URL is not configured." in result.stdout
    assert "readiness_check" not in result.stderr
