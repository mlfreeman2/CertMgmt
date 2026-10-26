import os
import subprocess
import sys
from pathlib import Path

import pytest

from certmgmt import compat
from certmgmt.registry import DRIVERS

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("driver", DRIVERS)
def test_help_needs_no_third_party_dependencies(driver):
    result = subprocess.run(
        [sys.executable, "-S", "-m", "certmgmt", "driver", driver, "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--no-verify" in result.stdout
    assert "--operation-timeout" in result.stdout
    assert "-h, --help" in result.stdout


@pytest.mark.parametrize("driver", DRIVERS)
def test_missing_arguments_exit_two(driver):
    result = subprocess.run(
        [sys.executable, "-m", "certmgmt", "driver", driver], capture_output=True
    )
    assert result.returncode == 2


@pytest.mark.parametrize(
    "launcher",
    sorted(ROOT.glob("drivers/driver-*"))
    + [ROOT / "cert-sync.sh", ROOT / "certbot-setup.sh"],
)
def test_legacy_executable_help(launcher):
    env = dict(
        os.environ,
        CERTMGMT_PYTHON=sys.executable,
        PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
    )
    result = subprocess.run(
        [str(launcher), "--help"], env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_parse_error_redacts_secret():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "certmgmt",
            "driver",
            "idrac",
            "-H",
            "host",
            "-u",
            "admin",
            "--password",
            "TOP_SECRET",
            "--bad",
            "TOP_SECRET",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "TOP_SECRET" not in result.stderr


def test_legacy_argument_translation(monkeypatch):
    calls = []
    monkeypatch.setattr(compat, "cli", lambda args: calls.append(args))
    compat.main("driver-idrac.sh", ["-h", "host", "-p", "secret"])
    compat.main("cert-sync.sh", ["-D", "-n", "-c", "custom.json"])
    compat.main("driver-shell-command.sh", ["-c", "true"])
    assert calls == [
        ["driver", "idrac", "--host", "host", "-p", "secret"],
        ["verify", "--config", "custom.json"],
        ["driver", "shell-command", "--command", "true"],
    ]
