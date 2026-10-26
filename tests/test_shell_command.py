"""Exercise real child processes, cancellation and the public driver CLI offline."""

import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from certmgmt.errors import ConfigurationError, DeploymentError
from certmgmt.registry import deploy, prepare


def invoke(command, *args):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "certmgmt",
            "driver",
            "shell-command",
            "--command",
            command,
            *map(str, args),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_stream_paths_with_spaces_and_chdir(tmp_path, pem_pairs):
    marker = tmp_path / "stream"
    cert, key = pem_pairs["rsa"]
    result = invoke(
        'pwd; cat "$KEY_FILE" "$CERT_FILE" > ' + shlex.quote(str(marker)),
        "--cert-file",
        cert,
        "--key-file",
        key,
        "--chdir",
        tmp_path,
        "--no-verify",
    )
    assert result.returncode == 0, result.stderr
    assert str(tmp_path) in result.stderr
    assert marker.read_bytes() == Path(key).read_bytes() + Path(cert).read_bytes()


@pytest.mark.parametrize("command", ['read -r value; test -z "$value"', "true"])
def test_closed_stdin_and_zero_command_timeout(command):
    result = invoke(command, "--timeout", "0", "--no-verify")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("command", ["false | cat", "exit 7"])
def test_command_failure(command):
    result = invoke(command, "--no-verify")
    assert result.returncode == 1
    assert "command failed" in result.stderr


@pytest.mark.parametrize(
    "args", [("--timeout", "1"), ("--timeout", "0", "--operation-timeout", "1")]
)
def test_timeout_stops_descendants(tmp_path, args):
    marker = tmp_path / "late"
    result = invoke(
        "(sleep 2; touch " + shlex.quote(str(marker)) + ") & wait", "--no-verify", *args
    )
    assert result.returncode == 1
    time.sleep(1.5)
    assert not marker.exists()


@pytest.mark.parametrize(
    "values",
    [
        {"timeout": -1},
        {"timeout": True},
        {"operation_timeout": 0},
        {"verify_port": 0},
        {"chdir": "/nonexistent-certmgmt-test"},
        {"command": ""},
    ],
)
def test_invalid_options_before_delivery(values):
    with pytest.raises(ConfigurationError):
        prepare("shell-command", {"command": "true", "no_verify": True} | values)


def test_missing_verification_before_delivery(tmp_path):
    marker = tmp_path / "marker"
    result = invoke("touch " + shlex.quote(str(marker)))
    assert result.returncode == 2
    assert not marker.exists()


def test_certificate_mismatch_before_delivery(tmp_path, pem_pairs):
    marker = tmp_path / "marker"
    result = invoke(
        "touch " + shlex.quote(str(marker)),
        "--cert-file",
        pem_pairs["rsa"][0],
        "--key-file",
        pem_pairs["ec"][1],
        "--no-verify",
    )
    assert result.returncode == 2
    assert not marker.exists()


def test_failed_post_delivery_verification(tmp_path, pem_pairs, monkeypatch):
    marker = tmp_path / "marker"
    request = prepare(
        "shell-command",
        {
            "command": "touch " + shlex.quote(str(marker)),
            "verify_host": "example.test",
            "verify_cert_file": pem_pairs["rsa"][0],
        },
    )

    def fail(*args, **kwargs):
        raise DeploymentError("mismatch")

    monkeypatch.setattr("certmgmt.registry.verify", fail)
    with pytest.raises(DeploymentError):
        deploy(request)
    assert marker.exists()


def test_private_key_and_command_not_logged(pem_pairs):
    cert, key = pem_pairs["rsa"]
    result = invoke(
        'cat "$KEY_FILE"',
        "--cert-file",
        cert,
        "--key-file",
        key,
        "--no-verify",
        "--debug",
    )
    assert result.returncode == 0
    assert "PRIVATE KEY-----" not in result.stderr
    assert 'cat "$KEY_FILE"' not in result.stderr
    assert "<private key redacted>" in result.stderr


def test_quiet():
    result = invoke("echo output", "--no-verify", "--quiet")
    assert result.returncode == 0
    assert not result.stdout and not result.stderr


def test_docker_services_and_working_directory(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "certmgmt.drivers.dispatch.run_command",
        lambda argv, **kwargs: calls.append((argv, kwargs)),
    )
    deploy(
        prepare(
            "docker-compose",
            {
                "compose_dir": str(tmp_path),
                "service": ["caddy", "other"],
                "no_verify": True,
            },
        )
    )
    assert calls[0][0] == [
        "docker",
        "compose",
        "up",
        "-d",
        "--force-recreate",
        "--",
        "caddy",
        "other",
    ]
    assert calls[0][1]["cwd"] == str(tmp_path)


def test_failure_output_redacts_full_key_before_truncating(tmp_path):
    key = tmp_path / "key"
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        + "SENSITIVEKEYDATA" * 200
        + "\n-----END PRIVATE KEY-----\n"
    )
    result = invoke("cat " + shlex.quote(str(key)) + "; exit 1", "--no-verify")
    assert result.returncode == 1
    assert "SENSITIVEKEYDATA" not in result.stderr
    assert "<private key redacted>" in result.stderr


@pytest.mark.parametrize("signum", [2, 15])
def test_signal_stops_child_group(tmp_path, signum):
    started, late = tmp_path / "started", tmp_path / "late"
    command = (
        "touch "
        + shlex.quote(str(started))
        + "; (sleep 2; touch "
        + shlex.quote(str(late))
        + ") & wait"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "certmgmt",
            "driver",
            "shell-command",
            "--command",
            command,
            "--no-verify",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        limit = time.monotonic() + 5
        while not started.exists() and time.monotonic() < limit:
            time.sleep(0.02)
        assert started.exists()
        process.send_signal(signum)
        process.communicate(timeout=6)
        assert process.returncode == 128 + signum
        time.sleep(2.1)
        assert not late.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
