import fcntl
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from certmgmt import installer, scanner
from certmgmt.certificates import read_certificates
from certmgmt.errors import ConfigurationError, DeploymentError


@pytest.fixture
def installation(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text('{"certs": {}}')
    wheel = tmp_path / "certmgmt-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("certmgmt/runtime-requirements.txt", "fixture")
        archive.writestr("certmgmt-0.1.0.dist-info/METADATA", "Name: certmgmt")
    args = SimpleNamespace(
        config=str(config),
        wheel=str(wheel),
        prefix=str(tmp_path / "app"),
        hook_dir=str(tmp_path / "hooks"),
        python="fixture-python",
        dry_run=False,
    )
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "")

    monkeypatch.setattr(installer, "run_command", run)
    return args, calls


def test_fresh_repeat_and_rollback_preserve_unrelated_files(installation):
    args, calls = installation
    hooks = Path(args.hook_dir)
    hooks.mkdir()
    unrelated = hooks / "unrelated.sh"
    unrelated.write_text("unchanged")
    config_before = Path(args.config).read_bytes()
    assert installer.run(args) == 0
    root = Path(args.prefix)
    receipt = (root / "last-install.json").read_bytes()
    assert (root / "current").is_symlink()
    assert installer.MARKER in (hooks / "cert-dispatcher.sh").read_text()
    assert installer.run(args) == 0
    assert (root / "last-install.json").read_bytes() == receipt
    assert sum(argv[1:3] == ["-m", "venv"] for argv in calls) == 1
    assert installer.rollback(args) == 0
    assert not (root / "current").exists()
    assert not (root / "bin/certmgmt").exists()
    assert not (hooks / "cert-dispatcher.sh").exists()
    assert unrelated.read_text() == "unchanged"
    assert Path(args.config).read_bytes() == config_before


def test_upgrade_restores_old_hook_and_environment(installation):
    args, _ = installation
    root, hooks = Path(args.prefix), Path(args.hook_dir)
    root.mkdir()
    hooks.mkdir()
    previous = root / "old"
    previous.mkdir()
    (root / "current").symlink_to(previous)
    hook = hooks / "cert-dispatcher.sh"
    original = "# cert-dispatcher.sh -- Certbot deploy hook dispatcher\nold contents\n"
    hook.write_text(original)
    hook.chmod(0o700)
    installer.run(args)
    assert all(path.name == "cert-dispatcher.sh" for path in hooks.iterdir())
    installer.rollback(args)
    assert (root / "current").resolve() == previous
    assert hook.read_text() == original and hook.stat().st_mode & 0o777 == 0o700


def test_failed_build_preserves_current_and_hook(installation, monkeypatch):
    args, _ = installation
    root, hooks = Path(args.prefix), Path(args.hook_dir)
    root.mkdir()
    hooks.mkdir()
    previous = root / "old"
    previous.mkdir()
    (root / "current").symlink_to(previous)
    hook = hooks / "cert-dispatcher.sh"
    original = installer.MARKER + "\nold"
    hook.write_text(original)

    def fail(argv, **kwargs):
        if "install" in argv:
            raise DeploymentError("fixture pip failure")

    monkeypatch.setattr(installer, "run_command", fail)
    with pytest.raises(DeploymentError):
        installer.run(args)
    assert (root / "current").resolve() == previous
    assert hook.read_text() == original
    assert list((root / "versions").iterdir()) == []


def test_activation_failure_rolls_back(installation, monkeypatch):
    args, _ = installation
    original = installer.atomic_text

    def fail_receipt(path, *values):
        if Path(path).name == "last-install.json":
            raise OSError("fixture full disk")
        original(path, *values)

    monkeypatch.setattr(installer, "atomic_text", fail_receipt)
    with pytest.raises(OSError):
        installer.run(args)
    assert not (Path(args.prefix) / "current").exists()
    assert not (Path(args.prefix) / "bin/certmgmt").exists()
    assert not (Path(args.hook_dir) / "cert-dispatcher.sh").exists()


def test_dry_run_and_unowned_hook(installation):
    args, _ = installation
    args.dry_run = True
    assert installer.run(args) == 0
    assert not Path(args.prefix).exists() and not Path(args.hook_dir).exists()
    Path(args.hook_dir).mkdir()
    (Path(args.hook_dir) / "cert-dispatcher.sh").write_text("unrelated")
    args.dry_run = False
    with pytest.raises(ConfigurationError):
        installer.run(args)


def test_installer_serializes_mutations(installation):
    args, _ = installation
    Path(args.prefix).mkdir()
    with (Path(args.prefix) / ".install.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(DeploymentError, match="another CertMgmt"):
            installer.run(args)


def test_inventory_ipv6_and_tls_failure(tmp_path, pem_pairs, monkeypatch, capsys):
    calls = []

    def nmap(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            '<nmaprun><host><address addr="::1" addrtype="ipv6"/><ports><port portid="443"><state state="open"/></port><port portid="8443"><state state="open"/></port></ports></host></nmaprun>',
        )

    der = read_certificates(pem_pairs["rsa"][0])[0].public_bytes(Encoding.DER)

    def tls(host, port, **kwargs):
        if port == 8443:
            raise OSError("fixture refusal")
        return der

    monkeypatch.setattr(scanner, "run_command", nmap)
    monkeypatch.setattr(scanner, "served_certificate", tls)
    args = SimpleNamespace(
        subnets=["::1/128"],
        ports="443,8443",
        timeout=1,
        scan_timeout=30,
        config=None,
        output=str(tmp_path / "report.jsonl"),
    )
    assert scanner.run(args) == 1
    assert "-6" in calls[0]
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rows[0]["dns_names"] == ["device.example.test"]
    assert rows[1]["error"]
    assert len(Path(args.output).read_text().splitlines()) == 2


def test_inventory_nmap_failure(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "run_command",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, ""),
    )
    args = SimpleNamespace(
        subnets=["192.0.2.0/24"],
        ports="443",
        timeout=1,
        scan_timeout=30,
        config=None,
        output=None,
    )
    assert scanner.run(args) == 1
