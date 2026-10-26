import json
import shutil
from pathlib import Path

import pytest

from certmgmt import cli, config, orchestration, reconcile
from certmgmt.errors import ConfigurationError, DeploymentError


@pytest.fixture
def site(tmp_path, pem_pairs):
    lineage = tmp_path / "live" / "test-lineage"
    lineage.mkdir(parents=True)
    for name, source in [
        ("cert.pem", pem_pairs["rsa"][0]),
        ("fullchain.pem", pem_pairs["chain"][0]),
        ("privkey.pem", pem_pairs["rsa"][1]),
    ]:
        shutil.copyfile(source, lineage / name)
    data = {
        "certbot_config_dir": str(tmp_path),
        "certs": {
            "test-lineage": {
                "domains": ["device.example.test"],
                "key_type": "rsa",
                "key_size": 2048,
                "healthchecks_url": "https://hc.example.test/private",
                "targets": [],
            }
        },
    }
    path = tmp_path / "config.json"

    def write(*targets):
        data["certs"]["test-lineage"]["targets"] = list(targets)
        path.write_text(json.dumps(data))
        return str(path)

    return data, write, lineage


def target(name="one", **changes):
    return {
        "name": name,
        "driver": "shell-command",
        "command": "true",
        "verify_host": "device.example.test",
    } | changes


def test_failure_continues_and_healthcheck_fails(site, monkeypatch):
    _, write, _ = site
    calls, pings = [], []
    monkeypatch.setattr(orchestration, "already_current", lambda request: False)

    def deliver(request):
        calls.append(request.options.command)
        if request.options.command == "false":
            raise DeploymentError("fixture failure")

    monkeypatch.setattr(orchestration, "deploy", deliver)
    monkeypatch.setattr(orchestration, "ping", lambda *args: pings.append(args))
    assert (
        cli.main(["deploy", "--config", write(target(command="false"), target("two"))])
        == 1
    )
    assert calls == ["false", "true"]
    assert [call[1] for call in pings] == ["/start", "/fail"]
    assert "one" in pings[-1][2]


def test_current_skip_force_and_bootstrap(site, monkeypatch):
    _, write, _ = site
    calls = []
    monkeypatch.setattr(
        orchestration, "already_current", lambda request: bool(request.endpoints)
    )
    monkeypatch.setattr(orchestration, "deploy", lambda request: calls.append(request))
    monkeypatch.setattr(orchestration, "ping", lambda *args: None)
    path = write(target())
    assert cli.main(["deploy", "--config", path]) == 0 and not calls
    assert cli.main(["deploy", "--config", path, "--force"]) == 0 and len(calls) == 1
    assert cli.main(["deploy", "--config", write(target(verify=False))]) == 0
    assert not calls[-1].endpoints


@pytest.mark.parametrize(
    "changes",
    [
        {"command": ""},
        {"verify_host": None},
        {"timeout": True},
        {"cert_file": "../other.pem"},
        {"verify": "false"},
    ],
)
def test_whole_batch_validated_before_side_effects(site, monkeypatch, changes):
    _, write, _ = site
    calls = []
    for name in ("already_current", "deploy", "ping"):
        monkeypatch.setattr(orchestration, name, lambda *args: calls.append(args))
    assert (
        cli.main(["deploy", "--config", write(target(), target("bad", **changes))]) == 2
    )
    assert not calls


def test_verify_does_not_need_credentials_or_private_key(site, monkeypatch):
    _, write, lineage = site
    (lineage / "privkey.pem").unlink()
    checks = []
    monkeypatch.setattr(
        orchestration, "verify", lambda *args, **kwargs: checks.append(args)
    )

    def forbidden(*args):
        pytest.fail("verification attempted deployment or healthcheck")

    monkeypatch.setattr(orchestration, "deploy", forbidden)
    monkeypatch.setattr(
        orchestration, "ping", lambda url, *args: forbidden() if url else None
    )
    assert (
        cli.main(
            [
                "verify",
                "--config",
                write(
                    {"name": "device", "driver": "idrac", "host": "device.example.test"}
                ),
            ]
        )
        == 0
    )
    assert len(checks) == 1
    assert cli.main(["verify", "--config", write(target(verify=False))]) == 0
    assert len(checks) == 1


def test_dry_run_and_empty_targets_do_not_ping(site, monkeypatch):
    _, write, _ = site

    def forbidden(*args):
        pytest.fail("dry run or empty target group caused side effects")

    for name in ("already_current", "deploy", "ping"):
        monkeypatch.setattr(orchestration, name, forbidden)
    assert cli.main(["deploy", "--config", write(target()), "--dry-run"]) == 0
    assert cli.main(["deploy", "--config", write()]) == 0


def test_hook_uses_custom_config_and_lineage_result(site, tmp_path, monkeypatch):
    _, write, lineage = site
    result = tmp_path / "result.json"
    monkeypatch.setenv("CERTMGMT_CONFIG_OVERRIDE", write())
    monkeypatch.setenv("RENEWED_LINEAGE", str(lineage))
    monkeypatch.setenv("CERTMGMT_HOOK_RESULT", str(result))
    assert cli.main(["hook", "--config", "/does/not/exist"]) == 0
    assert json.loads(result.read_text()) == {
        "cert_name": "test-lineage",
        "exit_code": 0,
    }


def test_config_rejects_unknown_and_unmatched_selection(site):
    data, write, _ = site
    loaded = config.load(write(target()))
    with pytest.raises(ConfigurationError):
        config.selected(loaded, targets=["missing"])
    data["unexpected"] = True
    with pytest.raises(ConfigurationError):
        config.load(write())


def test_reconcile_no_destructive_plan(site):
    data, write, lineage = site
    path = write()
    assert reconcile.plan(config.load(path))[0][2] == []
    data["certs"]["test-lineage"]["domains"].append("new.example.test")
    assert reconcile.plan(config.load(write()))[0][2] == ["domains differ"]
    (lineage / "cert.pem").unlink()
    assert reconcile.plan(config.load(write()))[0][2] == ["certificate missing"]


@pytest.mark.parametrize(
    "certbot_exit,hook_exit,expected", [(0, 0, 0), (0, 1, 1), (0, None, 1), (1, 0, 1)]
)
def test_sync_requires_both_issuance_and_deployment_success(
    site, monkeypatch, certbot_exit, hook_exit, expected
):
    from subprocess import CompletedProcess

    data, write, lineage = site
    data["certs"]["test-lineage"]["domains"].append("new.example.test")
    hook = lineage.parents[1] / "renewal-hooks/deploy/cert-dispatcher.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text("# Managed by CertMgmt Python")
    (lineage.parents[1] / "cloudflare.ini").write_text("fixture")
    path = write()

    def certbot(argv, **kwargs):
        assert argv[1] == "certonly"
        assert "revoke" not in argv and "delete" not in argv
        assert argv[argv.index("--deploy-hook") + 1] == str(hook)
        assert kwargs["env"]["CERTMGMT_CONFIG_OVERRIDE"] == path
        if hook_exit is not None:
            Path(kwargs["env"]["CERTMGMT_HOOK_RESULT"]).write_text(
                json.dumps({"cert_name": "test-lineage", "exit_code": hook_exit})
            )
        return CompletedProcess(argv, certbot_exit, "")

    monkeypatch.setattr(reconcile, "run_command", certbot)
    assert cli.main(["sync", "--config", path, "--yes"]) == expected


def test_verify_rejects_string_opt_out(site):
    _, write, _ = site
    assert cli.main(["verify", "--config", write(target(no_verify="false"))]) == 2


def test_multiple_verification_ports_and_separate_sni(site, monkeypatch):
    _, write, _ = site
    endpoints = []
    monkeypatch.setattr(
        orchestration, "verify", lambda endpoint, **kwargs: endpoints.append(endpoint)
    )
    path = write(
        {
            "name": "pve",
            "driver": "proxmox",
            "host": "192.0.2.50",
            "verify_ports": [8006, 443],
            "verify_server_name": "pve.example.test",
        }
    )
    assert cli.main(["verify", "--config", path]) == 0
    assert [
        (endpoint.host, endpoint.port, endpoint.server_name) for endpoint in endpoints
    ] == [
        ("192.0.2.50", 8006, "pve.example.test"),
        ("192.0.2.50", 443, "pve.example.test"),
    ]
