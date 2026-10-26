"""Offline process tests. No root, network access, or installed CertMgmt files needed.

Copies of the orchestration scripts redirect /etc/letsencrypt into a temporary
fixture. Only the copied cert-sync root guard is bypassed. SSH/verification and
healthchecks are local stand-ins; the real driver and dispatcher logic execute.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class ShellCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="certmgmt-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.drivers = self.root / "drivers"
        self.drivers.mkdir()
        self.driver = self.drivers / "driver-shell-command.sh"
        shutil.copy2(REPO / "drivers" / self.driver.name, self.driver)
        self.lineage = self.root / "live" / "test-lineage"
        self.lineage.mkdir(parents=True)
        for name, content in [
            ("privkey.pem", "TEST KEY\n"),
            ("fullchain.pem", "TEST CHAIN\n"),
            ("cert.pem", "TEST LEAF\n"),
        ]:
            (self.lineage / name).write_text(content)
        self.marker = self.root / "delivered"
        self.verify_log = self.root / "verify-args"
        self.hc_log = self.root / "healthchecks"
        self.env = os.environ.copy()
        self.env.update(
            {
                "DELIVERED_FILE": str(self.marker),
                "VERIFY_LOG": str(self.verify_log),
                "VERIFY_MODE": "after-delivery",
                "HC_LOG": str(self.hc_log),
            }
        )
        self.write_executable(
            self.drivers / "verify-deployed-cert.sh",
            """#!/bin/bash
printf '%s\\0' "$@" >> "$VERIFY_LOG"
case "$VERIFY_MODE" in
  pass) exit 0 ;;
  fail) exit 1 ;;
  after-delivery) test -f "$DELIVERED_FILE" ;;
esac
""",
        )
        self.write_executable(
            self.drivers / "curl",
            """#!/bin/bash
printf '%s\\n' "${@: -1}" >> "$HC_LOG"
""",
        )
        self.env["PATH"] = str(self.drivers) + os.pathsep + self.env["PATH"]
        self.config_path = self.root / "deploy-config.json"
        self.dispatcher = self.copy_orchestrator("cert-dispatcher.sh")
        self.sync = self.copy_orchestrator("cert-sync.sh")

    @staticmethod
    def write_executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def copy_orchestrator(self, name):
        source = (REPO / name).read_text()
        self.assertIn("/etc/letsencrypt", source)
        source = source.replace("/etc/letsencrypt", str(self.root))
        if name == "cert-sync.sh":
            guard = 'if [ "$EUID" -ne 0 ]; then'
            self.assertEqual(source.count(guard), 1)
            source = source.replace(guard, "if false; then")
        path = self.root / name
        self.write_executable(path, source)
        return path

    def run_script(self, script, *args, **kwargs):
        return subprocess.run(
            ["bash", str(script), *map(str, args)],
            check=False,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            **kwargs,
        )

    def run_driver(self, command, *args, verify=False, **kwargs):
        options = ["--command", command, *args]
        if not verify:
            options.append("--no-verify")
        return self.run_script(self.driver, *options, **kwargs)

    def target(self, **overrides):
        target = {
            "name": "fixture-caddy",
            "driver": "shell-command",
            "command": 'cat "$KEY_FILE" "$CERT_FILE" > "$DELIVERED_FILE"',
            "verify_host": "forgejo.example.invalid",
            "timeout": 0,
        }
        target.update(overrides)
        return target

    def configure(self, *targets):
        self.config_path.write_text(
            json.dumps(
                {
                    "site_name": "offline-fixture",
                    "cert_driver_dir": str(self.drivers),
                    "log_file": str(self.root / "deploy.log"),
                    "certs": {
                        "test-lineage": {
                            "domains": ["*.example.invalid"],
                            "targets": list(targets),
                            "healthchecks_url": "https://healthchecks.example.invalid/ping/test",
                        }
                    },
                }
            )
        )
        self.env["RENEWED_LINEAGE"] = str(self.lineage)
        self.env["RENEWED_DOMAINS"] = "*.example.invalid"

    def test_stream_paths_with_spaces_and_chdir(self):
        inputs = self.root / "input files"
        inputs.mkdir()
        (inputs / "key").write_text("KEY\n")
        (inputs / "chain").write_text("CHAIN\n")
        working = self.root / "working directory"
        working.mkdir()
        self.env["EXPECTED_CWD"] = str(working)
        self.env["EXPECTED_CERT_DIR"] = str(inputs)
        result = self.run_driver(
            'test "$PWD" = "$EXPECTED_CWD" && test "$CERT_DIR" = "$EXPECTED_CERT_DIR" && cat "$KEY_FILE" "$CERT_FILE" > "$DELIVERED_FILE"',
            "--key-file",
            "input files/key",
            "--cert-file",
            "input files/chain",
            "--chdir",
            working,
            cwd=self.root,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.marker.read_text(), "KEY\nCHAIN\n")

    def test_command_stdin_is_empty(self):
        result = self.run_driver('test -z "$(cat)"', input="caller input")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_pipeline_failure_propagates(self):
        result = self.run_driver("false | cat")
        self.assertNotEqual(result.returncode, 0)

    def test_command_exit_status_propagates(self):
        result = self.run_driver("exit 23")
        self.assertEqual(result.returncode, 23)
        self.assertFalse(self.verify_log.exists())

    def test_timeout_stops_local_descendants(self):
        result = self.run_driver(
            '(sleep 2; touch "$DELIVERED_FILE") & wait', "--timeout", "1"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stdout)
        time.sleep(1.2)
        self.assertFalse(self.marker.exists())

    def test_zero_timeout_is_supported(self):
        result = self.run_driver("true", "--timeout", "0")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_invalid_options_fail_before_delivery(self):
        for args in [
            ("--timeout", "bad"),
            ("--verify-port", "0"),
            ("--verify-port", "65536"),
            ("--key-file", "missing"),
            ("--chdir", "missing"),
            ("--timeout",),
        ]:
            with self.subTest(args=args):
                result = self.run_script(
                    self.driver,
                    "--command",
                    'touch "$DELIVERED_FILE"',
                    "--no-verify",
                    *args,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_missing_verification_fails_before_delivery(self):
        result = self.run_driver('touch "$DELIVERED_FILE"', verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_verification_failure_propagates(self):
        self.env["VERIFY_MODE"] = "fail"
        result = self.run_driver(
            'touch "$DELIVERED_FILE"',
            "--cert-file",
            self.lineage / "cert.pem",
            "--verify-host",
            "forgejo.example.invalid",
            verify=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assertIn(b"forgejo.example.invalid\0", self.verify_log.read_bytes())

    def test_command_is_not_logged(self):
        result = self.run_driver("true # DO_NOT_LOG_THIS_COMMAND")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("DO_NOT_LOG_THIS_COMMAND", result.stdout)

    def test_dispatcher_delivers_then_verifies(self):
        self.configure(self.target())
        result = self.run_script(self.dispatcher)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.marker.read_text(), "TEST KEY\nTEST CHAIN\n")
        args = self.verify_log.read_bytes().split(b"\0")
        self.assertEqual(args.count(b"--host"), 2)  # before and after delivery
        self.assertIn(b"15", args)
        self.assertEqual(
            self.hc_log.read_text().splitlines(),
            [
                "https://healthchecks.example.invalid/ping/test/start",
                "https://healthchecks.example.invalid/ping/test",
            ],
        )

    def test_dispatcher_skips_current_certificate(self):
        self.env["VERIFY_MODE"] = "pass"
        self.configure(self.target())
        result = self.run_script(self.dispatcher)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("already serving current cert", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_sample_ssh_command_streams_key_then_chain(self):
        self.env["SSH_LOG"] = str(self.root / "ssh-args")
        self.write_executable(
            self.drivers / "ssh",
            """#!/bin/bash
printf '%s\\0' "$@" > "$SSH_LOG"
cat > "$DELIVERED_FILE"
""",
        )
        sample = json.loads((REPO / "deploy-config-SAMPLE.json").read_text())
        targets = sample["certs"]["CHANGEME.example.com-wildcard"]["targets"]
        target = next(t for t in targets if t["driver"] == "shell-command")
        self.configure(target)
        result = self.run_script(self.dispatcher)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.marker.read_text(), "TEST KEY\nTEST CHAIN\n")
        args = (self.root / "ssh-args").read_bytes().split(b"\0")
        self.assertIn(b"StrictHostKeyChecking=yes", args)
        self.assertIn(b"BatchMode=yes", args)
        self.assertEqual(args[-2], b"install")

    def test_dispatcher_reports_failure_and_continues_other_targets(self):
        self.configure(
            self.target(command="exit 23"), self.target(name="second", verify=False)
        )
        result = self.run_script(self.dispatcher)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1/2 succeeded", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertTrue(self.hc_log.read_text().endswith("/fail\n"))

    def test_dispatcher_requires_verification_host(self):
        self.configure(self.target(verify_host=""))
        result = self.run_script(self.dispatcher)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_dispatcher_rejects_empty_command_even_if_cert_is_current(self):
        self.env["VERIFY_MODE"] = "pass"
        self.configure(self.target(command=""))
        result = self.run_script(self.dispatcher)
        self.assertNotEqual(result.returncode, 0)

    def test_dispatcher_explicit_bootstrap_skips_all_verification(self):
        self.configure(self.target(verify=False, verify_host=""))
        result = self.run_script(self.dispatcher)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.verify_log.exists())

    def test_dispatcher_post_delivery_verification_failure(self):
        self.env["VERIFY_MODE"] = "fail"
        self.configure(self.target())
        result = self.run_script(self.dispatcher)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assertTrue(self.hc_log.read_text().endswith("/fail\n"))

    def test_verification_only_never_runs_delivery(self):
        self.env["VERIFY_MODE"] = "pass"
        self.configure(self.target(verify_port=8443, verify_cert_file="fullchain.pem"))
        result = self.run_script(
            self.sync, "--config", self.config_path, "-D", "--dry-run"
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("1/1 passed", result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertIn(b"8443\0", self.verify_log.read_bytes())
        self.assertIn(
            str(self.lineage / "fullchain.pem").encode(), self.verify_log.read_bytes()
        )

    def test_verification_only_missing_host_is_failure(self):
        self.configure(self.target(verify_host=""))
        result = self.run_script(
            self.sync, "--config", self.config_path, "-D", "--dry-run"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0/1 passed", result.stdout)

    def test_verification_only_explicit_skip(self):
        self.configure(self.target(verify=False))
        result = self.run_script(
            self.sync, "--config", self.config_path, "-D", "--dry-run"
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("1 skipped", result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.verify_log.exists())


if __name__ == "__main__":
    unittest.main()
