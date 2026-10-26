"""Real PEM validation and filesystem recovery, with an isolated Caddy stand-in.

Only the copied receiver's config location is changed. Faults intercept filesystem
commands, including process-group SIGKILL immediately before/after activation.
No root, SSH connection, installed configuration, or live service is needed.
"""

import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RECEIVER = REPO / "caddy-cert-receive" / "caddy-cert-receive.sh"


class CaddyReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_temp = tempfile.TemporaryDirectory(prefix="receiver-certs-")
        cls.addClassCleanup(cls.cert_temp.cleanup)
        cls.certs = Path(cls.cert_temp.name)
        for name, days, san in [
            ("old", 2, "*.apps.example.com"),
            ("new", 4, "*.apps.example.com"),
            ("other", 4, "other.example.com"),
            ("short", 1, "*.apps.example.com"),
        ]:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-nodes",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-days",
                    str(days),
                    "-subj",
                    f"/CN={san}",
                    "-addext",
                    f"subjectAltName=DNS:{san}",
                    "-keyout",
                    str(cls.certs / f"{name}.key"),
                    "-out",
                    str(cls.certs / f"{name}.pem"),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="caddy-receiver-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "cert slots"
        self.slot = self.base / "apps.example.com"
        self.slot.mkdir(parents=True)
        self.slot.chmod(0o2750)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.reload_log = self.root / "reloads"
        self.config = self.root / "receiver.conf"
        self.config.write_text(
            f"CERT_BASE={shlex.quote(str(self.base))}\n"
            f"CADDYFILE={shlex.quote(str(self.root / 'config space' / 'Caddyfile'))}\n"
        )
        source = RECEIVER.read_text()
        config_line = 'GLOBAL_CONF="/etc/caddy-cert-receive.conf"'
        self.assertEqual(source.count(config_line), 1)
        self.receiver = self.root / "receiver.sh"
        self.receiver.write_text(
            source.replace(config_line, f"GLOBAL_CONF={shlex.quote(str(self.config))}")
        )
        self.env = os.environ.copy()
        self.env.pop("SSH_ORIGINAL_COMMAND", None)
        self.env.update(
            {
                "PATH": str(self.bin) + os.pathsep + self.env["PATH"],
                "TEST_SLOT": str(self.slot),
                "RELOAD_LOG": str(self.reload_log),
                "REAL_MV": shutil.which("mv"),
                "REAL_INSTALL": shutil.which("install"),
            }
        )
        self.command("logger", "#!/bin/sh\nexit 0\n")
        self.command(
            "caddy",
            """#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
slot = pathlib.Path(os.environ["TEST_SLOT"])
current = (slot / "current").resolve(strict=True)
cert = subprocess.check_output(["openssl", "x509", "-in", str(current / "fullchain.pem"), "-noout", "-pubkey"])
key = subprocess.check_output(["openssl", "pkey", "-in", str(current / "privkey.pem"), "-pubout"], stderr=subprocess.DEVNULL)
assert cert == key, "Reload saw an incomplete or mismatched pair"
with open(os.environ["RELOAD_LOG"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("RELOAD_STARTED"):
    pathlib.Path(os.environ["RELOAD_STARTED"]).touch()
    deadline = time.monotonic() + 5
    while not pathlib.Path(os.environ["RELOAD_GATE"]).exists():
        assert time.monotonic() < deadline, "Reload gate timed out"
        time.sleep(0.02)
sys.exit(9 if os.environ.get("RELOAD_FAIL") else 0)
""",
        )
        fault_command = """#!/usr/bin/env python3
import os, pathlib, signal, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
dest = pathlib.Path(sys.argv[-1]).name
point = {("install", "privkey.pem"): "stage-key", ("install", "fullchain.pem"): "stage-chain", ("mv", "previous"): "previous", ("mv", "current"): "activate"}.get((name, dest), "")
fault = os.environ.get("FAULT", "")
if point and fault == point:
    sys.exit(73)
if point == "activate" and fault == "kill-before":
    os.killpg(os.getpgrp(), signal.SIGKILL)
rc = subprocess.call([os.environ["REAL_" + name.upper()], *sys.argv[1:]])
if point == "activate" and rc == 0 and fault == "kill-after":
    os.killpg(os.getpgrp(), signal.SIGKILL)
sys.exit(rc)
"""
        self.command("install", fault_command)
        self.command("mv", fault_command)

    def command(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def pem(self, name):
        return (self.certs / f"{name}.key").read_bytes() + (
            self.certs / f"{name}.pem"
        ).read_bytes()

    def run_receiver(self, name="new", verb="install", data=None, env=None):
        return subprocess.run(
            ["bash", str(self.receiver), verb],
            check=False,
            input=self.pem(name) if data is None else data,
            env=self.env if env is None else env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            start_new_session=True,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout.decode())

    def assert_pair(self, name, link="current"):
        generation = self.slot / link
        self.assertTrue(generation.is_symlink())
        self.assertEqual(
            (generation / "privkey.pem").read_bytes(),
            (self.certs / f"{name}.key").read_bytes(),
        )
        self.assertEqual(
            (generation / "fullchain.pem").read_bytes(),
            (self.certs / f"{name}.pem").read_bytes(),
        )

    def test_first_install_check_status_permissions_and_identical_retry(self):
        self.assert_success(self.run_receiver(verb="check"))
        self.assertFalse((self.slot / "current").exists())
        self.assertFalse(self.reload_log.exists())
        self.assertNotEqual(self.run_receiver(verb="status", data=b"").returncode, 0)
        self.assert_success(self.run_receiver())
        self.assert_pair("new")
        generation = (self.slot / "current").resolve()
        self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o2750)
        for name in ["privkey.pem", "fullchain.pem"]:
            self.assertEqual(stat.S_IMODE((generation / name).stat().st_mode), 0o640)
            self.assertEqual((generation / name).stat().st_gid, self.slot.stat().st_gid)
        self.assert_success(self.run_receiver(verb="status", data=b""))
        self.assert_success(self.run_receiver())
        self.assertEqual((self.slot / "current").resolve(), generation)
        args = [json.loads(line) for line in self.reload_log.read_text().splitlines()]
        self.assertEqual(len(args), 2)
        self.assertEqual(
            args[0],
            [
                "reload",
                "--config",
                str(self.root / "config space" / "Caddyfile"),
                "--adapter",
                "caddyfile",
                "--force",
            ],
        )

    def test_changed_pair_preserves_previous_generation(self):
        self.assert_success(self.run_receiver("old"))
        old = (self.slot / "current").resolve()
        self.assert_success(self.run_receiver("new"))
        self.assert_pair("new")
        self.assert_pair("old", "previous")
        self.assertEqual((self.slot / "previous").resolve(), old)

    def test_staging_or_activation_failure_preserves_active_pair_and_retries(self):
        self.assert_success(self.run_receiver("old"))
        old = (self.slot / "current").resolve()
        self.reload_log.unlink()
        for fault in ["stage-key", "stage-chain", "previous", "activate"]:
            with self.subTest(fault=fault):
                result = self.run_receiver(env={**self.env, "FAULT": fault})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.slot / "current").resolve(), old)
                self.assert_pair("old")
                self.assertFalse(self.reload_log.exists())
        self.assert_success(self.run_receiver())
        self.assert_pair("new")
        self.assert_pair("old", "previous")

    def test_failed_first_install_publishes_no_partial_pair(self):
        for fault in ["stage-key", "stage-chain", "activate"]:
            with self.subTest(fault=fault):
                result = self.run_receiver(env={**self.env, "FAULT": fault})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.slot / "current").is_symlink())
                self.assertFalse(self.reload_log.exists())
        self.assert_success(self.run_receiver())
        self.assert_pair("new")

    def test_killed_before_activation_preserves_pair_and_retries(self):
        self.assert_success(self.run_receiver("old"))
        self.reload_log.unlink()
        result = self.run_receiver(env={**self.env, "FAULT": "kill-before"})
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assert_pair("old")
        self.assertFalse(self.reload_log.exists())
        self.assert_success(self.run_receiver())
        self.assert_pair("new")

    def test_killed_after_activation_retains_complete_pair_and_retries_reload(self):
        self.assert_success(self.run_receiver("old"))
        self.reload_log.unlink()
        result = self.run_receiver(env={**self.env, "FAULT": "kill-after"})
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assert_pair("new")
        self.assert_pair("old", "previous")
        generation = (self.slot / "current").resolve()
        self.assertFalse(self.reload_log.exists())
        self.assert_success(self.run_receiver())
        self.assertEqual((self.slot / "current").resolve(), generation)
        self.assertEqual(len(self.reload_log.read_text().splitlines()), 1)

    def test_reload_failure_is_reported_and_identical_delivery_retries(self):
        self.assert_success(self.run_receiver("old"))
        result = self.run_receiver(env={**self.env, "RELOAD_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"retained for retry", result.stdout)
        self.assert_pair("new")
        self.assert_pair("old", "previous")
        self.assert_success(self.run_receiver())

    def test_custom_reload_pipeline_failure_is_reported(self):
        with self.config.open("a") as config:
            config.write("RELOAD_CMD='false | cat'\n")
        result = self.run_receiver()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"reload failed", result.stdout)
        self.assert_pair("new")
        with self.config.open("a") as config:
            config.write("RELOAD_CMD=''\n")
        self.assert_success(self.run_receiver())

    def test_same_leaf_changed_chain_is_installed(self):
        self.assert_success(self.run_receiver())
        old = (self.slot / "current").resolve()
        extra = (self.certs / "other.pem").read_bytes()
        self.assert_success(self.run_receiver(data=self.pem("new") + extra))
        self.assertNotEqual((self.slot / "current").resolve(), old)
        self.assertEqual(
            (self.slot / "current/fullchain.pem").read_bytes(),
            (self.certs / "new.pem").read_bytes() + extra,
        )

    def test_refusals_preserve_current(self):
        self.assert_success(self.run_receiver())
        old = (self.slot / "current").resolve()
        self.reload_log.unlink()
        for data in [
            b"",
            b"not PEM",
            self.pem("other"),
            self.pem("old"),
            self.pem("short"),
            (self.certs / "old.key").read_bytes()
            + (self.certs / "new.pem").read_bytes(),
            self.pem("new") + self.pem("new"),
            b"x" * 262145,
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\ninvalid\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ]:
            with self.subTest(size=len(data)):
                self.assertNotEqual(self.run_receiver(data=data).returncode, 0)
                self.assertEqual((self.slot / "current").resolve(), old)
                self.assert_pair("new")
                self.assertFalse(self.reload_log.exists())

    def test_legacy_layout_requires_explicit_migration(self):
        for ext, name in [("key", "privkey.pem"), ("pem", "fullchain.pem")]:
            shutil.copyfile(self.certs / f"old.{ext}", self.slot / name)
        result = self.run_receiver()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"legacy flat files", result.stdout)
        self.assertFalse((self.slot / "current").exists())
        self.assertEqual(
            (self.slot / "privkey.pem").read_bytes(),
            (self.certs / "old.key").read_bytes(),
        )

    def test_bad_current_link_and_missing_key_are_reported(self):
        (self.slot / "current").symlink_to("../outside")
        self.assertNotEqual(self.run_receiver().returncode, 0)
        (self.slot / "current").unlink()
        self.assert_success(self.run_receiver())
        (self.slot / "current/privkey.pem").unlink()
        self.assertNotEqual(self.run_receiver(verb="status", data=b"").returncode, 0)
        self.assert_success(self.run_receiver())
        self.assert_pair("new")

    def test_forced_command_does_not_execute_sender_text(self):
        marker = self.root / "unexpected-command"
        result = self.run_receiver(
            env={**self.env, "SSH_ORIGINAL_COMMAND": f"install; touch {marker}"}
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(marker.exists())
        self.assertFalse((self.slot / "current").exists())

    def test_shell_command_driver_stream_contract(self):
        result = subprocess.run(
            [
                "bash",
                str(REPO / "drivers/driver-shell-command.sh"),
                "--command",
                'cat "$KEY_FILE" "$CERT_FILE" | bash '
                + shlex.quote(str(self.receiver))
                + " install",
                "--cert-file",
                str(self.certs / "new.pem"),
                "--key-file",
                str(self.certs / "new.key"),
                "--no-verify",
            ],
            check=False,
            env=self.env,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assert_pair("new")

    def test_concurrent_delivery_waits_until_reload_finishes(self):
        gate = self.root / "continue-reload"
        started = self.root / "reload-started"
        processes = []

        def launch(name, env):
            process = subprocess.Popen(
                ["bash", str(self.receiver), "install"],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes.append(process)
            process.stdin.write(self.pem(name))
            process.stdin.close()
            process.stdin = None
            return process

        try:
            first = launch(
                "old",
                {**self.env, "RELOAD_STARTED": str(started), "RELOAD_GATE": str(gate)},
            )
            deadline = time.monotonic() + 5
            while not started.exists():
                self.assertIsNone(first.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            second = launch("new", self.env)
            time.sleep(0.15)
            self.assertIsNone(second.poll())
            self.assert_pair("old")
            gate.touch()
            for process in processes:
                output, _ = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, output.decode())
            self.assert_pair("new")
            self.assert_pair("old", "previous")
        finally:
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()


if __name__ == "__main__":
    unittest.main()
