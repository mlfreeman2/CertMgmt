"""Real local TLS probes with simulated nginx configuration/reload commands."""

import os
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "proxmox-nginx-reload" / "pveproxy-cert-reload.sh"


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.server.cert, self.server.key)
        context.set_servername_callback(
            lambda _sock, name, _ctx: self.server.names.append(name)
        )
        self.request.settimeout(2)
        try:
            with context.wrap_socket(self.request, server_side=True) as connection:
                connection.recv(1)
        except (OSError, ssl.SSLError):
            pass


class NginxCertificateReloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory(prefix="nginx-certs-")
        cls.addClassCleanup(cls.certs.cleanup)
        for name in ("old", "new"):
            prefix = Path(cls.certs.name) / name
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
                    "2",
                    "-subj",
                    "/CN=pve.example.invalid",
                    "-addext",
                    "subjectAltName=DNS:pve.example.invalid",
                    "-keyout",
                    str(prefix.with_suffix(".key")),
                    "-out",
                    str(prefix.with_suffix(".pem")),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nginx-reload-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.expected = self.root / "expected.pem"
        self.served = self.root / "served.pem"
        self.served_key = self.root / "served.key"
        self.copy_pair("old")
        shutil.copyfile(Path(self.certs.name) / "new.pem", self.expected)
        self.commands = self.root / "commands"
        self.server = socketserver.TCPServer(("127.0.0.1", 0), TLSHandler)
        self.server.cert = self.served
        self.server.key = self.served_key
        self.server.names = []
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": str(self.bin) + os.pathsep + self.env["PATH"],
                "CERT_FILE": str(self.expected),
                "TLS_CONNECT": f"127.0.0.1:{self.server.server_address[1]}",
                "TLS_SERVER_NAME": "pve.example.invalid",
                "COMMAND_LOG": str(self.commands),
                "SERVED_CERT": str(self.served),
                "SERVED_KEY": str(self.served_key),
                "NEW_KEY": str(Path(self.certs.name) / "new.key"),
                "RELOAD_MODE": "apply",
                "CONFIG_OK": "yes",
                "ACTIVE": "yes",
            }
        )
        self.write_command(
            "nginx",
            """#!/bin/bash
printf 'nginx %s\\n' "$*" >> "$COMMAND_LOG"
[[ "$*" == "-t" && "$CONFIG_OK" == yes ]]
""",
        )
        self.write_command(
            "systemctl",
            """#!/bin/bash
printf 'systemctl %s\\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  'is-active --quiet nginx') [[ "$ACTIVE" == yes ]] ;;
  'reload nginx')
    case "$RELOAD_MODE" in
      fail) exit 1 ;;
      noop) exit 0 ;;
      apply) cp "$CERT_FILE" "$SERVED_CERT"; cp "$NEW_KEY" "$SERVED_KEY" ;;
    esac
    ;;
  *) exit 90 ;;
esac
""",
        )

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def copy_pair(self, name):
        shutil.copyfile(Path(self.certs.name) / f"{name}.pem", self.served)
        shutil.copyfile(Path(self.certs.name) / f"{name}.key", self.served_key)

    def write_command(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def run_helper(self):
        return subprocess.run(
            ["bash", str(HELPER)],
            env=self.env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )

    def log(self):
        return self.commands.read_text() if self.commands.exists() else ""

    def test_current_certificate_does_not_reload(self):
        self.copy_pair("new")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("reload", self.log())
        self.assertNotIn("nginx -t", self.log())
        self.assertEqual(self.server.names, ["pve.example.invalid"])

    def test_stale_certificate_reloads_and_verifies(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("nginx now serves", result.stdout)
        self.assertEqual(
            self.log().splitlines(),
            ["systemctl is-active --quiet nginx", "nginx -t", "systemctl reload nginx"],
        )
        self.assertGreaterEqual(len(self.server.names), 2)
        self.commands.write_text("")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("reload", self.log())

    def test_invalid_config_prevents_reload_and_next_run_retries(self):
        self.env["CONFIG_OK"] = "no"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("systemctl reload", self.log())
        self.env["CONFIG_OK"] = "yes"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("systemctl reload nginx", self.log())

    def test_reload_request_failure_is_reported(self):
        self.env["RELOAD_MODE"] = "fail"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reload request failed", result.stdout)

    def test_successful_signal_without_new_certificate_is_failure(self):
        self.env["RELOAD_MODE"] = "noop"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still does not serve", result.stdout)
        self.env["RELOAD_MODE"] = "apply"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_inactive_nginx_is_not_started(self):
        self.env["ACTIVE"] = "no"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log().splitlines(), ["systemctl is-active --quiet nginx"])

    def test_missing_or_invalid_disk_certificate_fails(self):
        for content in (None, "not a certificate"):
            with self.subTest(content=content):
                if content is None:
                    self.expected.unlink()
                else:
                    self.expected.write_text(content)
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.log(), "")

    def test_server_name_must_be_configured(self):
        for name in ("", "CHANGE_ME"):
            with self.subTest(name=name):
                self.env["TLS_SERVER_NAME"] = name
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.log(), "")


if __name__ == "__main__":
    unittest.main()
