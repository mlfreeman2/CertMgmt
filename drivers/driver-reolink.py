#!/usr/bin/env python3

# driver-reolink.py -- Deploy TLS certificate to a Reolink camera
#
# Tested against: Reolink CX410W (and likely other Reolink models with HTTPS web UI)
# Note: Reolink cameras only support RSA certificates, not ECDSA.
#
# Requires: pip install requests
#
# Usage: driver-reolink.py -H HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [--no-verify] [--quiet] [--debug]

import argparse
import base64
import logging
import os
import subprocess
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class ReolinkUpdater:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token = None

    def _api(self, cmd, payload, token=None):
        """POST to the Reolink JSON API and return the parsed response."""
        url = f"{self.base_url}/cgi-bin/api.cgi?cmd={cmd}"
        if token:
            url += f"&token={token}"
        log.debug("POST %s", url)
        r = requests.post(url, json=payload, verify=False, timeout=60)
        if not r.ok:
            log.error("API call %r failed (HTTP %s)", cmd, r.status_code)
            sys.exit(2)
        data = r.json()
        log.debug("response: %s", data)
        return data

    def login(self):
        log.info("Logging in...")
        payload = [
            {
                "cmd": "Login",
                "action": 0,
                "param": {
                    "User": {"userName": self.username, "password": self.password}
                },
            }
        ]
        data = self._api("Login", payload)
        try:
            self.token = data[0]["value"]["Token"]["name"]
        except (KeyError, IndexError, TypeError):
            log.error("Login failed — unexpected response: %s", data)
            sys.exit(2)
        log.info("  Logged in successfully.")

    def upload_cert(self, cert_file, key_file):
        log.info("Uploading certificate...")
        with open(cert_file, "rb") as f:
            cert_bytes = f.read()
        with open(key_file, "rb") as f:
            key_bytes = f.read()

        payload = [
            {
                "cmd": "ImportCertificate",
                "action": 0,
                "param": {
                    "importCertificate": {
                        "crt": {
                            "size": len(cert_bytes),
                            "name": "server.crt",
                            "content": base64.b64encode(cert_bytes).decode("utf-8"),
                        },
                        "key": {
                            "size": len(key_bytes),
                            "name": "server.key",
                            "content": base64.b64encode(key_bytes).decode("utf-8"),
                        },
                    }
                },
            }
        ]
        data = self._api("ImportCertificate", payload, token=self.token)
        try:
            code = data[0].get("code", 0)
            if code != 0:
                log.error(
                    "ImportCertificate returned error code %s: %s", code, data
                )
                sys.exit(2)
        except (KeyError, IndexError, TypeError):
            pass
        log.info("  Certificate uploaded. Waiting for web daemon restart...")
        time.sleep(5)

    def logout(self):
        url = f"{self.base_url}/cgi-bin/api.cgi?cmd=Logout&token={self.token}"
        try:
            requests.get(url, verify=False, timeout=60)
        except Exception:
            pass  # Best-effort; camera may have already restarted
        self.token = None
        log.info("  Logged out.")


def main():
    parser = argparse.ArgumentParser(
        description="Deploy TLS certificate to a Reolink camera"
    )
    parser.add_argument(
        "-H",
        "--host",
        required=True,
        help="Camera IP or hostname (https:// will be prepended)",
    )
    parser.add_argument(
        "-u", "--username", required=True, help='Camera username (usually "admin")'
    )
    parser.add_argument("-p", "--password", required=True, help="Camera password")
    parser.add_argument(
        "-c",
        "--cert-file",
        required=True,
        help="Path to certificate file (cert.pem, not fullchain.pem — Reolink does not accept a certificate chain)",
    )
    parser.add_argument(
        "-k", "--key-file", required=True, help="Path to private key file (privkey.pem)"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip post-deployment certificate verification",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Do not output anything if successful"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Output additional debugging information"
    )
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(format="%(message)s", level=level)

    # Reolink cameras only support RSA certificates
    cert_check = subprocess.run(
        ["openssl", "x509", "-in", args.cert_file, "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if cert_check.returncode != 0:
        log.error("Cannot read certificate file: %s", args.cert_file)
        sys.exit(1)
    if "rsaEncryption" not in cert_check.stdout:
        log.error(
            "Reolink cameras require an RSA certificate, but %s is not RSA.",
            args.cert_file,
        )
        log.error('Set "key_type": "rsa" in your deploy-config.json for this cert.')
        sys.exit(1)

    with open(args.cert_file) as f:
        cert_content = f.read()
    if cert_content.count("-----BEGIN CERTIFICATE-----") > 1:
        log.error(
            "%s contains a certificate chain. "
            "Reolink requires a single leaf certificate (cert.pem, not fullchain.pem).",
            args.cert_file,
        )
        log.error(
            'Set "cert_file": "cert.pem" for this target in deploy-config.json.'
        )
        sys.exit(1)

    base_url = args.host
    if not base_url.startswith("https://"):
        base_url = f"https://{base_url}"

    updater = ReolinkUpdater(base_url, args.username, args.password)

    updater.login()
    updater.upload_cert(args.cert_file, args.key_file)
    updater.logout()

    log.info("All done!")

    # Post-deployment verification via openssl s_client
    if not args.no_verify:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        verify_script = os.path.join(script_dir, "verify-deployed-cert.sh")
        result = subprocess.run(
            [
                verify_script,
                "--host",
                args.host,
                "--cert-file",
                args.cert_file,
                "--wait",
                "15",
                "--retries",
                "3",
            ],
        )
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
