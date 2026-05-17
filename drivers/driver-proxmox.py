#!/usr/bin/env python3

# driver-proxmox.py -- Deploy TLS certificate to Proxmox VE via REST API
#
# Uploads a custom certificate to pveproxy using the Proxmox API on port 8006.
# pveproxy automatically restarts to pick up the new cert.
#
# Proxmox-side setup:
#   1. Create a PVE API token: Datacenter > Permissions > API Tokens
#      Use root@pam or a user with Sys.Modify on /nodes/{node}.
#      Uncheck "Privilege Separation" so the token inherits user privileges.
#   2. To share the cert with nginx on the same host, point nginx at:
#        ssl_certificate     /etc/pve/local/pveproxy-ssl.pem;
#        ssl_certificate_key /etc/pve/local/pveproxy-ssl.key;
#      and create a systemd .path unit to reload nginx when the cert changes.
#
# Requires: pip install requests
#
# Usage: driver-proxmox.py -H HOST -a API_TOKEN -n NODE -c CERT_FILE -k KEY_FILE [--no-verify] [--quiet] [--debug]

import argparse
import logging
import os
import subprocess
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class ProxmoxUpdater:
    def __init__(self, base_url, api_token, node):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.node = node
        self.headers = {"Authorization": f"PVEAPIToken={api_token}"}

    def upload_cert(self, cert_file, key_file):
        log.info("Uploading certificate to Proxmox...")

        with open(cert_file) as f:
            cert_pem = f.read()
        with open(key_file) as f:
            key_pem = f.read()

        url = f"{self.base_url}/api2/json/nodes/{self.node}/certificates/custom"
        payload = {
            "certificates": cert_pem,
            "key": key_pem,
            "restart": 1,
            "force": 1,
        }

        log.debug("POST %s", url)

        r = requests.post(
            url, data=payload, headers=self.headers, verify=False, timeout=30
        )

        log.debug("HTTP %s: %s", r.status_code, r.text[:500])

        if not r.ok:
            log.error(
                "Certificate upload failed (HTTP %s): %s", r.status_code, r.text
            )
            sys.exit(2)

        log.info("  Certificate uploaded. pveproxy restarting...")


def main():
    parser = argparse.ArgumentParser(description="Deploy TLS certificate to Proxmox VE")
    parser.add_argument(
        "-H",
        "--host",
        required=True,
        help="Proxmox host IP or hostname (connects on port 8006)",
    )
    parser.add_argument(
        "-a",
        "--api-token",
        required=True,
        help="PVE API token (format: user@realm!tokenid=secret)",
    )
    parser.add_argument(
        "-n",
        "--node",
        required=True,
        help="Proxmox node name (e.g. 'pve')",
    )
    parser.add_argument(
        "-c",
        "--cert-file",
        required=True,
        help="Path to certificate file (fullchain.pem)",
    )
    parser.add_argument(
        "-k",
        "--key-file",
        required=True,
        help="Path to private key file (privkey.pem)",
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

    host = args.host
    if host.startswith("https://") or host.startswith("http://"):
        # Strip protocol — we build the URL ourselves with port 8006
        host = host.split("://", 1)[1]

    base_url = f"https://{host}:8006"

    updater = ProxmoxUpdater(base_url, args.api_token, args.node)

    updater.upload_cert(args.cert_file, args.key_file)

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
                "--port",
                "8006",
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
