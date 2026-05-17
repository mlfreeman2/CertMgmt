#!/usr/bin/env python3
# driver-truenas.py -- Deploy certificate to TrueNAS Scale via WebSocket API
# Usage: driver-truenas.py -h HOST -a API_KEY -D DOMAIN -c CERT_FILE -k KEY_FILE [-l LEAF_CERT_FILE]

import argparse
import asyncio
import json
import logging
import os
import ssl
import subprocess
import sys
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import websockets

log = logging.getLogger(__name__)


async def upload_cert(host, api_key, domain, cert_file, key_file, leaf_cert_file):
    log.info("Deploying certificate to TrueNAS Scale at %s...", host)

    # Read certificate files
    # Use leaf cert for fingerprint (just the leaf cert, not the chain)
    with open(leaf_cert_file, "r") as f:
        cert_only = f.read()

    # Use cert_file for upload (typically fullchain.pem, includes intermediates)
    with open(cert_file, "r") as f:
        cert_data = f.read()

    with open(key_file, "r") as f:
        key_data = f.read()

    # Calculate SHA-1 fingerprint from the leaf certificate only.
    # TrueNAS returns SHA-1 fingerprints from its certificate.query API,
    # so we must use SHA-1 here to match against it.
    cert_obj = x509.load_pem_x509_certificate(cert_only.encode(), default_backend())
    cert_fingerprint = cert_obj.fingerprint(hashes.SHA1()).hex().upper()
    cert_fingerprint_formatted = ":".join(
        [cert_fingerprint[i : i + 2] for i in range(0, len(cert_fingerprint), 2)]
    )

    log.info("Certificate SHA1 fingerprint: %s", cert_fingerprint_formatted)

    # Create certificate name
    cert_name = f"LetsEncrypt-{domain.replace('.', '-')}-{datetime.now().strftime('%Y%m%d')}"

    # WebSocket URI
    uri = f"wss://{host}/websocket"

    # Disable SSL verification (self-signed cert)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(uri, ssl=ssl_context) as ws:
            # Authenticate
            await ws.send(
                json.dumps(
                    {"msg": "connect", "version": "1", "support": ["1"]}
                )
            )

            # Read auth response
            await ws.recv()

            # Send authentication
            await ws.send(
                json.dumps(
                    {
                        "id": "auth",
                        "msg": "method",
                        "method": "auth.login_with_api_key",
                        "params": [api_key],
                    }
                )
            )

            auth_response = json.loads(await ws.recv())
            if auth_response.get("error"):
                log.error("Authentication failed: %s", auth_response["error"])
                sys.exit(1)

            log.info("Authenticated with TrueNAS")

            # Upload certificate (with full chain)
            log.info("Uploading certificate...")
            await ws.send(
                json.dumps(
                    {
                        "id": "cert-create",
                        "msg": "method",
                        "method": "certificate.create",
                        "params": [
                            {
                                "name": cert_name,
                                "create_type": "CERTIFICATE_CREATE_IMPORTED",
                                "certificate": cert_data,
                                "privatekey": key_data,
                            }
                        ],
                    }
                )
            )

            create_response = json.loads(await ws.recv())
            if create_response.get("error"):
                log.error("Certificate upload failed: %s", create_response["error"])
                sys.exit(1)

            log.info("Certificate uploaded (Name: %s)", cert_name)

            # Wait for TrueNAS to fully commit the certificate
            log.info("Waiting for certificate to be committed...")
            await asyncio.sleep(5)

            # Query to find cert by name and verify fingerprint
            log.info("Finding certificate ID and verifying fingerprint...")
            await ws.send(
                json.dumps(
                    {
                        "id": "cert-query",
                        "msg": "method",
                        "method": "certificate.query",
                        "params": [[["name", "=", cert_name]]],
                    }
                )
            )

            query_response = json.loads(await ws.recv())

            if (
                not query_response.get("result")
                or len(query_response["result"]) == 0
            ):
                log.error("Certificate not found after creation")
                log.error("  Tried to find: %s", cert_name)
                sys.exit(1)

            # Find cert with matching fingerprint
            cert_id = None
            for cert in query_response["result"]:
                if cert.get("fingerprint") == cert_fingerprint_formatted:
                    cert_id = cert["id"]
                    break

            if not cert_id:
                log.error("Certificate found by name but fingerprint doesn't match")
                log.error("  Expected fingerprint: %s", cert_fingerprint_formatted)
                for cert in query_response["result"]:
                    log.error(
                        "  Found: ID=%s, fingerprint=%s",
                        cert["id"],
                        cert.get("fingerprint"),
                    )
                sys.exit(1)

            log.info("Certificate ID found and fingerprint verified: %s", cert_id)

            # Update system to use new certificate
            log.info("Setting certificate as active for web UI...")
            await ws.send(
                json.dumps(
                    {
                        "id": "system-update",
                        "msg": "method",
                        "method": "system.general.update",
                        "params": [{"ui_certificate": cert_id}],
                    }
                )
            )

            update_response = json.loads(await ws.recv())
            if update_response.get("error"):
                log.error("Failed to set certificate as active")
                log.error("  Error: %s", update_response["error"])
                log.error(
                    "  Certificate was uploaded but couldn't be activated automatically"
                )
                sys.exit(1)

            log.info("Certificate set as active")

            # Delete old certificates for this domain
            cert_prefix = f"LetsEncrypt-{domain.replace('.', '-')}-"
            log.info("Checking for old certificates matching '%s'...", cert_prefix)
            await ws.send(
                json.dumps(
                    {
                        "id": "cert-query-all",
                        "msg": "method",
                        "method": "certificate.query",
                        "params": [],
                    }
                )
            )

            all_certs_response = json.loads(await ws.recv())
            if all_certs_response.get("result"):
                old_certs = [
                    c for c in all_certs_response["result"]
                    if c["name"].startswith(cert_prefix) and c["id"] != cert_id
                ]
                if old_certs:
                    log.info("Found %d old certificate(s) to remove", len(old_certs))
                    for old_cert in old_certs:
                        log.info(
                            "  Deleting: %s (ID: %s)",
                            old_cert["name"],
                            old_cert["id"],
                        )
                        await ws.send(
                            json.dumps(
                                {
                                    "id": f"cert-delete-{old_cert['id']}",
                                    "msg": "method",
                                    "method": "certificate.delete",
                                    "params": [old_cert["id"]],
                                }
                            )
                        )
                        delete_response = json.loads(await ws.recv())
                        if delete_response.get("error"):
                            log.warning(
                                "    Failed to delete: %s",
                                delete_response["error"],
                            )
                        else:
                            log.info("    Deleted successfully")
                else:
                    log.info("No old certificates found to clean up")

            # Restart web UI
            log.info("Restarting TrueNAS web UI...")
            await ws.send(
                json.dumps(
                    {
                        "id": "ui-restart",
                        "msg": "method",
                        "method": "system.general.ui_restart",
                        "params": [],
                    }
                )
            )

            await ws.recv()
            log.info("Web UI restart initiated")
            log.info("Certificate deployed to TrueNAS successfully")
            log.info(
                "  Note: Web UI will be unavailable for ~10-15 seconds while restarting"
            )

    except Exception as e:
        log.error("Error: %s", e)
        import traceback

        traceback.print_exc()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Deploy SSL certificate to TrueNAS Scale via WebSocket API"
    )
    parser.add_argument(
        "-H", "--host", required=True, help="TrueNAS IP or hostname"
    )
    parser.add_argument(
        "-a", "--api-key", required=True, help="TrueNAS API key"
    )
    parser.add_argument(
        "-D", "--domain", required=True, help="Domain name (used for cert naming)"
    )
    parser.add_argument(
        "-c", "--cert-file", required=True, help="Path to certificate file (fullchain.pem)"
    )
    parser.add_argument(
        "-k", "--key-file", required=True, help="Path to private key file (privkey.pem)"
    )
    parser.add_argument(
        "-l",
        "--leaf-cert-file",
        required=False,
        help="Path to leaf-only cert for fingerprint verification (default: cert.pem in same dir as cert-file)",
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

    # Default leaf cert to cert.pem in same directory as cert-file
    if args.leaf_cert_file is None:
        args.leaf_cert_file = os.path.join(
            os.path.dirname(args.cert_file), "cert.pem"
        )

    for path in [args.cert_file, args.key_file, args.leaf_cert_file]:
        if not os.path.isfile(path):
            log.error("File not found: %s", path)
            sys.exit(1)

    asyncio.run(
        upload_cert(
            args.host,
            args.api_key,
            args.domain,
            args.cert_file,
            args.key_file,
            args.leaf_cert_file,
        )
    )

    # Post-deployment verification via openssl s_client
    if not args.no_verify:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        verify_script = os.path.join(script_dir, "verify-deployed-cert.sh")
        leaf_cert = args.leaf_cert_file
        result = subprocess.run(
            [verify_script, "--host", args.host, "--cert-file", leaf_cert,
             "--wait", "30", "--retries", "3"],
        )
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
