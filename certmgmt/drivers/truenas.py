"""TrueNAS legacy WebSocket protocol, with response IDs and finite waits."""

import asyncio
import json
import logging
import ssl
from datetime import UTC, datetime
from pathlib import Path

from ..certificates import https_url, read_certificates
from ..errors import DeploymentError

log = logging.getLogger(__name__)


async def upload(options):
    import websockets
    from cryptography.hazmat.primitives import hashes

    context = ssl.create_default_context(cafile=options.api_ca_file)
    if not options.api_ca_file and not options.api_tls_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    uri = https_url(options.host, options.port).replace("https:", "wss:") + "/websocket"
    leaf = read_certificates(options.cert_file)[0]
    fp = ":".join(f"{byte:02X}" for byte in leaf.fingerprint(hashes.SHA1()))
    # Keep the existing ownership prefix so cleanup cannot select unrelated certs.
    prefix = "LetsEncrypt-" + options.domain.replace(".", "-") + "-"
    name = prefix + datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    async with websockets.connect(
        uri,
        ssl=context,
        open_timeout=options.connect_timeout,
        close_timeout=5,
        proxy=None,
    ) as ws:

        async def receive(message_id=None):
            async with asyncio.timeout(options.connect_timeout):
                while True:
                    response = json.loads(await ws.recv())
                    if not isinstance(response, dict):
                        raise DeploymentError("TrueNAS returned a malformed response")
                    if response.get("msg") == "ping":
                        await ws.send(
                            json.dumps(
                                {
                                    "msg": "pong",
                                    **(
                                        {"id": response["id"]}
                                        if "id" in response
                                        else {}
                                    ),
                                }
                            )
                        )
                        continue
                    if message_id is None or response.get("id") == message_id:
                        if response.get("error"):
                            raise DeploymentError(
                                f"TrueNAS rejected operation {message_id or 'connect'}"
                            )
                        return response

        async def call(message_id, method, params):
            await ws.send(
                json.dumps(
                    {
                        "id": message_id,
                        "msg": "method",
                        "method": method,
                        "params": params,
                    }
                )
            )
            return (await receive(message_id)).get("result")

        await ws.send(json.dumps({"msg": "connect", "version": "1", "support": ["1"]}))
        if (await receive()).get("msg") != "connected":
            raise DeploymentError("TrueNAS WebSocket negotiation failed")
        if await call("auth", "auth.login_with_api_key", [options.api_key]) is not True:
            raise DeploymentError("TrueNAS authentication failed")
        await call(
            "create",
            "certificate.create",
            [
                {
                    "name": name,
                    "create_type": "CERTIFICATE_CREATE_IMPORTED",
                    "certificate": Path(options.cert_file).read_text(),
                    "privatekey": Path(options.key_file).read_text(),
                }
            ],
        )
        await asyncio.sleep(5)
        certs = await call("query", "certificate.query", [[["name", "=", name]]])
        if not isinstance(certs, list):
            raise DeploymentError("TrueNAS certificate query returned no list")
        cert_id = next(
            (cert.get("id") for cert in certs if cert.get("fingerprint") == fp), None
        )
        if cert_id is None:
            raise DeploymentError(
                "TrueNAS uploaded certificate fingerprint was not found"
            )
        await call("activate", "system.general.update", [{"ui_certificate": cert_id}])
        certs = await call("all", "certificate.query", [])
        if not isinstance(certs, list):
            raise DeploymentError("TrueNAS cleanup query returned no list")
        for cert in certs:
            if cert.get("name", "").startswith(prefix) and cert.get("id") != cert_id:
                try:
                    await call(
                        "delete-" + str(cert["id"]), "certificate.delete", [cert["id"]]
                    )
                except DeploymentError:
                    log.warning("TrueNAS could not delete an older managed certificate")
        await call("restart", "system.general.ui_restart", [])


def apply(options):
    asyncio.run(upload(options))
