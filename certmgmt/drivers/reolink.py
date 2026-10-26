"""Reolink's JSON certificate import protocol."""

import base64
import time
from pathlib import Path

from ..errors import DeploymentError
from ..runtime import protect
from .http import require_ok


def apply(session, base, options):
    token = None

    def call(command, params):
        query = {"cmd": command}
        if token:
            query["token"] = token
        response = require_ok(
            session.post(
                base + "/cgi-bin/api.cgi",
                params=query,
                json=[{"cmd": command, "action": 0, "param": params}],
                timeout=60,
            ),
            command,
        )
        data = response.json()
        if (
            not isinstance(data, list)
            or len(data) != 1
            or not isinstance(data[0], dict)
            or data[0].get("code") != 0
        ):
            raise DeploymentError(
                f"Reolink {command} returned a failed or malformed response"
            )
        return data[0]

    result = call(
        "Login", {"User": {"userName": options.username, "password": options.password}}
    )
    try:
        token = protect(result["value"]["Token"]["name"])
        if not token:
            raise KeyError("empty token")
    except KeyError, TypeError:
        raise DeploymentError("Reolink login returned no token") from None
    try:

        def upload(path, name):
            contents = Path(path).read_bytes()
            return {
                "size": len(contents),
                "name": name,
                "content": base64.b64encode(contents).decode(),
            }

        call(
            "ImportCertificate",
            {
                "importCertificate": {
                    "crt": upload(options.cert_file, "server.crt"),
                    "key": upload(options.key_file, "server.key"),
                }
            },
        )
        time.sleep(5)
    finally:
        try:
            session.get(
                base + "/cgi-bin/api.cgi",
                params={"cmd": "Logout", "token": token},
                timeout=60,
            )
        except DeploymentError:
            pass  # The camera may have restarted after import.
