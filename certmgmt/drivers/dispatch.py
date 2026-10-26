"""Invoke adapters without routing secrets through child process arguments."""

import logging
import os
from pathlib import Path

from ..certificates import https_url
from ..errors import DeploymentError
from ..runtime import run_command

log = logging.getLogger(__name__)


def apply(driver, options):
    if driver == "shell-command":
        env = dict(
            os.environ,
            CERT_FILE=options.cert_file or "",
            KEY_FILE=options.key_file or "",
            CERT_DIR=str(Path(options.cert_file).parent) if options.cert_file else "",
        )
        run_command(
            ["bash", "-o", "pipefail", "-c", options.command],
            timeout=options.timeout,
            cwd=options.chdir,
            env=env,
            report=True,
        )
        return
    if driver == "docker-compose":
        run_command(
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--force-recreate",
                "--",
                *options.service,
            ],
            cwd=options.compose_dir,
            timeout=options.timeout,
            report=True,
        )
        return
    if driver == "truenas-scale":
        from .truenas import apply as truenas

        truenas(options)
        return
    from .http import Session, require_ok

    with Session(options) as session:
        base = https_url(options.host, options.port)
        if driver == "idrac":
            session.auth = (options.username, options.password)
            action = (
                base
                + "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/"
            )
            require_ok(
                session.post(
                    action + "DelliDRACCardService.UploadSSLKey",
                    json={"SSLKeyString": Path(options.key_file).read_text()},
                ),
                "key upload",
            )
            require_ok(
                session.post(
                    action + "DelliDRACCardService.ImportSSLCertificate",
                    json={
                        "CertificateType": "Server",
                        "SSLCertificateFile": Path(options.cert_file).read_text(),
                    },
                ),
                "certificate import",
            )
            require_ok(
                session.post(
                    action + "DelliDRACCardService.iDRACReset",
                    json={"Force": "Graceful"},
                ),
                "iDRAC restart",
            )
        elif driver == "glinet-kvm":
            response = require_ok(
                session.post(
                    base + "/api/system/ssl_cert",
                    headers={
                        "X-KVMD-User": options.username,
                        "X-KVMD-Passwd": options.password,
                    },
                    json={
                        "ssl_cert": Path(options.cert_file).read_text(),
                        "ssl_key": Path(options.key_file).read_text(),
                    },
                ),
                "certificate upload",
            )
            if response.json().get("ok") is not True:
                raise DeploymentError("KVMD rejected the certificate upload")
        elif driver == "proxmox":
            require_ok(
                session.post(
                    base + f"/api2/json/nodes/{options.node}/certificates/custom",
                    headers={"Authorization": f"PVEAPIToken={options.api_token}"},
                    data={
                        "certificates": Path(options.cert_file).read_text(),
                        "key": Path(options.key_file).read_text(),
                        "restart": 1,
                        "force": 1,
                    },
                ),
                "Proxmox certificate upload/restart",
            )
        elif driver == "reolink":
            from .reolink import apply as reolink

            reolink(session, base, options)
        elif driver == "supermicro-ipmi":
            from .supermicro import apply as supermicro

            supermicro(session, base, options)
        elif driver == "brother-printer":
            from .brother import apply as brother

            brother(session, base, options)
        else:
            raise DeploymentError(f"driver has no implementation: {driver}")
