"""One driver catalog for CLI help, dispatch, defaults and verification."""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from .certificates import VerifyEndpoint, fingerprint, hostname, validate_pair, verify
from .errors import ConfigurationError, DeploymentError
from .runtime import deadline, protect

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DriverSpec:
    description: str
    auth: str | None = "password"
    port: int = 443
    wait: int = 30
    retries: int = 3
    rsa_only: bool = False
    leaf_only: bool = False
    local: bool = False


DRIVERS = {
    "idrac": DriverSpec(
        "Dell iDRAC Redfish; full chain; restarts iDRAC (~2–3 minutes)",
        wait=60,
        retries=5,
    ),
    "glinet-kvm": DriverSpec(
        "GL.iNet KVMD; single leaf certificate; reloads TLS", wait=15, leaf_only=True
    ),
    "docker-compose": DriverSpec(
        "Force-recreate Compose services; certificates must already be mounted",
        auth=None,
        wait=15,
        local=True,
    ),
    "shell-command": DriverSpec(
        "Trusted Bash delivery command; exports CERT_FILE, KEY_FILE and CERT_DIR",
        auth=None,
        wait=15,
        local=True,
    ),
    "proxmox": DriverSpec(
        "Proxmox pveproxy; full chain; restarts pveproxy",
        auth="api_token",
        port=8006,
        wait=15,
    ),
    "reolink": DriverSpec(
        "Reolink; RSA leaf only; activation may take ten minutes",
        retries=19,
        rsa_only=True,
        leaf_only=True,
    ),
    "truenas-scale": DriverSpec(
        "TrueNAS Scale WebSocket API; full chain; restarts web UI", auth="api_key"
    ),
    "supermicro-ipmi": DriverSpec(
        "Supermicro X10/X11; RSA; reboots BMC unless --no-reboot",
        wait=180,
        retries=5,
        rsa_only=True,
    ),
    "brother-printer": DriverSpec(
        "Brother; RSA converted to PKCS#12; restarts printer web service", rsa_only=True
    ),
}

DEFAULTS = dict(
    host=None,
    port=None,
    username=None,
    password=None,
    api_key=None,
    api_token=None,
    cert_file=None,
    key_file=None,
    leaf_cert_file=None,
    domain=None,
    node=None,
    model=None,
    no_reboot=False,
    service=None,
    compose_dir=None,
    command=None,
    chdir=None,
    timeout=120,
    operation_timeout=900,
    connect_timeout=10,
    verify_wait=None,
    verify_retries=None,
    verify_interval=30,
    verify_host=None,
    verify_port=None,
    verify_ports=None,
    verify_server_name=None,
    verify_cert_file=None,
    no_verify=False,
    api_tls_verify=False,
    api_ca_file=None,
)


def integer(value, label, minimum=0, maximum=86400):
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or not str(value).isdigit()
    ):
        raise ConfigurationError(f"{label} must be a whole number")
    number = int(value)
    if not minimum <= number <= maximum:
        raise ConfigurationError(f"{label} must be between {minimum} and {maximum}")
    return number


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{label} must be a nonempty string")
    return value


def secret(options, name):
    choices = [
        options.get(name),
        options.get(name + "_file"),
        options.get(name + "_env"),
    ]
    if sum(v is not None for v in choices) != 1:
        raise ConfigurationError(
            f"supply exactly one of {name}, {name}_file or {name}_env"
        )
    if choices[1] is not None:
        try:
            value = Path(text(choices[1], name + "_file")).read_text().rstrip("\r\n")
        except OSError:
            raise ConfigurationError(f"cannot read {name} credential file") from None
    elif choices[2] is not None:
        value = os.environ.get(text(choices[2], name + "_env"))
    else:
        value = choices[0]
    return protect(text(value, name))


@dataclass
class Deployment:
    driver: str
    options: SimpleNamespace
    endpoints: tuple[VerifyEndpoint, ...]


def prepare(driver, values) -> Deployment:
    if driver not in DRIVERS:
        raise ConfigurationError(f"unknown driver: {driver}")
    spec = DRIVERS[driver]
    options = DEFAULTS | {k: v for k, v in values.items() if v is not None}
    for name in ("no_reboot", "no_verify", "api_tls_verify"):
        if type(options[name]) is not bool:
            raise ConfigurationError(f"{name} must be a boolean")
    for name in (
        "timeout",
        "operation_timeout",
        "verify_wait",
        "verify_retries",
        "verify_interval",
        "connect_timeout",
    ):
        if options.get(name) is not None:
            options[name] = integer(
                options[name],
                name,
                minimum=1 if name in ("connect_timeout", "operation_timeout") else 0,
            )
    for name, default in (
        ("port", spec.port),
        ("verify_port", options.get("port") or spec.port),
    ):
        options[name] = integer(
            default if options.get(name) is None else options[name], name, 1, 65535
        )
    if not spec.local:
        options["host"] = hostname(text(options["host"], "host"))
        options[spec.auth] = secret(options, spec.auth)
        if spec.auth == "password":
            text(options["username"], "username")
        text(options["cert_file"], "cert_file")
        text(options["key_file"], "key_file")
    if driver == "proxmox":
        node = text(options["node"], "node")
        if any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for c in node
        ):
            raise ConfigurationError("node contains invalid characters")
    if driver == "truenas-scale":
        text(options["domain"], "domain")
    if options["model"] not in (None, "X10", "X11"):
        raise ConfigurationError("model must be X10 or X11")
    if driver == "shell-command":
        text(options["command"], "command")
    if driver == "docker-compose":
        text(options["compose_dir"], "compose_dir")
        options["service"] = options["service"] or ["caddy"]
        if (
            not isinstance(options["service"], list)
            or not options["service"]
            or any(
                not isinstance(s, str) or not s or s.startswith("-")
                for s in options["service"]
            )
        ):
            raise ConfigurationError("service must contain nonempty service names")
    for name in (
        "cert_file",
        "key_file",
        "leaf_cert_file",
        "verify_cert_file",
        "api_ca_file",
    ):
        if options[name] is not None:
            path = Path(text(options[name], name)).resolve()
            if not path.is_file():
                raise ConfigurationError(f"{name} is not a readable file: {path}")
            options[name] = str(path)
    for name in ("chdir", "compose_dir"):
        if options[name] is not None:
            path = Path(text(options[name], name)).resolve()
            if not path.is_dir():
                raise ConfigurationError(f"{name} is not a directory: {path}")
            options[name] = str(path)
    if options["cert_file"] or options["key_file"]:
        if not options["cert_file"] or not options["key_file"]:
            raise ConfigurationError("cert_file and key_file must be supplied together")
        validate_pair(
            options["cert_file"],
            options["key_file"],
            rsa_only=spec.rsa_only,
            leaf_only=spec.leaf_only,
        )
    if options["leaf_cert_file"] and fingerprint(
        options["leaf_cert_file"]
    ) != fingerprint(options["cert_file"]):
        raise ConfigurationError("leaf_cert_file does not match cert_file")
    if options["verify_wait"] is None:
        options["verify_wait"] = (
            30 if driver == "supermicro-ipmi" and options["no_reboot"] else spec.wait
        )
    if options["verify_retries"] is None:
        options["verify_retries"] = spec.retries
    endpoints = ()
    if not options["no_verify"]:
        host = hostname(text(options["verify_host"] or options["host"], "verify_host"))
        expected = text(
            options["verify_cert_file"] or options["cert_file"], "verify_cert_file"
        )
        fingerprint(expected)  # Validate before delivery, not after a mutation.
        ports = (
            options["verify_ports"]
            if options["verify_ports"] is not None
            else [options["verify_port"]]
        )
        if not isinstance(ports, list) or not ports:
            raise ConfigurationError("verify_ports must be a nonempty array")
        server_name = options["verify_server_name"]
        if server_name is not None:
            server_name = hostname(server_name)
        endpoints = tuple(
            VerifyEndpoint(
                host, integer(port, "verify_port", 1, 65535), expected, server_name
            )
            for port in ports
        )
    return Deployment(driver, SimpleNamespace(**options), endpoints)


def deploy(request: Deployment):
    from .drivers import dispatch

    opts = request.options
    with deadline(opts.operation_timeout):
        dispatch.apply(request.driver, opts)
        for index, endpoint in enumerate(request.endpoints):
            verify(
                endpoint,
                wait=opts.verify_wait if index == 0 else 0,
                retries=opts.verify_retries,
                interval=opts.verify_interval,
                timeout=opts.connect_timeout,
            )
    if not request.endpoints:
        log.info("Deployment completed; verification explicitly disabled")
    else:
        log.info("Deployment completed and verified")


def already_current(request):
    if not request.endpoints:
        return False
    try:
        with deadline(request.options.operation_timeout):
            for endpoint in request.endpoints:
                verify(endpoint, timeout=request.options.connect_timeout)
        return True
    except DeploymentError:
        return False
