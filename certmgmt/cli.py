"""Public CLI. Help and argument errors require only the standard library."""

import argparse
import logging
import sys

from . import __version__
from .errors import (
    ConfigurationError,
    DeploymentError,
    OperationCancelled,
    OperationTimeout,
)
from .registry import DRIVERS
from .runtime import cancellation, configure_logging, protect, redact


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        kwargs.setdefault("formatter_class", argparse.ArgumentDefaultsHelpFormatter)
        super().__init__(*args, **kwargs)

    def error(self, message):
        super().error(redact(message))


def number(minimum=0, maximum=86400):
    def parse(value):
        from .registry import integer

        try:
            return integer(value, "value", minimum, maximum)
        except ConfigurationError as error:
            raise argparse.ArgumentTypeError(str(error)) from None

    return parse


def output_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--quiet", action="store_true", help="show warnings and errors only"
    )
    group.add_argument(
        "--debug",
        action="store_true",
        help="show diagnostics without credentials or HTTP payloads",
    )


def verification_options(parser):
    parser.add_argument(
        "--verify-host", help="TLS connection host (defaults to device host)"
    )
    parser.add_argument(
        "--verify-port",
        type=number(1, 65535),
        help="TLS port (defaults to device API port)",
    )
    parser.add_argument(
        "--verify-server-name", help="TLS SNI name when connecting by IP"
    )
    parser.add_argument(
        "--verify-cert-file",
        help="expected PEM leaf/fullchain (defaults to --cert-file)",
    )
    parser.add_argument(
        "--verify-wait",
        type=number(),
        help="seconds before first post-deploy check (device-specific default)",
    )
    parser.add_argument(
        "--verify-retries",
        type=number(),
        help="retries after first check (device-specific default)",
    )
    parser.add_argument(
        "--verify-interval",
        type=number(),
        default=30,
        help="seconds between TLS probes",
    )
    parser.add_argument(
        "--connect-timeout",
        type=number(1),
        default=10,
        help="connection timeout in seconds",
    )
    parser.add_argument(
        "--operation-timeout",
        type=number(1),
        default=900,
        help="whole deployment deadline in seconds, including verification",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="explicitly skip served-certificate verification; does not control API TLS trust",
    )


def driver_parser(subparsers, name):
    spec = DRIVERS[name]
    examples = {
        "idrac": "-H idrac.example.test -u root --password-file /run/secrets/idrac -c /certs/fullchain.pem -k /certs/privkey.pem",
        "glinet-kvm": "-H kvm.example.test -u admin --password-file /run/secrets/kvm -c /certs/cert.pem -k /certs/privkey.pem",
        "proxmox": "-H pve.example.test --api-token-file /run/secrets/pve --node pve -c /certs/fullchain.pem -k /certs/privkey.pem",
        "reolink": "-H 192.0.2.21 -u admin --password-file /run/secrets/camera -c /certs/cert.pem -k /certs/privkey.pem",
        "truenas-scale": "-H nas.example.test --api-key-file /run/secrets/nas --domain example.test -c /certs/fullchain.pem -k /certs/privkey.pem",
        "supermicro-ipmi": "-H bmc.example.test -u ADMIN --password-file /run/secrets/bmc -c /certs/fullchain.pem -k /certs/privkey.pem",
        "brother-printer": "-H printer.example.test -u admin --password-file /run/secrets/printer -c /certs/fullchain.pem -k /certs/privkey.pem",
        "docker-compose": "--compose-dir /srv/web --service caddy --verify-host web.example.test --verify-cert-file /certs/cert.pem",
        "shell-command": '--command \'cat "$KEY_FILE" "$CERT_FILE" | ssh -o BatchMode=yes -o StrictHostKeyChecking=yes cert-receiver@caddy.example.test install\' -c /certs/fullchain.pem -k /certs/privkey.pem --verify-host web.example.test',
    }
    parser = subparsers.add_parser(
        name,
        description=spec.description,
        help=spec.description,
        epilog="Certificate paths may come from any fetcher. No site config or Certbot is required. Exit: 0 success, 1 operation failed (device may have changed), 2 invalid arguments/configuration. Direct invocation always deploys. Example: certmgmt driver "
        + name
        + " "
        + examples[name],
    )
    if not spec.local:
        parser.add_argument(
            "-H",
            "--host",
            required=True,
            help="device IP or hostname; HTTPS URLs without a port/path also accepted",
        )
        parser.add_argument(
            "--port",
            type=number(1, 65535),
            default=spec.port,
            help="management API port",
        )
        if spec.auth == "password":
            parser.add_argument(
                "-u", "--username", required=True, help="device administrator username"
            )
        credential = spec.auth.replace("_", "-")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "-p" if spec.auth == "password" else "-a",
            "--" + credential,
            help="credential value (prefer a file or environment variable)",
        )
        group.add_argument(
            "--" + credential + "-file",
            help="read credential from a protected file, removing trailing newlines",
        )
        group.add_argument(
            "--" + credential + "-env",
            help="name of environment variable containing the credential",
        )
        parser.add_argument(
            "--api-tls-verify",
            action="store_true",
            help="validate management API CA and hostname (legacy default is disabled for appliance bootstrap)",
        )
        parser.add_argument(
            "--api-ca-file",
            help="CA bundle for management API; enables API TLS verification",
        )
    parser.add_argument(
        "-c",
        "--cert-file",
        required=not spec.local,
        help="PEM certificate: "
        + (
            "one RSA leaf"
            if spec.rsa_only and spec.leaf_only
            else "one leaf"
            if spec.leaf_only
            else "leaf followed by intermediates"
        ),
    )
    parser.add_argument(
        "-k",
        "--key-file",
        required=not spec.local,
        help="matching unencrypted PEM private key"
        + (" (RSA required)" if spec.rsa_only else ""),
    )
    if name == "proxmox":
        parser.add_argument("-n", "--node", required=True, help="Proxmox node name")
    elif name == "truenas-scale":
        parser.add_argument(
            "-D",
            "--domain",
            required=True,
            help="domain label used to name and clean up managed certificates",
        )
        parser.add_argument(
            "-l",
            "--leaf-cert-file",
            help="optional legacy leaf path; defaults to leaf extracted from --cert-file",
        )
    elif name == "supermicro-ipmi":
        parser.add_argument(
            "-m",
            "--model",
            choices=("X10", "X11"),
            help="board model; autodetected if omitted",
        )
        parser.add_argument(
            "--no-reboot",
            action="store_true",
            help="upload without BMC reboot; verification still requires the new cert to be served",
        )
    elif name == "docker-compose":
        parser.add_argument(
            "-d", "--compose-dir", required=True, help="Compose project directory"
        )
        parser.add_argument(
            "-s",
            "--service",
            action="append",
            help="service to recreate; repeat for multiple services (default: caddy)",
        )
    elif name == "shell-command":
        parser.add_argument(
            "--command",
            required=True,
            help="trusted Bash command; pipefail enabled, stdin closed; output is logged",
        )
        parser.add_argument(
            "-d",
            "--chdir",
            help="working directory; input paths are resolved before changing directory",
        )
    if spec.local:
        parser.add_argument(
            "--timeout",
            type=number(),
            default=120,
            help="local command deadline; 0 disables this deadline, not the whole-operation limit",
        )
    verification_options(parser)
    output_options(parser)


def selection_options(parser):
    parser.add_argument(
        "--config",
        default="/etc/letsencrypt/deploy-config.json",
        help="site JSON configuration",
    )
    parser.add_argument("--cert-name", help="select one configured certificate")
    parser.add_argument(
        "--target",
        action="append",
        help="select a target by name; repeat for multiple targets",
    )
    parser.add_argument(
        "--lineage", help="override certificate directory (requires --cert-name)"
    )
    output_options(parser)


def build_parser():
    parser = Parser(
        prog="certmgmt",
        description="Deploy certificates from any fetcher; optionally manage Certbot lineages.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(
        dest="command_name", required=True, parser_class=Parser
    )
    drivers = commands.add_parser("driver", help="run a standalone device driver")
    names = drivers.add_subparsers(
        dest="driver_name", required=True, parser_class=Parser
    )
    for name in DRIVERS:
        driver_parser(names, name)
    deploy = commands.add_parser(
        "deploy", help="deploy configured certificates to selected targets"
    )
    selection_options(deploy)
    deploy.add_argument(
        "--force",
        action="store_true",
        help="deploy even when the served leaf fingerprint matches (also use for chain-only updates)",
    )
    deploy.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and show selected targets without network requests or deployment",
    )
    check = commands.add_parser(
        "verify", help="check served certificates without changing devices"
    )
    selection_options(check)
    check.add_argument(
        "-H", "--host", help="standalone TLS connection host; bypasses site config"
    )
    check.add_argument(
        "--port", type=number(1, 65535), default=443, help="standalone TLS port"
    )
    check.add_argument(
        "-c",
        "--cert-file",
        help="expected PEM leaf/fullchain for standalone verification",
    )
    check.add_argument("--server-name", help="standalone TLS SNI name")
    check.add_argument(
        "--wait", type=number(), default=0, help="seconds before first probe"
    )
    check.add_argument(
        "--retries", type=number(), default=0, help="retries after first probe"
    )
    check.add_argument(
        "--interval", type=number(), default=30, help="seconds between probes"
    )
    check.add_argument(
        "--connect-timeout", type=number(1), default=10, help="connection timeout"
    )
    check.add_argument(
        "--operation-timeout",
        type=number(1),
        default=900,
        help="whole verification deadline",
    )
    hook = commands.add_parser(
        "hook", help="Certbot renewal hook using RENEWED_LINEAGE"
    )
    hook.add_argument("--config", default="/etc/letsencrypt/deploy-config.json")
    output_options(hook)
    sync = commands.add_parser(
        "sync",
        help="create/update Certbot certificates; never implicitly revoke or delete",
    )
    selection_options(sync)
    sync.add_argument(
        "--dry-run",
        action="store_true",
        help="show reconciliation actions without requesting certificates",
    )
    sync.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="apply the displayed certificate changes without prompting",
    )
    sync.add_argument("--certbot", default="certbot", help="Certbot executable")
    sync.add_argument(
        "--certbot-timeout",
        type=number(1),
        default=1800,
        help="deadline for each issuance request",
    )
    for name in ("revoke", "delete"):
        destructive = commands.add_parser(
            name, help=f"explicitly {name} a Certbot certificate"
        )
        destructive.add_argument("--cert-name", required=True)
        destructive.add_argument(
            "--yes",
            action="store_true",
            required=True,
            help="acknowledge this explicit destructive operation",
        )
        destructive.add_argument("--certbot", default="certbot")
        output_options(destructive)
    scan = commands.add_parser(
        "scan", help="inventory TLS certificates on specified subnets"
    )
    scan.add_argument("subnets", nargs="+", help="authorized CIDR subnet(s)")
    scan.add_argument(
        "-p", "--ports", default="443,8443,8006", help="comma-separated TCP ports"
    )
    scan.add_argument("-o", "--output", help="report file (default: stdout only)")
    scan.add_argument(
        "--config", help="mark certificates matching configured domains/lineages"
    )
    scan.add_argument(
        "--timeout", type=number(1), default=10, help="per-host TLS deadline"
    )
    scan.add_argument(
        "--scan-timeout", type=number(1), default=600, help="nmap deadline per subnet"
    )
    output_options(scan)
    install = commands.add_parser(
        "install",
        help="install a built wheel into a versioned environment and register its hook",
    )
    install.add_argument("--wheel", required=True, help="built CertMgmt wheel")
    install.add_argument(
        "--python",
        default=sys.executable,
        help="Python >=3.14.2 executable for installed environment",
    )
    install.add_argument(
        "--prefix", default="/opt/certmgmt", help="versioned application directory"
    )
    install.add_argument(
        "--config",
        default="/etc/letsencrypt/deploy-config.json",
        help="existing config to validate and preserve",
    )
    install.add_argument(
        "--hook-dir",
        default="/etc/letsencrypt/renewal-hooks/deploy",
        help="Certbot deploy-hook directory",
    )
    install.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and show installation paths without changes",
    )
    output_options(install)
    rollback = commands.add_parser(
        "rollback", help="restore the previous installed issuer tooling and deploy hook"
    )
    rollback.add_argument(
        "--prefix",
        default="/opt/certmgmt",
        help="application directory containing installation receipt",
    )
    rollback.add_argument(
        "--dry-run", action="store_true", help="show restoration without changes"
    )
    output_options(rollback)
    return parser


def main(argv=None):
    with cancellation():
        return run(argv)


def run(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    for index, value in enumerate(argv):
        if value in (
            "-p",
            "-a",
            "--password",
            "--api-key",
            "--api-token",
            "--command",
        ) and index + 1 < len(argv):
            protect(argv[index + 1])
        for option in ("--password=", "--api-key=", "--api-token=", "--command="):
            if value.startswith(option):
                protect(value[len(option) :])
    args = build_parser().parse_args(argv)
    configure_logging(getattr(args, "quiet", False), getattr(args, "debug", False))
    try:
        if sys.version_info < (3, 14, 2):
            raise ConfigurationError("CertMgmt requires Python 3.14.2 or newer")
        command = args.command_name
        if command == "driver":
            from .registry import deploy, prepare

            deploy(prepare(args.driver_name, vars(args)))
        elif command == "verify" and args.host:
            from .certificates import VerifyEndpoint, hostname, verify
            from .runtime import deadline

            if not args.cert_file:
                raise ConfigurationError("standalone verification needs --cert-file")
            with deadline(args.operation_timeout):
                verify(
                    VerifyEndpoint(
                        hostname(args.host),
                        args.port,
                        args.cert_file,
                        hostname(args.server_name) if args.server_name else None,
                    ),
                    wait=args.wait,
                    retries=args.retries,
                    interval=args.interval,
                    timeout=args.connect_timeout,
                )
        elif command in ("deploy", "verify", "hook"):
            from .orchestration import dispatch

            if command == "hook":
                import json
                import os
                from pathlib import Path

                args.config = os.environ.get("CERTMGMT_CONFIG_OVERRIDE", args.config)
                result = 1
                try:
                    result = dispatch(args)
                    return result
                finally:
                    result_file = os.environ.get("CERTMGMT_HOOK_RESULT")
                    if result_file:
                        Path(result_file).write_text(
                            json.dumps(
                                {
                                    "cert_name": Path(
                                        os.environ.get("RENEWED_LINEAGE", "")
                                    ).name,
                                    "exit_code": result,
                                }
                            )
                        )
            return dispatch(args)
        elif command in ("sync", "revoke", "delete"):
            from .reconcile import run

            return run(args)
        elif command == "scan":
            from .scanner import run

            return run(args)
        elif command == "install":
            from .installer import run

            return run(args)
        elif command == "rollback":
            from .installer import rollback

            return rollback(args)
        return 0
    except ConfigurationError as error:
        logging.error("Invalid configuration: %s", error)
        return 2
    except (DeploymentError, OperationTimeout) as error:
        logging.error("Operation failed: %s", error)
        return 1
    except KeyboardInterrupt:
        logging.error("Interrupted; completed remote changes may remain")
        return 130
    except OperationCancelled as error:
        logging.error("Terminated; completed remote changes may remain")
        return 128 + error.signum
    except Exception as error:
        # Unexpected library/transport errors must not expose request bodies or secrets.
        logging.error(
            "Operation failed (%s); completed remote changes may remain",
            type(error).__name__,
        )
        return 1
