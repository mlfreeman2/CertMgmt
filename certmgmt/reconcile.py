"""Use supported Certbot updates; never destroy a lineage to replace a cert."""

import logging
from pathlib import Path

from . import config
from .certificates import read_certificates
from .errors import ConfigurationError, DeploymentError
from .runtime import run_command

log = logging.getLogger(__name__)


def plan(site, cert_name=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    actions = []
    for name, cert, _targets in config.selected(site, cert_name):
        domains = cert.get("domains", [])
        if not domains:
            continue
        path = site.lineage(name) / "cert.pem"
        reasons = []
        if not path.exists():
            reasons.append("certificate missing")
        else:
            leaf = read_certificates(path)[0]
            try:
                actual_domains = leaf.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                actual_domains = []
            if set(actual_domains) != set(domains):
                reasons.append("domains differ")
            key = leaf.public_key()
            actual_type = (
                "rsa"
                if isinstance(key, rsa.RSAPublicKey)
                else "ecdsa"
                if isinstance(key, ec.EllipticCurvePublicKey)
                else "unknown"
            )
            if actual_type != cert.get("key_type", "ecdsa"):
                reasons.append("key type differs")
            if (
                actual_type == "rsa"
                and cert.get("key_type", "ecdsa") == "rsa"
                and cert.get("key_size") is not None
                and key.key_size != int(cert["key_size"])
            ):
                reasons.append("RSA key size differs")
        actions.append((name, cert, reasons))
    return actions


def run(args):
    if args.command_name in ("revoke", "delete"):
        name = config.certificate_name(args.cert_name)
        command = [
            args.certbot,
            args.command_name,
            "--cert-name",
            name,
            "--non-interactive",
        ]
        if args.command_name == "revoke":
            command += ["--no-delete-after-revoke"]
        run_command(command, timeout=300, report=True)
        return 0
    if args.target or args.lineage:
        raise ConfigurationError(
            "sync selects certificates; --target/--lineage belong to deploy or verify"
        )
    site = config.load(args.config)
    actions = plan(site, args.cert_name)
    changes = [(name, cert, reasons) for name, cert, reasons in actions if reasons]
    for name, _cert, reasons in actions:
        log.info(
            "%s: %s",
            name,
            ", ".join(reasons) if reasons else "already matches configuration",
        )
    if args.dry_run or not changes:
        return 0
    import json
    import os
    import sys
    import tempfile

    credentials = site.resolve(
        site.data.get(
            "cloudflare_credentials", str(site.certbot_dir / "cloudflare.ini")
        )
    )
    if not credentials.is_file():
        raise ConfigurationError(f"Cloudflare credentials are missing: {credentials}")
    hook = site.certbot_dir / "renewal-hooks/deploy/cert-dispatcher.sh"
    if not hook.is_file() or "# Managed by CertMgmt Python" not in hook.read_text():
        raise ConfigurationError(
            "sync requires the Python-managed Certbot hook; run certmgmt install first"
        )
    if not args.yes:
        if not sys.stdin.isatty():
            raise ConfigurationError(
                "sync needs --yes in noninteractive use; preview with --dry-run"
            )
        if input("Apply the displayed certificate changes? [y/N] ").lower() != "y":
            log.info("No changes applied")
            return 0
    failed = 0
    for name, cert, _reasons in changes:
        command = [
            args.certbot,
            "certonly",
            "--cert-name",
            name,
            "--config-dir",
            str(site.certbot_dir),
            "--dns-cloudflare",
            "--dns-cloudflare-credentials",
            str(credentials),
            "--dns-cloudflare-propagation-seconds",
            str(site.data.get("cloudflare_propagation_seconds", 60)),
            "--key-type",
            cert.get("key_type", "ecdsa"),
            "--non-interactive",
            "--agree-tos",
            "--force-renewal",
            "--renew-with-new-domains",
            "--deploy-hook",
            str(hook),
        ]
        if cert.get("key_type", "ecdsa") == "rsa" and cert.get("key_size"):
            command += ["--rsa-key-size", str(cert["key_size"])]
        if site.data.get("email"):
            command += ["--email", site.data["email"]]
        else:
            command += ["--register-unsafely-without-email"]
        for domain in cert["domains"]:
            command += ["-d", domain]
        # Certbot can exit zero when a deploy hook failed. Require an explicit
        # result from our hook, bound to this certificate and this invocation.
        with tempfile.TemporaryDirectory(prefix="certmgmt-hook-") as temporary:
            result_file = Path(temporary) / "result.json"
            env = dict(
                os.environ,
                CERTMGMT_CONFIG_OVERRIDE=str(site.path),
                CERTMGMT_HOOK_RESULT=str(result_file),
            )
            try:
                result = run_command(
                    command,
                    timeout=args.certbot_timeout,
                    env=env,
                    check=False,
                    report=True,
                )
            except (DeploymentError, OSError) as error:
                failed += 1
                log.error(
                    "Certificate update failed for %s (%s)", name, type(error).__name__
                )
                continue
            try:
                outcome = json.loads(result_file.read_text())
                hook_ok = (
                    outcome.get("cert_name") == name and outcome.get("exit_code") == 0
                )
            except OSError, ValueError, AttributeError:
                hook_ok = False
        if result.returncode or not hook_ok:
            failed += 1
            log.error(
                "Certificate issuance or deployment failed for %s; no revoke/delete was attempted",
                name,
            )
        else:
            log.info("Certificate update completed for %s", name)
    return 1 if failed else 0
