"""Certbot-independent fan-out; a small adapter handles Certbot's environment."""

import logging
import os
from pathlib import Path

from . import config
from .certificates import verify
from .errors import ConfigurationError, DeploymentError, OperationTimeout
from .registry import already_current, deploy, integer, prepare
from .runtime import configure_logging, deadline, protect

log = logging.getLogger(__name__)


def ping(url, suffix, body=""):
    if not url:
        return
    import requests

    protect(url)
    try:
        with deadline(15):
            requests.post(
                url + suffix, data=body.encode(), timeout=(5, 5)
            ).raise_for_status()
    except Exception, OperationTimeout:
        log.warning("Healthchecks notification failed (non-fatal)")


def dispatch(args):
    site = config.load(args.config)
    log_file = site.data.get("log_file")
    configure_logging(
        args.quiet, args.debug, site.resolve(log_file) if log_file else None
    )
    cert_name = getattr(args, "cert_name", None)
    lineage = getattr(args, "lineage", None)
    if args.command_name == "hook":
        lineage = os.environ.get("RENEWED_LINEAGE")
        if not lineage:
            raise ConfigurationError("RENEWED_LINEAGE is required for the Certbot hook")
        cert_name = Path(lineage).name
        if cert_name not in site.data["certs"]:
            log.info("No configured deployment for renewed certificate %s", cert_name)
            return 0
    if lineage and not cert_name:
        raise ConfigurationError("--lineage requires --cert-name")
    groups = config.selected(site, cert_name, getattr(args, "target", None))
    checking = args.command_name == "verify"
    prepared = []
    # Prepare the entire selected batch before pings, probes, or device mutations.
    for name, cert, targets in groups:
        entries = []
        for target in targets:
            values = config.target_options(site, name, target, lineage)
            if checking:
                request = config.verification_endpoints(target["driver"], values)
                values["connect_timeout"] = integer(
                    values.get("connect_timeout", 10), "connect_timeout", 1
                )
                values["operation_timeout"] = integer(
                    values.get("operation_timeout", 900), "operation_timeout", 1
                )
            else:
                request = prepare(target["driver"], values)
            entries.append((target["name"], values, request))
        prepared.append((name, cert, entries))
    if getattr(args, "dry_run", False):
        for name, _cert, entries in prepared:
            for target_name, _values, _request in entries:
                log.info("Would deploy %s to %s", name, target_name)
        return 0
    failed = 0
    passed = 0
    skipped = 0
    for name, cert, entries in prepared:
        if not entries:
            continue
        url = cert.get("healthchecks_url") if not checking else None
        ping(url, "/start")
        failures = []
        try:
            for target_name, values, request in entries:
                try:
                    if checking:
                        if not request:
                            log.info(
                                "SKIP %s: verification explicitly disabled", target_name
                            )
                            skipped += 1
                            continue
                        with deadline(values["operation_timeout"]):
                            for endpoint in request:
                                verify(endpoint, timeout=values["connect_timeout"])
                    elif not getattr(args, "force", False) and already_current(request):
                        log.info(
                            "SKIP %s: already serving expected leaf certificate",
                            target_name,
                        )
                        skipped += 1
                        continue
                    else:
                        deploy(request)
                    passed += 1
                    log.info("PASS %s", target_name)
                except (Exception, OperationTimeout) as error:
                    failed += 1
                    failures.append(target_name)
                    log.error(
                        "FAIL %s: %s; remote changes may remain",
                        target_name,
                        str(error)
                        if isinstance(
                            error,
                            (ConfigurationError, DeploymentError, OperationTimeout),
                        )
                        else type(error).__name__,
                    )
        except BaseException:
            ping(url, "/fail", "Certificate deployment interrupted")
            raise
        ping(
            url,
            "/fail" if failures else "",
            "Failed targets: " + ", ".join(failures)
            if failures
            else "Certificate deployment completed",
        )
    log.info("Result: %s passed, %s skipped, %s failed", passed, skipped, failed)
    return 1 if failed else 0
