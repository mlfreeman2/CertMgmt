"""TLS inventory using nmap discovery and the common TLS/certificate code."""

import fnmatch
import hashlib
import ipaddress
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from . import config
from .certificates import fingerprint, served_certificate
from .errors import ConfigurationError, DeploymentError, OperationTimeout
from .registry import integer
from .runtime import deadline, run_command

log = logging.getLogger(__name__)


def run(args):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    subnets = []
    for subnet in args.subnets:
        try:
            subnets.append(str(ipaddress.ip_network(subnet, strict=False)))
        except ValueError:
            raise ConfigurationError(f"invalid subnet: {subnet}") from None
    ports = ",".join(
        str(integer(port, "port", 1, 65535)) for port in args.ports.split(",")
    )
    managed_fps = set()
    managed_domains = set()
    if args.config:
        site = config.load(args.config)
        for name, cert, _targets in config.selected(site):
            managed_domains.update(cert.get("domains", []))
            path = site.lineage(name) / "cert.pem"
            if path.exists():
                managed_fps.add(fingerprint(path))
    rows = []
    failed = False
    endpoints = set()
    for subnet in subnets:
        result = run_command(
            [
                "nmap",
                *(["-6"] if ":" in subnet else []),
                "-sT",
                "-p",
                ports,
                "--open",
                "-T4",
                "-oX",
                "-",
                subnet,
            ],
            timeout=args.scan_timeout,
            check=False,
        )
        if result.returncode:
            failed = True
            log.error("nmap failed for %s", subnet)
            continue
        try:
            tree = ET.fromstring(result.stdout)
        except ET.ParseError:
            raise DeploymentError("nmap returned malformed XML") from None
        for host in tree.findall("host"):
            address = next(
                (
                    a.get("addr")
                    for a in host.findall("address")
                    if a.get("addrtype") in ("ipv4", "ipv6")
                ),
                None,
            )
            if not address:
                continue
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    endpoints.add((address, int(port.get("portid"))))
    for host, port in sorted(endpoints):
        try:
            with deadline(args.timeout):
                der = served_certificate(host, port, timeout=args.timeout)
            cert = x509.load_der_x509_certificate(der)
            fp = hashlib.sha256(der).hexdigest()
            try:
                names = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            match = (
                "fingerprint"
                if fp in managed_fps
                else "domain"
                if any(
                    fnmatch.fnmatchcase(name, pattern)
                    for name in names
                    for pattern in managed_domains
                )
                else None
            )
            rows.append(
                {
                    "host": host,
                    "port": port,
                    "sha256": fp,
                    "common_name": cn[0].value if cn else "",
                    "dns_names": names,
                    "issuer": cert.issuer.rfc4514_string(),
                    "expires": cert.not_valid_after_utc.isoformat(),
                    "managed_match": match,
                }
            )
        except OSError, ValueError, OperationTimeout:
            rows.append(
                {
                    "host": host,
                    "port": port,
                    "error": "TLS certificate could not be read",
                }
            )
            failed = True
    output = "\n".join(json.dumps(row, sort_keys=True) for row in rows) + (
        "\n" if rows else ""
    )
    print(output, end="")
    if args.output:
        Path(args.output).write_text(output)
    return 1 if failed else 0
