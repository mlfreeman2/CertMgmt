"""Validate site configuration before any side effects."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .certificates import VerifyEndpoint, fingerprint, hostname
from .errors import ConfigurationError
from .registry import DEFAULTS, DRIVERS, integer, text

TOP_KEYS = {
    "site_name",
    "email",
    "cert_driver_dir",
    "log_file",
    "certs",
    "certbot_config_dir",
    "cloudflare_credentials",
    "cloudflare_propagation_seconds",
}
CERT_KEYS = {"domains", "key_type", "key_size", "healthchecks_url", "targets"}
TARGET_KEYS = (
    set(DEFAULTS)
    | {"name", "driver", "ip", "verify", "services", "service_name"}
    | {
        kind + suffix
        for kind in ("password", "api_key", "api_token")
        for suffix in ("_file", "_env")
    }
)


def fields(value, allowed, label):
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be an object")
    unknown = set(value) - allowed
    unknown = {key for key in unknown if not key.startswith("_")}
    if unknown:
        raise ConfigurationError(
            f"unknown fields in {label}: {', '.join(sorted(unknown))}"
        )


def certificate_name(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)
        or ".." in value
    ):
        raise ConfigurationError(
            "certificate name must be a simple Certbot lineage name"
        )
    return value


@dataclass
class Site:
    path: Path
    data: dict

    @property
    def certbot_dir(self):
        return self.resolve(self.data.get("certbot_config_dir", "/etc/letsencrypt"))

    def resolve(self, value):
        path = Path(text(value, "path"))
        return path if path.is_absolute() else (self.path.parent / path).resolve()

    def lineage(self, name, override=None):
        return (
            Path(override).resolve() if override else self.certbot_dir / "live" / name
        )


def load(path) -> Site:
    path = Path(path).resolve()
    try:
        data = json.loads(path.read_text())
    except OSError, ValueError:
        raise ConfigurationError(f"cannot read valid JSON config: {path}") from None
    fields(data, TOP_KEYS, "config")
    certs = data.get("certs")
    if not isinstance(certs, dict):
        raise ConfigurationError("certs must be an object")
    for name, cert in certs.items():
        certificate_name(name)
        fields(cert, CERT_KEYS, f"certificate {name}")
        domains = cert.get("domains", [])
        if not isinstance(domains, list) or any(
            not isinstance(d, str)
            or not d
            or any(c.isspace() for c in d)
            or d.startswith("-")
            for d in domains
        ):
            raise ConfigurationError(
                f"domains for {name} must be an array of DNS names"
            )
        if len(set(domains)) != len(domains):
            raise ConfigurationError(f"duplicate domains for {name}")
        if cert.get("key_type", "ecdsa") not in ("rsa", "ecdsa"):
            raise ConfigurationError(f"invalid key_type for {name}")
        if cert.get("key_size") is not None:
            integer(cert["key_size"], "key_size", 2048, 16384)
        targets = cert.get("targets", [])
        if not isinstance(targets, list):
            raise ConfigurationError(f"targets for {name} must be an array")
        names = set()
        for target in targets:
            fields(target, TARGET_KEYS, f"target in {name}")
            target_name = text(target.get("name"), "target name")
            if target_name in names:
                raise ConfigurationError(f"duplicate target {target_name} in {name}")
            names.add(target_name)
            if (
                not isinstance(target.get("driver"), str)
                or target["driver"] not in DRIVERS
            ):
                raise ConfigurationError(f"unknown driver for {target_name}")
            if "verify" in target and type(target["verify"]) is not bool:
                raise ConfigurationError(f"verify for {target_name} must be a boolean")
            for flag in ("no_verify", "no_reboot", "api_tls_verify"):
                if flag in target and type(target[flag]) is not bool:
                    raise ConfigurationError(
                        f"{flag} for {target_name} must be a boolean"
                    )
            if "ip" in target and "host" in target:
                raise ConfigurationError(
                    f"{target_name}: choose host or legacy ip, not both"
                )
        healthcheck = cert.get("healthchecks_url")
        if healthcheck is not None and (
            not isinstance(healthcheck, str) or not healthcheck.startswith("https://")
        ):
            raise ConfigurationError(
                f"healthchecks_url for {name} must be an HTTPS URL"
            )
    site = Site(path, data)
    site.certbot_dir  # Validate the configured path before a later mutation.
    if data.get("log_file") is not None:
        site.resolve(data["log_file"])
    integer(
        data.get("cloudflare_propagation_seconds", 60),
        "cloudflare_propagation_seconds",
        0,
        3600,
    )
    return site


def selected(site, cert_name=None, targets=None):
    certs = site.data["certs"]
    if cert_name is not None and cert_name not in certs:
        raise ConfigurationError(f"certificate is not configured: {cert_name}")
    wanted = set(targets or [])
    found = set()
    result = []
    for name, cert in certs.items():
        if cert_name is not None and name != cert_name:
            continue
        chosen = [
            target
            for target in cert.get("targets", [])
            if not wanted or target["name"] in wanted
        ]
        found.update(target["name"] for target in chosen)
        result.append((name, cert, chosen))
    if wanted - found:
        raise ConfigurationError(
            "targets are not configured in selection: "
            + ", ".join(sorted(wanted - found))
        )
    return result


def target_options(site, name, target, lineage=None):
    options = {
        key: value
        for key, value in target.items()
        if key in DEFAULTS or key.endswith(("_file", "_env"))
    }
    spec = DRIVERS[target["driver"]]
    if "ip" in target:
        options["host"] = target["ip"]
    options["no_verify"] = target.get("verify") is False or target.get(
        "no_verify", False
    )
    if "services" in target or "service_name" in target:
        options["service"] = target.get(
            "services", [target.get("service_name", "caddy")]
        )
    directory = site.lineage(name, lineage)
    if target["driver"] != "docker-compose":
        options.setdefault(
            "cert_file", "cert.pem" if spec.leaf_only else "fullchain.pem"
        )
        options.setdefault("key_file", "privkey.pem")
    options.setdefault("verify_cert_file", options.get("cert_file", "cert.pem"))
    for field in ("cert_file", "key_file", "verify_cert_file", "leaf_cert_file"):
        if options.get(field) is not None:
            relative = Path(text(options[field], field))
            if relative.is_absolute() or ".." in relative.parts:
                raise ConfigurationError(
                    f"configured {field} must be relative to its lineage"
                )
            options[field] = str(directory / relative)
    for field in (
        "password_file",
        "api_key_file",
        "api_token_file",
        "api_ca_file",
        "compose_dir",
        "chdir",
    ):
        if options.get(field) is not None:
            options[field] = str(site.resolve(options[field]))
    return options


def verification_endpoints(driver, options):
    if options.get("no_verify"):
        return ()
    spec = DRIVERS[driver]
    host = hostname(
        text(options.get("verify_host") or options.get("host"), "verify_host")
    )
    expected = text(
        options.get("verify_cert_file") or options.get("cert_file"), "verify_cert_file"
    )
    fingerprint(expected)
    ports = options.get(
        "verify_ports", [options.get("verify_port", options.get("port", spec.port))]
    )
    if not isinstance(ports, list) or not ports:
        raise ConfigurationError("verify_ports must be a nonempty array")
    sni = options.get("verify_server_name")
    return tuple(
        VerifyEndpoint(
            host,
            integer(port, "verify_port", 1, 65535),
            expected,
            hostname(sni) if sni else None,
        )
        for port in ports
    )
