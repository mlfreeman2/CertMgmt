"""Certificate formats and TLS verification, shared by every driver."""

import hashlib
import ipaddress
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .errors import ConfigurationError, DeploymentError

log = logging.getLogger(__name__)


def hostname(value: str) -> str:
    """Accept a plain name/IP or HTTPS URL, but reject embedded credentials/paths."""
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ConfigurationError("host must be a nonempty hostname or IP")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        port = parsed.port
    except ValueError:
        raise ConfigurationError("invalid host; supply the port separately") from None
    if (
        parsed.scheme not in ("", "https")
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
    ):
        raise ConfigurationError(
            "host must not contain credentials, a port, or a path; use --port"
        )
    return parsed.hostname


def https_url(host, port=443):
    host = hostname(host)
    return f"https://{'[' + host + ']' if ':' in host else host}:{port}"


def read_certificates(path):
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
        if not certs:
            raise ValueError("no certificates")
        return certs
    except (OSError, ValueError) as error:
        raise ConfigurationError(
            f"cannot read PEM certificates from {path}: {error}"
        ) from None


def fingerprint(path):
    from cryptography.hazmat.primitives import hashes

    return read_certificates(path)[0].fingerprint(hashes.SHA256()).hex()


def validate_pair(cert_file, key_file, *, rsa_only=False, leaf_only=False):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    certs = read_certificates(cert_file)
    try:
        key = serialization.load_pem_private_key(
            Path(key_file).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as error:
        raise ConfigurationError(
            f"cannot read unencrypted private key from {key_file}: {type(error).__name__}"
        ) from None

    def encode(key):
        return key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    if encode(key.public_key()) != encode(certs[0].public_key()):
        raise ConfigurationError("private key does not match the leaf certificate")
    if rsa_only and not isinstance(key, rsa.RSAPrivateKey):
        raise ConfigurationError("this device requires an RSA certificate and key")
    if leaf_only and len(certs) != 1:
        raise ConfigurationError(
            "this device requires a single leaf certificate, not a full chain"
        )
    now = datetime.now(UTC)
    if not certs[0].not_valid_before_utc <= now < certs[0].not_valid_after_utc:
        raise ConfigurationError("leaf certificate is expired or not yet valid")
    return certs


@dataclass(frozen=True)
class VerifyEndpoint:
    host: str
    port: int
    cert_file: str
    server_name: str | None = None


def served_certificate(host, port=443, server_name=None, timeout=10):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # This observes a pinned leaf, independently of API CA/hostname validation.
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        with context.wrap_socket(
            connection, server_hostname=server_name or host
        ) as tls:
            return tls.getpeercert(binary_form=True)


def verify(endpoint: VerifyEndpoint, *, wait=0, retries=0, interval=30, timeout=10):
    expected = fingerprint(endpoint.cert_file)
    if wait:
        time.sleep(wait)
    last = "no certificate returned"
    for attempt in range(retries + 1):
        try:
            actual = hashlib.sha256(
                served_certificate(
                    endpoint.host, endpoint.port, endpoint.server_name, timeout
                )
            ).hexdigest()
            if actual == expected:
                log.info(
                    "Verified %s:%s: SHA256 %s", endpoint.host, endpoint.port, actual
                )
                return
            last = f"fingerprint mismatch (expected {expected}, served {actual})"
        except (OSError, ValueError) as error:
            last = f"TLS connection failed ({type(error).__name__})"
        if attempt < retries:
            time.sleep(interval)
    raise DeploymentError(
        f"verification failed for {endpoint.host}:{endpoint.port}: {last}"
    )
