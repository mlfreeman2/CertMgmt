import sys
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@pytest.fixture(scope="session", autouse=True)
def launcher_python():
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CERTMGMT_PYTHON", sys.executable)
        yield


@pytest.fixture(scope="session")
def pem_pairs(tmp_path_factory):
    directory = tmp_path_factory.mktemp("certificates with spaces")
    pairs = {}
    for name in ("rsa", "ec", "other", "expired"):
        key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if name == "rsa"
            else ec.generate_private_key(ec.SECP256R1())
        )
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "device.example.test")]
        )
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=3))
            .not_valid_after(now + timedelta(days=-1 if name == "expired" else 30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("device.example.test")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        pairs[name] = (str(cert_path), str(key_path))
    chain = directory / "chain.pem"
    chain.write_text(
        (directory / "rsa.pem").read_text() + (directory / "ec.pem").read_text()
    )
    pairs["chain"] = (str(chain), pairs["rsa"][1])
    return pairs
