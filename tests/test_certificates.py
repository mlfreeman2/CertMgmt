import socket
import ssl
import threading

import pytest

from certmgmt.certificates import (
    VerifyEndpoint,
    fingerprint,
    hostname,
    https_url,
    validate_pair,
    verify,
)
from certmgmt.errors import ConfigurationError, DeploymentError


def test_pair_validation(pem_pairs):
    validate_pair(*pem_pairs["rsa"], rsa_only=True, leaf_only=True)
    validate_pair(*pem_pairs["chain"])
    assert fingerprint(pem_pairs["chain"][0]) == fingerprint(pem_pairs["rsa"][0])
    for pair, kwargs in [
        (pem_pairs["ec"], {"rsa_only": True}),
        (pem_pairs["chain"], {"leaf_only": True}),
        ((pem_pairs["rsa"][0], pem_pairs["ec"][1]), {}),
        (pem_pairs["expired"], {}),
    ]:
        with pytest.raises(ConfigurationError):
            validate_pair(*pair, **kwargs)


@pytest.mark.parametrize(
    "value",
    [
        "http://host",
        "https://u:p@host",
        "host/path",
        "host:443",
        "host:nope",
        "https://[broken",
        "white space",
        "host:0",
    ],
)
def test_bad_host(value):
    with pytest.raises(ConfigurationError):
        hostname(value)


def test_host_normalization():
    assert hostname("https://EXAMPLE.test/") == "example.test"
    assert https_url("::1", 8443) == "https://[::1]:8443"


def test_real_tls_pin_and_sni(pem_pairs):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*pem_pairs["rsa"])
    names = []
    context.sni_callback = lambda connection, name, context: names.append(name)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    port = listener.getsockname()[1]
    errors = []

    def serve():
        try:
            for _ in range(2):
                connection, _ = listener.accept()
                with context.wrap_socket(connection, server_side=True):
                    pass
        except Exception as error:
            errors.append(error)
        finally:
            listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    verify(
        VerifyEndpoint("127.0.0.1", port, pem_pairs["rsa"][0], "device.example.test")
    )
    with pytest.raises(DeploymentError, match="fingerprint mismatch"):
        verify(
            VerifyEndpoint(
                "127.0.0.1", port, pem_pairs["other"][0], "device.example.test"
            )
        )
    worker.join(timeout=6)
    assert not worker.is_alive() and not errors
    assert names == ["device.example.test"] * 2
