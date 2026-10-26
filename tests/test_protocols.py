import asyncio
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12

from certmgmt.certificates import read_certificates
from certmgmt.drivers import brother, dispatch, http, reolink, supermicro, truenas
from certmgmt.errors import DeploymentError
from certmgmt.registry import prepare


class Response:
    def __init__(self, data=None, text="", status=200, headers=None):
        self.data, self.text, self.status_code = data, text, status
        self.ok = 200 <= status < 400
        self.headers = headers or {}

    def json(self):
        return self.data


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        import requests

        self.cookies = requests.cookies.RequestsCookieJar()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def request(self, method, url, *args, **kwargs):
        self.calls.append((method, url, args, kwargs))
        return next(self.responses)

    def get(self, url, *args, **kwargs):
        return self.request("GET", url, *args, **kwargs)

    def post(self, url, *args, **kwargs):
        return self.request("POST", url, *args, **kwargs)


def options(driver, pem_pairs, **changes):
    cert, key = pem_pairs["rsa"]
    return prepare(
        driver,
        {
            "host": "device.example.test",
            "username": "admin",
            "password": "fixture-password",
            "api_token": "token",
            "api_key": "key",
            "node": "pve",
            "domain": "example.test",
            "cert_file": cert,
            "key_file": key,
            "no_verify": True,
        }
        | changes,
    ).options


@pytest.mark.parametrize(
    "driver,count", [("idrac", 3), ("glinet-kvm", 1), ("proxmox", 1)]
)
def test_http_upload_contracts(driver, count, pem_pairs, monkeypatch):
    session = Session([Response({"ok": True}) for _ in range(count)])
    monkeypatch.setattr(http, "Session", lambda opts: session)
    opts = options(driver, pem_pairs)
    dispatch.apply(driver, opts)
    assert len(session.calls) == count
    if driver == "idrac":
        assert session.auth == ("admin", "fixture-password")
        assert session.calls[0][3]["json"] == {
            "SSLKeyString": Path(opts.key_file).read_text()
        }
        assert session.calls[1][3]["json"]["CertificateType"] == "Server"
        assert session.calls[2][1].endswith("DelliDRACCardService.iDRACReset")
    elif driver == "glinet-kvm":
        assert session.calls[0][1].endswith("/api/system/ssl_cert")
        assert session.calls[0][3]["headers"]["X-KVMD-Passwd"] == "fixture-password"
        assert (
            session.calls[0][3]["json"]["ssl_cert"] == Path(opts.cert_file).read_text()
        )
    else:
        assert session.calls[0][1].endswith("/nodes/pve/certificates/custom")
        assert session.calls[0][3]["headers"]["Authorization"] == "PVEAPIToken=token"
        assert session.calls[0][3]["data"]["restart"] == 1


@pytest.mark.parametrize(
    "responses",
    [[Response(status=500)], [Response(), Response(), Response(status=500)]],
)
def test_idrac_failure_stops_sequence(responses, pem_pairs, monkeypatch):
    session = Session(responses)
    monkeypatch.setattr(http, "Session", lambda opts: session)
    with pytest.raises(DeploymentError):
        dispatch.apply("idrac", options("idrac", pem_pairs))
    assert len(session.calls) == len(responses)


@pytest.mark.parametrize(
    "verify,ca,expected",
    [(False, None, False), (True, None, True), (False, "/bundle", "/bundle")],
)
def test_api_tls_policy_overrides_legacy_call_flags(monkeypatch, verify, ca, expected):
    import requests

    calls = []
    monkeypatch.setattr(
        requests.Session, "request", lambda *args, **kwargs: calls.append(kwargs)
    )
    with http.Session(
        SimpleNamespace(connect_timeout=7, api_ca_file=ca, api_tls_verify=verify)
    ) as session:
        session.get("https://example.test", verify=False, timeout=15)
        assert not session.trust_env
    assert len(calls) == 1
    assert calls[0]["verify"] == expected
    assert calls[0]["timeout"] == (7, 15)


@pytest.mark.parametrize("reply", [[{"code": 0}], [{"code": 1}], [], {}])
def test_reolink_upload_and_malformed_response(reply, pem_pairs, monkeypatch):
    session = Session(
        [
            Response([{"code": 0, "value": {"Token": {"name": "session-secret"}}}]),
            Response(reply),
            Response(),
        ]
    )
    monkeypatch.setattr(reolink.time, "sleep", lambda seconds: None)
    opts = options("reolink", pem_pairs)
    if reply == [{"code": 0}]:
        reolink.apply(session, "https://device", opts)
    else:
        with pytest.raises(DeploymentError):
            reolink.apply(session, "https://device", opts)
    data = session.calls[1][3]["json"][0]["param"]["importCertificate"]
    assert base64.b64decode(data["key"]["content"]) == Path(opts.key_file).read_bytes()
    assert data["crt"]["size"] == Path(opts.cert_file).stat().st_size
    assert session.calls[-1][3]["params"]["cmd"] == "Logout"


def test_truenas_ids_ping_and_managed_cleanup(pem_pairs, monkeypatch):
    opts = options("truenas-scale", pem_pairs)
    fp = ":".join(
        f"{byte:02X}"
        for byte in read_certificates(opts.cert_file)[0].fingerprint(hashes.SHA1())
    )

    class Socket:
        def __init__(self):
            self.sent, self.pending = [], []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def send(self, message):
            message = json.loads(message)
            self.sent.append(message)
            if message["msg"] == "connect":
                self.pending += [
                    {"msg": "ping", "id": "keepalive"},
                    {"msg": "connected"},
                ]
            elif message["msg"] == "method":
                result = {
                    "auth": True,
                    "query": [{"id": 2, "fingerprint": fp}],
                    "all": [
                        {"id": 1, "name": "LetsEncrypt-example-test-old"},
                        {"id": 2, "name": "LetsEncrypt-example-test-new"},
                        {"id": 3, "name": "unrelated"},
                    ],
                }.get(message["id"], True)
                self.pending += [
                    {"id": "unrelated-event"},
                    {"id": message["id"], "result": result},
                ]

        async def recv(self):
            return json.dumps(self.pending.pop(0))

    socket = Socket()
    import websockets

    monkeypatch.setattr(websockets, "connect", lambda *args, **kwargs: socket)

    async def no_sleep(seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    truenas.apply(opts)
    assert {"msg": "pong", "id": "keepalive"} in socket.sent
    deletions = [
        message
        for message in socket.sent
        if message.get("method") == "certificate.delete"
    ]
    assert [message["params"] for message in deletions] == [[1]]
    activation = next(
        message for message in socket.sent if message.get("id") == "activate"
    )
    assert activation["params"] == [{"ui_certificate": 2}]
    assert socket.sent[-1]["method"] == "system.general.ui_restart"


@pytest.mark.parametrize(
    "updater", [supermicro.IPMIX10Updater, supermicro.IPMIX11Updater]
)
def test_supermicro_no_existing_certificate_and_upload(updater, pem_pairs, monkeypatch):
    session = Session(
        [
            Response(text='<IPMI><SSL_INFO><STATUS CERT_EXIST="0"/></SSL_INFO></IPMI>'),
            Response(text="CONFPAGE_RESET", headers={"Content-Type": "text/html"}),
        ]
    )
    device = updater(session, "https://device")
    monkeypatch.setattr(device, "get_xhr_headers", lambda name: {})
    monkeypatch.setattr(device, "get_csrf_headers", lambda name: {})
    monkeypatch.setattr(device, "get_csrf_token", lambda name: "csrf")
    assert device.get_ipmi_cert_info() == {
        "has_cert": False,
        "valid_from": None,
        "valid_until": None,
    }
    cert, key = pem_pairs["rsa"]
    assert device.upload_cert(key, cert)
    assert session.calls[-1][3]["files"]


def test_brother_pkcs12(pem_pairs):
    device = brother.BrotherPrinterUpdater(Session([]), "https://device")
    data = device.build_p12(*pem_pairs["chain"])
    key, cert, chain = pkcs12.load_key_and_certificates(data, b"")
    assert key is not None and cert == read_certificates(pem_pairs["rsa"][0])[0]
    assert len(chain) == 1


def test_brother_missing_selector_does_not_update_settings():
    session = Session(
        [
            Response(
                text='<form><input type="hidden" name="CSRFToken" value="csrf"><select name="unrelated"><option value="1">other</option></select></form>'
            )
        ]
    )
    device = brother.BrotherPrinterUpdater(session, "https://device")
    with pytest.raises(DeploymentError):
        device.activate_cert("new-id")
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    "location",
    [
        "https://other.example.test/steal",
        "http://device.example.test/downgrade",
        "https://device.example.test:8443/other-port",
    ],
)
def test_device_redirect_does_not_forward_credentials(location):
    import requests

    response = requests.Response()
    response.status_code = 302
    response.url = "https://device.example.test/login"
    response.headers["Location"] = location
    with http.Session(
        SimpleNamespace(connect_timeout=7, api_ca_file=None, api_tls_verify=False)
    ) as session:
        with pytest.raises(DeploymentError, match="changed origin"):
            session.get_redirect_target(response)
        response.headers["Location"] = "/home"
        assert session.get_redirect_target(response) == "/home"


def test_brother_activation_preserves_protocol_fields_and_confirms():
    settings = """<form><input type="hidden" name="logout" value="1"></form>
    <form><input type="hidden" name="CSRFToken" value="first">
    <input type="checkbox" name="https_enabled" value="1" checked>
    <input type="checkbox" name="http_enabled" value="1">
    <select name="certificate"><option value="1" selected>old</option><option value="2">new</option></select>
    <select name="other_setting"><option value="keep" selected>keep</option></select></form>"""
    confirm = '<form><input type="hidden" name="CSRFToken" value="second"><input type="hidden" name="http_page_mode" value="3"></form>'
    session = Session([Response(text=settings), Response(text=confirm), Response()])
    device = brother.BrotherPrinterUpdater(session, "https://device")
    device.activate_cert("2")
    data = session.calls[1][3]["data"]
    assert data["certificate"] == "2" and data["B6b4"] == "1"
    assert data["https_enabled"] == "1" and data["other_setting"] == "keep"
    assert "http_enabled" not in data and "logout" not in data
    assert session.calls[2][3]["data"] == {
        "CSRFToken": "second",
        "http_page_mode": "4",
        "active_other_protocol": "1",
    }


def test_brother_import_uses_detected_field_and_confirms(pem_pairs, monkeypatch):
    form = """<form><input type="hidden" name="logout" value="1"></form>
    <form enctype="multipart/form-data"><input type="hidden" name="CSRFToken" value="first">
    <input type="hidden" name="pageid" value="keep"><input type="file" name="device_file_field">
    <input type="password" name="p12_password"></form>"""
    confirm = '<form><input type="hidden" name="CSRFToken" value="second"><input type="hidden" name="hidden_certificate_process_control" value="2"></form>'
    session = Session([Response(text=form), Response(text=confirm), Response()])
    device = brother.BrotherPrinterUpdater(session, "https://device")
    certificates = iter(
        [
            {"1": "same.example.test"},
            {"1": "same.example.test", "2": "same.example.test"},
        ]
    )
    monkeypatch.setattr(device, "_get_cert_list", lambda: next(certificates))
    monkeypatch.setattr(brother.time, "sleep", lambda seconds: None)
    assert device.upload_cert(*pem_pairs["rsa"]) == (
        "2",
        "same.example.test",
        {"1": "same.example.test"},
    )
    upload = session.calls[1][3]
    assert upload["data"] == {
        "CSRFToken": "first",
        "pageid": "keep",
        "p12_password": "",
    }
    assert upload["files"]["device_file_field"][2] == "application/x-pkcs12"
    assert session.calls[2][3]["data"] == {
        "CSRFToken": "second",
        "hidden_certificate_process_control": "2",
    }
