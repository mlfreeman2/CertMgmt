"""Supermicro X10/X11 form protocols retained from the hardware-tested adapter."""

import logging
import re
from base64 import b64encode
from datetime import UTC, datetime
from urllib.parse import urlparse

from lxml import etree

from ..errors import DeploymentError

REQUEST_TIMEOUT = 5.0
log = logging.getLogger(__name__)


class IPMIUpdater:
    def __init__(self, session, ipmi_url):
        self.session = session
        self.ipmi_url = ipmi_url

        self.login_url = f"{ipmi_url}/cgi/login.cgi"
        self.cert_info_url = f"{ipmi_url}/cgi/ipmi.cgi"
        self.upload_cert_url = f"{ipmi_url}/cgi/upload_ssl.cgi"
        self.url_redirect_template = f"{ipmi_url}/cgi/url_redirect.cgi?url_name=%s"

        self.use_b64encoded_login = True

        self._csrf_token = None

    def get_csrf_token(self, url_name):
        if self._csrf_token is not None:
            return self._csrf_token

        page_url = self.url_redirect_template % url_name
        result = self.session.get(page_url)
        result.raise_for_status()

        match = re.search(
            r'SmcCsrfInsert\s*\("CSRF_TOKEN",\s*"([^"]*)"\);', result.text
        )
        if match:
            return match.group(1)

    def get_csrf_headers(self, url_name):
        page_url = self.url_redirect_template % url_name

        headers = {
            "Origin": self.ipmi_url,
            "Referer": page_url,
        }
        csrf_token = self.get_csrf_token(url_name)
        if csrf_token is not None:
            headers["CSRF_TOKEN"] = csrf_token

        return headers

    def get_xhr_headers(self, url_name):
        headers = self.get_csrf_headers(url_name)
        headers["X-Requested-With"] = "XMLHttpRequest"
        return headers

    def login(self, username, password):
        """
        Log into IPMI interface
        :param username: username to use for logging in
        :param password: password to use for logging in
        :return: bool
        """
        if self.use_b64encoded_login:
            login_data = {
                "name": b64encode(username.encode("UTF-8")),
                "pwd": b64encode(password.encode("UTF-8")),
                "check": "00",
            }
        else:
            login_data = {"name": username, "pwd": password}

        try:
            result = self.session.post(
                self.login_url, login_data, timeout=REQUEST_TIMEOUT, verify=False
            )
        except DeploymentError:
            return False
        if not result.ok:
            return False
        if "/cgi/url_redirect.cgi?url_name=mainmenu" not in result.text:
            return False

        # Set mandatory cookies:
        url_parts = urlparse(self.ipmi_url)
        mandatory_cookies = {"langSetFlag": "0", "language": "English"}
        for cookie_name, cookie_value in mandatory_cookies.items():
            self.session.cookies.set(
                cookie_name, cookie_value, domain=url_parts.hostname
            )

        return True

    def get_ipmi_cert_info(self):
        """
        Verify existing certificate information
        :return: dict
        """

        headers = self.get_xhr_headers("config_ssl")

        cert_info_data = self._get_op_data("SSL_STATUS.XML", "(0,0)")

        try:
            result = self.session.post(
                self.cert_info_url,
                cert_info_data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        except DeploymentError:
            return False
        if not result.ok:
            return False

        root = etree.fromstring(
            result.text.encode(),
            parser=etree.XMLParser(resolve_entities=False, no_network=True),
        )
        status = root.xpath("//IPMI/SSL_INFO/STATUS")
        if not status:
            return False
        status = status[0]
        has_cert = bool(int(status.get("CERT_EXIST")))
        valid_from = valid_until = None
        if has_cert:
            valid_from = status.get("VALID_FROM")
            valid_until = status.get("VALID_UNTIL")

        return {
            "has_cert": has_cert,
            "valid_from": valid_from,
            "valid_until": valid_until,
        }

    def get_ipmi_cert_valid(self):
        """
        Verify existing certificate information
        :return: bool
        """

        headers = self.get_xhr_headers("config_ssl")

        cert_info_data = self._get_op_data("SSL_VALIDATE.XML", "(0,0)")

        try:
            result = self.session.post(
                self.cert_info_url,
                cert_info_data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        except DeploymentError:
            return False
        if not result.ok:
            return False

        root = etree.fromstring(
            result.text.encode(),
            parser=etree.XMLParser(resolve_entities=False, no_network=True),
        )
        status = root.xpath("//IPMI/SSL_INFO")
        if not status:
            return False
        status = status[0]
        return bool(int(status.get("VALIDATE")))

    def upload_cert(self, key_file, cert_file):
        """
        Send X.509 certificate and private key to server
        :param key_file: filename to X.509 certificate private key
        :param cert_file: filename to X.509 certificate PEM
        :return: bool
        """
        with open(key_file, "rb") as filehandle:
            key_data = filehandle.read()
        with open(cert_file, "rb") as filehandle:
            cert_data = filehandle.read()
            # extract certificates only (IPMI doesn't like DH PARAMS)
            cert_data = (
                b"\n".join(
                    re.findall(
                        b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        cert_data,
                        re.DOTALL,
                    )
                )
                + b"\n"
            )

        files_to_upload = self._get_upload_data(cert_data, key_data)

        headers = self.get_csrf_headers("config_ssl")
        csrf_token = self.get_csrf_token("config_ssl")
        csrf_data = {}
        if csrf_token is not None:
            csrf_data["CSRF_TOKEN"] = csrf_token

        try:
            result = self.session.post(
                self.upload_cert_url,
                csrf_data,
                files=files_to_upload,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        except DeploymentError:
            return False
        if not result.ok:
            return False

        if (
            "Content-Type" not in result.headers.keys()
            or result.headers["Content-Type"] != "text/html"
        ):
            return False
        if "CONFPAGE_RESET" not in result.text:
            return False

        return True

    def _check_reboot_result(self, result):
        return True

    def reboot_ipmi(self):
        headers = self.get_xhr_headers("config_ssl")

        reboot_data = self._get_op_data("main_bmcreset", None)

        try:
            result = self.session.post(
                self.reboot_url,
                reboot_data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        except DeploymentError:
            return False
        if not result.ok:
            return False

        if not self._check_reboot_result(result):
            return False
        return True


class IPMIX10Updater(IPMIUpdater):
    def __init__(self, session, ipmi_url):
        super().__init__(session, ipmi_url)
        self.reboot_url = f"{ipmi_url}/cgi/BMCReset.cgi"
        self.use_b64encoded_login = False

    def _get_op_data(self, op, r):
        timestamp = datetime.now(UTC).strftime("%a %d %b %Y %H:%M:%S GMT")

        data = {"time_stamp": timestamp}
        if r is not None:
            data[op] = r
        return data

    def _get_upload_data(self, cert_data, key_data):
        return [
            ("cert_file", ("cert.pem", cert_data, "application/octet-stream")),
            ("key_file", ("privkey.pem", key_data, "application/octet-stream")),
        ]

    def _check_reboot_result(self, result):
        root = etree.fromstring(
            result.text.encode(),
            parser=etree.XMLParser(resolve_entities=False, no_network=True),
        )
        status = root.xpath("//IPMI/BMC_RESET/STATE")
        if not status:
            return False
        if status[0].get("CODE") == "OK":
            return True
        return False


class IPMIX11Updater(IPMIUpdater):
    def __init__(self, session, ipmi_url):
        super().__init__(session, ipmi_url)
        self.reboot_url = f"{ipmi_url}/cgi/op.cgi"
        self.use_b64encoded_login = True

    def _get_op_data(self, op, r):
        data = {"op": op}

        if r is not None:
            data["r"] = r
        data["_"] = ""
        return data

    def _get_upload_data(self, cert_data, key_data):
        return [
            ("cert_file", ("fullchain.pem", cert_data, "application/octet-stream")),
            ("key_file", ("privkey.pem", key_data, "application/octet-stream")),
        ]


def create_updater(session, ipmi_url, model):
    if model is None:
        model = determine_model(session, ipmi_url)

    log.info("Board model is %s", model)

    if model == "X10":
        return IPMIX10Updater(session, ipmi_url)
    elif model == "X11":
        return IPMIX11Updater(session, ipmi_url)
    else:
        raise Exception(f"Unknown model: {model}")


def determine_model(session, ipmi_url):
    redfish_url = f"{ipmi_url}/redfish/v1/"

    try:
        r = session.get(redfish_url, timeout=REQUEST_TIMEOUT, verify=False)
    except DeploymentError:
        log.error("Failed to determine model: connection error")
        raise DeploymentError("Supermicro model detection failed")
    if not r.ok:
        log.error(
            "Failed to determine model (try --model): %s %s", r.status_code, r.reason
        )
        raise DeploymentError("Supermicro model detection failed")

    data = r.json()

    # The UpdateService methods are only available on newer X11 based boards
    if "UpdateService" in data:
        return "X11"
    else:
        return "X10"


def apply(session, base, options):
    updater = create_updater(session, base, options.model)
    if not updater.login(options.username, options.password):
        raise DeploymentError("Supermicro login failed")
    before = updater.get_ipmi_cert_info()
    if not before:
        raise DeploymentError("could not read Supermicro certificate status")
    if not updater.upload_cert(options.key_file, options.cert_file):
        raise DeploymentError("Supermicro certificate upload failed")
    if not updater.get_ipmi_cert_valid():
        raise DeploymentError("Supermicro rejected the uploaded certificate/key")
    if not updater.get_ipmi_cert_info():
        raise DeploymentError(
            "could not read Supermicro certificate status after upload"
        )
    if not options.no_reboot and not updater.reboot_ipmi():
        raise DeploymentError("certificate uploaded but Supermicro reboot failed")
