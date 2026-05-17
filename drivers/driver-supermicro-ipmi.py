#!/usr/bin/env python3

# Usage: driver-ipmi.py -H HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [-m MODEL] [--no-reboot] [--debug]

import argparse
import logging
import os
import re
import subprocess
import sys
from base64 import b64encode
from datetime import datetime
from urllib.parse import urlparse

import requests
from lxml import etree

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

        log.debug("HEADERS:%s", headers)
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
        except ConnectionError:
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
        except ConnectionError:
            return False
        if not result.ok:
            return False

        log.debug(result.text)
        root = etree.fromstring(result.text)
        status = root.xpath("//IPMI/SSL_INFO/STATUS")
        if not status:
            return False
        status = status[0]
        has_cert = bool(int(status.get("CERT_EXIST")))
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
        except ConnectionError:
            return False
        if not result.ok:
            return False

        log.debug(result.text)
        root = etree.fromstring(result.text)
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
        except ConnectionError:
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
        except ConnectionError:
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
        timestamp = datetime.utcnow().strftime("%a %d %b %Y %H:%M:%S GMT")

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
        log.debug(result.text)
        root = etree.fromstring(result.text)
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
    except (ConnectionError, requests.exceptions.SSLError) as err:
        log.error("Failed to determine model: connection error")
        log.debug("%s", err)
        exit(2)
    if not r.ok:
        log.error("Failed to determine model (try --model): %s %s", r.status_code, r.reason)
        exit(2)

    data = r.json()

    # The UpdateService methods are only available on newer X11 based boards
    if "UpdateService" in data:
        return "X11"
    else:
        return "X10"


def run(
    ipmi_url,
    username,
    password,
    key_file,
    cert_file,
    model=None,
    no_reboot=False,
):
    """Core logic, callable from CLI or dispatcher."""
    # Validate files
    if not os.path.isfile(key_file):
        log.error("Key file doesn't exist: %s", key_file)
        exit(2)
    if not os.path.isfile(cert_file):
        log.error("Cert file doesn't exist: %s", cert_file)
        exit(2)
    if ipmi_url[-1] == "/":
        ipmi_url = ipmi_url[0:-1]

    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    session = requests.session()
    updater = create_updater(session, ipmi_url, model)

    if not updater.login(username, password):
        log.error("Login failed. Cannot continue!")
        exit(2)

    cert_info = updater.get_ipmi_cert_info()
    if not cert_info:
        log.error("Failed to extract certificate information from IPMI!")
        exit(2)
    if cert_info["has_cert"]:
        log.info(
            "There exists a certificate, which is valid until: %s",
            cert_info["valid_until"],
        )

    if not updater.upload_cert(key_file, cert_file):
        log.error("Failed to upload X.509 files to IPMI!")
        exit(2)

    cert_valid = updater.get_ipmi_cert_valid()
    if not cert_valid:
        log.error("Uploads failed validation")
        exit(2)

    log.info("Uploaded files ok.")

    cert_info = updater.get_ipmi_cert_info()
    if not cert_info:
        log.error("Failed to extract certificate information from IPMI!")
        exit(2)
    if cert_info["has_cert"]:
        log.info(
            "After upload, there exists a certificate, which is valid until: %s",
            cert_info["valid_until"],
        )

    if not no_reboot:
        log.info("Rebooting IPMI to apply changes.")
        if not updater.reboot_ipmi():
            log.error("Rebooting failed! Go reboot it manually?")

    log.info("All done!")


def main():
    parser = argparse.ArgumentParser(
        description="Update Supermicro IPMI SSL certificate"
    )
    parser.add_argument(
        "-H",
        "--host",
        required=True,
        help="IPMI IP or hostname (https:// will be prepended)",
    )
    parser.add_argument(
        "-m",
        "--model",
        required=False,
        help="Board model: X10 or X11 (auto-detected if omitted)",
    )
    parser.add_argument(
        "-k", "--key-file", required=True, help="Path to private key file (privkey.pem)"
    )
    parser.add_argument(
        "-c",
        "--cert-file",
        required=True,
        help="Path to certificate file (fullchain.pem)",
    )
    parser.add_argument(
        "-u", "--username", required=True, help="IPMI username with admin access"
    )
    parser.add_argument("-p", "--password", required=True, help="IPMI user password")
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="Skip BMC reboot after certificate upload",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip post-deployment certificate verification",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Do not output anything if successful"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Output additional debugging"
    )
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(format="%(message)s", level=level)

    if args.debug:
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1

        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    # Supermicro IPMI only supports RSA certificates
    cert_check = subprocess.run(
        ["openssl", "x509", "-in", args.cert_file, "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if cert_check.returncode != 0:
        log.error("Cannot read certificate file: %s", args.cert_file)
        sys.exit(1)
    if "rsaEncryption" not in cert_check.stdout:
        log.error(
            "Supermicro IPMI requires an RSA certificate, but %s is not RSA.",
            args.cert_file,
        )
        log.error(
            'Set "key_type": "rsa" in your deploy-config.json for this cert.'
        )
        sys.exit(1)

    # Prepend https:// if not present
    ipmi_url = args.host
    if not ipmi_url.startswith("https://"):
        ipmi_url = f"https://{ipmi_url}"

    run(
        ipmi_url=ipmi_url,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        cert_file=args.cert_file,
        model=args.model,
        no_reboot=args.no_reboot,
    )

    # Post-deployment verification via openssl s_client
    if not args.no_verify:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        verify_script = os.path.join(script_dir, "verify-deployed-cert.sh")
        wait = "30" if args.no_reboot else "180"
        result = subprocess.run(
            [
                verify_script,
                "--host",
                args.host,
                "--cert-file",
                args.cert_file,
                "--wait",
                wait,
                "--retries",
                "5",
            ],
        )
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
