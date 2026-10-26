"""HTTP session policy shared by the device adapters."""

from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from ..errors import DeploymentError


class Session(requests.Session):
    def __init__(self, options):
        super().__init__()
        self.request_timeout = options.connect_timeout
        self.api_verify = options.api_ca_file or options.api_tls_verify
        self.trust_env = False  # Appliance requests must not inherit an HTTP proxy.
        if not self.api_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def request(self, method, url, **kwargs):
        kwargs["verify"] = self.api_verify
        kwargs["timeout"] = (self.request_timeout, kwargs.get("timeout", 30))
        try:
            return super().request(method, url, **kwargs)
        except requests.RequestException as error:
            # Requests exception strings can contain URLs with tokens or headers.
            raise DeploymentError(
                f"device HTTP request failed ({type(error).__name__})"
            ) from None

    def get_redirect_target(self, response):
        target = super().get_redirect_target(response)
        if target:
            before = urlsplit(response.url)
            after = urlsplit(urljoin(response.url, target))
            if (before.scheme, before.hostname, before.port or 443) != (
                after.scheme,
                after.hostname,
                after.port or 443,
            ):
                raise DeploymentError(
                    "device redirect changed origin; refusing to forward credentials"
                )
        return target


def require_ok(response, action):
    if not response.ok:
        raise DeploymentError(f"{action} failed (HTTP {response.status_code})")
    return response
