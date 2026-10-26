"""Brother form/confirmation protocol retained from the hardware-tested adapter."""

import html as html_mod
import logging
import re
import time
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    NoEncryption,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)

from ..errors import DeploymentError

log = logging.getLogger(__name__)


class BrotherPrinterUpdater:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url.rstrip("/")

        self.status_url = f"{self.base_url}/home/status.html"
        self.import_url = f"{self.base_url}/net/security/certificate/import.html"
        self.cert_list_url = (
            f"{self.base_url}/net/security/certificate/certificate.html"
        )
        self.certificate_html_url = (
            f"{self.base_url}/net/security/certificate/certificate.html"
        )
        self.cert_delete_url = f"{self.base_url}/net/security/certificate/delete.html"
        self.http_settings_url = f"{self.base_url}/net/net/certificate/http.html"

    def _extract_csrf(self, html):
        """Extract CSRF token value from a Brother web UI page.

        Matches on either id="CSRFToken" or name="CSRFToken" — different pages
        (and different firmware versions) use one or both attributes.
        """
        m = re.search(
            r'<input[^>]+(?:id|name)=["\']CSRFToken["\'][^>]+value=["\']([^"\']+)["\']'
            r'|<input[^>]+value=["\']([^"\']+)["\'][^>]+(?:id|name)=["\']CSRFToken["\']',
            html,
        )
        if not m:
            return None
        return m.group(1) or m.group(2)

    def _extract_form_html(self, html, marker):
        """Return the <form>...</form> block containing 'marker' text.

        Brother pages have multiple forms (import form, logout form, etc.).
        This lets callers scope input extraction to the correct form so
        fields from other forms (e.g. B5f2 from the logout form) don't
        leak into POSTs.  Falls back to full page HTML if no match.
        """
        for m in re.finditer(
            r"<form\b[^>]*>.*?</form>", html, re.DOTALL | re.IGNORECASE
        ):
            if marker in m.group(0):
                return m.group(0)
        return html

    def _extract_hidden_inputs(self, html):
        """Return all hidden input fields as a {name: value} dict.

        Using this as the base for form POSTs means pageid, process-control
        flags, and other hidden bookkeeping fields are captured automatically
        regardless of model or firmware version.
        """
        result = {}
        for m in re.finditer(r"<input\b[^>]*/?>|<input\b[^>]*>", html, re.IGNORECASE):
            tag = m.group(0)
            if not re.search(r'\btype=["\']hidden["\']', tag, re.IGNORECASE):
                continue
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag)
            val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag)
            if name_m:
                result[name_m.group(1)] = val_m.group(1) if val_m else ""
        return result

    def _extract_cert_info(self, html):
        """Extract {cert_id: cert_name} from the certificate list table.

        The cert list page renders certs as table rows with:
          - Name in <div class="certificateName">HTML-entity-encoded name</div>
          - ID in ?idx=N links (view/delete/export)
        """
        result = {}
        # Each cert is a <tr> containing a certificateName div and ?idx= links
        for row in re.finditer(
            r"<tr\b[^>]*>(.*?)</tr>", html, re.DOTALL | re.IGNORECASE
        ):
            row_html = row.group(1)
            name_m = re.search(
                r'class=["\']certificateName["\'][^>]*>(.*?)</div>',
                row_html,
                re.DOTALL | re.IGNORECASE,
            )
            idx_m = re.search(r"\?idx=(\d+)", row_html)
            if name_m and idx_m:
                cert_name = html_mod.unescape(name_m.group(1).strip())
                cert_id = idx_m.group(1)
                result[cert_id] = cert_name
        return result

    def _extract_all_form_inputs(self, html):
        """Return all submittable form field values as a {name: value} dict.

        Unlike _extract_hidden_inputs, this captures visible fields too
        (checkboxes, selects, text inputs) so that protocol settings on
        http.html are preserved when we POST the cert-selection form.
        Submit/button/file inputs are excluded.
        """
        result = {}

        # Input elements (all types except submit/button/image/reset/file)
        for m in re.finditer(r"<input\b[^>]*/?>|<input\b[^>]*>", html, re.IGNORECASE):
            tag = m.group(0)
            type_m = re.search(r'\btype=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            input_type = type_m.group(1).lower() if type_m else "text"
            if input_type in ("submit", "button", "image", "reset", "file"):
                continue
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag)
            if not name_m:
                continue
            name = name_m.group(1)
            if input_type == "checkbox":
                if re.search(r"\bchecked\b", tag, re.IGNORECASE):
                    val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag)
                    result[name] = val_m.group(1) if val_m else "on"
            else:
                val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag)
                result[name] = val_m.group(1) if val_m else ""

        # Select elements — capture the currently selected option value
        for m in re.finditer(
            r'<select\b[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
            html,
            re.DOTALL | re.IGNORECASE,
        ):
            name = m.group(1)
            body = m.group(2)
            sel = re.search(
                r'<option[^>]+selected\b[^>]*value=["\']([^"\']*)["\']'
                r'|<option[^>]+value=["\']([^"\']*)["\'][^>]+selected\b',
                body,
                re.IGNORECASE,
            )
            if sel:
                result[name] = sel.group(1) or sel.group(2)
            else:
                first = re.search(r'<option[^>]+value=["\']([^"\']*)["\']', body)
                if first:
                    result[name] = first.group(1)

        return result

    def _find_cert_selector(self, html, cert_id):
        """Return the name of the <select> that has cert_id as one of its options, or None."""
        for m in re.finditer(
            r'<select\b[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
            html,
            re.DOTALL | re.IGNORECASE,
        ):
            name = m.group(1)
            body = m.group(2)
            option_values = re.findall(r'<option[^>]+value=["\'](\d+)["\']', body)
            if cert_id in option_values:
                return name
        return None

    def login(self, username, password):
        """Login to the printer web UI and establish a session."""
        log.info("Logging in to printer...")

        # GET the login page — follow any redirects and use the final URL for
        # the POST. Brother models vary: some use /general/status.html, others
        # /home/status.html. Posting to the wrong path is the most common cause
        # of "no AuthCookie" even when credentials are correct.
        r = self.session.get(self.status_url, verify=False, timeout=15)
        if not r.ok:
            log.error(
                "Could not reach printer at %s (HTTP %s)",
                self.status_url,
                r.status_code,
            )
            raise DeploymentError("Brother device operation failed")
        login_url = r.url  # actual endpoint after redirects

        # Find the password input field name dynamically
        m = re.search(
            r'<input[^>]+type=["\']password["\'][^>]+name=["\']([^"\']+)["\']'
            r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']password["\']',
            r.text,
        )
        if not m:
            log.error(
                "Could not find password field on login page. Firmware may have changed."
            )
            raise DeploymentError("Brother device operation failed")
        pwd_field = m.group(1) or m.group(2)

        # Find the username field — some models omit it entirely (password-only login)
        u = re.search(
            r'<input[^>]+type=["\']text["\'][^>]+name=["\']([^"\']+)["\']'
            r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']text["\']',
            r.text,
        )
        username_field = (u.group(1) or u.group(2)) if u else None

        login_path = urlparse(login_url).path
        payload = {pwd_field: password, "loginurl": login_path}
        if username_field:
            payload[username_field] = username

        r = self.session.post(
            login_url, data=payload, verify=False, timeout=15, allow_redirects=True
        )
        if not r.ok:
            log.error("Login POST failed (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")

        if "AuthCookie" not in self.session.cookies:
            log.error("Login failed — no AuthCookie received. Check credentials.")
            raise DeploymentError("Brother device operation failed")

        log.info("  Login successful.")

    def _get_cert_list(self):
        """Return {cert_id: cert_name} for all certs on the printer."""
        r = self.session.get(self.cert_list_url, verify=False, timeout=15)
        if not r.ok:
            log.error("Could not retrieve cert list (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")
        return self._extract_cert_info(r.text)

    def build_p12(self, cert_file, key_file):
        """Convert PEM cert + key to PKCS#12 bytes (no passphrase)."""
        with open(cert_file, "rb") as f:
            cert_pem = f.read()
        with open(key_file, "rb") as f:
            key_pem = f.read()

        private_key = load_pem_private_key(key_pem, password=None)

        # Parse all certs from the PEM (fullchain may have multiple)
        certs = []
        for match in re.finditer(
            b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_pem,
            re.DOTALL,
        ):
            certs.append(x509.load_pem_x509_certificate(match.group(0)))

        if not certs:
            log.error("No certificates found in cert file.")
            raise DeploymentError("Brother certificate conversion failed")

        leaf_cert = certs[0]
        ca_certs = certs[1:] if len(certs) > 1 else []

        # Brother has a 2-cert chain limit; warn if we'd exceed it
        if len(certs) > 2:
            log.warning(
                "fullchain has %d certs; Brother supports max 2. "
                "Using leaf + first intermediate only.",
                len(certs),
            )
            ca_certs = ca_certs[:1]

        p12_bytes = serialize_key_and_certificates(
            name=None,
            key=private_key,
            cert=leaf_cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=NoEncryption(),
        )
        return p12_bytes

    def upload_cert(self, cert_file, key_file):
        """Upload the certificate as P12 to the printer."""
        log.info("Converting certificate to PKCS#12 format...")
        p12_bytes = self.build_p12(cert_file, key_file)

        # Snapshot certs before upload so we can find the new one
        certs_before = self._get_cert_list()
        log.info("  Certs before upload: %s", certs_before or "(none)")

        log.info("Uploading certificate...")
        # GET import page for CSRF token and form structure
        r = self.session.get(self.import_url, verify=False, timeout=15)
        if not r.ok:
            log.error("Could not load import page (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")
        csrf = self._extract_csrf(r.text)
        if not csrf:
            log.error("Could not find CSRF token on import page.")
            raise DeploymentError("Brother device operation failed")

        # Detect the file input field name — varies by model/firmware
        fm = re.search(
            r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']'
            r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']file["\']',
            r.text,
        )
        if not fm:
            log.error(
                "Could not find file input on import page. Firmware may have changed."
            )
            raise DeploymentError("Brother device operation failed")
        file_field = fm.group(1) or fm.group(2)

        # Extract hidden fields from the import form only (not the logout form
        # which also lives on the page and contains B5f2 — sending that field
        # causes the printer to treat the POST as a logout).
        import_form = self._extract_form_html(r.text, "multipart/form-data")
        data = self._extract_hidden_inputs(import_form)
        data["CSRFToken"] = csrf

        # Include the P12 import password field if present (empty = no passphrase)
        pm = re.search(
            r'<input[^>]+type=["\']password["\'][^>]+name=["\']([^"\']+)["\']'
            r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']password["\']',
            r.text,
        )
        if pm:
            data[pm.group(1) or pm.group(2)] = ""

        files = {
            file_field: ("certificate.p12", p12_bytes, "application/x-pkcs12"),
        }
        r = self.session.post(
            self.import_url, files=files, data=data, verify=False, timeout=30
        )
        if not r.ok:
            log.error("Certificate upload failed (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")

        # Step 2: confirm the import. The upload response page contains a
        # confirmation form with hidden_certificate_process_control=2 and a
        # fresh CSRF token — POST it back to complete the import.
        csrf2 = self._extract_csrf(r.text)
        if not csrf2:
            log.error(
                "Could not find CSRF token in upload response. Firmware may have changed."
            )
            raise DeploymentError("Brother device operation failed")
        confirm_form = self._extract_form_html(
            r.text, "hidden_certificate_process_control"
        )
        confirm_data = self._extract_hidden_inputs(confirm_form)
        confirm_data["CSRFToken"] = csrf2

        r = self.session.post(
            self.import_url, data=confirm_data, verify=False, timeout=15
        )
        if not r.ok:
            log.error("Certificate import confirmation failed (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")

        log.info("  Import confirmed. Waiting 20s for device to process...")
        time.sleep(20)

        # Find the new cert ID by diffing before/after
        certs_after = self._get_cert_list()
        new_ids = set(certs_after) - set(certs_before)
        if not new_ids:
            log.error(
                "Certificate upload appeared to succeed but no new cert appeared in the list."
            )
            log.error(
                "  The file input field name may have changed in a firmware update."
            )
            raise DeploymentError("Brother device operation failed")

        new_id = next(iter(new_ids))
        new_cert_name = certs_after.get(new_id, "")
        log.info(
            "  New certificate ID: %s (%s)", new_id, new_cert_name or "unknown name"
        )
        return new_id, new_cert_name, certs_before

    def activate_cert(self, cert_id):
        """Activate the imported certificate for HTTPS on the printer.

        Confirmed flow (selectcert HAR): two POSTs to http.html only.
        POST 1 — assigns the cert to HTTPS (preserving existing protocol settings).
        POST 2 — confirmation ("Yes, restart now") which triggers a ~60 s reboot.
        """
        log.info("Activating certificate %s...", cert_id)

        # --- HTTPS protocol settings page ---
        # GET the page to capture current protocol settings (checkboxes, selects)
        # so we don't accidentally change them — we only change the cert selector.
        r = self.session.get(self.http_settings_url, verify=False, timeout=15)
        if not r.ok:
            log.error("Could not load HTTP settings page (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")
        csrf = self._extract_csrf(r.text)
        if not csrf:
            log.error("Could not find CSRF token on HTTP settings page.")
            raise DeploymentError("Brother device operation failed")

        # Preserve all visible form fields (protocol flags, checkboxes, etc.)
        # Scope to the settings form (contains <select> elements), not the logout form.
        settings_form = self._extract_form_html(r.text, "<select")
        data = self._extract_all_form_inputs(settings_form)
        data["CSRFToken"] = csrf

        # Find the HTTPS cert selector <select> and point it at our new cert
        cert_selector = self._find_cert_selector(settings_form, cert_id)
        if cert_selector:
            data[cert_selector] = cert_id
            # Restart flag — the onsubmit JS (netews_set_restart_flag) sets B6b4
            # to 1 when any monitored field (like the cert dropdown) changes from
            # its default.  Without this the printer may mishandle the POST.
            data["B6b4"] = "1"
        else:
            raise DeploymentError(
                "Brother HTTPS settings contain no selector for the imported certificate"
            )

        r = self.session.post(
            self.http_settings_url, data=data, verify=False, timeout=15
        )
        if not r.ok:
            log.error("HTTP settings update failed (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")

        # Confirmation POST — triggers device restart ("device will reset in 60 s")
        csrf2 = self._extract_csrf(r.text)
        if not csrf2:
            log.error("Could not find CSRF token in HTTP settings response.")
            raise DeploymentError("Brother device operation failed")
        confirm_form = self._extract_form_html(r.text, "http_page_mode")
        confirm_data = self._extract_hidden_inputs(confirm_form)
        confirm_data["CSRFToken"] = csrf2
        confirm_data["active_other_protocol"] = "1"
        confirm_data["http_page_mode"] = "4"

        r = self.session.post(
            self.http_settings_url, data=confirm_data, verify=False, timeout=15
        )
        if not r.ok:
            log.error("HTTP settings confirmation failed (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")

        log.info("  Certificate activated. Device will restart in ~60 s.")

    def delete_cert(self, cert_id):
        """Delete the certificate with the given ID from the printer's store."""
        log.info("Deleting old certificate %s...", cert_id)

        # GET delete page for CSRF token and hidden fields.
        # ?idx= tells the server which cert to pre-populate in hidden_certificate_idx.
        r = self.session.get(
            f"{self.cert_delete_url}?idx={cert_id}", verify=False, timeout=15
        )
        if not r.ok:
            log.error("Could not load cert delete page (HTTP %s)", r.status_code)
            raise DeploymentError("Brother device operation failed")
        csrf = self._extract_csrf(r.text)
        if not csrf:
            log.error("Could not find CSRF token on delete page.")
            raise DeploymentError("Brother device operation failed")

        # First DELETE POST — hidden_certificate_idx already set by server in hidden inputs
        delete_form = self._extract_form_html(r.text, "hidden_certificate_idx")
        data = self._extract_hidden_inputs(delete_form)
        data["CSRFToken"] = csrf

        r = self.session.post(self.cert_delete_url, data=data, verify=False, timeout=15)
        if not r.ok:
            log.error("Cert deletion step 1 failed (HTTP %s)", r.status_code)
            return  # Non-fatal: cert is already activated, deletion failure just leaves old cert around

        csrf2 = self._extract_csrf(r.text)
        if not csrf2:
            log.warning(
                "Could not find CSRF token for deletion confirmation. Old cert may remain."
            )
            return

        # Confirmation POST — hidden_certificate_idx still present in response hidden inputs
        confirm_form = self._extract_form_html(r.text, "hidden_certificate_idx")
        data2 = self._extract_hidden_inputs(confirm_form)
        data2["CSRFToken"] = csrf2

        r = self.session.post(
            self.cert_delete_url, data=data2, verify=False, timeout=15
        )
        if not r.ok:
            log.warning(
                "Cert deletion step 2 failed (HTTP %s). Old cert may remain.",
                r.status_code,
            )
            return

        log.info("  Old certificate deleted.")


def apply(session, base, options):
    updater = BrotherPrinterUpdater(session, base)
    updater.login(options.username, options.password)
    new_id, new_name, old_certs = updater.upload_cert(
        options.cert_file, options.key_file
    )
    updater.activate_cert(new_id)
    # Retain the original cleanup rule, including its documented fallback. This
    # policy is independent of the Python migration and requires a separate change.
    old_ids = (
        [cid for cid, name in old_certs.items() if name == new_name]
        if new_name
        else list(old_certs)
    )
    if not new_name and old_ids:
        log.warning(
            "Printer returned no certificate name; existing cleanup policy selects all older certificates"
        )
    if old_ids:
        time.sleep(120)
        try:
            updater.login(options.username, options.password)
            for cert_id in old_ids:
                updater.delete_cert(cert_id)
        except DeploymentError:
            log.warning(
                "Printer cleanup failed after activation; older certificates may remain"
            )
