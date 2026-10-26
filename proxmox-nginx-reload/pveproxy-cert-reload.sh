#!/bin/bash
# Reconcile nginx's served leaf certificate with the custom pveproxy certificate.
# No timestamps or cached success: every invocation checks a fresh TLS connection.

set -euo pipefail

CERT_FILE="${CERT_FILE:-/etc/pve/local/pveproxy-ssl.pem}"
TLS_CONNECT="${TLS_CONNECT:-127.0.0.1:443}"
TLS_SERVER_NAME="${TLS_SERVER_NAME:-}"

fail() { echo "nginx certificate check: $*" >&2; exit 1; }

[[ -n "$TLS_SERVER_NAME" && "$TLS_SERVER_NAME" != CHANGE_ME ]] || fail "set TLS_SERVER_NAME to the hostname used to open the PVE UI"
[[ -r "$CERT_FILE" ]] || fail "cannot read $CERT_FILE"

disk_fingerprint() {
  openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256
}

served_fingerprint() {
  local response
  # Capture first, then parse: an early-closing x509 pipe must not SIGPIPE s_client.
  response=$(timeout --kill-after=1s 5s openssl s_client \
    -connect "$TLS_CONNECT" -servername "$TLS_SERVER_NAME" </dev/null 2>/dev/null) || return 1
  printf '%s\n' "$response" | openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

expected=$(disk_fingerprint) || fail "certificate file does not parse"
timeout --kill-after=1s 5s systemctl is-active --quiet nginx || fail "nginx is not active; no start or restart attempted"

if served=$(served_fingerprint) && [[ "$served" == "$expected" ]]; then
  exit 0
fi

echo "nginx certificate differs from disk, or TLS probe failed; validating before reload"
# This also checks that nginx's configured certificate and private key match.
# A partially completed upload fails here and is retried at the next timer tick.
timeout --kill-after=1s 10s nginx -t || fail "nginx configuration test failed; reload not attempted"
timeout --kill-after=1s 10s systemctl reload nginx || fail "nginx reload request failed"

# Reload completion is asynchronous. Only a fresh TLS handshake proves it applied.
for attempt in 1 2 3 4 5; do
  expected=$(disk_fingerprint) || fail "certificate changed to an unreadable value during reload"
  if served=$(served_fingerprint) && [[ "$served" == "$expected" ]]; then
    echo "nginx now serves the certificate from $CERT_FILE"
    exit 0
  fi
  [[ "$attempt" -eq 5 ]] || sleep 1
done

fail "nginx still does not serve the expected certificate at $TLS_CONNECT (SNI $TLS_SERVER_NAME); next timer run will retry"
