#!/bin/bash
# verify-deployed-cert.sh -- Verify a deployed certificate is being served
#
# Connects to a host via openssl s_client, grabs the served certificate,
# and compares its SHA-256 fingerprint against the expected cert file.
# Used by driver scripts to confirm deployment actually took effect.

set -e

usage() {
  echo "Usage: $(basename "$0") -H HOST [-p PORT] -c CERT_FILE [-w WAIT] [-r RETRIES]"
  echo ""
  echo "Verify that a deployed certificate is being served by the target host."
  echo ""
  echo "Options:"
  echo "  -H, --host        Host to connect to (IP or hostname)"
  echo "  -p, --port        Port to connect to (default: 443)"
  echo "  -c, --cert-file   Path to the expected certificate file (PEM)"
  echo "  -w, --wait        Seconds to wait before first check (default: 30)"
  echo "  -r, --retries     Number of retries if check fails (default: 3)"
  echo ""
  echo "The cert file can be a fullchain (only the first/leaf cert is used)."
  echo "Exit code 0 = fingerprints match, 1 = mismatch or connection failure."
  exit 1
}

# --- Parse arguments ---
HOST=""
PORT="443"
CERT_FILE=""
WAIT=30
RETRIES=3
RETRY_INTERVAL=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--host)      HOST="$2"; shift 2 ;;
    -p|--port)      PORT="$2"; shift 2 ;;
    -c|--cert-file) CERT_FILE="$2"; shift 2 ;;
    -w|--wait)      WAIT="$2"; shift 2 ;;
    -r|--retries)   RETRIES="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$HOST" || -z "$CERT_FILE" ]]; then
  echo "Error: --host and --cert-file are required."
  usage
fi

if [[ ! -f "$CERT_FILE" ]]; then
  echo "Error: Certificate file not found: $CERT_FILE"
  exit 1
fi

# --- Extract leaf cert from file (first PEM block only) ---
extract_leaf_cert() {
  awk '/-----BEGIN CERTIFICATE-----/{found=1} found{print} /-----END CERTIFICATE-----/{if(found) exit}' "$1"
}

# --- Compute SHA-256 fingerprint of a PEM cert on stdin ---
fingerprint_from_pem() {
  openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr -d ':'
}

# --- Compute expected fingerprint ---
EXPECTED_FP=$(extract_leaf_cert "$CERT_FILE" | fingerprint_from_pem)

if [[ -z "$EXPECTED_FP" ]]; then
  echo "Error: Could not compute fingerprint from $CERT_FILE"
  exit 1
fi

echo "Expected SHA-256 fingerprint: $EXPECTED_FP"
echo "Verifying cert served by $HOST:$PORT..."

# --- Wait for service to restart ---
if [[ "$WAIT" -gt 0 ]]; then
  echo "Waiting ${WAIT}s for service to restart..."
  sleep "$WAIT"
fi

# --- Check served cert with retries ---
ATTEMPT=0
MAX_ATTEMPTS=$((RETRIES + 1))

while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
  ATTEMPT=$((ATTEMPT + 1))

  # Grab the served certificate
  SERVED_CERT=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null \
    | openssl x509 -outform PEM 2>/dev/null) || true

  if [[ -z "$SERVED_CERT" ]]; then
    echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Could not retrieve certificate from $HOST:$PORT"
  else
    SERVED_FP=$(echo "$SERVED_CERT" | fingerprint_from_pem)
    echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Served fingerprint: $SERVED_FP"

    if [[ "$EXPECTED_FP" = "$SERVED_FP" ]]; then
      echo "Verification PASSED: Certificate fingerprints match"
      exit 0
    else
      echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Fingerprint mismatch"
    fi
  fi

  if [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; then
    echo "Retrying in ${RETRY_INTERVAL}s..."
    sleep "$RETRY_INTERVAL"
  fi
done

echo "Verification FAILED: Certificate on $HOST:$PORT does not match expected cert after $MAX_ATTEMPTS attempts"
echo "  Expected: $EXPECTED_FP"
echo "  Served:   ${SERVED_FP:-<could not retrieve>}"
exit 1
