#!/bin/bash
# driver-glinet-kvm.sh -- Deploy certificate to GL.iNet KVM/KVMD
# Usage: driver-glinet-kvm.sh -h HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [--no-verify]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $(basename "$0") -h HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [--no-verify]"
  echo ""
  echo "Deploy an SSL certificate to a GL.iNet KVM (KVMD) device."
  echo ""
  echo "Options:"
  echo "  -h, --host        KVM IP or hostname"
  echo "  -u, --username    KVMD username"
  echo "  -p, --password    KVMD password"
  echo "  -c, --cert-file   Path to certificate file (e.g. cert.pem)"
  echo "  -k, --key-file    Path to private key file (e.g. privkey.pem)"
  echo "  --no-verify       Skip post-deployment certificate verification"
  exit 1
}

# Parse arguments
HOST="" USER="" PASS="" CERT_FILE="" KEY_FILE="" VERIFY=true
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--host)      HOST="$2"; shift 2 ;;
    -u|--username)   USER="$2"; shift 2 ;;
    -p|--password)   PASS="$2"; shift 2 ;;
    -c|--cert-file) CERT_FILE="$2"; shift 2 ;;
    -k|--key-file)  KEY_FILE="$2"; shift 2 ;;
    --no-verify)    VERIFY=false; shift ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$HOST" || -z "$USER" || -z "$PASS" || -z "$CERT_FILE" || -z "$KEY_FILE" ]]; then
  echo "Error: All options are required."
  usage
fi

CERT_BLOCKS=$(grep -c 'BEGIN CERTIFICATE' "$CERT_FILE" 2>/dev/null || true)
if [ "$CERT_BLOCKS" -gt 1 ]; then
  echo "Error: $CERT_FILE contains a certificate chain. GL.iNet KVM requires a single leaf certificate (cert.pem, not fullchain.pem)."
  echo 'Set "cert_file": "cert.pem" for this target in deploy-config.json.'
  exit 1
fi

echo "Deploying certificate to GL.iNet KVM at $HOST..."

# Read and JSON-encode cert and key
CERT=$(cat "$CERT_FILE" | jq -Rs .)
KEY=$(cat "$KEY_FILE" | jq -Rs .)

# Upload to GL.iNet
RESPONSE=$(curl -s -X POST "https://$HOST/api/system/ssl_cert" \
  -H "Content-Type: application/json" \
  -H "X-KVMD-User: $USER" \
  -H "X-KVMD-Passwd: $PASS" \
  -k \
  -d "{\"ssl_cert\": $CERT, \"ssl_key\": $KEY}")

# Check response
OK=$(echo "$RESPONSE" | jq -r '.ok // false')

if [ "$OK" = "true" ]; then
  echo "Certificate uploaded to GL.iNet KVM successfully"
else
  echo "Failed to upload certificate to GL.iNet KVM"
  echo "Response: $RESPONSE"
  exit 1
fi

# Verify the new cert is being served
if [[ "$VERIFY" = true ]]; then
  "$SCRIPT_DIR/verify-deployed-cert.sh" \
    --host "$HOST" --cert-file "$CERT_FILE" --wait 15 --retries 3
fi
