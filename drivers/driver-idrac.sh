#!/bin/bash
# driver-idrac.sh -- Deploy certificate to Dell iDRAC via Redfish API
# Usage: driver-idrac.sh -h HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [--no-verify]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $(basename "$0") -h HOST -u USER -p PASS -c CERT_FILE -k KEY_FILE [--no-verify]"
  echo ""
  echo "Deploy an SSL certificate to a Dell iDRAC via the Redfish API."
  echo ""
  echo "Options:"
  echo "  -h, --host        iDRAC IP or hostname"
  echo "  -u, --username    iDRAC username"
  echo "  -p, --password    iDRAC password"
  echo "  -c, --cert-file   Path to certificate file (e.g. fullchain.pem)"
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

echo "Deploying certificate to Dell iDRAC at $HOST..."

# Read cert and key
CERT=$(cat "$CERT_FILE")
KEY=$(cat "$KEY_FILE")

# Step 1: Upload SSL Key
echo "Uploading SSL private key..."
KEY_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -k \
  -u "$USER:$PASS" \
  -X POST "https://$HOST/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.UploadSSLKey" \
  -H "Content-Type: application/json" \
  --data-binary @- << EOF
{
  "SSLKeyString": $(echo "$KEY" | jq -Rs .)
}
EOF
)

if ! echo "$KEY_RESPONSE" | grep -q "HTTP_CODE:200"; then
  echo "Failed to upload SSL key"
  echo "Response: $KEY_RESPONSE"
  exit 1
fi

echo "SSL key uploaded"

# Step 2: Import SSL Certificate
echo "Importing SSL certificate..."
CERT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -k \
  -u "$USER:$PASS" \
  -X POST "https://$HOST/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate" \
  -H "Content-Type: application/json" \
  --data-binary @- << EOF
{
  "CertificateType": "Server",
  "SSLCertificateFile": $(echo "$CERT" | jq -Rs .)
}
EOF
)

if ! echo "$CERT_RESPONSE" | grep -q "HTTP_CODE:200"; then
  echo "Failed to import SSL certificate"
  echo "Response: $CERT_RESPONSE"
  exit 1
fi

echo "SSL certificate imported"

# Step 3: Restart iDRAC to apply changes
echo "Restarting iDRAC to apply certificate..."
RESET_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -k \
  -u "$USER:$PASS" \
  -X POST "https://$HOST/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.iDRACReset" \
  -H "Content-Type: application/json" \
  --data '{"Force": "Graceful"}')

if ! echo "$RESET_RESPONSE" | grep -q "HTTP_CODE:200"; then
  echo "Warning: iDRAC reset may have failed"
  echo "Response: $RESET_RESPONSE"
  echo "  Certificate was uploaded but you may need to restart iDRAC manually"
else
  echo "iDRAC reset initiated"
fi

echo "Certificate deployed to Dell iDRAC successfully"
echo "  Note: iDRAC will be unavailable for ~2-3 minutes while restarting"

# Step 4: Verify the new cert is being served
if [[ "$VERIFY" = true ]]; then
  "$SCRIPT_DIR/verify-deployed-cert.sh" \
    --host "$HOST" --cert-file "$CERT_FILE" --wait 60 --retries 5
fi
