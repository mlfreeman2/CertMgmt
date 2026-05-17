#!/bin/bash
# driver-docker-compose.sh -- Restart Docker containers to pick up renewed certificate
# Usage: driver-docker-compose.sh -d COMPOSE_DIR -s SERVICE [-s SERVICE ...] [--verify-host HOST] [--verify-port PORT] [--verify-cert-file FILE] [--no-verify]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $(basename "$0") -d COMPOSE_DIR -s SERVICE [-s SERVICE ...] [options]"
  echo ""
  echo "Force-recreate one or more Docker compose services."
  echo ""
  echo "Options:"
  echo "  -d, --compose-dir      Path to docker compose project directory"
  echo "  -s, --service          Service name (can be specified multiple times)"
  echo "  --verify-host HOST     Host to verify certificate against after restart"
  echo "  --verify-port PORT     Port to verify against (default: 443)"
  echo "  --verify-cert-file FILE  Path to expected cert file for verification"
  echo "  --no-verify            Skip post-deployment certificate verification"
  exit 1
}

# Parse arguments
COMPOSE_DIR=""
SERVICES=()
VERIFY=true
VERIFY_HOST=""
VERIFY_PORT="443"
VERIFY_CERT_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--compose-dir)      COMPOSE_DIR="$2"; shift 2 ;;
    -s|--service)          SERVICES+=("$2"); shift 2 ;;
    --verify-host)         VERIFY_HOST="$2"; shift 2 ;;
    --verify-port)         VERIFY_PORT="$2"; shift 2 ;;
    --verify-cert-file)    VERIFY_CERT_FILE="$2"; shift 2 ;;
    --no-verify)           VERIFY=false; shift ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$COMPOSE_DIR" ]]; then
  echo "Error: --compose-dir is required."
  usage
fi

if [[ ${#SERVICES[@]} -eq 0 ]]; then
  SERVICES=("caddy")
fi

echo "Restarting ${SERVICES[*]} in $COMPOSE_DIR..."

cd "$COMPOSE_DIR"
docker compose up -d --force-recreate "${SERVICES[@]}"

echo "Services restarted successfully: ${SERVICES[*]}"

# Verify the new cert is being served
if [[ "$VERIFY" = true ]]; then
  if [[ -z "$VERIFY_HOST" || -z "$VERIFY_CERT_FILE" ]]; then
    echo "Skipping verification: --verify-host and --verify-cert-file required"
  else
    "$SCRIPT_DIR/verify-deployed-cert.sh" \
      --host "$VERIFY_HOST" --port "$VERIFY_PORT" \
      --cert-file "$VERIFY_CERT_FILE" --wait 15 --retries 3
  fi
fi
