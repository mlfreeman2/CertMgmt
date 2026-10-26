#!/bin/bash
# Run a trusted local command, then verify the certificate served by its target.
# CERT_FILE, KEY_FILE and CERT_DIR are exported for the command; stdin is closed.
# Commands and their output run with the caller's privileges. Keep secrets in files,
# not in the command string, and never print private keys or passwords.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: driver-shell-command.sh --command COMMAND [options]

  -c, --command COMMAND     Trusted Bash command to deliver/apply the certificate
  -d, --chdir DIR           Working directory for the command
      --cert-file FILE      Certificate path, exported as CERT_FILE
      --key-file FILE       Private-key path, exported as KEY_FILE
      --timeout SECONDS     Command deadline (default: 120; 0 disables)
      --verify-host HOST    TLS hostname to verify (also used as SNI)
      --verify-port PORT    TLS port (default: 443)
      --verify-cert-file F  Expected certificate (defaults to --cert-file)
      --no-verify           Explicitly skip verification, e.g. during bootstrap
  -h, --help                Show this help

Verification requires a host and expected certificate unless --no-verify is used.
CERT_DIR is the directory containing CERT_FILE. Supplied paths are made absolute
before --chdir is applied. Bash pipefail is enabled for the delivery command.
EOF
}

fail() { echo "Error: $*" >&2; exit 1; }

COMMAND=""
CHDIR=""
CERT_FILE=""
KEY_FILE=""
TIMEOUT=120
VERIFY=true
VERIFY_HOST=""
VERIFY_PORT=443
VERIFY_CERT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --no-verify) VERIFY=false; shift; continue ;;
    -c|--command|-d|--chdir|--cert-file|--key-file|--timeout|--verify-host|--verify-port|--verify-cert-file)
      [[ $# -ge 2 && -n "$2" ]] || fail "$1 requires a value"
      ;;
    *) fail "Unknown option: $1" ;;
  esac
  case "$1" in
    -c|--command) COMMAND="$2" ;;
    -d|--chdir) CHDIR="$2" ;;
    --cert-file) CERT_FILE="$2" ;;
    --key-file) KEY_FILE="$2" ;;
    --timeout) TIMEOUT="$2" ;;
    --verify-host) VERIFY_HOST="$2" ;;
    --verify-port) VERIFY_PORT="$2" ;;
    --verify-cert-file) VERIFY_CERT_FILE="$2" ;;
  esac
  shift 2
done

[[ -n "$COMMAND" ]] || fail "--command is required"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || fail "--timeout must be a whole number of seconds"
[[ "$VERIFY_PORT" =~ ^[0-9]{1,5}$ ]] || fail "invalid TLS port"
(( 10#$VERIFY_PORT >= 1 && 10#$VERIFY_PORT <= 65535 )) || fail "invalid TLS port"

VERIFY_CERT_FILE="${VERIFY_CERT_FILE:-$CERT_FILE}"
if $VERIFY; then
  [[ -n "$VERIFY_HOST" && -n "$VERIFY_CERT_FILE" ]] ||
    fail "verification needs --verify-host and --verify-cert-file (or --cert-file); use --no-verify to skip explicitly"
  [[ -x "$SCRIPT_DIR/verify-deployed-cert.sh" ]] || fail "verification helper is missing or not executable"
fi

# Resolve before changing directory so relative input paths keep their meaning.
for var in CERT_FILE KEY_FILE VERIFY_CERT_FILE; do
  path="${!var}"
  [[ -n "$path" ]] || continue
  [[ -f "$path" && -r "$path" ]] || fail "file is missing or unreadable: $path"
  resolved=$(realpath -- "$path") || fail "cannot resolve path: $path"
  printf -v "$var" '%s' "$resolved"
done
CERT_DIR=""
[[ -z "$CERT_FILE" ]] || CERT_DIR=$(dirname -- "$CERT_FILE")
export CERT_FILE KEY_FILE CERT_DIR

if [[ -n "$CHDIR" ]]; then
  cd -- "$CHDIR" || fail "cannot enter working directory: $CHDIR"
fi

# GNU timeout manages the local command's process group. Do not use --foreground:
# that would allow its children (including ssh) to outlive the timeout.
echo "Running certificate delivery command..."
RC=0
timeout --kill-after=5s "$TIMEOUT" bash -o pipefail -c "$COMMAND" </dev/null || RC=$?
if [[ "$RC" -eq 124 ]]; then
  fail "delivery command timed out after ${TIMEOUT}s"
elif [[ "$RC" -ne 0 ]]; then
  echo "Error: delivery command failed (exit code: $RC)" >&2
  exit "$RC"
fi
echo "Delivery command completed successfully"

if $VERIFY; then
  "$SCRIPT_DIR/verify-deployed-cert.sh" \
    --host "$VERIFY_HOST" --port "$VERIFY_PORT" \
    --cert-file "$VERIFY_CERT_FILE" --wait 15 --retries 3
else
  echo "Verification explicitly disabled (--no-verify)"
fi
