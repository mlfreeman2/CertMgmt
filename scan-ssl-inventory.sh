#!/bin/bash
# scan-ssl-inventory.sh -- Discover and report all SSL/TLS certs on a subnet
#
# Scans one or more subnets for open SSL ports and prints full certificate
# details for every responding host. No config file required — designed for
# surveying an unknown network to help build a new deploy-config.json.
#
# Usage: scan-ssl-inventory.sh [OPTIONS] <subnet> [subnet2 ...]
#
# Requirements: nmap, openssl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PORTS="443,8443,993,995,465,636,5986,853"

# Terminal colors (suppressed when redirecting)
if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
  BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] <subnet> [subnet2 ...]

Scans subnets for open SSL/TLS ports and reports every certificate found.
No config file needed — use this to survey an unknown network before writing
a deploy-config.json for a new site.

Arguments:
  subnet          CIDR notation, e.g. 192.168.1.0/24 (multiple allowed)

Options:
  -p PORTS        Comma-separated SSL ports to scan (default: ${DEFAULT_PORTS})
  -o FILE         Save plaintext report to FILE (default: auto-generated ssl-inventory-YYYYMMDD-HHMMSS.txt)
  -n              Do not write a report file; print to stdout only
  -t SECS         Per-host TLS connection timeout in seconds (default: 30)
  -h              Show this help

Examples:
  $(basename "$0") 192.168.4.0/24
  $(basename "$0") 192.168.4.0/24 10.20.0.0/24
  $(basename "$0") -p 443,8443 -n 192.168.4.0/24   # stdout only
  $(basename "$0") -o site4.txt 192.168.4.0/24      # custom filename

Exit codes:
  0  Scan completed
  1  Fatal error (missing dependency, bad arguments, nmap failure)
EOF
  exit 0
}

# ---- Option parsing --------------------------------------------------------

PORTS="$DEFAULT_PORTS"
OUTPUT_FILE=""
NO_FILE=false
TIMEOUT=30

while getopts "p:o:nt:h" opt; do
  case $opt in
    p) PORTS="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    n) NO_FILE=true ;;
    t) TIMEOUT="$OPTARG" ;;
    h) print_usage ;;
    *) print_usage ;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
  echo "Error: at least one subnet argument is required." >&2
  echo "Run '$(basename "$0") -h' for usage." >&2
  exit 1
fi

SUBNETS=("$@")

# ---- Helpers ---------------------------------------------------------------

log() {
  local line="${1:-}"
  echo -e "$line"
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
  fi
}

die() { echo "Error: $*" >&2; exit 1; }

# ---- Dependency check ------------------------------------------------------

check_deps() {
  local missing=()
  for cmd in nmap openssl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}
Install with: sudo apt-get install ${missing[*]}"
  fi
}

# ---- TLS cert fetcher ------------------------------------------------------
# Prints tab-separated: fingerprint  CN  SANs  issuer_O  expiry
# Returns non-zero if no cert could be retrieved.

get_cert_info() {
  local host="$1" port="$2"
  local pem
  pem=$(echo \
        | timeout "$TIMEOUT" openssl s_client \
            -connect "${host}:${port}" \
            -servername "$host" \
            -verify_quiet \
            2>/dev/null) || return 1

  echo "$pem" | grep -q "BEGIN CERTIFICATE" || return 1

  local fp cn issuer expiry sans
  fp=$(echo "$pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
       | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')

  cn=$(echo "$pem" | openssl x509 -noout -subject 2>/dev/null \
       | grep -oP '(?<=CN\s=\s)[^,/]+' | head -1 \
       || echo "$pem" | openssl x509 -noout -subject 2>/dev/null \
          | sed 's/.*CN *= *//' | sed 's/[,/].*//')

  issuer=$(echo "$pem" | openssl x509 -noout -issuer 2>/dev/null \
           | grep -oP '(?<=O\s=\s)[^,/]+' | head -1 || true)

  expiry=$(echo "$pem" | openssl x509 -noout -enddate 2>/dev/null \
           | sed 's/notAfter=//')

  # SANs: "DNS:a.com, DNS:b.com" -> "a.com,b.com"
  sans=$(echo "$pem" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
         | grep -oP 'DNS:[^,\s]+' | sed 's/DNS://' | paste -sd,) || true
  [[ -z "$sans" ]] && sans="$cn"

  printf '%s\t%s\t%s\t%s\t%s' \
    "${fp:-unknown}" "${cn:-unknown}" "${sans}" "${issuer:-unknown}" "${expiry:-unknown}"
}

# ---- Issuer classifier -----------------------------------------------------
# Returns a short human-readable tag for the issuer field.

issuer_tag() {
  local issuer="$1" cn="$2"
  if echo "$issuer" | grep -qi "let.s encrypt\|letsencrypt"; then
    echo "${GREEN}[LET'S ENCRYPT]${NC}"
  elif echo "$issuer" | grep -qi "^unknown$\|^$"; then
    # No O= field in subject — likely self-signed
    echo "${YELLOW}[SELF-SIGNED]${NC}"
  elif echo "$cn" | grep -qi "$issuer" 2>/dev/null || [[ "$issuer" == "$cn" ]]; then
    echo "${YELLOW}[SELF-SIGNED]${NC}"
  else
    echo "${CYAN}[OTHER CA: ${issuer}]${NC}"
  fi
}

# ---- Main ------------------------------------------------------------------

check_deps

# Initialise output file (auto-generate name unless -n was given)
if ! $NO_FILE && [[ -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="${SCRIPT_DIR}/ssl-inventory-$(date '+%Y%m%d-%H%M%S').txt"
fi
[[ -n "$OUTPUT_FILE" ]] && : > "$OUTPUT_FILE"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
log "${BOLD}=== SSL/TLS Inventory ===${NC}"
log "Timestamp : $TIMESTAMP"
log "Subnets   : ${SUBNETS[*]}"
log "Ports     : $PORTS"
log "Timeout   : ${TIMEOUT}s per host"
[[ -n "$OUTPUT_FILE" ]] && log "Report    : $OUTPUT_FILE"
log ""

TOTAL_FOUND=0; TOTAL_LE=0; TOTAL_SELF=0; TOTAL_OTHER=0; TOTAL_FAIL=0

for SUBNET in "${SUBNETS[@]}"; do
  log "${BOLD}--- Scanning ${SUBNET} ---${NC}"

  NMAP_OUT=$(nmap -sT -p "$PORTS" --open -T4 -oG - "$SUBNET" 2>/dev/null) \
    || { log "nmap failed for ${SUBNET} (try running as root for faster SYN scan)"; continue; }

  declare -a PAIRS=()
  while IFS= read -r line; do
    [[ "$line" =~ ^Host: ]] || continue
    host=$(echo "$line" | grep -oP 'Host: \K[\d.a-fA-F:]+')
    while IFS= read -r port; do
      [[ -n "$port" ]] && PAIRS+=("${host}:${port}")
    done < <(echo "$line" | grep -oP '\d+/open/tcp' | cut -d/ -f1)
  done <<< "$NMAP_OUT"

  HOST_COUNT=$(echo "$NMAP_OUT" | grep -c '^Host:' || true)
  OPEN_COUNT=${#PAIRS[@]}
  log "${DIM}  nmap done: ${HOST_COUNT} host(s) up, ${OPEN_COUNT} open SSL port(s)${NC}"
  log ""

  if [[ $OPEN_COUNT -eq 0 ]]; then
    log "  No open SSL ports found."
    log ""; unset PAIRS; continue
  fi

  for hp in "${PAIRS[@]}"; do
    host="${hp%:*}"; port="${hp#*:}"

    cert_info=$(get_cert_info "$host" "$port" 2>/dev/null) || {
      ((TOTAL_FAIL++)) || true; continue
    }

    IFS=$'\t' read -r fp cn sans issuer expiry <<< "$cert_info"
    tag=$(issuer_tag "$issuer" "$cn")
    ((TOTAL_FOUND++)) || true

    # Tally by type
    if echo "$issuer" | grep -qi "let.s encrypt\|letsencrypt"; then
      ((TOTAL_LE++)) || true
    elif echo "$issuer" | grep -qi "^unknown$\|^$" || [[ "$issuer" == "$cn" ]]; then
      ((TOTAL_SELF++)) || true
    else
      ((TOTAL_OTHER++)) || true
    fi

    log "  ${BOLD}${host}:${port}${NC}  ${tag}"
    log "    CN      : ${cn}"
    log "    SANs    : ${sans}"
    log "    Issuer  : ${issuer}"
    log "    Expires : ${expiry}"
    log "    SHA-256 : ${fp}"
    log ""
  done

  unset PAIRS
done

# ---- Summary ---------------------------------------------------------------

log "${BOLD}=== Summary ===${NC}"
log "Total SSL endpoints found   : ${TOTAL_FOUND}"
log "${GREEN}Let's Encrypt               : ${TOTAL_LE}${NC}"
log "${YELLOW}Self-signed                 : ${TOTAL_SELF}${NC}"
log "${CYAN}Other CA                    : ${TOTAL_OTHER}${NC}"
log "No cert / failed            : ${TOTAL_FAIL}"
[[ -n "$OUTPUT_FILE" ]] && log "" && log "Report saved to: ${OUTPUT_FILE}"
