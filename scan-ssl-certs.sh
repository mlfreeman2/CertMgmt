#!/bin/bash
# scan-ssl-certs.sh -- Scan subnets for SSL/TLS services and identify project-managed certs
#
# Scans one or more subnets for open SSL ports, fetches each certificate,
# and reports whether the cert is managed by this project (certbot/Let's Encrypt).
# Useful for discovering devices on your networks that are serving project certs,
# as well as spotting unknown or unconfigured TLS endpoints.
#
# Usage: scan-ssl-certs.sh [OPTIONS] <subnet> [subnet2 ...]
#
# Requirements: nmap, openssl, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/deploy-config.json"
LETSENCRYPT_DIR="/etc/letsencrypt/live"
DEFAULT_PORTS="443,8443,993,995,465,636,5986,853"

# Terminal colors (suppressed when redirecting)
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] <subnet> [subnet2 ...]

Scans subnets for SSL/TLS services and reports whether each host is serving
a certificate managed by this project (certbot / Let's Encrypt).

Arguments:
  subnet          CIDR notation, e.g. 192.168.1.0/24 (multiple allowed)

Options:
  -c FILE         Path to deploy-config.json (default: ${CONFIG_FILE})
  -p PORTS        Comma-separated SSL ports to scan (default: ${DEFAULT_PORTS})
  -o FILE         Save plaintext report to FILE (default: auto-generated ssl-scan-YYYYMMDD-HHMMSS.txt)
  -n              Do not write a report file; print to stdout only
  -t SECS         Per-host TLS connection timeout in seconds (default: 30)
  -v              Verbose: show cert details for every host, not just matches
  -h              Show this help

Examples:
  $(basename "$0") 192.168.1.0/24
  $(basename "$0") 192.168.1.0/24 10.10.0.0/24 172.16.5.0/24
  $(basename "$0") -p 443,8443 -v 192.168.1.0/24
  $(basename "$0") -n 192.168.1.0/24                        # stdout only, no file
  $(basename "$0") -o my-report.txt 192.168.1.0/24          # custom filename

Exit codes:
  0  Scan completed (project certs may or may not have been found)
  1  Fatal error (missing dependency, bad arguments, nmap failure)
EOF
  exit 0
}

# ---- Option parsing --------------------------------------------------------

PORTS="$DEFAULT_PORTS"
OUTPUT_FILE=""
NO_FILE=false
TIMEOUT=30
VERBOSE=false

while getopts "c:p:o:nt:vh" opt; do
  case $opt in
    c) CONFIG_FILE="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    n) NO_FILE=true ;;
    t) TIMEOUT="$OPTARG" ;;
    v) VERBOSE=true ;;
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

# Write a line to stdout and optionally to the report file (strip ANSI for file)
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
  for cmd in nmap openssl jq; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}
Install with: sudo apt-get install ${missing[*]}"
  fi
}

# ---- Load project cert knowledge -------------------------------------------
# Populates:
#   FINGERPRINT_TO_DOMAIN  (associative: sha256_fp -> cert_name)
#   PROJECT_DOMAINS        (array of all managed domain patterns)

declare -A FINGERPRINT_TO_DOMAIN=()
declare -a PROJECT_DOMAINS=()

load_project_certs() {
  # 1. Fingerprints from live certbot directory (strongest match signal)
  if [[ -d "$LETSENCRYPT_DIR" ]]; then
    while IFS= read -r -d '' cert_file; do
      local cert_name fp
      cert_name=$(basename "$(dirname "$cert_file")")
      fp=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null \
           | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]') || continue
      [[ -n "$fp" ]] && FINGERPRINT_TO_DOMAIN["$fp"]="$cert_name"
    done < <(find "$LETSENCRYPT_DIR" -name "cert.pem" -print0 2>/dev/null)
  fi

  # 2. Domain patterns from deploy-config.json (covers cases where the certbot
  #    directory isn't present, e.g. running the scanner on a different host)
  if [[ -f "$CONFIG_FILE" ]]; then
    local -a cfg_domains
    mapfile -t cfg_domains < <(
      jq -r '.certs | to_entries[] | .value.domains[]' "$CONFIG_FILE" 2>/dev/null \
      | sort -u
    )
    PROJECT_DOMAINS+=("${cfg_domains[@]}")
  fi

  # Deduplicate
  mapfile -t PROJECT_DOMAINS < <(printf '%s\n' "${PROJECT_DOMAINS[@]}" | sort -u)
}

# ---- Domain matching -------------------------------------------------------
# Returns 0 if $1 matches any project domain pattern (exact or wildcard)

domain_is_project() {
  local target="$1" pd
  for pd in "${PROJECT_DOMAINS[@]}"; do
    [[ "$target" == "$pd" ]] && return 0
    if [[ "$pd" == \*.* ]]; then
      local base="${pd#\*.}"
      [[ "$target" == *".$base" || "$target" == "$base" ]] && return 0
    fi
  done
  return 1
}

# ---- TLS cert fetcher ------------------------------------------------------
# Prints tab-separated: fingerprint  CN  SANs  issuer_O  expiry
# Returns non-zero if no cert could be retrieved.

get_cert_info() {
  local host="$1" port="$2"
  local pem
  # -verify_quiet suppresses verification errors we don't care about
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

# ---- Cert classifier -------------------------------------------------------
# Prints a classification string: <type>[:<detail>]
# Types: fingerprint | domain+le | domain | letsencrypt | other

classify_cert() {
  local fp="$1" cn="$2" sans="$3" issuer="$4"

  # 1. Exact fingerprint match against a cert we currently hold
  if [[ -v FINGERPRINT_TO_DOMAIN["$fp"] ]]; then
    echo "fingerprint:${FINGERPRINT_TO_DOMAIN[$fp]}"
    return
  fi

  local is_le=false
  echo "$issuer" | grep -qi "let.s encrypt\|letsencrypt" && is_le=true

  # 2. SAN/CN domain match
  local domain
  IFS=',' read -ra san_list <<< "$sans"
  for domain in "${san_list[@]}"; do
    domain="${domain// /}"  # strip whitespace
    if domain_is_project "$domain"; then
      if $is_le; then
        echo "domain+le:$domain"
      else
        echo "domain:$domain"
      fi
      return
    fi
  done

  # 3. Let's Encrypt but not one of our domains
  $is_le && echo "letsencrypt" && return

  echo "other"
}

# ---- Main ------------------------------------------------------------------

check_deps
load_project_certs

# Initialise output file (auto-generate name unless -n was given)
if ! $NO_FILE && [[ -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="${SCRIPT_DIR}/ssl-scan-$(date '+%Y%m%d-%H%M%S').txt"
fi
[[ -n "$OUTPUT_FILE" ]] && : > "$OUTPUT_FILE"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
log "${BOLD}=== SSL Certificate Survey ===${NC}"
log "Timestamp  : $TIMESTAMP"
log "Subnets    : ${SUBNETS[*]}"
log "Ports      : $PORTS"
log "Config     : $CONFIG_FILE"
log "LE dir     : $LETSENCRYPT_DIR"
log "Fingerprints loaded : ${#FINGERPRINT_TO_DOMAIN[@]}"
log "Managed domains     : ${#PROJECT_DOMAINS[@]}$(
  [[ ${#PROJECT_DOMAINS[@]} -gt 0 ]] \
    && printf ' (%s)' "$(printf '%s ' "${PROJECT_DOMAINS[@]}" | xargs)" \
    || echo ' (none — is deploy-config.json present?)')"
log ""

# Aggregated totals across all subnets
TOTAL_PROJ=0; TOTAL_OTHER_LE=0; TOTAL_OTHER=0; TOTAL_FAIL=0

for SUBNET in "${SUBNETS[@]}"; do
  log "${BOLD}--- Scanning ${SUBNET} ---${NC}"

  # nmap: TCP connect scan, -T4 aggressive timing, grepable output
  NMAP_OUT=$(nmap -sT -p "$PORTS" --open -T4 -oG - "$SUBNET" 2>/dev/null) \
    || { log "${RED}nmap failed for ${SUBNET} (try running as root for faster SYN scan)${NC}"; continue; }

  # Parse "Host: <ip>  (<hostname>)  Ports: 443/open/tcp/..." lines
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
    log ""; continue
  fi

  for hp in "${PAIRS[@]}"; do
    host="${hp%:*}"; port="${hp#*:}"

    # Fetch cert (suppress errexit for this call)
    cert_info=$(get_cert_info "$host" "$port" 2>/dev/null) || {
      ((TOTAL_FAIL++)) || true; continue
    }

    IFS=$'\t' read -r fp cn sans issuer expiry <<< "$cert_info"
    classification=$(classify_cert "$fp" "$cn" "$sans" "$issuer")
    ctype="${classification%%:*}"
    cdetail="${classification#*:}"

    case "$ctype" in
      fingerprint)
        badge="${GREEN}[PROJECT CERT]${NC} fingerprint match → ${cdetail}"
        ((TOTAL_PROJ++)) || true ;;
      domain+le)
        badge="${GREEN}[PROJECT CERT]${NC} domain+LE match → ${cdetail}"
        ((TOTAL_PROJ++)) || true ;;
      domain)
        badge="${YELLOW}[PROJECT DOMAIN]${NC} domain match but issuer is not Let's Encrypt"
        ((TOTAL_PROJ++)) || true ;;
      letsencrypt)
        badge="${CYAN}[LET'S ENCRYPT]${NC} not in project config"
        ((TOTAL_OTHER_LE++)) || true ;;
      *)
        badge="${RED}[OTHER]${NC} not a project cert"
        ((TOTAL_OTHER++)) || true ;;
    esac

    log "  ${BOLD}${host}:${port}${NC}  ${badge}"

    # Always show details for project cert matches; show for all if -v
    if $VERBOSE || [[ "$ctype" == fingerprint || "$ctype" == domain* ]]; then
      log "    CN      : ${cn}"
      log "    SANs    : ${sans}"
      log "    Issuer  : ${issuer}"
      log "    Expires : ${expiry}"
      log "    SHA-256 : ${fp}"
    fi
    log ""
  done

  unset PAIRS
done

# ---- Final summary ---------------------------------------------------------

GRAND_TOTAL=$((TOTAL_PROJ + TOTAL_OTHER_LE + TOTAL_OTHER + TOTAL_FAIL))
log "${BOLD}=== Summary ===${NC}"
log "Total SSL endpoints probed  : ${GRAND_TOTAL}"
log "${GREEN}Project certs found         : ${TOTAL_PROJ}${NC}"
log "${CYAN}Other Let's Encrypt certs   : ${TOTAL_OTHER_LE}${NC}"
log "${RED}Other/unknown certs         : ${TOTAL_OTHER}${NC}"
log "Connection failures         : ${TOTAL_FAIL}"
[[ -n "$OUTPUT_FILE" ]] && log "" && log "Report saved to: ${OUTPUT_FILE}"
