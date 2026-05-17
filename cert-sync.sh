#!/bin/bash
# cert-sync.sh -- Synchronize local certbot certificates to match config
#
# Reads deploy-config.json, compares desired cert state (domains, key type,
# key size) to what certbot currently has, and brings them into alignment.
# Mismatched certs are revoked, deleted, and re-requested.
#
# Usage: cert-sync.sh [-c CONFIG] [-n] [-y]

set -u

usage() {
  echo "Usage: $(basename "$0") [-c CONFIG] [-n] [-y]"
  echo ""
  echo "Synchronize local certbot certificates to match the deploy config."
  echo ""
  echo "Options:"
  echo "  -c, --config   Path to deploy-config.json (default: /etc/letsencrypt/deploy-config.json)"
  echo "  -n, --dry-run  Show what would be done without making changes"
  echo "  -y, --yes      Skip confirmation prompts"
  echo "  -D, --deploy   Push current certs to all targets; with --dry-run, verify instead"
  exit 1
}

# --- Parse arguments ---
CONFIG_FILE="/etc/letsencrypt/deploy-config.json"
DRY_RUN=false
AUTO_YES=false
DEPLOY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config)  CONFIG_FILE="$2"; shift 2 ;;
    -n|--dry-run) DRY_RUN=true; shift ;;
    -y|--yes)     AUTO_YES=true; shift ;;
    -D|--deploy)  DEPLOY=true; shift ;;
    -h|--help)    usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# --- Validate config ---
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Error: Config file not found: $CONFIG_FILE"
  exit 1
fi

if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
  echo "Error: Invalid JSON in config file: $CONFIG_FILE"
  exit 1
fi

SITE_NAME=$(jq -r '.site_name' "$CONFIG_FILE")
EMAIL=$(jq -r '.email // empty' "$CONFIG_FILE")
echo "=== cert-sync for site: $SITE_NAME ==="
if $DRY_RUN; then
  echo "    (dry-run mode — no changes will be made)"
fi
echo ""

# --- Collect desired state from config ---
# Build arrays of cert names and their desired properties
CERT_NAMES=()
declare -A DESIRED_DOMAINS
declare -A DESIRED_KEY_TYPE
declare -A DESIRED_KEY_SIZE

while read -r CERT_NAME; do
  CERT_NAMES+=("$CERT_NAME")

  # Get domains as sorted, space-separated string for comparison
  DESIRED_DOMAINS["$CERT_NAME"]=$(jq -r ".certs[\"$CERT_NAME\"].domains // [] | sort | join(\" \")" "$CONFIG_FILE")
  DESIRED_KEY_TYPE["$CERT_NAME"]=$(jq -r ".certs[\"$CERT_NAME\"].key_type // \"ecdsa\"" "$CONFIG_FILE")
  DESIRED_KEY_SIZE["$CERT_NAME"]=$(jq -r ".certs[\"$CERT_NAME\"].key_size // empty" "$CONFIG_FILE")
done < <(jq -r '.certs | keys[]' "$CONFIG_FILE")

DRIVER_DIR=$(jq -r '.cert_driver_dir // "/etc/letsencrypt/cert-drivers"' "$CONFIG_FILE")
DISPATCHER="/etc/letsencrypt/renewal-hooks/deploy/cert-dispatcher.sh"

# --- Deploy mode: push certs to all targets (or verify with --dry-run) ---
if $DEPLOY; then
  if $DRY_RUN; then
    echo "--- Deploy check: verifying served certificates ---"
    echo ""
    VERIFY_SCRIPT="$DRIVER_DIR/verify-deployed-cert.sh"
    if [ ! -f "$VERIFY_SCRIPT" ]; then
      echo "Error: Verify script not found at $VERIFY_SCRIPT"
      echo "       Run certbot-setup.sh first."
      exit 1
    fi
    VTOTAL=0; VPASSED=0; VFAILED=0; VSKIPPED=0
    for CERT_NAME in "${CERT_NAMES[@]}"; do
      LINEAGE="/etc/letsencrypt/live/$CERT_NAME"
      echo "Certificate: $CERT_NAME"
      if [ ! -d "$LINEAGE" ]; then
        echo "  SKIP: no lineage at $LINEAGE"
        echo ""
        continue
      fi
      TARGETS=$(jq -c ".certs[\"$CERT_NAME\"].targets // []" "$CONFIG_FILE")
      if [ "$TARGETS" = "[]" ] || [ "$TARGETS" = "null" ]; then
        echo "  (no targets configured)"
        echo ""
        continue
      fi
      while read -r TARGET; do
        TARGET_NAME=$(echo "$TARGET" | jq -r '.name')
        DRIVER_TYPE=$(echo "$TARGET" | jq -r '.driver')
        if echo "$TARGET" | jq -e '.verify == false' >/dev/null 2>&1; then
          echo "  SKIP $TARGET_NAME: verification disabled"
          VSKIPPED=$((VSKIPPED + 1))
          continue
        fi
        VERIFY_HOST=""
        VERIFY_PORTS="443"
        VERIFY_CERT_REL="cert.pem"
        case "$DRIVER_TYPE" in
          idrac|glinet-kvm|truenas-scale|supermicro-ipmi|reolink|brother-printer)
            VERIFY_HOST=$(echo "$TARGET" | jq -r '.ip')
            VERIFY_CERT_REL=$(echo "$TARGET" | jq -r '.cert_file // "cert.pem"')
            ;;
          proxmox)
            VERIFY_HOST=$(echo "$TARGET" | jq -r '.ip')
            VERIFY_PORTS="8006 443"
            VERIFY_CERT_REL=$(echo "$TARGET" | jq -r '.cert_file // "fullchain.pem"')
            ;;
          docker-compose)
            VERIFY_HOST=$(echo "$TARGET" | jq -r '.verify_host // empty')
            VERIFY_PORTS=$(echo "$TARGET" | jq -r '.verify_port // "443"')
            VERIFY_CERT_REL=$(echo "$TARGET" | jq -r '.verify_cert_file // "cert.pem"')
            ;;
        esac
        if [ -z "$VERIFY_HOST" ]; then
          echo "  SKIP $TARGET_NAME: no host to verify against"
          VSKIPPED=$((VSKIPPED + 1))
          continue
        fi
        for VERIFY_PORT in $VERIFY_PORTS; do
          VTOTAL=$((VTOTAL + 1))
          VERIFY_OUT=$("$VERIFY_SCRIPT" \
            --host "$VERIFY_HOST" --port "$VERIFY_PORT" \
            --cert-file "$LINEAGE/$VERIFY_CERT_REL" \
            --wait 0 --retries 0 2>&1) && VRESULT=0 || VRESULT=$?
          if [ "$VRESULT" -eq 0 ]; then
            echo "  PASS: $TARGET_NAME ($DRIVER_TYPE @ $VERIFY_HOST:$VERIFY_PORT)"
            VPASSED=$((VPASSED + 1))
          else
            echo "  FAIL: $TARGET_NAME ($DRIVER_TYPE @ $VERIFY_HOST:$VERIFY_PORT)"
            echo "    ${VERIFY_OUT//$'\n'/$'\n'    }"
            VFAILED=$((VFAILED + 1))
          fi
        done
      done < <(echo "$TARGETS" | jq -c '.[]')
      echo ""
    done
    echo "=== Deploy check: $VPASSED/$VTOTAL passed, $VSKIPPED skipped ==="
    [ "$VFAILED" -eq 0 ] || exit 1
  else
    if [ ! -f "$DISPATCHER" ]; then
      echo "Error: Dispatcher not found at $DISPATCHER"
      echo "       Run certbot-setup.sh first."
      exit 1
    fi
    echo "--- Deploying all certs to targets ---"
    echo ""
    DTOTAL=0; DSUCCEEDED=0
    for CERT_NAME in "${CERT_NAMES[@]}"; do
      LINEAGE="/etc/letsencrypt/live/$CERT_NAME"
      DOMAINS="${DESIRED_DOMAINS[$CERT_NAME]}"
      TARGETS=$(jq -c ".certs[\"$CERT_NAME\"].targets // []" "$CONFIG_FILE")
      if [ ! -d "$LINEAGE" ]; then
        echo "SKIP $CERT_NAME: no lineage at $LINEAGE (run cert-sync to create it)"
        echo ""
        continue
      fi
      if [ "$TARGETS" = "[]" ] || [ "$TARGETS" = "null" ]; then
        echo "SKIP $CERT_NAME: no targets configured"
        echo ""
        continue
      fi
      DTOTAL=$((DTOTAL + 1))
      echo "Deploying: $CERT_NAME"
      if RENEWED_LINEAGE="$LINEAGE" RENEWED_DOMAINS="$DOMAINS" "$DISPATCHER"; then
        DSUCCEEDED=$((DSUCCEEDED + 1))
      fi
      echo ""
    done
    echo "=== Deploy complete: $DSUCCEEDED/$DTOTAL succeeded ==="
    [ "$DSUCCEEDED" -eq "$DTOTAL" ] || exit 1
  fi
  exit 0
fi

# --- Collect current certbot state ---
# Parse `certbot certificates` output into associative arrays
declare -A CURRENT_DOMAINS
declare -A CURRENT_CERT_PATH

CERTBOT_OUTPUT=$(certbot certificates 2>/dev/null) || {
  echo "Error: Failed to run 'certbot certificates'"
  exit 1
}

CURRENT_NAME=""
while IFS= read -r LINE; do
  # Match "Certificate Name: xxx"
  if [[ "$LINE" =~ ^[[:space:]]*Certificate\ Name:\ (.+)$ ]]; then
    CURRENT_NAME="${BASH_REMATCH[1]}"
  fi
  # Match "Domains: xxx"
  if [[ "$LINE" =~ ^[[:space:]]*Domains:\ (.+)$ ]] && [ -n "$CURRENT_NAME" ]; then
    # Sort domains for consistent comparison
    CURRENT_DOMAINS["$CURRENT_NAME"]=$(echo "${BASH_REMATCH[1]}" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
  fi
  # Match "Certificate Path: xxx"
  if [[ "$LINE" =~ ^[[:space:]]*Certificate\ Path:\ (.+)$ ]] && [ -n "$CURRENT_NAME" ]; then
    CURRENT_CERT_PATH["$CURRENT_NAME"]="${BASH_REMATCH[1]}"
  fi
done <<< "$CERTBOT_OUTPUT"

# --- Helper: get key type and size from an existing cert ---
get_cert_key_info() {
  local cert_path="$1"
  local key_algo key_size

  if [ ! -f "$cert_path" ]; then
    echo "unknown 0"
    return
  fi

  local cert_text
  cert_text=$(openssl x509 -in "$cert_path" -noout -text 2>/dev/null)

  # Determine key type
  if echo "$cert_text" | grep -q "rsaEncryption"; then
    key_algo="rsa"
  elif echo "$cert_text" | grep -q "id-ecPublicKey"; then
    key_algo="ecdsa"
  else
    key_algo="unknown"
  fi

  # Determine key size (RSA: "RSA Public-Key: (2048 bit)", EC: "256 bit" etc)
  key_size=$(echo "$cert_text" | grep -oP 'Public-Key:\s*\(\K[0-9]+' | head -1)
  if [ -z "$key_size" ]; then
    key_size=0
  fi

  echo "$key_algo $key_size"
}

# --- Compare and plan actions ---
declare -a ACTIONS_CREATE   # certs to create (new)
declare -a ACTIONS_REPLACE  # certs to revoke+delete+recreate
declare -a ACTIONS_OK       # certs already matching
declare -a REPLACE_REASONS  # human-readable reasons for replacement

for CERT_NAME in "${CERT_NAMES[@]}"; do
  WANTED_DOMAINS="${DESIRED_DOMAINS[$CERT_NAME]}"
  WANTED_KEY_TYPE="${DESIRED_KEY_TYPE[$CERT_NAME]}"
  WANTED_KEY_SIZE="${DESIRED_KEY_SIZE[$CERT_NAME]}"

  # Skip certs with no domains configured
  if [ -z "$WANTED_DOMAINS" ]; then
    continue
  fi

  if [ -z "${CURRENT_DOMAINS[$CERT_NAME]+_}" ]; then
    # Cert doesn't exist yet
    ACTIONS_CREATE+=("$CERT_NAME")
    continue
  fi

  # Cert exists — check for mismatches
  REASONS=""

  # Compare domains
  EXISTING_DOMAINS="${CURRENT_DOMAINS[$CERT_NAME]}"
  if [ "$WANTED_DOMAINS" != "$EXISTING_DOMAINS" ]; then
    REASONS="domains mismatch (have: $EXISTING_DOMAINS, want: $WANTED_DOMAINS)"
  fi

  # Compare key type and size
  CERT_PATH="${CURRENT_CERT_PATH[$CERT_NAME]}"
  if [ -n "$CERT_PATH" ]; then
    read -r EXISTING_KEY_TYPE EXISTING_KEY_SIZE <<< "$(get_cert_key_info "$CERT_PATH")"

    if [ "$WANTED_KEY_TYPE" != "$EXISTING_KEY_TYPE" ]; then
      if [ -n "$REASONS" ]; then REASONS="$REASONS; "; fi
      REASONS="${REASONS}key type mismatch (have: $EXISTING_KEY_TYPE, want: $WANTED_KEY_TYPE)"
    fi

    if [ "$WANTED_KEY_TYPE" = "rsa" ] && [ -n "$WANTED_KEY_SIZE" ] && [ "$WANTED_KEY_SIZE" != "$EXISTING_KEY_SIZE" ]; then
      if [ -n "$REASONS" ]; then REASONS="$REASONS; "; fi
      REASONS="${REASONS}key size mismatch (have: ${EXISTING_KEY_SIZE}bit, want: ${WANTED_KEY_SIZE}bit)"
    fi
  fi

  if [ -n "$REASONS" ]; then
    ACTIONS_REPLACE+=("$CERT_NAME")
    REPLACE_REASONS+=("$REASONS")
  else
    ACTIONS_OK+=("$CERT_NAME")
  fi
done

# --- Print plan ---
echo "--- Current state ---"
if [ ${#ACTIONS_OK[@]} -gt 0 ]; then
  for CERT_NAME in "${ACTIONS_OK[@]}"; do
    echo "  OK: $CERT_NAME"
  done
fi
echo ""

CHANGES_NEEDED=false

if [ ${#ACTIONS_CREATE[@]} -gt 0 ]; then
  CHANGES_NEEDED=true
  echo "--- Certificates to CREATE (not on disk) ---"
  for CERT_NAME in "${ACTIONS_CREATE[@]}"; do
    echo "  + $CERT_NAME"
    echo "    domains: ${DESIRED_DOMAINS[$CERT_NAME]}"
    echo "    key_type: ${DESIRED_KEY_TYPE[$CERT_NAME]} ${DESIRED_KEY_SIZE[$CERT_NAME]:+(${DESIRED_KEY_SIZE[$CERT_NAME]} bit)}"
  done
  echo ""
fi

if [ ${#ACTIONS_REPLACE[@]} -gt 0 ]; then
  CHANGES_NEEDED=true
  echo "--- Certificates to REVOKE + REPLACE (mismatched) ---"
  for i in "${!ACTIONS_REPLACE[@]}"; do
    CERT_NAME="${ACTIONS_REPLACE[$i]}"
    echo "  ~ $CERT_NAME"
    echo "    reason: ${REPLACE_REASONS[$i]}"
    echo "    new domains: ${DESIRED_DOMAINS[$CERT_NAME]}"
    echo "    new key_type: ${DESIRED_KEY_TYPE[$CERT_NAME]} ${DESIRED_KEY_SIZE[$CERT_NAME]:+(${DESIRED_KEY_SIZE[$CERT_NAME]} bit)}"
  done
  echo ""
fi

if ! $CHANGES_NEEDED; then
  echo "All certificates match the config. Nothing to do."
  exit 0
fi

# --- Confirm ---
if $DRY_RUN; then
  echo "Dry-run complete. No changes were made."
  exit 0
fi

if ! $AUTO_YES; then
  echo -n "Proceed with the above changes? [y/N] "
  read -r CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Aborted."
    exit 0
  fi
  echo ""
fi

# --- Helper: build and run certbot certonly command ---
request_cert() {
  local cert_name="$1"
  local key_type="${DESIRED_KEY_TYPE[$cert_name]}"
  local key_size="${DESIRED_KEY_SIZE[$cert_name]}"
  local domains="${DESIRED_DOMAINS[$cert_name]}"

  local cmd=(certbot certonly
    --dns-cloudflare
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini
    --dns-cloudflare-propagation-seconds 60
    --key-type "$key_type"
    --cert-name "$cert_name"
    --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/cert-dispatcher.sh
    --disable-hook-validation
    --non-interactive
    --agree-tos
  )

  if [ -n "$EMAIL" ]; then
    cmd+=(--email "$EMAIL")
  else
    cmd+=(--register-unsafely-without-email)
  fi

  if [ "$key_type" = "rsa" ] && [ -n "$key_size" ]; then
    cmd+=(--rsa-key-size "$key_size")
  fi

  # Add each domain as a separate -d flag
  for domain in $domains; do
    cmd+=(-d "$domain")
  done

  echo "  Running: ${cmd[*]}"
  if ! "${cmd[@]}"; then
    echo "  FAILED: certbot certonly for $cert_name"
    return 1
  fi
  return 0
}

# --- Execute: create new certs ---
TOTAL=0
SUCCEEDED=0

for CERT_NAME in "${ACTIONS_CREATE[@]}"; do
  TOTAL=$((TOTAL + 1))
  echo "--- Creating: $CERT_NAME ---"
  if request_cert "$CERT_NAME"; then
    echo "  Created successfully"
    SUCCEEDED=$((SUCCEEDED + 1))
  fi
  echo ""
done

# --- Execute: revoke + delete + recreate mismatched certs ---
for i in "${!ACTIONS_REPLACE[@]}"; do
  CERT_NAME="${ACTIONS_REPLACE[$i]}"
  TOTAL=$((TOTAL + 1))
  echo "--- Replacing: $CERT_NAME ---"
  echo "  Reason: ${REPLACE_REASONS[$i]}"

  # Step 1: Revoke
  echo "  Revoking..."
  if ! certbot revoke --cert-name "$CERT_NAME" --non-interactive --no-delete-after-revoke --reason superseded 2>&1; then
    echo "  WARNING: Revocation failed, continuing with delete..."
  fi

  # Step 2: Delete
  echo "  Deleting local cert..."
  if ! certbot delete --cert-name "$CERT_NAME" --non-interactive 2>&1; then
    echo "  FAILED: Could not delete cert $CERT_NAME"
    echo ""
    continue
  fi

  # Step 3: Re-request
  echo "  Re-requesting..."
  if request_cert "$CERT_NAME"; then
    echo "  Replaced successfully"
    SUCCEEDED=$((SUCCEEDED + 1))
  fi
  echo ""
done

# --- Summary ---
echo "=== cert-sync complete: $SUCCEEDED/$TOTAL succeeded ==="
if [ "$SUCCEEDED" -lt "$TOTAL" ]; then
  exit 1
fi
