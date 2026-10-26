#!/bin/bash
# cert-dispatcher.sh -- Certbot deploy hook dispatcher
#
# This is the only script in /etc/letsencrypt/renewal-hooks/deploy/.
# Certbot invokes it on every certificate renewal with $RENEWED_LINEAGE set.
# It reads deploy-config.json to find which targets need the renewed cert,
# then invokes the appropriate driver script for each target.

set -u

CONFIG_FILE="/etc/letsencrypt/deploy-config.json"
LOGFILE=$(jq -r '.log_file // "/var/log/cert-deploy.log"' "$CONFIG_FILE" 2>/dev/null || echo "/var/log/cert-deploy.log")
DRIVER_DIR=$(jq -r '.cert_driver_dir // "/etc/letsencrypt/cert-drivers"' "$CONFIG_FILE" 2>/dev/null || echo "/etc/letsencrypt/cert-drivers")

# --- Healthchecks.io ping helper ---
# Pings are best-effort: failures are logged but never affect the exit code.
ping_healthchecks() {
  local suffix="$1"  # "" for success, "/start" or "/fail"
  local body="${2:-}"
  if [ -z "$HC_URL" ]; then
    return
  fi
  if [ -n "$body" ]; then
    curl -fsS -m 10 --retry 3 --data-raw "$body" "${HC_URL}${suffix}" >/dev/null 2>&1 || \
      log "WARNING: Healthchecks ping failed for ${HC_URL}${suffix} (non-fatal)"
  else
    curl -fsS -m 10 --retry 3 "${HC_URL}${suffix}" >/dev/null 2>&1 || \
      log "WARNING: Healthchecks ping failed for ${HC_URL}${suffix} (non-fatal)"
  fi
}

# --- Logging helper ---
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

# --- Pre-deploy fingerprint check ---
# Returns 0 if the device is already serving the local cert (skip deployment).
# Returns 1 if cert is stale, host unreachable, or port not TLS (proceed with deploy).
cert_already_deployed() {
  local host="$1" port="${2:-443}" cert_file="$3"
  "$DRIVER_DIR/verify-deployed-cert.sh" \
    --host "$host" --port "$port" --cert-file "$cert_file" \
    --wait 0 --retries 0 \
    >/dev/null 2>&1
}

# --- Target config helpers ---
# Read a field from the current $TARGET JSON, with optional default.
target_field() {
  local field="$1" default="${2:-}"
  if [ -n "$default" ]; then
    echo "$TARGET" | jq -r ".$field // \"$default\""
  else
    echo "$TARGET" | jq -r ".$field // empty"
  fi
}

# Build full cert/key paths from target config.
target_cert_path() {
  local default="${1:-fullchain.pem}"
  echo "$RENEWED_LINEAGE/$(target_field cert_file "$default")"
}

target_key_path() {
  echo "$RENEWED_LINEAGE/$(target_field key_file "privkey.pem")"
}

# Check if target is already deployed; if so, log SKIP and return 0.
# Caller should `continue` the loop on success.
check_skip_deployed() {
  local host="$1" port="${2:-443}" cert_file="$3"
  if cert_already_deployed "$host" "$port" "$cert_file"; then
    log "SKIP: $TARGET_NAME already serving current cert"
    SUCCEEDED=$((SUCCEEDED + 1))
    return 0
  fi
  return 1
}

# Run a driver command, teeing output to the log file, and set RESULT.
run_driver() {
  "$@" 2>&1 | tee -a "$LOGFILE"; RESULT=${PIPESTATUS[0]}
}

# --- Validate environment ---
if [ ! -f "$CONFIG_FILE" ]; then
  log "ERROR: Config file not found: $CONFIG_FILE"
  exit 1
fi

if [ -z "${RENEWED_LINEAGE:-}" ]; then
  log "ERROR: RENEWED_LINEAGE not set. Not running under certbot?"
  exit 1
fi

CERT_NAME=$(basename "$RENEWED_LINEAGE")

# Healthchecks URL is strictly per-cert. A shared check would let one cert's
# success mask another cert's failure when several lineages renew in the same
# certbot run — certs without their own URL send no pings at all.
HC_URL=$(jq -r ".certs[\"$CERT_NAME\"].healthchecks_url // empty" "$CONFIG_FILE" 2>/dev/null)

log "=== Certificate renewed: $CERT_NAME ==="
log "Lineage: $RENEWED_LINEAGE"
log "Domains: ${RENEWED_DOMAINS:-}"

# --- Look up targets in config ---
TARGETS=$(jq -c ".certs[\"$CERT_NAME\"].targets // empty" "$CONFIG_FILE")

if [ -z "$TARGETS" ] || [ "$TARGETS" = "null" ] || [ "$TARGETS" = "[]" ]; then
  log "No deployment targets configured for cert '$CERT_NAME'. Nothing to do."
  exit 0
fi

# Ping /start only once we know there is work to do — a cert with no targets
# must not leave its check dangling in the "started" state.
ping_healthchecks "/start"

# --- Track overall success ---
TOTAL=0
SUCCEEDED=0
FAILED_NAMES=""

# --- Iterate targets (using process substitution to avoid subshell) ---
while read -r TARGET; do
  TOTAL=$((TOTAL + 1))
  TARGET_NAME=$(echo "$TARGET" | jq -r '.name')
  DRIVER_TYPE=$(echo "$TARGET" | jq -r '.driver')

  log "--- Deploying to: $TARGET_NAME (driver: $DRIVER_TYPE) ---"

  # Check if verification is disabled for this target
  VERIFY_ARGS=()
  if echo "$TARGET" | jq -e '.verify == false' >/dev/null 2>&1; then
    VERIFY_ARGS=(--no-verify)
  fi

  # Build the command based on driver type
  RESULT=0
  case "$DRIVER_TYPE" in
    idrac)
      IP=$(target_field ip)
      CERT_FILE=$(target_cert_path "fullchain.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver "$DRIVER_DIR/driver-idrac.sh" \
        --host "$IP" --username "$(target_field username)" --password "$(target_field password)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    glinet-kvm)
      IP=$(target_field ip)
      CERT_FILE=$(target_cert_path "cert.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver "$DRIVER_DIR/driver-glinet-kvm.sh" \
        --host "$IP" --username "$(target_field username)" --password "$(target_field password)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    docker-compose)
      COMPOSE_DIR=$(target_field compose_dir)
      # Build --service flags from services array (falls back to service_name for compat)
      SERVICE_ARGS=()
      if echo "$TARGET" | jq -e '.services' >/dev/null 2>&1; then
        while read -r SVC; do
          SERVICE_ARGS+=(--service "$SVC")
        done < <(echo "$TARGET" | jq -r '.services[]')
      else
        SVC=$(target_field service_name "caddy")
        SERVICE_ARGS=(--service "$SVC")
      fi
      # Build verification args for docker-compose (needs explicit host since no IP)
      DC_VERIFY_ARGS=()
      if [ ${#VERIFY_ARGS[@]} -eq 0 ]; then
        VERIFY_HOST=$(target_field verify_host)
        VERIFY_PORT=$(target_field verify_port)
        VERIFY_CERT=$(target_field verify_cert_file)
        VERIFY_CERT_FILE="$RENEWED_LINEAGE/${VERIFY_CERT:-cert.pem}"
        if [ -n "$VERIFY_HOST" ]; then
          DC_VERIFY_ARGS+=(--verify-host "$VERIFY_HOST")
          if [ -n "$VERIFY_PORT" ]; then
            DC_VERIFY_ARGS+=(--verify-port "$VERIFY_PORT")
          fi
          DC_VERIFY_ARGS+=(--verify-cert-file "$VERIFY_CERT_FILE")
          check_skip_deployed "$VERIFY_HOST" "${VERIFY_PORT:-443}" "$VERIFY_CERT_FILE" && continue
        fi
      else
        DC_VERIFY_ARGS=("${VERIFY_ARGS[@]}")
      fi
      run_driver "$DRIVER_DIR/driver-docker-compose.sh" \
        --compose-dir "$COMPOSE_DIR" "${SERVICE_ARGS[@]}" "${DC_VERIFY_ARGS[@]}"
      ;;

    truenas-scale)
      IP=$(target_field ip)
      CERT_FILE=$(target_cert_path "fullchain.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver python3 "$DRIVER_DIR/driver-truenas-scale.py" \
        --host "$IP" --api-key "$(target_field api_key)" --domain "$(target_field domain)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    supermicro-ipmi)
      IP=$(target_field ip)
      MODEL=$(target_field model)
      CERT_FILE=$(target_cert_path "fullchain.pem")
      KEY_FILE=$(target_key_path)
      MODEL_ARGS=()
      if [ -n "$MODEL" ]; then
        MODEL_ARGS=(--model "$MODEL")
      fi
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver python3 "$DRIVER_DIR/driver-supermicro-ipmi.py" \
        --host "$IP" --username "$(target_field username)" --password "$(target_field password)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${MODEL_ARGS[@]}" "${VERIFY_ARGS[@]}"
      ;;

    brother-printer)
      IP=$(target_field ip)
      CERT_FILE=$(target_cert_path "fullchain.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver python3 "$DRIVER_DIR/driver-brother-printer.py" \
        --host "$IP" --username "$(target_field username)" --password "$(target_field password)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    reolink)
      IP=$(target_field ip)
      # Reolink rejects cert chains — default to the leaf cert
      CERT_FILE=$(target_cert_path "cert.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "443" "$CERT_FILE" && continue
      run_driver python3 "$DRIVER_DIR/driver-reolink.py" \
        --host "$IP" --username "$(target_field username)" --password "$(target_field password)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    proxmox)
      IP=$(target_field ip)
      CERT_FILE=$(target_cert_path "fullchain.pem")
      KEY_FILE=$(target_key_path)
      check_skip_deployed "$IP" "8006" "$CERT_FILE" && continue
      run_driver python3 "$DRIVER_DIR/driver-proxmox.py" \
        --host "$IP" --api-token "$(target_field api_token)" --node "$(target_field node)" \
        --cert-file "$CERT_FILE" --key-file "$KEY_FILE" \
        "${VERIFY_ARGS[@]}"
      ;;

    *)
      log "ERROR: Unknown driver type '$DRIVER_TYPE' for target '$TARGET_NAME'"
      RESULT=1
      ;;
  esac

  if [ "$RESULT" -eq 0 ]; then
    log "OK: $TARGET_NAME deployed successfully"
    SUCCEEDED=$((SUCCEEDED + 1))
  else
    log "FAIL: $TARGET_NAME deployment failed (exit code: $RESULT)"
    FAILED_NAMES="$FAILED_NAMES $TARGET_NAME"
  fi

done < <(echo "$TARGETS" | jq -c '.[]')

log "=== Deployment complete: $SUCCEEDED/$TOTAL succeeded ==="
if [ -n "$FAILED_NAMES" ]; then
  log "FAILED targets:$FAILED_NAMES"
  ping_healthchecks "/fail" "cert: $CERT_NAME -- $SUCCEEDED/$TOTAL succeeded, FAILED:$FAILED_NAMES"
  exit 1
fi

ping_healthchecks "" "cert: $CERT_NAME -- $SUCCEEDED/$TOTAL succeeded"
