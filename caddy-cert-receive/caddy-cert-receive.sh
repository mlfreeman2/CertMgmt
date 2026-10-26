#!/bin/bash
# caddy-cert-receive -- forced-command receiver for TLS certificates.
#
# The only thing the sender's SSH key may run. Reads a private key followed by its certificate chain
# as one PEM stream on stdin, validates it, picks the slot directory from the certificate's own SAN,
# stages a complete generation, switches the current symlink, and reloads Caddy with --force.
# Caddyfile paths must use <slot>/current/{fullchain.pem,privkey.pem}; see README.md.
#
#   cat privkey.pem fullchain.pem | ssh -i KEY cert-receiver@CADDY install
#   cat privkey.pem fullchain.pem | ssh -i KEY cert-receiver@CADDY check    # validate only
#   ssh -i KEY cert-receiver@CADDY status                                    # what each slot holds
#
# A slot is a directory under $CERT_BASE named after the certificate's SAN minus any leading "*.".
# The set of directories is the allowlist, and this script never creates one.
#
# Exit codes: 0 success (status: every slot holds a valid pair); nonzero on refusal or failure;
# 2 for an unknown verb. Errors go to stderr; explicit refusal/reload messages also go to syslog.

set -euo pipefail
umask 027

# ---- configuration --------------------------------------------------------------------------
# Defaults. A root-owned /etc/caddy-cert-receive.conf may override any of them; the client cannot,
# because PermitUserEnvironment is off and `restrict` is on.

CERT_BASE="/etc/caddy/certs"
CERT_FILE="fullchain.pem"
KEY_FILE="privkey.pem"
CADDYFILE="/etc/caddy/Caddyfile"
RELOAD_CMD=""                             # empty -> the caddy default built in reload_target()
MIN_REMAINING_SECS=$((24 * 3600))         # refuse anything expiring within one day
MAX_INPUT_BYTES=$((256 * 1024))           # key + chain is ~6 KB; anything near this is not a cert
LOG_TAG="caddy-cert-receive"

GLOBAL_CONF="/etc/caddy-cert-receive.conf"
if [[ -f "$GLOBAL_CONF" ]]; then
  # shellcheck source=/dev/null
  . "$GLOBAL_CONF"
fi

# ---- plumbing -------------------------------------------------------------------------------

log() {
  echo "$LOG_TAG: $*" >&2
  logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true
}

die() {
  log "ERROR: $*"
  exit 1
}

TMP=""
cleanup() {
  if [[ -n "$TMP" ]]; then rm -rf -- "$TMP"; fi
}
trap cleanup EXIT

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2
}

not_after_epoch() {
  local end
  end=$(openssl x509 -in "$1" -noout -enddate) || return 1
  date -d "${end#notAfter=}" +%s
}

san_names() {
  # One DNS SAN per line. `-ext` needs OpenSSL 1.1.1+, which every supported Debian has.
  openssl x509 -in "$1" -noout -ext subjectAltName | tr ',' '\n' | sed -E 's/^ *DNS://; t; d'
}

# What a slot is called for a given DNS name: the name with any leading `*.` removed.
slot_of_name() {
  local n="${1#\*.}"
  # Derived from the certificate, but validated anyway -- a SAN is not this script's data to trust,
  # and the result becomes a path.
  [[ "$n" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$n" != *..* ]] || return 1
  echo "$n"
}


reload_target() {
  local out
  # --force is the whole point of the default: a reload diffs the new config against the running one
  # and no-ops when they match, and renewing a certificate does not change the Caddyfile.
  if [[ -n "$RELOAD_CMD" ]]; then
    if ! out=$(bash -o pipefail -c "$RELOAD_CMD" </dev/null 2>&1); then
      die "reload failed; current generation retained for retry: $out"
    fi
  elif ! out=$(caddy reload --config "$CADDYFILE" --adapter caddyfile --force </dev/null 2>&1); then
    die "Caddy reload failed; current generation retained for retry: $out"
  fi
  log "reload completed"
}

# Only receiver-managed, relative generation links are accepted. Never migrate a legacy pair
# implicitly: its Caddyfile still names the flat files and would not follow a new current link.
load_current() {
  CURRENT_TARGET=""
  CURRENT_DIR=""
  if [[ -L "$SLOT_DIR/current" ]]; then
    CURRENT_TARGET=$(readlink -- "$SLOT_DIR/current")
    [[ "$CURRENT_TARGET" =~ ^\.generation\.[a-zA-Z0-9]+$ &&
       -d "$SLOT_DIR/$CURRENT_TARGET" && ! -L "$SLOT_DIR/$CURRENT_TARGET" ]] ||
      die "slot $SLOT: current must point to a local .generation directory"
    CURRENT_DIR="$SLOT_DIR/$CURRENT_TARGET"
  elif [[ -e "$SLOT_DIR/current" ]]; then
    die "slot $SLOT: current exists but is not a generation symlink"
  elif [[ -e "$SLOT_DIR/$CERT_FILE" || -L "$SLOT_DIR/$CERT_FILE" ||
          -e "$SLOT_DIR/$KEY_FILE" || -L "$SLOT_DIR/$KEY_FILE" ]]; then
    die "slot $SLOT: legacy flat files need migration and Caddyfile path updates; see README.md"
  fi
}

# ---- the stream -----------------------------------------------------------------------------

# Split one PEM stream into a key file and a chain file, refusing anything that is neither. Lines
# outside a BEGIN/END block are dropped (as openssl itself would); an unexpected block type, a
# nested or unterminated block, or an ENCRYPTED key is a refusal, not a warning.
split_pem() {
  local in="$1" key="$2" chain="$3"
  awk -v key="$key" -v chain="$chain" '
    { sub(/\r$/, "") }
    /^-----BEGIN / {
      if (inblock) { print "nested BEGIN at line " NR > "/dev/stderr"; exit 3 }
      type = $0; sub(/^-----BEGIN /, "", type); sub(/-----$/, "", type)
      if (type ~ /ENCRYPTED/)             { print "refusing an encrypted block: " type > "/dev/stderr"; exit 3 }
      else if (type ~ /PRIVATE KEY$/)     { out = key;   nkeys++ }
      else if (type == "CERTIFICATE")     { out = chain; ncerts++ }
      else                                { print "unexpected PEM block: " type > "/dev/stderr"; exit 3 }
      inblock = 1
    }
    inblock { print > out }
    /^-----END / {
      if (!inblock) { print "END without BEGIN at line " NR > "/dev/stderr"; exit 3 }
      inblock = 0; out = ""
    }
    END {
      if (inblock) { print "unterminated PEM block" > "/dev/stderr"; exit 3 }
      printf "%d %d\n", nkeys, ncerts
    }
  ' "$in"
}

# Sets SLOT and SLOT_DIR. The directory's existence is the authorization check: no directory, no
# delivery -- and this script never creates one.
resolve_slot() {
  local n cand tried=()
  while read -r n; do
    cand=$(slot_of_name "$n") || continue
    # `*.x` and `x` both reduce to the same slot; do not say the name twice in the refusal.
    [[ " ${tried[*]-} " == *" $cand "* ]] || tried+=("$cand")
    if [[ -d "$CERT_BASE/$cand" && ! -L "$CERT_BASE/$cand" ]]; then
      SLOT="$cand"
      SLOT_DIR="$CERT_BASE/$SLOT"
      return 0
    fi
  done < <(san_names "$TMP/chain")
  die "no slot for this certificate -- none of ${tried[*]:-<no usable DNS SAN>} is a directory in $CERT_BASE"
}

# Read stdin into $TMP/in.pem, validate it into $TMP/key and $TMP/chain, and resolve the slot.
# Validate before changing a slot's active generation. Temporary input stays under $CERT_BASE.
read_and_validate() {
  local size counts nkeys ncerts

  head -c "$((MAX_INPUT_BYTES + 1))" > "$TMP/in.pem"
  size=$(stat -c %s "$TMP/in.pem")
  (( size > 0 )) || die "nothing on stdin -- send privkey.pem followed by fullchain.pem"
  (( size <= MAX_INPUT_BYTES )) || die "input exceeds $MAX_INPUT_BYTES bytes; that is not a certificate"

  counts=$(split_pem "$TMP/in.pem" "$TMP/key" "$TMP/chain") || die "malformed PEM stream"
  read -r nkeys ncerts <<< "$counts"
  (( nkeys == 1 )) || die "expected exactly one private key block, got $nkeys"
  (( ncerts >= 1 )) || die "no CERTIFICATE block in the stream"

  # `-passin pass:` so a key that somehow wants a passphrase fails instead of waiting for a tty.
  openssl pkey -in "$TMP/key" -noout -passin pass: 2>/dev/null || die "private key does not parse"
  openssl crl2pkcs7 -nocrl -certfile "$TMP/chain" 2>/dev/null |
    openssl pkcs7 -print_certs -noout >/dev/null 2>&1 || die "certificate chain does not parse"

  # Also the check that the LEAF came first: the key matches the leaf, not an intermediate.
  [[ "$(openssl x509 -in "$TMP/chain" -noout -pubkey)" == "$(openssl pkey -in "$TMP/key" -pubout 2>/dev/null)" ]] ||
    die "private key does not match the first certificate in the chain"

  resolve_slot
  load_current

  openssl x509 -in "$TMP/chain" -noout -checkend "$MIN_REMAINING_SECS" >/dev/null ||
    die "certificate expires within $((MIN_REMAINING_SECS / 3600))h -- refusing to install it"

  # This receiver refuses an earlier notAfter within the same slot, to catch accidental older
  # deliveries. Deliberate rollback or a shorter certificate lifetime requires local intervention.
  local old_epoch new_epoch
  if [[ -n "$CURRENT_DIR" ]] && old_epoch=$(not_after_epoch "$CURRENT_DIR/$CERT_FILE" 2>/dev/null); then
    new_epoch=$(not_after_epoch "$TMP/chain")
    (( new_epoch >= old_epoch )) ||
      die "slot $SLOT: refusing to replace a certificate expiring $(date -d "@$old_epoch" +%F) with one expiring $(date -d "@$new_epoch" +%F)"
  fi
}

# ---- verbs ----------------------------------------------------------------------------------

do_install() {
  local new_fp generation target

  read_and_validate
  new_fp=$(fingerprint "$TMP/chain")
  log "slot $SLOT: received $(san_names "$TMP/chain" | paste -sd, -), expires $(openssl x509 -in "$TMP/chain" -noout -enddate | cut -d= -f2), sha256 $new_fp"

  # Compare the entire chain and key: an intermediate can change without changing the leaf.
  if [[ -n "$CURRENT_DIR" ]] && cmp -s "$TMP/chain" "$CURRENT_DIR/$CERT_FILE" &&
     cmp -s "$TMP/key" "$CURRENT_DIR/$KEY_FILE"; then
    log "slot $SLOT: identical to what is installed -- reloading anyway"
  else
    # Both files are complete before one same-filesystem rename publishes their directory.
    # Never remove generations automatically, including on failure: the switch may have completed
    # just before a signal or failed reload. Unreferenced staging directories are safe to retain.
    generation=$(mktemp -d "$SLOT_DIR/.generation.XXXXXXXXXX")
    chmod 2750 "$generation"
    install -m 0640 "$TMP/key" "$generation/$KEY_FILE"
    install -m 0640 "$TMP/chain" "$generation/$CERT_FILE"
    target=${generation##*/}
    if [[ -n "$CURRENT_TARGET" ]]; then
      ln -s -- "$CURRENT_TARGET" "$generation/.previous"
      mv -Tf -- "$generation/.previous" "$SLOT_DIR/previous"
    fi
    ln -s -- "$target" "$generation/.current"
    mv -Tf -- "$generation/.current" "$SLOT_DIR/current"
    log "slot $SLOT: activated $target (earlier generations retained)"
  fi

  # Unconditional, including when the bytes matched: "the file was already right so I
  # did nothing" is the reasoning that leaves a stale certificate loaded after an earlier reload
  # died between the install and the apply. The sender's own pre-deploy check is what prevents pointless
  # redeliveries; this end does the thing it was asked to do.
  reload_target
}

do_check() {
  read_and_validate
  log "check: valid, slot $SLOT -- $(san_names "$TMP/chain" | paste -sd, -), expires $(openssl x509 -in "$TMP/chain" -noout -enddate | cut -d= -f2), sha256 $(fingerprint "$TMP/chain"); nothing installed"
}

# Every enrolled slot, whether or not anything has been delivered to it yet. Exit 1 if any slot is
# empty. It does not say what is being SERVED -- the sender checks that over TLS after every delivery.
do_status() {
  local dir slot rc=0 seen=0
  for dir in "$CERT_BASE"/*/; do
    [[ -d "$dir" ]] || break
    [[ ! -L "${dir%/}" ]] || continue
    slot=$(basename "$dir")
    SLOT="$slot"
    SLOT_DIR="${dir%/}"
    load_current
    seen=1
    echo "slot $slot:"
    if [[ -z "$CURRENT_DIR" || ! -f "$CURRENT_DIR/$CERT_FILE" || ! -f "$CURRENT_DIR/$KEY_FILE" ]]; then
      echo "  installed: no complete current pair"
      rc=1
      continue
    fi
    local cert_key private_key
    cert_key=$(openssl x509 -in "$CURRENT_DIR/$CERT_FILE" -noout -pubkey) || return 1
    private_key=$(openssl pkey -in "$CURRENT_DIR/$KEY_FILE" -pubout -passin pass: 2>/dev/null) || return 1
    [[ "$cert_key" == "$private_key" ]] || die "slot $SLOT: current certificate/key mismatch"
    echo "  current:   $CURRENT_TARGET"
    echo "  installed: sha256 $(fingerprint "$CURRENT_DIR/$CERT_FILE")"
    echo "  names:     $(san_names "$CURRENT_DIR/$CERT_FILE" | paste -sd, -)"
    echo "  expires:   $(openssl x509 -in "$CURRENT_DIR/$CERT_FILE" -noout -enddate | cut -d= -f2)"
  done
  (( seen )) || die "no slot directories in $CERT_BASE -- nothing is enrolled to receive"
  return "$rc"
}

# ---- main -----------------------------------------------------------------------------------

[[ -d "$CERT_BASE" && -w "$CERT_BASE" ]] || die "$CERT_BASE is missing or not writable by $(id -un)"
[[ "$CERT_FILE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ &&
   "$KEY_FILE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ && "$CERT_FILE" != "$KEY_FILE" ]] ||
  die "CERT_FILE and KEY_FILE must be distinct simple filenames"

# Under the forced command $1 is never set; it exists so the script can be exercised locally.
VERB="${SSH_ORIGINAL_COMMAND:-${1:-install}}"

# One delivery at a time, across all slots; a second caller waits rather than interleaving renames.
exec 9>"$CERT_BASE/.lock"
flock -w 30 9 || die "another delivery is in progress"

TMP=$(mktemp -d "$CERT_BASE/.incoming.XXXXXX")

# Everything below runs with fd 9 CLOSED. A descriptor opened by `exec` is not close-on-exec, so
# any process the work spawns inherits the lock and holds it after this script exits -- one reload
# that leaves something running behind it, and every future renewal dies on "another delivery is in
# progress" until the box is rebooted. Closing it once here covers every child there will ever be,
# rather than a list of call sites to keep in step. Measured, not theorised: a test listener started
# by the reload held this lock across runs.
(
  exec 9>&-
  case "$VERB" in
    install|"") do_install ;;
    check)      do_check ;;
    status)     do_status ;;
    *)
      log "refused command from ${SSH_CLIENT:-local}: ${VERB@Q}"
      exit 2
      ;;
  esac
)
