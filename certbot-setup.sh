#!/bin/bash
set -e

echo "=== Certbot + Certificate Deployment Setup ==="
echo ""

# --- Find our directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# --- Validate required files exist alongside this script ---
ERRORS=false

if [ ! -f "$SCRIPT_DIR/deploy-config.json" ]; then
  echo "Error: deploy-config.json not found in $SCRIPT_DIR"
  echo "  Rename the appropriate deploy-config-<site>.json to deploy-config.json"
  ERRORS=true
fi

if [ ! -f "$SCRIPT_DIR/cloudflare.ini" ]; then
  echo "Error: cloudflare.ini not found in $SCRIPT_DIR"
  echo "  Rename the appropriate cloudflare-<site>.ini to cloudflare.ini"
  ERRORS=true
fi

if [ ! -f "$SCRIPT_DIR/cert-dispatcher.sh" ]; then
  echo "Error: cert-dispatcher.sh not found in $SCRIPT_DIR"
  ERRORS=true
fi

if [ ! -d "$SCRIPT_DIR/drivers" ]; then
  echo "Error: drivers/ directory not found in $SCRIPT_DIR"
  ERRORS=true
fi

if $ERRORS; then
  echo ""
  echo "Setup aborted. Fix the above errors and re-run."
  exit 1
fi

# --- Read site name from config ---
SITE_NAME=$(jq -r '.site_name // "unknown"' "$SCRIPT_DIR/deploy-config.json" 2>/dev/null || echo "unknown")
echo "Setting up site: $SITE_NAME"
echo "Source directory: $SCRIPT_DIR"

# --- Install packages ---
echo ""
echo "Installing packages..."
apt update
apt install -y certbot python3-certbot-dns-cloudflare jq curl openssh-client \
  python3-requests python3-lxml python3-websockets python3-cryptography

# --- Copy cloudflare credentials ---
echo ""
echo "Installing cloudflare.ini..."
mkdir -p /etc/letsencrypt
cp "$SCRIPT_DIR/cloudflare.ini" /etc/letsencrypt/cloudflare.ini
chmod 600 /etc/letsencrypt/cloudflare.ini

# --- Copy deploy config ---
echo "Installing deploy-config.json..."
cp "$SCRIPT_DIR/deploy-config.json" /etc/letsencrypt/deploy-config.json
chmod 600 /etc/letsencrypt/deploy-config.json

# --- Wipe and install dispatcher ---
echo "Installing dispatcher..."
DEPLOY_HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
mkdir -p "$DEPLOY_HOOK_DIR"

# Remove ALL existing scripts in the deploy hook directory.
# The old per-site setup copied individual scripts (deploy-to-kvm.sh,
# deploy-to-truenas.sh, restart-caddy.sh, ipmi-updater.py, etc.) here.
# We replace all of that with a single dispatcher.
if ls "$DEPLOY_HOOK_DIR"/* >/dev/null 2>&1; then
  echo "  Removing old deploy hooks:"
  for f in "$DEPLOY_HOOK_DIR"/*; do
    echo "    $(basename "$f")"
  done
  rm -f "$DEPLOY_HOOK_DIR"/*
fi

cp "$SCRIPT_DIR/cert-dispatcher.sh" "$DEPLOY_HOOK_DIR/cert-dispatcher.sh"
chmod +x "$DEPLOY_HOOK_DIR/cert-dispatcher.sh"

# --- Wipe and install drivers ---
echo "Installing drivers..."
DRIVER_DIR=$(jq -r '.cert_driver_dir // "/etc/letsencrypt/cert-drivers"' "$SCRIPT_DIR/deploy-config.json")
if [ -d "$DRIVER_DIR" ]; then
  rm -f "$DRIVER_DIR"/*
fi
mkdir -p "$DRIVER_DIR"
cp "$SCRIPT_DIR/drivers/"* "$DRIVER_DIR/"
chmod +x "$DRIVER_DIR/"*

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Installed:"
echo "  Cloudflare:  /etc/letsencrypt/cloudflare.ini"
echo "  Config:      /etc/letsencrypt/deploy-config.json"
echo "  Dispatcher:  $DEPLOY_HOOK_DIR/cert-dispatcher.sh"
echo "  Drivers:     $DRIVER_DIR/"
echo ""
echo "Next steps:"
echo "  # Fetch/reconcile certificates per config (dry-run first):"
echo "  sudo $SCRIPT_DIR/cert-sync.sh --dry-run"
echo ""
echo "  # Then apply for real:"
echo "  sudo $SCRIPT_DIR/cert-sync.sh"
echo ""
echo "Certbot will auto-renew and run the dispatcher every 60 days."
