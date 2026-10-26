# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Config-driven Let's Encrypt certificate management system that automatically deploys SSL certificates to network devices. Written in Bash (orchestration) and Python 3 (device drivers).

## Key Commands

All orchestration scripts require root:

```bash
sudo ./certbot-setup.sh          # One-time setup: install certbot, copy configs/drivers to /etc/letsencrypt/
sudo ./cert-sync.sh --dry-run    # Preview certificate changes without applying
sudo ./cert-sync.sh              # Reconcile certificates to match deploy-config.json
```

Manual driver invocation (each driver accepts standard CLI args):
```bash
./drivers/driver-idrac.sh -h HOST -u USER -p PASS -c CERT_PATH -k KEY_PATH
python3 ./drivers/driver-truenas-scale.py -H HOST -a API_KEY -D DOMAIN -c CERT_PATH -k KEY_PATH
```

All drivers support `--no-verify` to skip post-deployment certificate check.

### Linting

- **Bash**: `shellcheck <script>` (auto-runs in VS Code)
- **Python**: `ruff check` / `ruff format` (auto-format on save in VS Code)

Run `python3 -m unittest discover -s tests -v` for the shell-command driver/integration, Caddy receiver, and nginx certificate helper. These use isolated fixtures, real PEM validation, injected receiver failures, and a local TLS server, not live devices. Live verification uses `--dry-run` mode and post-deployment cert checks.

`caddy-cert-receive/` is installed separately on the target host. Its versioned certificate directories are activated through a single `current` symlink; Caddyfile paths must include `/current/`. The issuer installer only copies `drivers/`.

## Architecture

### Flow

1. Certbot fetches/renews certs via Cloudflare DNS-01 challenge
2. On renewal, certbot invokes `cert-dispatcher.sh` (deploy hook)
3. Dispatcher reads `deploy-config.json`, routes each cert to its target drivers
4. Each driver deploys the cert to a specific device type
5. `verify-deployed-cert.sh` confirms the cert is being served (optional per-target)

### Core Scripts

- **cert-sync.sh** — State reconciler. Compares desired state (deploy-config.json) against actual state (certbot certificates). Creates, revokes, or re-requests certs as needed.
- **cert-dispatcher.sh** — Certbot renewal hook. Parses config, dispatches to drivers. Receives `RENEWED_LINEAGE` and `RENEWED_DOMAINS` env vars from certbot.
- **certbot-setup.sh** — One-time installer. Copies dispatcher, drivers, and config into `/etc/letsencrypt/`.

### Driver Plugin System

Drivers live in `drivers/` and follow a common interface:
- Accept CLI args for host, credentials, cert/key file paths
- Return exit code 0 on success
- Optionally call `verify-deployed-cert.sh` for post-deploy validation

| Driver | Script | Protocol |
|--------|--------|----------|
| `idrac` | driver-idrac.sh | Redfish REST API |
| `glinet-kvm` | driver-glinet-kvm.sh | KVMD API |
| `docker-compose` | driver-docker-compose.sh | Local service restart |
| `shell-command` | driver-shell-command.sh | Trusted local command, e.g. SSH certificate delivery |
| `truenas-scale` | driver-truenas-scale.py | WebSocket API |
| `supermicro-ipmi` | driver-supermicro-ipmi.py | HTTP + CSRF tokens |
| `reolink` | driver-reolink.py | HTTP JSON API |
| `brother-printer` | driver-brother-printer.py | HTTP forms + PKCS#12 |
| `proxmox` | driver-proxmox.py | REST API (port 8006) |

### Configuration

- **deploy-config.json** — Single source of truth for all certificates and deployment targets. See `deploy-config-SAMPLE.json` for all supported device types.
- **cloudflare.ini** — Cloudflare API token for DNS-01 challenges.
- Both are copied to `/etc/letsencrypt/` by `certbot-setup.sh`.

## Conventions

- Bash scripts use `set -e` and parse args with `getopts`
- JSON parsing done via `jq` in shell scripts
- Python drivers use `argparse` for CLI args and `requests`/`websockets` for network calls
- Python dependencies: requests, websockets, cryptography, lxml
- Logging goes to the path specified by `log_file` in deploy-config.json (default: `/var/log/cert-deploy.log`)
- Adding a new device type requires its driver, dispatcher routing, verification-only routing in cert-sync, and a sample config entry
