# Certificate Deployment System

CertMgmt deploys certificates to nine kinds of devices and services. The issuer-side
application is Python 3.14 (minimum 3.14.2), matching the Venstar Home Assistant
components. Every driver is a standalone CLI: it accepts ordinary PEM paths and
credentials, with no Certbot or site configuration required.

Certbot integration adds configuration-based fan-out, renewal hooks, and Cloudflare
DNS-01 reconciliation. The remotely installed [Caddy receiver](caddy-cert-receive/README.md)
and [PVE nginx helper](proxmox-nginx-reload/README.md) remain separate Bash programs.
They do not need Python, and the issuer installer does not modify them.

## Install or upgrade the issuer

Use Linux with Python >=3.14.2 and venv/pip support. Certbot and its Cloudflare DNS
plugin stay in their existing installation; CertMgmt invokes the `certbot` executable.
Install Bash for `shell-command`, Docker Compose for that driver, OpenSSH for SSH
commands, and nmap only if using inventory. CertMgmt's Python environment is separate
from Certbot's environment. No Python upgrade is required on appliances or receivers.

Build from this checkout using the locked dependencies:

```bash
python3.14 -m pip install uv==0.13.5
uv sync --locked
uv build
```

On a new issuer, create `/etc/letsencrypt/deploy-config.json` from
[deploy-config-SAMPLE.json](deploy-config-SAMPLE.json), select the appropriate targets,
and create `/etc/letsencrypt/cloudflare.ini` from `cloudflare-SAMPLE.ini`. Protect
these files and credential files with mode 0600. Existing issuers keep their files.
Install with the wheel's actual filename:

```bash
sudo .venv/bin/python -m certmgmt install \
  --wheel dist/certmgmt-0.1.0-py3-none-any.whl \
  --python /path/to/python3.14 \
  --config /etc/letsencrypt/deploy-config.json --dry-run

# Apply the reviewed installation paths by removing --dry-run.
```

The installer creates `/opt/certmgmt/versions/<wheel-hash>/`, installs runtime
requirements with hashes, checks the environment, and switches `/opt/certmgmt/current`.
The CLI is `/opt/certmgmt/bin/certmgmt`; add its directory to PATH if desired.
It replaces only its recognized `cert-dispatcher.sh` deploy hook. Other hooks,
site configuration, credentials, and the old `cert-drivers/` directory remain intact.
Backups and receipts live outside Certbot's executable hook directory. Concurrent
installation or rollback attempts are rejected.

Use the installed CLI for the examples below. Installation does not issue certificates
or push to devices. A normal Certbot renewal invokes the installed hook automatically.

```bash
sudo /opt/certmgmt/bin/certmgmt sync --dry-run
sudo /opt/certmgmt/bin/certmgmt sync --yes
sudo /opt/certmgmt/bin/certmgmt verify
sudo /opt/certmgmt/bin/certmgmt deploy --dry-run
sudo /opt/certmgmt/bin/certmgmt deploy
```

For a custom Certbot directory, set `certbot_config_dir` in the site config and pass
the matching `--hook-dir <directory>/renewal-hooks/deploy` when installing.
`sync` requires that managed hook and passes the selected config to it explicitly.

Tooling rollback restores the previous environment and hook, including a legacy Bash
hook if this was the first migration. It does not revert issued or deployed certificates:

```bash
sudo /opt/certmgmt/bin/certmgmt rollback --dry-run
sudo /opt/certmgmt/bin/certmgmt rollback
```

Keep the old checkout and installed drivers until live acceptance is complete. For
recovery, restore backed-up Certbot state, config, credentials and delivery SSH keys;
install the desired CertMgmt wheel, preview `sync`, then explicitly deploy as needed.

## Standalone drivers and emergency pushes

`certmgmt driver NAME --help` describes formats, defaults, restart behavior, and a
complete example. `python -m certmgmt` is equivalent to the installed command.
All drivers use `-h/--help`, `-H/--host`, `-c/--cert-file`, and `-k/--key-file` where
applicable. Argument abbreviations are disabled. Direct driver invocation always
performs delivery; the configured `deploy` command can skip current targets.

Examples use certificates from `/certs`, which may be populated by any fetcher:

```bash
certmgmt driver idrac -H idrac.example.test -u root \
  --password-file /run/secrets/idrac -c /certs/fullchain.pem -k /certs/privkey.pem

certmgmt driver glinet-kvm -H kvm.example.test -u admin \
  --password-file /run/secrets/kvm -c /certs/cert.pem -k /certs/privkey.pem

certmgmt driver truenas-scale -H nas.example.test \
  --api-key-file /run/secrets/nas --domain example.test \
  -c /certs/fullchain.pem -k /certs/privkey.pem

certmgmt driver supermicro-ipmi -H bmc.example.test -u ADMIN \
  --password-file /run/secrets/bmc --model X11 \
  -c /certs/fullchain.pem -k /certs/privkey.pem

certmgmt driver reolink -H 192.0.2.21 -u admin \
  --password-file /run/secrets/camera -c /certs/cert.pem -k /certs/privkey.pem

certmgmt driver brother-printer -H printer.example.test -u admin \
  --password-file /run/secrets/printer -c /certs/fullchain.pem -k /certs/privkey.pem

certmgmt driver proxmox -H pve.example.test --node pve \
  --api-token-file /run/secrets/pve -c /certs/fullchain.pem -k /certs/privkey.pem

certmgmt driver docker-compose --compose-dir /srv/web --service caddy \
  --verify-host web.example.test --verify-cert-file /certs/cert.pem

certmgmt driver shell-command \
  --command 'cat "$KEY_FILE" "$CERT_FILE" | ssh -i /etc/letsencrypt/caddy-deploy-key -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 cert-receiver@caddy.example.test install' \
  -c /certs/fullchain.pem -k /certs/privkey.pem --verify-host web.example.test
```

Credentials accept exactly one of `--password`, `--password-file`, or `--password-env`
(the last names an environment variable). API drivers use the corresponding
`--api-key*` or `--api-token*` options. Files avoid exposing credential values in process
arguments. The Proxmox token file contains `user@realm!tokenid=secret`.

Exit codes are **0** for success, **1** for an operation failure, **2** for invalid
arguments/configuration, **130** for SIGINT, and **143** for SIGTERM. A failure after upload can leave
the device changed. `--quiet` suppresses normal progress, while `--debug` retains
credential redaction and does not enable HTTP/WebSocket payload logging.

## Verification and timeouts

All drivers validate readable PEM input, matching key, validity dates, and applicable
RSA/leaf restrictions before upload. Verification compares the SHA-256 fingerprint
of the served leaf with the first certificate in the expected PEM file. It does not
establish trust in the whole chain or detect a chain-only change.

`--verify-host`, `--verify-port`, `--verify-server-name` (SNI), and
`--verify-cert-file` override the device/default certificate endpoint. Local shell
and Compose drivers require verification host and expected certificate unless
`--no-verify` is explicit. To connect by IP and send a separate SNI name:

```bash
certmgmt verify -H 192.0.2.10 --port 443 --server-name web.example.test \
  -c /certs/fullchain.pem
```

`--no-verify` controls the post-delivery fingerprint check. Management API trust is
separate: the legacy bootstrap default does not validate appliance CA/hostname;
`--api-tls-verify` enables it, and `--api-ca-file` enables it with a specified CA bundle.

The whole deployment has a 900-second deadline, adjustable with
`--operation-timeout`. Connection timeout defaults to 10 seconds; verification wait
and retry defaults follow the device, with 30 seconds between probes. Reolink gets
19 retries after the first probe. Shell/Compose commands also have `--timeout 120`;
zero disables only that command deadline. Timeout or interruption terminates the
local process group, including descendants. It cannot undo remote changes.

## Configured deployment and Certbot

`deploy-config.json` retains the existing `certs`/`targets` structure and driver names.
Unknown fields are rejected; underscore-prefixed comments are allowed. `host` is the
preferred connection field; legacy `ip` is accepted. `cert_driver_dir` is accepted for
migration but unused: drivers now come from the installed package.

Certificate filenames in targets are relative to the lineage; absolute paths and
`..` traversal are rejected. They default to `fullchain.pem` and `privkey.pem`, except
leaf-only devices use `cert.pem`. Credential files, CA bundles, working directories,
and `certbot_config_dir` resolve relative to the config file. Direct driver paths
resolve relative to the caller's directory before any `--chdir`.

Targets accept credential fields such as `password_file` or `api_key_env`, common
verification/timeouts, and their driver's options. `verify: false` explicitly disables
fingerprint checks. `verify_ports` checks every listed port during deployment,
already-current detection, and verification-only operation. Compose accepts
`services` (legacy `service_name` also works).

```bash
# Select a certificate and target; bypass current-leaf skipping for an emergency push.
certmgmt deploy --config /etc/letsencrypt/deploy-config.json \
  --cert-name example.test --target office-printer --force

# Certificates obtained outside Certbot can use the configured targets too.
certmgmt deploy --cert-name example.test --lineage /srv/cert-fetcher/example.test

# These commands never upload or reload devices.
certmgmt deploy --dry-run
certmgmt verify --cert-name example.test --target office-printer
```

The entire selected deployment batch is validated before probes or mutations.
A failed target is reported and remaining targets continue. `deploy` skips a target
only when all configured endpoints already serve the expected leaf; use `--force`
for chain-only changes. `verify` needs no device credential or private key and never
runs delivery commands. `deploy --dry-run` validates and lists targets without network
requests; it is distinct from `verify`, which connects to the devices.

`sync` compares configured domains and key parameters with Certbot's local leaf
certificates. It creates or updates changed lineages using `certbot certonly`, retaining
the existing lineage on failed issuance. Missing config entries never trigger deletion.
Normal expiry renewal remains the job of `certbot renew` and its existing timer.
A sync update succeeds only if Certbot succeeds **and** the managed hook records a
successful deployment. `--dry-run` previews; `--yes` applies without prompting.
Revocation and deletion are explicit, separate operations:

```bash
certmgmt revoke --cert-name example.test --yes
certmgmt delete --cert-name example.test --yes
```

These explicit operations use Certbot's default configuration directory; revoke does
not implicitly delete the lineage. Back up Certbot state before deliberate removal.

Optional `healthchecks_url` on a certificate receives `/start` and aggregate success
or `/fail` notifications during deployment. No notifications are sent for empty
target groups, dry runs, or verification-only commands. Notification failures are
nonfatal; deployment failures still determine the exit status. `log_file` enables a
redacted file log in addition to console output.

## Remote helpers and device notes

The shell driver exports absolute `CERT_FILE`, `KEY_FILE`, and `CERT_DIR`. Its trusted
command runs as the caller under Bash with `pipefail` and closed stdin; output is
logged. The Caddy wire format remains **private key followed by full chain on stdin**.
Enroll the receiver and pin its SSH host key using the
[receiver instructions](caddy-cert-receive/README.md). The receiver validates and
activates its versioned certificate slot, then forces a Caddy reload. For a first
bootstrap delivery before the real Caddyfile is active, use `--no-verify` explicitly;
enable verification for normal operation. No remote Python installation is involved.

The Proxmox driver uploads to pveproxy on port 8006. nginx on the PVE host is optional.
If present, point it at `/etc/pve/local/pveproxy-ssl.pem` and use the unchanged
[PVE helper/timer](proxmox-nginx-reload/README.md) to reload it. Set
`"verify_ports": [8006, 443]` to require both listeners to serve the new leaf; this now
also applies during deployment and current-certificate skipping.

Reolink, Supermicro and Brother require RSA. Reolink and GL.iNet require a single
leaf. Connect to Reolink by IP: long connection hostnames have caused failures on
existing firmware. Some models take minutes to activate or need a reboot; the driver
preserves the tested import protocol and does not add a CertificateClear operation.
Supermicro reboots the BMC unless `--no-reboot`; that flag still requires the new
certificate to become visible for verified success.

Brother converts PEM to unencrypted PKCS#12 and keeps at most the first intermediate,
preserving the device's two-certificate limit. Existing cleanup behavior is retained:
remove older same-name certificates, or all older entries if firmware returns no name
(with a warning). TrueNAS retains its managed `LetsEncrypt-<domain>-` ownership prefix
for cleanup and its existing WebSocket API. Changing these device policies or adopting
a newer TrueNAS protocol is separate work.

## Existing hardware record

These are the previous implementation's recorded device results. The Python migration
has offline protocol coverage; it still needs representative live upload, activation,
and served-certificate acceptance before issuer cutover.

| Driver | Device | HW Revision | Firmware Version | Notes |
|---|---|---|---|---|
| `idrac` | PowerEdge T340 w/ 14G Monolithic | 0.01 | 7.00.00.174 | Tested with an Enterprise license; unverified whether Express/Basic suffices |
| `glinet-kvm` | GL-RM1PE | n/a | 1.8.0 Release 1 | 3 of them, at 3 locations |
| `docker-compose` | n/a -- local services | n/a | n/a | Restarts one or more containers. Requires /etc/letsencrypt mapped in to target containers. Only tested with caddy. |
| `shell-command` | Offline fixtures only | n/a | n/a | Driver, dispatcher, and verification-only tests; live SSH/Caddy acceptance pending |
| `truenas-scale` | n/a -- appliance OS | n/a | 25.10.1 | Uses the WebSocket JSON-RPC API |
| `supermicro-ipmi` | X11SDV-8C-TP8F | n/a | IPMI 01.25 (08/31/2018) | RSA certs only (see Driver Notes) |
| `supermicro-ipmi` | X10SDV-TLN4F | n/a | IPMI 03.88 (02/21/2020) | RSA certs only (see Driver Notes) |
| `reolink` | CX410 | IPC_NT1NA44MP | v3.1.0.3429_2404181313 | 3 of these. Slow to apply certs (see Driver Notes) |
| `reolink` | CX410W | IPC_NT1NA44MP | v3.1.0.4366_2412021479 | 2 of these. Slow to apply certs (see Driver Notes) |
| `reolink` | RLC-810WA | IPC_MS2NA48MP | v3.0.0.2737_23092700 | One of two units, each on its own firmware. Slow to apply certs (see Driver Notes) |
| `reolink` | RLC-810WA | IPC_MS2NA48MP | v3.0.0.5032_2506271657 | One of two units, each on its own firmware. Slow to apply certs (see Driver Notes) |
| `brother-printer` | HL-L3280CDW series | | MAIN 1.10 SUB3 2306291143 | RSA certs only (see Driver Notes) |
| `proxmox` | n/a -- hypervisor OS | n/a | pve-manager 9.1.4 | Single node, with nginx on 443 serving the same cert (see Driver Notes) |

## Inventory

```bash
certmgmt scan 192.0.2.0/24 --ports 443,8443,8006 --output inventory.jsonl
certmgmt scan 192.0.2.0/24 --config /etc/letsencrypt/deploy-config.json
```

nmap discovers open ports; Python reads TLS certificates. Reports are JSON Lines on
stdout, also written to `--output` if supplied. Each row includes address, port, leaf
fingerprint, names, issuer and expiry, or an error. Configured lineage fingerprints
and domain patterns can annotate managed certificates. A domain-pattern match is an
inventory hint, not proof of certificate identity. Failed scans or TLS probes produce
a nonzero exit status. IPv4 and IPv6 CIDRs are supported.

## Compatibility and source layout

The old issuer `.sh` and driver `.py` filenames are thin checkout launchers. Keep them
with the checkout; copying individual launchers to the old driver directory will not
install the package. Shell launchers use `CERTMGMT_PYTHON` if set, otherwise `python3`
from PATH. Activate the Python 3.14 environment when using these launchers.

- Legacy iDRAC/GL.iNet `-h HOST` is translated to `--host`; bare `-h` now shows help.
- `cert-sync.sh -D` maps to `deploy`; `-D --dry-run` retains verification-only behavior.
- `certbot-setup.sh` now needs explicit wheel/config options and preserves existing
  files. It no longer installs OS packages or overwrites credentials.
- `verify-deployed-cert.sh` maps its short options to `verify`; standalone verification
  now defaults to an immediate single probe. Use explicit wait/retry flags if needed.
- Scanner names remain launchers, but output is now JSONL, stdout-only by default.
- New failures are explicit: missing verification inputs, invalid certificate/key
  pairs, malformed config, and activation failures do not report success.

Implementation lives in `certmgmt/`: `cli`/`registry` define the public interface,
`drivers/` contains protocol adapters, `certificates`/`runtime` supply shared services,
and `config`, `orchestration`, `reconcile`, `installer`, and `scanner` implement commands.
The two remote-helper directories remain independently installable.

## Development and offline verification

```bash
uv sync --locked
uv run --no-sync ruff check certmgmt tests
uv run --no-sync ruff format --check certmgmt tests
uv run --no-sync pytest -q
uv build
uv pip check
```

Tests need Bash, OpenSSL, jq and GNU coreutils, but no production credentials or devices.
They cover CLI launchers, protocol fixtures, real local TLS, cancellation, aggregate
failures, Certbot outcomes, installation/rollback, and the existing remote helpers.
The helper fixtures use isolated temporary paths and service stand-ins.

`uv.lock` locks developer/runtime dependencies. When changing dependencies, regenerate
and commit the hashed runtime export packaged into the wheel:

```bash
uv lock
uv export --frozen --no-dev --no-emit-project --format requirements-txt \
  --output-file certmgmt/runtime-requirements.txt
```

CI uses Python 3.14 and verifies that export matches the lock. The
[migration plan](docs/plans/python-migration.md) records verification and the remaining
live acceptance boundary.

## License

MIT — see [LICENSE](LICENSE).
