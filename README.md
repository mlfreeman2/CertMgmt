# Certificate Deployment System

Config-driven Let's Encrypt certificate management with automatic deployment to network devices.

> **Disclosure:** All code in this repository was written by [Claude Code](https://claude.com/claude-code), Anthropic's AI coding tool, working under my direction. I designed the system, reviewed the code, and tested every driver against real hardware on my own network (see [Tested Hardware](#tested-hardware)). That said, treat it like anything else you find on the internet: read it before pointing it at devices you care about.

## How It Works

- **certbot** fetches and renews certificates via Cloudflare DNS-01 challenge
- On renewal, certbot runs **cert-dispatcher.sh**, which reads **deploy-config.json** to determine which devices need the new cert
- The dispatcher invokes the appropriate **driver script** for each target device
- Each driver verifies the cert is actually being served after deployment

## File Layout

```
CertMgmt/
  certbot-setup.sh                # One-time setup: installs certbot, copies config to /etc/letsencrypt
  cert-dispatcher.sh              # Certbot deploy hook (copied into certbot's hooks dir by setup)
  cert-sync.sh                    # Reconciles local certbot state to match config
  scan-ssl-certs.sh               # Scan subnets, identify project-managed certs
  scan-ssl-inventory.sh           # Scan subnets, report all certs found (no config needed)
  deploy-config.json              # Site config (renamed from deploy-config-<site>.json)
  cloudflare.ini                  # Cloudflare API token (renamed from cloudflare-<site>.ini)
  drivers/
    driver-idrac.sh               # Dell iDRAC (Redfish API)
    driver-glinet-kvm.sh          # GL.iNet KVM (KVMD API)
    driver-docker-compose.sh      # Docker compose service restart
    driver-truenas-scale.py       # TrueNAS Scale (WebSocket API)
    driver-supermicro-ipmi.py     # Supermicro IPMI (X10/X11)
    driver-reolink.py             # Reolink cameras (HTTP JSON API)
    driver-brother-printer.py     # Brother printers (HTTP forms + PKCS#12)
    driver-proxmox.py             # Proxmox VE (REST API, port 8006)
    verify-deployed-cert.sh       # Shared post-deployment verification helper
  proxmox-nginx-reload/           # Optional: systemd units to reload nginx on a PVE host when the cert changes
```

After `certbot-setup.sh` runs, copies live in `/etc/letsencrypt/`:
```
/etc/letsencrypt/
  cloudflare.ini
  deploy-config.json
  renewal-hooks/deploy/
    cert-dispatcher.sh            # Only file here (old per-device scripts are removed)
  cert-drivers/
    (all driver scripts)
  live/
    (certbot-managed certificates)
```

## Setup: New Machine, No Existing Certs

Use this when setting up a fresh machine or after a disaster recovery restore.

### 1. Copy this directory to the machine

```bash
# However you get it there (scp, rsync, restore from backup, etc.)
# It should end up at your project's certificates path, e.g.:
/home/myuser/my-project/certificates/
```

### 2. Select the site config

Delete the config and cloudflare files for the other sites, then rename your site's files:

```bash
cd /home/myuser/my-project/certificates

# Example for the "mysite" site:
rm deploy-config-site-b.json deploy-config-site-c.json
rm cloudflare-site-b.ini cloudflare-site-c.ini

mv deploy-config-mysite.json deploy-config.json
mv cloudflare-mysite.ini cloudflare.ini
```

### 3. Run setup

```bash
sudo ./certbot-setup.sh
```

This installs certbot and dependencies, copies config/drivers/dispatcher into `/etc/letsencrypt/`, and removes any old per-device deploy hooks.

### 4. Preview what cert-sync will do

```bash
sudo ./cert-sync.sh --dry-run
```

This compares the config to certbot's current state. Since no certs exist yet, it will show that all configured certs need to be requested.

### 5. Fetch certificates

```bash
sudo ./cert-sync.sh
```

This requests all certificates from Let's Encrypt. Each cert request triggers the dispatcher, which deploys the cert to all configured targets.

### 6. Done

Certbot will auto-renew certificates every ~60 days and the dispatcher will redeploy them automatically.

## Setup: New Machine, Certs Already Present

Use this when certbot already has certificates (e.g., you migrated `/etc/letsencrypt` from another machine, or you pulled certs down manually).

### 1. Copy this directory to the machine

Same as above.

### 2. Select the site config

Same as above -- delete the other sites' files, rename yours.

### 3. Run setup

```bash
sudo ./certbot-setup.sh
```

This installs the dispatcher and drivers. It does **not** touch existing certificates in `/etc/letsencrypt/live/`.

### 4. Preview cert-sync

```bash
sudo ./cert-sync.sh --dry-run
```

cert-sync compares what certbot has to what the config says you should have:

- **Matching certs**: reported as OK, no action needed
- **Wrong key type/size**: will be revoked, deleted, and re-requested
- **Wrong domains**: will be revoked, deleted, and re-requested
- **Extra certs** (in certbot but not in config): reported but left alone
- **Missing certs** (in config but not in certbot): will be requested

### 5. Apply changes (if any)

```bash
sudo ./cert-sync.sh
```

If everything matched, this is a no-op. If certs need to be fixed, it handles the revoke/delete/re-request cycle.

### 6. Deploy existing certs to devices

If certs were already present and matched the config, cert-sync didn't trigger the dispatcher (no renewal happened). To push the existing certs to all targets, manually invoke the dispatcher for each cert:

```bash
# Find your cert names
sudo certbot certificates

# Run the dispatcher for each cert
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/<cert-name> \
     RENEWED_DOMAINS="<domains>" \
     bash /etc/letsencrypt/renewal-hooks/deploy/cert-dispatcher.sh
```

For example:
```bash
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/example.com-wildcard \
     RENEWED_DOMAINS="*.example.com" \
     bash /etc/letsencrypt/renewal-hooks/deploy/cert-dispatcher.sh
```

## Adding a New Site

1. Create a `deploy-config-<site>.json` with your site's targets (use an existing one as a template)
2. Create a `cloudflare-<site>.ini` with the Cloudflare API token
3. Copy the whole directory to the new machine
4. Follow the "New Machine, No Existing Certs" steps above

No code changes needed -- just a new config file.

## Adding a New Device to a Site

Add a new entry to the `targets` array for the appropriate cert in `deploy-config.json`, then re-run setup to push the updated config:

```bash
sudo ./certbot-setup.sh
```

The new target will be deployed to on the next cert renewal. To deploy immediately, manually invoke the dispatcher as shown above.

## Running Drivers Manually

Each driver accepts standard CLI arguments and can be run independently:

```bash
# Dell iDRAC
./drivers/driver-idrac.sh -h 198.51.100.10 -u root -p PASSWORD \
  -c /etc/letsencrypt/live/CERT/fullchain.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem

# GL.iNet KVM
./drivers/driver-glinet-kvm.sh -h 198.51.100.11 -u admin -p PASSWORD \
  -c /etc/letsencrypt/live/CERT/cert.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem

# Docker Compose
./drivers/driver-docker-compose.sh -d /home/myuser/my-project -s caddy

# TrueNAS Scale
python3 ./drivers/driver-truenas-scale.py -H 198.51.100.12 -a API_KEY \
  -D example.com \
  -c /etc/letsencrypt/live/CERT/fullchain.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem

# Supermicro IPMI
python3 ./drivers/driver-supermicro-ipmi.py -H 198.51.100.13 -u USERNAME -p PASSWORD \
  -c /etc/letsencrypt/live/CERT/fullchain.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem \
  -m X10

# Reolink Camera
python3 ./drivers/driver-reolink.py -H 198.51.100.14 -u admin -p PASSWORD \
  -c /etc/letsencrypt/live/CERT/cert.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem

# Brother Printer
python3 ./drivers/driver-brother-printer.py -H 198.51.100.15 -u admin -p PASSWORD \
  -c /etc/letsencrypt/live/CERT/fullchain.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem

# Proxmox VE
python3 ./drivers/driver-proxmox.py -H 198.51.100.16 -a 'root@pam!tokenid=SECRET' \
  -n pve \
  -c /etc/letsencrypt/live/CERT/fullchain.pem \
  -k /etc/letsencrypt/live/CERT/privkey.pem
```

All drivers support `--no-verify` to skip the post-deployment certificate check.

## Scanning for SSL Certificates

Two standalone scripts scan your network for TLS endpoints. Neither requires root, but nmap may be faster with it.

**scan-ssl-certs.sh** — Identifies which certs on your network are managed by this project. Matches against deploy-config.json domains and certbot fingerprints.

```bash
./scan-ssl-certs.sh 192.168.1.0/24                    # scan a subnet
./scan-ssl-certs.sh 192.168.1.0/24 10.0.0.0/24        # multiple subnets
./scan-ssl-certs.sh -p 443,8443 -v 192.168.1.0/24     # custom ports, verbose
```

**scan-ssl-inventory.sh** — Reports every SSL cert found on a network. No config needed — useful for surveying an unknown network before writing a deploy-config.json.

```bash
./scan-ssl-inventory.sh 192.168.1.0/24                 # scan a subnet
./scan-ssl-inventory.sh -n 192.168.1.0/24              # stdout only, no report file
```

Both require `nmap` and `openssl`. `scan-ssl-certs.sh` also requires `jq`.

## Supported Driver Types

| Config `driver` value | Script | Target |
|---|---|---|
| `idrac` | driver-idrac.sh | Dell iDRAC via Redfish API |
| `glinet-kvm` | driver-glinet-kvm.sh | GL.iNet KVM via KVMD API |
| `docker-compose` | driver-docker-compose.sh | Docker Compose service restart |
| `truenas-scale` | driver-truenas-scale.py | TrueNAS Scale via WebSocket API |
| `supermicro-ipmi` | driver-supermicro-ipmi.py | Supermicro IPMI X10/X11 boards |
| `reolink` | driver-reolink.py | Reolink cameras via HTTP JSON API |
| `brother-printer` | driver-brother-printer.py | Brother network printers via HTTP forms |
| `proxmox` | driver-proxmox.py | Proxmox VE via REST API (port 8006) |

## Driver Notes

### Proxmox: nginx on the PVE host is optional

The proxmox driver only talks to the Proxmox API on port 8006 -- it uploads the cert to `pveproxy`, which restarts itself. Nothing in this system requires nginx.

That said, a common convenience is running nginx on the PVE host so you don't have to remember `:8006` -- listening on 443 with the same cert and redirecting to `https://<host>:8006`. If you do this:

- Point nginx at `/etc/pve/local/pveproxy-ssl.pem` (the API-uploaded cert), **not** the self-signed `pve-ssl.pem` -- otherwise nginx keeps serving the old self-signed cert forever.
- nginx does not notice when the driver uploads a new cert. Install the systemd path unit in [proxmox-nginx-reload/](proxmox-nginx-reload/) to reload nginx automatically on cert changes.
- To have `cert-sync.sh -D --dry-run` verify nginx's copy too, set `"verify_ports": [8006, 443]` on the proxmox target in deploy-config.json. The default is `[8006]` only, so hosts without nginx verify cleanly.

### Reolink: connect by IP, keep hostnames short

Reolink firmware is the quirkiest of the supported devices:

- **~32-character hostname limit.** The camera's HTTP stack misbehaves (401 errors, odd API behavior) when the URL hostname exceeds roughly 32 characters -- [documented in the field for RTSP](https://github.com/blakeblackshear/frigate/discussions/11214) and observed here with the HTTPS API as well. Use the camera's IP in deploy-config.json (the `ip` field does this naturally) and keep the camera's own device name short. The certificate itself can still carry a long wildcard domain; only the connection URL matters.
- **RSA only.** The cameras reject ECDSA certs -- set `"key_type": "rsa"` on the cert. The driver checks this before uploading.
- **Single leaf cert only.** Upload `cert.pem`, never `fullchain.pem` -- the camera rejects chains. The driver checks this too.
- **Slow to apply.** Cameras can take minutes to serve a newly uploaded cert, and [some models (e.g. E1 Pro) need a full reboot](https://gist.github.com/velzend/895c18d533b3992f3a0cc128f27c0894); the driver polls for up to ~10 minutes before declaring failure.
- **Re-import quirks on some models.** Some firmware won't overwrite an existing cert without a `CertificateClear` call first (not needed on the hardware tested here; see the gist above if you hit it).

### RSA-only devices

Reolink cameras, Supermicro IPMI (X10/X11), and Brother printers all reject ECDSA certificates -- set `"key_type": "rsa"` on any cert that deploys to them. All three drivers check the cert before uploading and fail with a clear error rather than leaving the device in a half-configured state.

## Tested Hardware

Every driver has been exercised against the devices below. Other models/firmware may work but haven't been verified — if a driver works on hardware not listed here, an issue or PR adding it is welcome.

| Driver | Device | HW Revision | Firmware Version | Notes |
|---|---|---|---|---|
| `idrac` | PowerEdge T340 w/ 14G Monolithic | 0.01 | 7.00.00.174 | Tested with an Enterprise license; unverified whether Express/Basic suffices |
| `glinet-kvm` | GL-RM1PE | n/a | 1.8.0 Release 1 | 3 of them, at 3 locations |
| `docker-compose` | n/a -- local services | n/a | n/a | Restarts one or more containers. Requires /etc/letsencrypt mapped in to target containers. Only tested with caddy. |
| `truenas-scale` | n/a -- appliance OS | n/a | 25.10.1 | Uses the WebSocket JSON-RPC API |
| `supermicro-ipmi` | X11SDV-8C-TP8F | n/a | IPMI 01.25 (08/31/2018) | RSA certs only (see Driver Notes) |
| `supermicro-ipmi` | X10SDV-TLN4F | n/a | IPMI 03.88 (02/21/2020) | RSA certs only (see Driver Notes) |
| `reolink` | CX410 | IPC_NT1NA44MP | v3.1.0.3429_2404181313 | 3 of these. Slow to apply certs (see Driver Notes) |
| `reolink` | CX410W | IPC_NT1NA44MP | v3.1.0.4366_2412021479 | 2 of these. Slow to apply certs (see Driver Notes) |
| `reolink` | RLC-810WA | IPC_MS2NA48MP | v3.0.0.2737_23092700 | One of two units, each on its own firmware. Slow to apply certs (see Driver Notes) |
| `reolink` | RLC-810WA | IPC_MS2NA48MP | v3.0.0.5032_2506271657 | One of two units, each on its own firmware. Slow to apply certs (see Driver Notes) |
| `brother-printer` | HL-L3280CDW series | | MAIN 1.10 SUB3 2306291143 | RSA certs only (see Driver Notes) |
| `proxmox` | n/a -- hypervisor OS | n/a | pve-manager 9.1.4 | Single node, with nginx on 443 serving the same cert (see Driver Notes) |

## Notifications (Optional)

The dispatcher can ping a [Healthchecks.io](https://healthchecks.io/) check on each cert deployment. Add a `healthchecks_url` to each cert in `deploy-config.json`:

```json
{
  "certs": {
    "example.com-wildcard": {
      "healthchecks_url": "https://hc.example.com/ping/THIS-CERTS-UUID",
      ...
    }
  }
}
```

This gives you:
- **Failure alerts** -- immediate notification when a deployment fails
- **Heartbeat monitoring** -- if certbot stops renewing (cron broken, machine down), the missed ping triggers an alert before certs expire

Use a dedicated check per cert. Certbot invokes the dispatcher once per renewed cert, so if certs shared a check the last cert to deploy would overwrite the check's status -- a cert that deploys cleanly could flip a check back to passing and mask another cert's failure.

The field is optional. Certs without it send no pings, and certs with no deployment targets never ping their check.

## Disaster Recovery

1. Restore project from backup
2. `sudo my-project/certificates/certbot-setup.sh`
3. `sudo my-project/certificates/cert-sync.sh`
4. Done -- renewals and deployments resume automatically

## License

This project is licensed under the [MIT License](LICENSE).
