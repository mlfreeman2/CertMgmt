# Keep nginx's PVE redirect certificate current

Use this when **nginx terminates HTTPS on port 443 and redirects the browser to
pveproxy on port 8006**. These are separate TLS listeners. Updating pveproxy's
certificate does not reload nginx, and the browser completes TLS on 443 before it
can receive the redirect.

The systemd timer checks nginx's served leaf certificate against
`/etc/pve/local/pveproxy-ssl.pem`. It reloads nginx only if they differ or the TLS
probe fails, after `nginx -t` succeeds. It then checks fresh TLS connections to
confirm the certificate was loaded. It never starts/restarts nginx or restarts
pveproxy, and does not request or upload certificates.

## Prerequisites

nginx must use the custom certificate uploaded through Proxmox's API:

```nginx
ssl_certificate     /etc/pve/local/pveproxy-ssl.pem;
ssl_certificate_key /etc/pve/local/pveproxy-ssl.key;
```

The `pve-ssl.pem` / `pve-ssl.key` pair is Proxmox's generated node certificate.
CertMgmt uploads to `pveproxy-ssl.*`; do not replace the generated node files.
The helper requires Bash, OpenSSL, GNU `timeout`, nginx, and systemd, available on
the Debian-based PVE host.

## Install or replace the old path watcher

Copy this directory from the updated CertMgmt checkout to the PVE host. Run the
following there as root, from that copied directory. Preserve any local edits to
the old units before replacing them.

1. Create `/etc/default/pveproxy-cert-reload` from
   `pveproxy-cert-reload-SAMPLE.conf`, root-owned and mode 0644. Set
   `TLS_SERVER_NAME` to the hostname you use in the browser, such as
   `pve.example.com`. The default connection is `127.0.0.1:443`; set `TLS_CONNECT`
   to the host's LAN address and port if nginx does not listen on loopback. Use
   the hostname for SNI even when connecting by IP.

   ```bash
   # First installation only; edit an existing config instead of overwriting it.
   install -m 644 pveproxy-cert-reload-SAMPLE.conf /etc/default/pveproxy-cert-reload
   editor /etc/default/pveproxy-cert-reload
   ```

2. Disable the old watcher. If you installed the former cron fallback, remove its
   `/etc/cron.d/nginx-cert-reload` entry too; the timer replaces both mechanisms.

   ```bash
   systemctl disable --now pveproxy-cert-reload.path
   ```

   A "unit does not exist" message is harmless on a first installation. Leave the
   old `.path` file disabled; it is no longer needed.

3. Install the helper and units, then run an immediate check:

   ```bash
   install -m 755 pveproxy-cert-reload.sh /usr/local/sbin/pveproxy-cert-reload
   install -m 644 pveproxy-cert-reload.service pveproxy-cert-reload.timer /etc/systemd/system/
   systemctl daemon-reload
   systemctl start pveproxy-cert-reload.service
   journalctl -u pveproxy-cert-reload.service -n 20 --no-pager
   ```

   Resolve any failure before enabling the timer. If nginx already serves the
   expected certificate, the helper succeeds without reloading it.

4. Enable periodic checks:

   ```bash
   systemctl enable --now pveproxy-cert-reload.timer
   systemctl list-timers pveproxy-cert-reload.timer
   ```

The timer runs shortly after boot and one minute after each check finishes.
Systemd does not start overlapping instances of the oneshot service. A failed
check is recorded in the journal and the next timer tick retries it. There is no
mtime stamp or cached success to suppress retries. No renewal is needed to install
or exercise the helper.

## Verify on the host and from the issuer

After installation, and after the next real renewal, compare the certificate on
disk with fresh connections to **both** listeners:

```bash
PVE_NAME=pve.example.com   # replace with the actual browser hostname
PVE_IP=127.0.0.1          # use the host's LAN address if loopback is not bound
openssl x509 -in /etc/pve/local/pveproxy-ssl.pem -noout -fingerprint -sha256 -enddate
for port in 443 8006; do
  echo "port $port"
  timeout 5s openssl s_client -connect "$PVE_IP:$port" -servername "$PVE_NAME" </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256 -enddate
done
```

All three leaf fingerprints should match. Also open `https://PVE_NAME/` and confirm
the browser redirects to `https://PVE_NAME:8006/` without a certificate warning.
The helper compares certificate identity; it does not replace browser validation
of the hostname, expiry, and trusted chain.

On the CertMgmt issuer, retain `"verify_ports": [8006, 443]` on this Proxmox target,
then run:

```bash
sudo ./cert-sync.sh -D --dry-run
```

This is a verification-only check. Both ports must pass. The Proxmox driver's
normal deployment check and already-current skip check cover **8006 only**;
`verify_ports` currently applies to `cert-sync.sh -D --dry-run`. A successful
deployment notification alone therefore does not establish nginx's state.

If a check fails, inspect `journalctl -u pveproxy-cert-reload.service` and nginx's
error log. A mismatched cert/key pair or invalid nginx config must be fixed before
reload. If the config test and reload request succeed but 443 stays wrong, check
which virtual host handles `TLS_SERVER_NAME` and which files it loads. The helper
reports failure and retries; it never restarts either listener as a fallback.

## Why the path watcher and cron caveat were replaced

The old `.path` unit depended on inotify for `/etc/pve`, the pmxcfs cluster
filesystem. Filesystem notifications are not a sufficient recovery mechanism:
changes can be missed, and a watcher on the PEM alone can run before the matching
key is written. Systemd documents the [inotify dependency of path
units](https://www.freedesktop.org/software/systemd/man/latest/systemd.path.html).
Proxmox also documents that remote pmxcfs updates [bypass local VFS notification
paths](https://lore.proxmox.com/pve-devel/6de5f1fc-f769-4fbc-abdf-bbd96b74abaa@proxmox.com/T/).
The reported incident is consistent with a missed or failed reload; its exact
cause requires the host's journal.

The former cron one-liner compared mtimes, sent a reload signal, then touched a
stamp. That could record success before nginx actually applied the change. nginx
can reject a reload and keep its old configuration; see [nginx reload
behavior](https://nginx.org/en/docs/control.html). Polling the served fingerprint
avoids both dependencies. A graceful reload is sufficient when the new config
and certificate are valid.

## Validation status

Local automated tests exercise real TLS fingerprint comparisons and simulated
nginx reload outcomes.

Live validation should cover the initial check, a scheduled timer run, TLS on
both listeners, and the HTTPS redirect. After the next real renewal, confirm
that the timer detects nginx's stale certificate, reloads it successfully, and
leaves both listeners serving the new certificate. Keep host-specific deployment
records outside this public repository.
