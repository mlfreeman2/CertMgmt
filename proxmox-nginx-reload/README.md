# Proxmox nginx cert-reload helper

Systemd units that automatically reload nginx when pveproxy's TLS certificate
changes. Use this when nginx on the Proxmox host shares the pveproxy cert
(i.e. `ssl_certificate /etc/pve/local/pveproxy-ssl.pem`).

## Prerequisites

Update nginx to use the **pveproxy** cert, not the default self-signed `pve-ssl.pem`:

```nginx
ssl_certificate     /etc/pve/local/pveproxy-ssl.pem;
ssl_certificate_key /etc/pve/local/pveproxy-ssl.key;
```

**Important:** Proxmox has two cert pairs in `/etc/pve/local/`:
- `pve-ssl.pem` / `pve-ssl.key` — auto-generated self-signed cert (default)
- `pveproxy-ssl.pem` / `pveproxy-ssl.key` — custom cert uploaded via the API

The API-uploaded cert only goes to `pveproxy-ssl.*`. If nginx points at
`pve-ssl.pem` it will keep serving the old self-signed cert.

## Install

```bash
cp pveproxy-cert-reload.path pveproxy-cert-reload.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pveproxy-cert-reload.path
```

## How it works

`PathModified=` uses inotify to detect writes to the pveproxy cert file.
When the cert-deploy driver uploads a new cert via the Proxmox API, pveproxy
writes the cert to `/etc/pve/local/pveproxy-ssl.pem`, systemd detects the
change, and runs `nginx -s reload`.

## Caveat

`/etc/pve/` is a FUSE-mounted cluster filesystem (pmxcfs). inotify works on
most FUSE mounts but is not guaranteed. If the path unit does not trigger on
your setup, use the cron fallback instead:

```bash
# /etc/cron.d/nginx-cert-reload
* * * * * root [ /etc/pve/local/pveproxy-ssl.pem -nt /run/nginx-cert-stamp ] && nginx -s reload && touch /run/nginx-cert-stamp
```
