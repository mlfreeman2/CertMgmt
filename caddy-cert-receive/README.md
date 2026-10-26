# Caddy certificate receiver over SSH

This is the target-side companion to the generic
[`shell-command` driver](../README.md#shell-command-certificate-delivery-to-caddy-over-ssh).
Install it on the Caddy host. The driver stays on the certificate issuer;
`certbot-setup.sh` does not install or configure this receiver.

The issuer sends a private key followed by its full certificate chain on SSH stdin.
The receiver checks the PEM stream, key/leaf match, remaining lifetime, and enrolled
DNS name. It stages a complete pair, switches a `current` symlink, then forces Caddy
to reload. The sender verifies the certificate served over TLS.

## Requirements and layout

The example assumes Debian with Bash, OpenSSL, OpenSSH server, GNU coreutils,
`awk`, `flock`, `logger`, and Caddy installed using its official package. Caddy must
already be running, with a Caddyfile readable by `cert-receiver` and a local admin
endpoint that account can reach. Keep the package's placeholder Caddyfile until
the first certificates have arrived.

Each enrolled certificate has a slot named after a DNS SAN with its leading `*.`
removed. For a certificate containing multiple SANs, the first matching enrolled
slot is selected; enroll one intended slot per certificate. Slot directories must
be real directories, not symlinks. They are the delivery allowlist, and the receiver
never creates them itself.

```text
/etc/caddy/certs/apps.example.com/
  .generation.<id>/
    fullchain.pem
    privkey.pem
  current  -> .generation.<active-id>
  previous -> .generation.<prior-id>
```

`previous` appears after a replacement. Generation directories are mode 2750,
owned by `cert-receiver` with group `caddy`; files are mode 0640. Certificate and
key filenames can be overridden but must be distinct simple filenames.

## Install on the Caddy host

Run as root from this directory, after installing Caddy. These user/key creation
commands are for a new receiver; preserve existing accounts and authorized keys
when upgrading.

```bash
useradd --system --user-group --create-home --shell /bin/sh --groups caddy cert-receiver
install -o root -g root -m 755 caddy-cert-receive.sh /usr/local/bin/caddy-cert-receive
install -d -m 2750 -o cert-receiver -g caddy /etc/caddy/certs
install -m 640 -o cert-receiver -g caddy /dev/null /etc/caddy/certs/.lock
install -d -m 2750 -o cert-receiver -g caddy /etc/caddy/certs/apps.example.com
```

The lock-file install is for first setup only; do not replace a lock file while
deliveries or maintenance may be using it. The login shell is required because
sshd invokes the forced command through it.
For an existing receiver account, ensure `usermod -aG caddy cert-receiver` has been
applied; a new SSH session picks up that group membership.

Defaults need no configuration file. To override them, install
`caddy-cert-receive-SAMPLE.conf` as `/etc/caddy-cert-receive.conf`, owned by root,
mode 0644, and uncomment the required assignments. It is sourced as shell code;
the receiver account must not be able to edit it or the installed script.

Set these values to the issuer's source address as seen by this host and its
dedicated delivery **public** key. Then install the forced-command entry:

```bash
CERT_SENDER_IP=192.0.2.10
CERT_SENDER_PUBKEY='ssh-ed25519 REPLACE_WITH_ISSUER_PUBLIC_KEY'
install -d -m 700 -o cert-receiver -g cert-receiver ~cert-receiver/.ssh
printf 'restrict,from="%s",command="/usr/local/bin/caddy-cert-receive" %s\n' \
  "$CERT_SENDER_IP" "$CERT_SENDER_PUBKEY" > ~cert-receiver/.ssh/authorized_keys
chown cert-receiver:cert-receiver ~cert-receiver/.ssh/authorized_keys
chmod 600 ~cert-receiver/.ssh/authorized_keys
```

Keep `PermitUserEnvironment no` for this account and do not configure sshd to
accept client variables such as `BASH_ENV` or `PATH`. The issuer's key is authorized
to deliver to every enrolled slot. It cannot select arbitrary shell commands or
destination paths through the SSH command string.

## Delivery and Caddy configuration

Use the issuer preparation, SSH host-key verification, bootstrap, and automatic
deployment instructions in the [driver README](../README.md#shell-command-certificate-delivery-to-caddy-over-ssh).
Once the SSH host key is trusted, these commands illustrate the receiver protocol:

```bash
cat privkey.pem fullchain.pem | ssh -i DELIVERY_KEY -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes cert-receiver@caddy.example.com check
cat privkey.pem fullchain.pem | ssh -i DELIVERY_KEY -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes cert-receiver@caddy.example.com install
ssh -i DELIVERY_KEY -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes cert-receiver@caddy.example.com status
```

`check` validates without installing or reloading. `status` reports the installed
current pairs, returning nonzero for empty or invalid slots; it does not test the
served certificate. Unsupported commands return 2. Delivery/refusal failures
return nonzero and are logged to stderr and syslog without the private key.

After bootstrap, point the real Caddyfile at **both files under `current`**:

```caddyfile
forgejo.apps.example.com {
    tls /etc/caddy/certs/apps.example.com/current/fullchain.pem /etc/caddy/certs/apps.example.com/current/privkey.pem
    reverse_proxy 127.0.0.1:3000
}
```

Replace the example upstream with the app's address. The default reload uses
`caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force`.
[`--force` reloads manually loaded certificate files even when the configuration
is unchanged](https://caddyserver.com/docs/command-line#caddy-reload).
It uses the [local admin API](https://caddyserver.com/docs/api), so this setup needs
no sudo access for `cert-receiver`.

## Failure and recovery behavior

- A failed validation, staging write, or `current` switch leaves the active pair
  in place. On first installation, a failed staging/switch leaves the slot empty.
- One same-filesystem rename switches `current` to a directory containing both
  files. There is no interval where the receiver moves active files out of the way.
- If interrupted after the switch, or if reload fails, the complete new pair stays
  on disk and the delivery fails. Caddy may still serve the older pair. Re-send
  the intended certificate through the driver directly: an identical delivery
  always retries the reload. The driver README explains forced redelivery.
- `previous` is updated before switching `current`. If activation fails, both links
  can point to the old active generation. All earlier generations remain on disk,
  including unreferenced or partial staging directories left by failures. Nothing
  automatically deletes them or private keys from earlier generations.
- A certificate with an earlier expiry than the current certificate is refused.
  This check is per slot; it is not issuer/chain authentication. The SSH delivery
  identity is trusted to supply the intended certificate.

For manual rollback, pause deliveries and acquire `/etc/caddy/certs/.lock`. Inspect
the desired generation's certificate/key, expiry and SANs. Create a temporary
symlink beside `current`, then replace `current` using `mv -Tf`; never copy the two
active files separately. Force a Caddy reload while holding the lock and verify
the served certificate. Rollback is an explicit local operation and bypasses the
receiver's earlier-expiry refusal. Retain the failed generation for diagnosis.

Manual Caddy validation/reloads must use the same lock as deliveries. Two independent
file opens could otherwise span a symlink switch. For the default paths, run as root:

```bash
flock --timeout 30 --close /etc/caddy/certs/.lock sh -ec '
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
  caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
'
```

Coordinate service restarts and package upgrades with deliveries too. A custom
`RELOAD_CMD` must finish applying the change before returning, and must not try to
acquire the lock already held by its receiver. Keep any certificate retention or
cleanup outside active deliveries; never remove a generation referenced by
`current` or `previous`.

## Adopting the older flat-file draft

The receiver refuses an existing flat pair at `<slot>/fullchain.pem` and
`<slot>/privkey.pem` when no managed `current` link exists. Installing the new
script alone is insufficient because the Caddyfile paths also change.

During a maintenance window with deliveries paused, back up the existing files
and Caddyfile. Under the receiver lock, copy the existing pair into a new
`.generation.<alphanumeric-id>` directory with the ownership/modes above, create
the `current` link, and change the Caddyfile paths to include `/current/`. Validate
and force-reload Caddy, then verify TLS before resuming deliveries. Keep the
original flat files until migration has been verified; the new receiver leaves
them untouched. First-time installations simply use empty slots and bootstrap.

## Validation

From the CertMgmt root:

```bash
python3 -m unittest discover -s tests -p test_caddy_cert_receive.py -v
```

Tests use real OpenSSL certificates, injected write/rename failures, abrupt process
termination around activation, serialized concurrent delivery, reload failure/retry,
and the real sender driver with a Caddy stand-in. They do not establish power-loss
durability or live SSH/Caddy acceptance. On the actual target, verify bootstrap,
changed-certificate delivery without a restart, rejection reporting, and the served
TLS fingerprint after retry. Keep host-specific deployment records outside this
public repository.
