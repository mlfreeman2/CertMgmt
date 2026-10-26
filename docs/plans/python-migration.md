# Issuer-side Python migration

Status: implementation and offline verification complete on `python-migration`;
live device acceptance and deployment pending.

Approved scope: Python 3.14 (minimum 3.14.2), installable CLI and library, all nine
drivers, shared verification, dispatch, Certbot reconciliation, scanners and installer.
The Caddy receiver and PVE nginx helper stay in Bash, as requested during implementation.
Their installed protocols and existing regression tests remain part of acceptance.

## Implementation sequence

1. Package, reproducible dependencies and Python CI.
2. Common arguments, validation, credentials, errors, logging and bounded operations.
3. Port four shell drivers and adapt five Python drivers; retain compatibility launchers.
4. Dispatch/verify/sync with one registry and explicit target selection. Replace the
   revoke/delete/re-request policy with Certbot updates that retain the old lineage on failure.
5. Versioned installation preserving other hooks and credentials; Python scanners.
6. Documentation, offline verification and final review.
7. Separately record representative hardware acceptance and issuer cutover. Offline
   tests do not mark this step complete. Keep the existing remote helpers deployed.

## What to test

CLI help/error/secret handling; generic PEM paths, mismatched keys and device key/chain
restrictions; protocol request construction and malformed responses; TLS/SNI probes;
process-group cancellation; configuration validation before mutation; partial deployment
failure and Healthchecks results; Certbot issuance failure preserving current certificates;
fresh/upgrade/repeated installation and restoration of tooling; scanner failures.
Retain receiver atomicity, locking, refusal and reload-retry tests without porting the receiver.

## Verify

Run the existing 44-test baseline, then the complete expanded suite under Python 3.14.
Install a built wheel in a fresh environment; run CLI help and a local TLS verification
outside the checkout. Check dependency consistency, Ruff, shell launcher syntax and diffs.
Device acceptance must distinguish upload, activation and observed served certificate.
No production device, certificate, hook or service is changed by offline validation.

## Offline evidence (2026-10-26)

- The pre-migration unittest baseline passed all 44 tests.
- Expanded pytest suite: 135 passed, plus 20 subtests, on each of CPython 3.14.2
  and 3.14.9. Both environments came from the checked-in `uv.lock`.
- Ruff lint and formatting passed. Ten compatibility shell launchers passed `sh -n`.
  Devcontainer JSONC and sample configuration schema validated.
- Built wheel and sdist; checked artifact contents and inclusion of the hashed runtime
  requirements. The runtime export matches the dependency lock. Dependency consistency
  checks passed in both test environments and the installed wheel environment.
- Real isolated installation exercised a fresh environment, hashed pip installs,
  version upgrade, repeated install, and tooling rollback. The CLI and generated hook
  ran outside the checkout. An unrelated hook and existing config were preserved.
- The installed wheel verified a real local TLS server with separate connection host
  and SNI, then ran shell delivery and verified the served leaf. Receiver and nginx
  regression tests retained their original sources; both remote-helper directories
  are byte-for-byte unchanged from the branch base.
- Process tests exercised pipeline failures, command/whole-operation deadlines,
  SIGINT/SIGTERM, descendant cleanup, and private-key redaction before error truncation.
  Fixtures covered all nine adapters, including Brother import/activation forms,
  Supermicro X10/X11 uploads, and TrueNAS response IDs/managed cleanup.

This is local verification, not a hosted CI result or live-device acceptance. The
new CI matrix runs the minimum Python patch and the current 3.14 patch. Devcontainer
configuration was parsed; a full devcontainer image rebuild was not performed.

## Remaining acceptance and cutover

1. Review the branch and intentional compatibility changes in README.
2. On a representative device of each used type, record upload response, activation
   or restart, and observed served fingerprint. Include both ports on PVE hosts
   using nginx, and confirm SSH delivery works with the existing Caddy receiver.
3. On the issuer, build/install the wheel with the existing config and credentials;
   preview installation first. Verify selected targets, perform a selected deployment,
   and exercise a Certbot renewal/hook before broad cutover.
4. Retain the prior issuer checkout/environment and hook backup through acceptance.
   A tooling rollback does not roll back certificates on devices.

No remote helper conversion, remote helper reinstall, production issuance, production
deployment, or repository push is part of the offline implementation above.
