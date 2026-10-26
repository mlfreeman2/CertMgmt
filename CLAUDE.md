# CertMgmt development

The issuer-side package in `certmgmt/` requires Python >=3.14.2, aligned with the
Venstar HA components. `README.md` describes the CLI, deployment contracts, migration
and installation. `docs/plans/python-migration.md` records scope and acceptance.

Use `uv sync --locked`, then `uv run --no-sync pytest -q`,
`uv run --no-sync ruff check certmgmt tests`,
`uv run --no-sync ruff format --check certmgmt tests`, `uv build`, and
`uv pip check`. Tests are offline; they are not device acceptance. Keep the hashed
`certmgmt/runtime-requirements.txt` export synchronized with `uv.lock`.

`registry.py` owns driver defaults and validation; `cli.py` owns argparse help/options.
Adapters share TLS verification and bounded runtime helpers. Keep secrets out of logs,
exception strings and subprocess argv. Device credentials support values/files/env.
Direct drivers take ordinary PEM paths and require neither Certbot nor a site config.
Invalid inputs must fail before device mutation. Explicit verification opt-out is
required; a completed upload alone is not a verified success.

`orchestration.py` handles batch selection, verification and aggregate results.
`reconcile.py` invokes supported Certbot updates; never restore automatic destructive
revoke/delete/re-request behavior. The versioned installer replaces only its own hook
and preserves config, credentials, unrelated hooks and prior tooling for rollback.

The old issuer filenames are compatibility launchers, not independently copied
scripts. The Caddy receiver and PVE nginx helper remain Bash and separately deployed.
Do not port, install or change their protocols as part of issuer-side work. Keep their
regression tests; real hardware acceptance and production cutover are separate steps.

Private site configs, Cloudflare credentials and PEM/key material are ignored by Git.
Never commit them. Changes belong in this repository; shared workspace configuration
belongs in Combined-DevContainer.
