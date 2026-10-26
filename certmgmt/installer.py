"""Versioned issuer installation. Does not install or modify remote helpers."""

import fcntl
import functools
import hashlib
import json
import logging
import os
import shlex
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from .config import load
from .errors import ConfigurationError, DeploymentError
from .runtime import run_command

log = logging.getLogger(__name__)
MARKER = "# Managed by CertMgmt Python"


def serialized(function):
    @functools.wraps(function)
    def wrapped(args):
        if args.dry_run:
            return function(args)
        root = Path(args.prefix).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with (root / ".install.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeploymentError(
                    "another CertMgmt installation or rollback is running"
                ) from None
            return function(args)

    return wrapped


def atomic_text(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".certmgmt-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_link(path, target):
    temporary = path.with_name(".certmgmt-link-" + uuid.uuid4().hex)
    try:
        temporary.symlink_to(target)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def restore(root, receipt):
    hook = Path(receipt["hook"])
    backup = Path(receipt["backup"])
    if receipt["had_hook"]:
        atomic_text(hook, backup.read_text(), receipt["hook_mode"])
    else:
        if hook.exists() and MARKER not in hook.read_text():
            raise DeploymentError(
                "refusing to remove a hook no longer owned by CertMgmt"
            )
        hook.unlink(missing_ok=True)
    current = root / "current"
    if receipt["previous"] is not None:
        atomic_link(current, receipt["previous"])
    else:
        current.unlink(missing_ok=True)
    launcher = root / "bin/certmgmt"
    if receipt.get("launcher_backup"):
        atomic_text(
            launcher,
            Path(receipt["launcher_backup"]).read_text(),
            receipt["launcher_mode"],
        )
    else:
        launcher.unlink(missing_ok=True)


@serialized
def rollback(args):
    root = Path(args.prefix).resolve()
    try:
        receipt_path = root / "last-install.json"
        receipt = json.loads(receipt_path.read_text())
    except OSError, ValueError:
        raise ConfigurationError(
            "no completed installation receipt is available"
        ) from None
    if receipt.get("rolled_back"):
        raise ConfigurationError("the last installation was already rolled back")
    if args.dry_run:
        log.info("Would restore previous CertMgmt environment and its deploy hook")
        return 0
    restore(root, receipt)
    receipt["rolled_back"] = True
    atomic_text(receipt_path, json.dumps(receipt, indent=2) + "\n")
    log.info(
        "Restored previous tooling and hook; device certificates were not rolled back"
    )
    return 0


@serialized
def run(args):
    site = load(args.config)
    wheel = Path(args.wheel).resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise ConfigurationError("--wheel must name a built CertMgmt wheel")
    try:
        with zipfile.ZipFile(wheel) as archive:
            locked = archive.read("certmgmt/runtime-requirements.txt").decode()
            metadata = [
                name
                for name in archive.namelist()
                if name.startswith("certmgmt-") and name.endswith(".dist-info/METADATA")
            ]
            if len(metadata) != 1:
                raise ValueError("wrong wheel")
    except OSError, KeyError, ValueError, zipfile.BadZipFile:
        raise ConfigurationError(
            "wheel is not a CertMgmt build with locked runtime dependencies"
        ) from None
    root = Path(args.prefix).resolve()
    hook = Path(args.hook_dir).resolve() / "cert-dispatcher.sh"
    current = root / "current"
    launcher = root / "bin/certmgmt"
    if launcher.is_symlink() or (
        launcher.exists() and MARKER not in launcher.read_text()
    ):
        raise ConfigurationError("refusing to replace a launcher not owned by CertMgmt")
    if current.exists() and not current.is_symlink():
        raise ConfigurationError("installation current path must be a symlink")
    if hook.is_symlink():
        raise ConfigurationError("refusing to replace a symlink deploy hook")
    old_hook = hook.read_text() if hook.exists() else None
    if (
        old_hook is not None
        and MARKER not in old_hook
        and "# cert-dispatcher.sh -- Certbot deploy hook dispatcher" not in old_hook
    ):
        raise ConfigurationError(
            "existing cert-dispatcher.sh is not a recognized CertMgmt hook"
        )
    run_command(
        [
            args.python,
            "-c",
            "import sys; sys.exit(0 if sys.version_info >= (3,14,2) else 2)",
        ],
        timeout=30,
    )
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()[:16]
    destination = root / "versions" / digest
    log.info(
        "Install %s into %s; hook %s; preserve %s",
        wheel.name,
        destination,
        hook,
        site.path,
    )
    if args.dry_run:
        return 0
    root.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Build at its final path: moving a venv breaks its absolute shebangs.
        destination.mkdir()
        try:
            run_command([args.python, "-m", "venv", str(destination)], timeout=120)
            lock_path = destination / "runtime-requirements.txt"
            lock_path.write_text(locked)
            python = str(destination / "bin/python")
            run_command(
                [
                    python,
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    "-r",
                    str(lock_path),
                ],
                timeout=900,
                report=True,
            )
            run_command(
                [python, "-m", "pip", "install", "--no-deps", str(wheel)],
                timeout=120,
                report=True,
            )
            run_command([python, "-m", "pip", "check"], timeout=30)
            run_command([python, "-m", "certmgmt", "--version"], timeout=30)
            (destination / ".complete").write_text(digest)
        except BaseException:
            shutil.rmtree(destination)
            raise
    elif not (destination / ".complete").is_file():
        raise ConfigurationError(
            "an incomplete installation occupies the version directory; inspect it before retrying"
        )
    else:
        run_command([str(destination / "bin/python"), "-m", "pip", "check"], timeout=30)
        run_command(
            [str(destination / "bin/python"), "-m", "certmgmt", "--version"], timeout=30
        )
    hook_text = (
        "#!/bin/sh\n"
        + MARKER
        + "\nexec "
        + shlex.join(
            [
                str(current / "bin/python"),
                "-m",
                "certmgmt",
                "hook",
                "--config",
                str(site.path),
            ]
        )
        + "\n"
    )
    if (
        current.is_symlink()
        and current.resolve() == destination
        and old_hook == hook_text
    ):
        log.info("This version and hook are already installed")
        return 0
    transaction = root / "transactions" / uuid.uuid4().hex
    transaction.mkdir(parents=True, mode=0o700)
    backup = transaction / "deploy-hook"
    if old_hook is not None:
        atomic_text(backup, old_hook)
    launcher_backup = transaction / "launcher"
    if launcher.exists():
        atomic_text(launcher_backup, launcher.read_text())
    receipt = {
        "previous": os.readlink(current) if current.is_symlink() else None,
        "installed": str(destination),
        "hook": str(hook),
        "backup": str(backup),
        "had_hook": old_hook is not None,
        "hook_mode": hook.stat().st_mode & 0o777 if hook.exists() else 0o755,
        "launcher_backup": str(launcher_backup) if launcher.exists() else None,
        "launcher_mode": launcher.stat().st_mode & 0o777
        if launcher.exists()
        else 0o755,
    }
    atomic_text(transaction / "receipt.json", json.dumps(receipt, indent=2) + "\n")
    try:
        atomic_link(current, str(destination))
        atomic_text(hook, hook_text, 0o755)
        atomic_text(
            root / "bin/certmgmt",
            "#!/bin/sh\n"
            + MARKER
            + "\nexec "
            + shlex.quote(str(current / "bin/certmgmt"))
            + ' "$@"\n',
            0o755,
        )
        atomic_text(root / "last-install.json", json.dumps(receipt, indent=2) + "\n")
    except BaseException:
        restore(root, receipt)
        raise
    log.info(
        "Installed. CLI: %s; restore tooling with certmgmt rollback --prefix %s",
        root / "bin/certmgmt",
        root,
    )
    return 0
