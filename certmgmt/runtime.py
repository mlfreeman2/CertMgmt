"""Bounded operations, child-process cleanup, and credential-safe logging."""

import base64
import contextlib
import logging
import os
import re
import signal
import subprocess
import tempfile
import threading
from collections.abc import Iterator

from .errors import DeploymentError, OperationCancelled, OperationTimeout

log = logging.getLogger(__name__)
_secrets: set[str] = set()


def protect(value: str) -> str:
    if value:
        _secrets.update((value, base64.b64encode(value.encode()).decode()))
    return value


def redact(value: object) -> str:
    text = str(value)
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        "<private key redacted>",
        text,
        flags=re.S,
    )
    text = re.sub(
        r"(?i)([?&](?:token|api_key|password)=)[^&\s]+", r"\1<redacted>", text
    )
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


class SafeFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))


def configure_logging(quiet=False, debug=False, log_file=None):
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING if quiet else root.level)
    console.setFormatter(SafeFormatter("%(message)s"))
    root.addHandler(console)
    if log_file:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(SafeFormatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(handler)
    # Debug output must never include transport headers, cookies or request bodies.
    for name in ("urllib3", "requests", "websockets"):
        logging.getLogger(name).setLevel(logging.WARNING)


@contextlib.contextmanager
def cancellation():
    def terminate(signum, _frame):
        raise OperationCancelled(signum)

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextlib.contextmanager
def deadline(seconds: float) -> Iterator[None]:
    """Linux main-thread deadline covers DNS, HTTP, sleeps and verification."""
    if not seconds:
        yield
        return
    if threading.current_thread() is not threading.main_thread():
        raise DeploymentError("bounded deployment must run on the main thread")

    def expired(_signum, _frame):
        raise OperationTimeout(
            f"operation exceeded {seconds:g}s; target may have changed"
        )

    old_handler = signal.signal(signal.SIGALRM, expired)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, old_handler)


def _stop_group(process):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The group may still contain descendants even if the leader has exited.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def run_command(
    argv, *, timeout=120, cwd=None, env=None, input_data=None, check=True, report=False
):
    """Never log argv: a configured shell command may contain credentials."""
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            start_new_session=True,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            process.communicate(input=input_data, timeout=timeout or None)
        except BaseException as error:
            _stop_group(process)
            if isinstance(error, subprocess.TimeoutExpired):
                raise DeploymentError(
                    f"command timed out after {timeout:g}s; remote changes may remain"
                ) from None
            raise
        output.seek(0)
        result = output.read(8 * 1024 * 1024 + 1)
        if len(result) > 8 * 1024 * 1024:
            raise DeploymentError("command output exceeded 8 MiB")
    text = result.decode(errors="replace")
    if report and text.strip():
        log.info("%s", text.rstrip())
    if check and process.returncode:
        raise DeploymentError(
            f"command failed (exit {process.returncode}): {redact(text)[-2000:]}"
        )
    return subprocess.CompletedProcess(argv, process.returncode, text)
