"""Argument translation only; all behavior lives in the Python application."""

import sys

from .cli import main as cli


def main(name=None, arguments=None):
    if name is None:
        name, *arguments = sys.argv[1:]
    args = list(sys.argv[1:] if arguments is None else arguments)
    if name.startswith("driver-"):
        driver = name.removeprefix("driver-").removesuffix(".sh").removesuffix(".py")
        translated = []
        for index, value in enumerate(args):
            if (
                driver in ("idrac", "glinet-kvm")
                and value == "-h"
                and index + 1 < len(args)
                and not args[index + 1].startswith("-")
            ):
                value = "--host"
            if driver == "shell-command" and value == "-c":
                value = "--command"
            translated.append(value)
        return cli(["driver", driver, *translated])
    if name == "verify-deployed-cert.sh":
        replacements = {"-p": "--port", "-w": "--wait", "-r": "--retries"}
        return cli(["verify", *[replacements.get(arg, arg) for arg in args]])
    if name == "cert-dispatcher.sh":
        return cli(["hook", *args])
    if name == "cert-sync.sh":
        deploying = "-D" in args or "--deploy" in args
        dry = "-n" in args or "--dry-run" in args
        command = "verify" if deploying and dry else "deploy" if deploying else "sync"
        translated = []
        for value in args:
            if value in ("-D", "--deploy") or (deploying and value in ("-y", "--yes")):
                continue
            if deploying and dry and value in ("-n", "--dry-run"):
                continue
            translated.append({"-c": "--config", "-n": "--dry-run"}.get(value, value))
        return cli([command, *translated])
    if name in ("scan-ssl-certs.sh", "scan-ssl-inventory.sh"):
        translated = [
            {"-c": "--config", "-t": "--timeout", "-v": "--debug"}.get(arg, arg)
            for arg in args
            if arg != "-n"
        ]
        if (
            name == "scan-ssl-certs.sh"
            and "--config" not in translated
            and not any(arg in ("-h", "--help") for arg in translated)
        ):
            translated += ["--config", "/etc/letsencrypt/deploy-config.json"]
        return cli(["scan", *translated])
    if name == "certbot-setup.sh":
        if not args:
            print(
                "Setup now installs a built wheel and preserves existing config/credentials.\nRun certbot-setup.sh --help for the explicit installation options.",
                file=sys.stderr,
            )
            return 2
        return cli(["install", *args])
    print("Unknown compatibility launcher", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
