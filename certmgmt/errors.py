"""Errors cross library boundaries; only the CLI chooses process exit codes."""


class ConfigurationError(ValueError):
    """Invalid input; fail before contacting a target."""


class DeploymentError(RuntimeError):
    """An operation failed, possibly after changing a device."""


class OperationTimeout(BaseException):
    """Cannot be swallowed by a device's best-effort cleanup handler."""


class OperationCancelled(BaseException):
    """External termination must unwind process groups and notification handlers."""

    def __init__(self, signum):
        self.signum = signum
