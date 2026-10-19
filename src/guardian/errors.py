"""Exceptions that the CLI maps to exit codes."""


class GuardianError(Exception):
    """Base class."""


class PolicyError(GuardianError):
    """The policy file is missing or invalid. CLI exit code 2."""


class ProjectError(GuardianError):
    """The project path is invalid or contains nothing to check. CLI exit code 2."""


class ScannerError(GuardianError):
    """An external scanner (Trivy) is missing or failed. CLI exit code 3.

    The gate must *fail closed*: if we could not scan, we must not report a pass.
    """
