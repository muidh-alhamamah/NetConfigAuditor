"""Expected, user-facing errors."""


class NCAuditError(Exception):
    """Base class for errors reported to the user without a traceback."""


class ConfigError(NCAuditError):
    """A configuration file could not be read or is not a Cisco IOS configuration."""
