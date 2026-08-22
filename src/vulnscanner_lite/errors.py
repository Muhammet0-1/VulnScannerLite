"""Expected application errors."""


class VulnScannerLiteError(Exception):
    """Base error for expected failures."""


class ConfigurationError(VulnScannerLiteError):
    """Raised when CLI or programmatic configuration is invalid."""


class ResolutionError(VulnScannerLiteError):
    """Raised when the target cannot be resolved into a safe pinned endpoint."""


class TransportError(VulnScannerLiteError):
    """Raised when an HTTP request cannot be completed safely."""


class AuditError(VulnScannerLiteError):
    """Raised when an audit cannot complete."""
