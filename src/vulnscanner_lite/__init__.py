"""Safe HTTP security posture auditing primitives."""

from .config import AuditConfig, TargetURL, parse_target_url
from .models import AuditReport, Finding, Severity
from .scanner import Auditor

__all__ = [
    "AuditConfig",
    "AuditReport",
    "Auditor",
    "Finding",
    "Severity",
    "TargetURL",
    "parse_target_url",
]

__version__ = "1.0.0"
