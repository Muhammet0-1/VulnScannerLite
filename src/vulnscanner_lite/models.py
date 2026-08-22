"""Immutable audit, response, and finding models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from socket import AddressFamily
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"

    @property
    def rank(self) -> int:
        return {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2}[self]


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
        }
        if self.evidence is not None:
            data["evidence"] = self.evidence
        return data


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    family: AddressFamily
    address: str
    scope_id: int = 0

    @property
    def ip_version(self) -> int:
        return 6 if self.family is AddressFamily.AF_INET6 else 4

    def socket_address(self, port: int) -> tuple[str, int] | tuple[str, int, int, int]:
        if self.family is AddressFamily.AF_INET6:
            return (self.address, port, 0, self.scope_id)
        return (self.address, port)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"address": self.address, "ip_version": self.ip_version}
        if self.scope_id:
            data["scope_id"] = self.scope_id
        return data


@dataclass(frozen=True, slots=True)
class HTTPResponseData:
    url: str
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    elapsed_ms: float

    def header(self, name: str) -> str | None:
        expected = name.lower()
        for key, value in self.headers:
            if key.lower() == expected:
                return value
        return None

    def headers_all(self, name: str) -> tuple[str, ...]:
        expected = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == expected)


@dataclass(frozen=True, slots=True)
class FormInfo:
    index: int
    action: str
    method: str
    field_names: tuple[str, ...]
    has_password: bool


@dataclass(frozen=True, slots=True)
class AuditReport:
    target_url: str
    final_url: str
    started_at: str
    duration_seconds: float
    status: int
    endpoints: tuple[ResolvedEndpoint, ...]
    selected_endpoint: ResolvedEndpoint
    request_count: int
    active_reflection: bool
    findings: tuple[Finding, ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            severity.value: sum(finding.severity is severity for finding in self.findings)
            for severity in Severity
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "target_url": self.target_url,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "status": self.status,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
            "selected_endpoint": self.selected_endpoint.to_dict(),
            "request_count": self.request_count,
            "active_reflection": self.active_reflection,
            "counts": self.counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }
