"""URL parsing and bounded audit configuration."""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

from .errors import ConfigurationError

DEFAULT_MAX_BODY_BYTES = 1_048_576
ABSOLUTE_MAX_BODY_BYTES = 5_242_880
DEFAULT_MAX_REDIRECTS = 3
ABSOLUTE_MAX_REDIRECTS = 5
MAX_URL_LENGTH = 2_048


@dataclass(frozen=True, slots=True)
class TargetURL:
    """Canonical HTTP(S) target with an explicit origin."""

    scheme: str
    hostname: str
    port: int
    path: str
    query: str = ""

    @property
    def default_port(self) -> int:
        return 443 if self.scheme == "https" else 80

    @property
    def host_header(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return host if self.port == self.default_port else f"{host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host_header}"

    @property
    def request_target(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path

    @property
    def url(self) -> str:
        return urlunsplit((self.scheme, self.host_header, self.path, self.query, ""))

    def same_origin(self, other: TargetURL) -> bool:
        return (
            self.scheme == other.scheme
            and self.hostname == other.hostname
            and self.port == other.port
        )


def parse_target_url(value: str) -> TargetURL:
    """Parse one absolute HTTP(S) URL and reject ambiguous or dangerous components."""

    if not value or value != value.strip():
        raise ConfigurationError("URL must not be empty or surrounded by whitespace")
    if len(value) > MAX_URL_LENGTH:
        raise ConfigurationError(f"URL exceeds the {MAX_URL_LENGTH}-character limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ConfigurationError("URL must not contain control characters")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ConfigurationError("URL scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("credentials must not be embedded in the URL")
    if parsed.fragment:
        raise ConfigurationError("URL fragments are not sent to servers and are not accepted")
    try:
        hostname_raw = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("URL contains an invalid port or host") from exc
    if hostname_raw is None:
        raise ConfigurationError("URL must include a hostname or IP address")

    hostname = _normalize_hostname(hostname_raw)
    if parsed.netloc.endswith(":") or port == 0:
        raise ConfigurationError("URL port must be between 1 and 65535")
    resolved_port = port if port is not None else (443 if scheme == "https" else 80)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="=&;%+,:@/?-._~")
    return TargetURL(scheme=scheme, hostname=hostname, port=resolved_port, path=path, query=query)


def _normalize_hostname(value: str) -> str:
    hostname = value.rstrip(".").lower()
    if not hostname:
        raise ConfigurationError("URL hostname must not be empty")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ConfigurationError("URL hostname is not valid IDNA") from exc
    if len(ascii_hostname) > 253:
        raise ConfigurationError("URL hostname is too long")
    labels = ascii_hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise ConfigurationError("URL hostname is invalid")
    return ascii_hostname


@dataclass(frozen=True, slots=True)
class AuditConfig:
    """Fail-fast resource and behavior limits."""

    target: TargetURL
    allow_public_target: bool = False
    timeout: float = 5.0
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    active_reflection: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.target, TargetURL):
            raise ConfigurationError("target must be a parsed TargetURL")
        try:
            canonical_target = parse_target_url(self.target.url)
        except (ConfigurationError, TypeError, ValueError) as exc:
            raise ConfigurationError("target must be a valid canonical TargetURL") from exc
        if canonical_target != self.target:
            raise ConfigurationError("target must be a valid canonical TargetURL")
        if not isinstance(self.allow_public_target, bool):
            raise ConfigurationError("allow_public_target must be a boolean")
        if not isinstance(self.active_reflection, bool):
            raise ConfigurationError("active_reflection must be a boolean")
        if not _valid_float(self.timeout, minimum=0.1, maximum=30.0):
            raise ConfigurationError("timeout must be between 0.1 and 30 seconds")
        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or not 1_024 <= self.max_body_bytes <= ABSOLUTE_MAX_BODY_BYTES
        ):
            raise ConfigurationError(
                f"maximum body size must be between 1024 and {ABSOLUTE_MAX_BODY_BYTES} bytes"
            )
        if (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or not 0 <= self.max_redirects <= ABSOLUTE_MAX_REDIRECTS
        ):
            raise ConfigurationError(
                f"maximum redirects must be between 0 and {ABSOLUTE_MAX_REDIRECTS}"
            )


def _valid_float(value: object, minimum: float, maximum: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and minimum <= numeric <= maximum
