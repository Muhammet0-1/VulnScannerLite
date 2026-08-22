"""Resolve one target once and pin the approved endpoint set."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any

from .config import AuditConfig
from .errors import ResolutionError
from .models import ResolvedEndpoint

MAX_RESOLVED_ENDPOINTS = 8
GetAddrInfo = Callable[..., Iterable[tuple[Any, Any, Any, Any, tuple[Any, ...]]]]
_IPV4_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_PRIVATE_NETWORK = ipaddress.ip_network("fc00::/7")


class AddressScope(str, Enum):
    LOCAL = "local"
    PUBLIC = "public"


class TargetResolver:
    """Validate every address before the transport opens a socket."""

    def __init__(self, getaddrinfo: GetAddrInfo | None = None) -> None:
        self._getaddrinfo = getaddrinfo if getaddrinfo is not None else socket.getaddrinfo

    def resolve(self, config: AuditConfig) -> tuple[ResolvedEndpoint, ...]:
        try:
            records = self._getaddrinfo(
                config.target.hostname,
                config.target.port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (socket.gaierror, UnicodeError, ValueError) as exc:
            raise ResolutionError(
                f"target hostname could not be resolved: {config.target.hostname}"
            ) from exc

        endpoints: dict[tuple[int, str, int], ResolvedEndpoint] = {}
        scopes: set[AddressScope] = set()
        for family_raw, _socktype, _protocol, _canonical, sockaddr in records:
            try:
                family = socket.AddressFamily(family_raw)
            except ValueError:
                continue
            if family not in (socket.AddressFamily.AF_INET, socket.AddressFamily.AF_INET6):
                continue
            try:
                parsed = ipaddress.ip_address(str(sockaddr[0]))
                scope_id = int(sockaddr[3]) if family is socket.AddressFamily.AF_INET6 else 0
            except (IndexError, TypeError, ValueError) as exc:
                raise ResolutionError("resolver returned an invalid address record") from exc
            expected_version = 6 if family is socket.AddressFamily.AF_INET6 else 4
            if parsed.version != expected_version or scope_id < 0:
                raise ResolutionError("resolver returned an invalid address record")
            address = str(parsed)
            scope = _classify_address(parsed)
            scopes.add(scope)
            key = (int(family), address, scope_id)
            endpoints[key] = ResolvedEndpoint(family=family, address=address, scope_id=scope_id)
            if len(endpoints) > MAX_RESOLVED_ENDPOINTS:
                raise ResolutionError(
                    f"target resolved to more than {MAX_RESOLVED_ENDPOINTS} addresses, "
                    "exceeding the configured safety limit"
                )

        if not endpoints:
            raise ResolutionError("target has no usable IPv4 or IPv6 address")
        if len(scopes) != 1:
            raise ResolutionError("target resolves to a mixed local/public address set")
        if AddressScope.PUBLIC in scopes and not config.allow_public_target:
            raise ResolutionError(
                "target resolves to a public address; pass --allow-public-target only with "
                "explicit authorization"
            )
        return tuple(sorted(endpoints.values(), key=_endpoint_sort_key))


def _classify_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> AddressScope:
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ResolutionError(f"target resolved to a prohibited address: {address}")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _classify_address(address.ipv4_mapped)
    if address.is_loopback or _is_explicitly_private(address):
        return AddressScope.LOCAL
    if address.is_global:
        return AddressScope.PUBLIC
    raise ResolutionError(f"target resolved to an unsupported reserved address: {address}")


def _is_explicitly_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in _IPV4_PRIVATE_NETWORKS)
    return address in _IPV6_PRIVATE_NETWORK


def _endpoint_sort_key(endpoint: ResolvedEndpoint) -> tuple[int, str, int]:
    return (endpoint.ip_version, endpoint.address, endpoint.scope_id)
