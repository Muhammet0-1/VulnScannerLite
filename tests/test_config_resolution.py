from __future__ import annotations

import socket

import pytest

from vulnscanner_lite.config import AuditConfig, TargetURL, parse_target_url
from vulnscanner_lite.errors import ConfigurationError, ResolutionError
from vulnscanner_lite.resolution import TargetResolver


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM", "https://example.com/"),
        ("http://127.0.0.1:8080/a%20b?q=x", "http://127.0.0.1:8080/a%20b?q=x"),
        ("https://[::1]/", "https://[::1]/"),
        ("https://bücher.example/", "https://xn--bcher-kva.example/"),
    ],
)
def test_parse_target_url_normalizes_valid_inputs(raw: str, expected: str) -> None:
    assert parse_target_url(raw).url == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " https://example.com",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com:99999",
        "https://example.com:0",
        "https://example.com:",
        "https://-bad.example",
        "https://example.com/\n",
    ],
)
def test_parse_target_url_rejects_ambiguous_inputs(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_target_url(raw)


def test_target_url_helpers_cover_ports_queries_and_origins() -> None:
    target = parse_target_url("https://example.com:8443/a?b=c")
    assert target.host_header == "example.com:8443"
    assert target.origin == "https://example.com:8443"
    assert target.request_target == "/a?b=c"
    assert target.same_origin(parse_target_url("https://example.com:8443/other"))
    assert not target.same_origin(parse_target_url("https://example.com/other"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": float("nan")},
        {"timeout": 0.01},
        {"timeout": 31},
        {"max_body_bytes": True},
        {"max_body_bytes": 1023},
        {"max_body_bytes": 5_242_881},
        {"max_redirects": -1},
        {"max_redirects": 6},
        {"allow_public_target": "false"},
        {"active_reflection": "false"},
    ],
)
def test_audit_config_rejects_invalid_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        AuditConfig(parse_target_url("http://127.0.0.1"), **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "target",
    [
        TargetURL("file", "127.0.0.1", 80, "/"),
        TargetURL("http", "LOCAL.TEST", 80, "/"),
        TargetURL("http", "local.test", 0, "/"),
        TargetURL("http", "local.test", 80, ""),
    ],
)
def test_audit_config_rejects_direct_noncanonical_target_construction(
    target: TargetURL,
) -> None:
    with pytest.raises(ConfigurationError, match="canonical TargetURL"):
        AuditConfig(target)


def _resolver(*addresses: str) -> TargetResolver:
    records = []
    for address in addresses:
        if ":" in address:
            records.append(
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 80, 0, 0))
            )
        else:
            records.append(
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 80))
            )
    return TargetResolver(lambda *_args, **_kwargs: records)


def test_resolver_accepts_deduplicated_local_addresses() -> None:
    config = AuditConfig(parse_target_url("http://local.test"))
    endpoints = _resolver("127.0.0.1", "127.0.0.1", "::1").resolve(config)
    assert [endpoint.address for endpoint in endpoints] == ["127.0.0.1", "::1"]


def test_resolver_requires_explicit_public_target_flag() -> None:
    resolver = _resolver("8.8.8.8")
    with pytest.raises(ResolutionError, match="public"):
        resolver.resolve(AuditConfig(parse_target_url("https://authorized.example")))
    endpoints = resolver.resolve(
        AuditConfig(parse_target_url("https://authorized.example"), allow_public_target=True)
    )
    assert endpoints[0].address == "8.8.8.8"


@pytest.mark.parametrize("address", ["0.0.0.0", "224.0.0.1", "169.254.1.1", "fe80::1"])
def test_resolver_rejects_prohibited_addresses(address: str) -> None:
    with pytest.raises(ResolutionError, match="prohibited"):
        _resolver(address).resolve(AuditConfig(parse_target_url("http://local.test")))


def test_resolver_rejects_mixed_local_public_answers() -> None:
    config = AuditConfig(parse_target_url("http://mixed.test"), allow_public_target=True)
    with pytest.raises(ResolutionError, match="mixed"):
        _resolver("127.0.0.1", "8.8.8.8").resolve(config)


def test_resolver_caps_the_address_set() -> None:
    addresses = tuple(f"10.0.0.{index}" for index in range(1, 10))
    with pytest.raises(ResolutionError, match="exceeding"):
        _resolver(*addresses).resolve(AuditConfig(parse_target_url("http://local.test")))


def test_resolver_stops_consuming_records_at_the_address_limit() -> None:
    yielded = 0

    def records() -> object:
        nonlocal yielded
        for index in range(1, 100):
            yielded += 1
            yield (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (f"10.0.0.{index}", 80),
            )

    resolver = TargetResolver(lambda *_args, **_kwargs: records())
    with pytest.raises(ResolutionError, match="exceeding"):
        resolver.resolve(AuditConfig(parse_target_url("http://local.test")))
    assert yielded == 9


@pytest.mark.parametrize(
    "address",
    ["192.0.2.1", "2001:db8::1", "2002:0808:0808::1", "2001::1"],
)
def test_resolver_does_not_treat_reserved_or_transition_ranges_as_local(
    address: str,
) -> None:
    with pytest.raises(ResolutionError, match="unsupported reserved"):
        _resolver(address).resolve(AuditConfig(parse_target_url("http://local.test")))


def test_resolver_classifies_ipv4_mapped_addresses_by_embedded_address() -> None:
    local = _resolver("::ffff:10.0.0.1").resolve(AuditConfig(parse_target_url("http://local.test")))
    assert local[0].address == "::ffff:10.0.0.1"

    with pytest.raises(ResolutionError, match="public"):
        _resolver("::ffff:8.8.8.8").resolve(AuditConfig(parse_target_url("http://public.test")))


def test_default_resolver_is_blocked_from_real_dns_by_test_guard() -> None:
    with pytest.raises(AssertionError, match="must not perform real DNS"):
        TargetResolver().resolve(AuditConfig(parse_target_url("http://local.test")))


def test_resolver_wraps_lookup_errors() -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise socket.gaierror("nope")

    with pytest.raises(ResolutionError, match="could not be resolved"):
        TargetResolver(fail).resolve(AuditConfig(parse_target_url("http://local.test")))


def test_resolver_rejects_address_family_mismatch() -> None:
    records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 80))]
    with pytest.raises(ResolutionError, match="invalid address record"):
        TargetResolver(lambda *_args, **_kwargs: records).resolve(
            AuditConfig(parse_target_url("http://local.test"))
        )
