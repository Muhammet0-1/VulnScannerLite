from __future__ import annotations

import socket
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from vulnscanner_lite.config import AuditConfig, parse_target_url
from vulnscanner_lite.errors import AuditError
from vulnscanner_lite.models import HTTPResponseData, ResolvedEndpoint
from vulnscanner_lite.scanner import Auditor

ENDPOINT = ResolvedEndpoint(socket.AddressFamily.AF_INET, "127.0.0.1")


class FakeResolver:
    def resolve(self, _config: AuditConfig) -> tuple[ResolvedEndpoint, ...]:
        return (ENDPOINT,)


class FakeTransport:
    def __init__(self, responses: list[HTTPResponseData]) -> None:
        self.responses = responses
        self.targets = []

    def fetch(
        self, target: object, endpoint: ResolvedEndpoint, _config: AuditConfig
    ) -> HTTPResponseData:
        self.targets.append(target)
        assert endpoint == ENDPOINT
        return self.responses.pop(0)


def http_response(
    *,
    url: str = "https://local.test/",
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<p>ok</p>",
) -> HTTPResponseData:
    return HTTPResponseData(url, status, "OK", headers, body, False, 1.0)


def auditor(transport: FakeTransport) -> Auditor:
    times = iter((10.0, 10.5))
    return Auditor(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        transport=transport,  # type: ignore[arg-type]
        wall_clock=lambda: datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc),
        monotonic=lambda: next(times),
        token_factory=lambda: "fixed-token",
    )


def test_audit_report_is_stable_and_uses_pinned_endpoint() -> None:
    transport = FakeTransport([http_response()])
    report = auditor(transport).run(AuditConfig(parse_target_url("https://local.test")))
    assert report.target_url == "https://local.test/"
    assert report.final_url == "https://local.test/"
    assert report.selected_endpoint == ENDPOINT
    assert report.request_count == 1
    assert report.duration_seconds == 0.5
    assert [finding.severity.rank for finding in report.findings] == sorted(
        (finding.severity.rank for finding in report.findings), reverse=True
    )


def test_same_origin_redirect_is_followed() -> None:
    transport = FakeTransport(
        [
            http_response(status=302, headers=(("Location", "/next"),)),
            http_response(url="https://local.test/next"),
        ]
    )
    report = auditor(transport).run(AuditConfig(parse_target_url("https://local.test")))
    assert report.final_url == "https://local.test/next"
    assert report.request_count == 2
    assert len(transport.targets) == 2


def test_cross_origin_redirect_is_blocked_without_second_request() -> None:
    transport = FakeTransport(
        [http_response(status=302, headers=(("Location", "https://other.test/"),))]
    )
    report = auditor(transport).run(AuditConfig(parse_target_url("https://local.test")))
    assert report.request_count == 1
    assert any(finding.check_id == "redirect.cross-origin" for finding in report.findings)


def test_redirect_limit_zero_blocks_the_first_redirect() -> None:
    transport = FakeTransport([http_response(status=302, headers=(("Location", "/next"),))])
    report = auditor(transport).run(
        AuditConfig(parse_target_url("https://local.test"), max_redirects=0)
    )
    assert report.request_count == 1
    assert any(finding.check_id == "redirect.limit" for finding in report.findings)


def test_redirect_limit_counts_redirects_not_the_initial_request() -> None:
    transport = FakeTransport(
        [
            http_response(status=302, headers=(("Location", "/one"),)),
            http_response(status=302, headers=(("Location", "/two"),)),
            http_response(status=302, headers=(("Location", "/three"),)),
        ]
    )
    report = auditor(transport).run(
        AuditConfig(parse_target_url("https://local.test"), max_redirects=2)
    )
    assert report.request_count == 3
    assert report.final_url == "https://local.test/two"
    assert any(finding.check_id == "redirect.limit" for finding in report.findings)


def test_active_reflection_uses_only_an_inert_get_query_token() -> None:
    transport = FakeTransport(
        [
            http_response(),
            http_response(body=b"echo vsl-fixed-token"),
        ]
    )
    report = auditor(transport).run(
        AuditConfig(parse_target_url("https://local.test/search?q=hello"), active_reflection=True)
    )
    probe = transport.targets[1]
    query = parse_qs(urlsplit(probe.url).query)  # type: ignore[attr-defined]
    assert query == {"q": ["hello"], "vsl_probe": ["vsl-fixed-token"]}
    assert "script" not in probe.url.lower()  # type: ignore[attr-defined]
    assert "select" not in probe.url.lower()  # type: ignore[attr-defined]
    assert report.request_count == 2
    reflection = next(
        finding for finding in report.findings if finding.check_id == "reflection.query-canary"
    )
    assert "does not demonstrate XSS" in reflection.description


def test_active_reflection_does_not_claim_a_finding_without_echo() -> None:
    transport = FakeTransport([http_response(), http_response(body=b"not reflected")])
    report = auditor(transport).run(
        AuditConfig(parse_target_url("https://local.test"), active_reflection=True)
    )
    assert not any(finding.check_id == "reflection.query-canary" for finding in report.findings)


def test_active_reflection_never_follows_a_probe_redirect() -> None:
    transport = FakeTransport(
        [
            http_response(),
            http_response(status=302, headers=(("Location", "/probe-destination"),)),
        ]
    )
    report = auditor(transport).run(
        AuditConfig(parse_target_url("https://local.test"), active_reflection=True)
    )
    assert report.request_count == 2
    assert len(transport.targets) == 2


def test_active_reflection_rejects_non_inert_injected_token_before_any_request() -> None:
    transport = FakeTransport([http_response()])
    instance = Auditor(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        transport=transport,  # type: ignore[arg-type]
        token_factory=lambda: "not inert!",
    )
    with pytest.raises(AuditError, match="non-inert"):
        instance.run(AuditConfig(parse_target_url("https://local.test"), active_reflection=True))
    assert transport.targets == []


def test_encoded_html_is_not_parsed_for_forms() -> None:
    transport = FakeTransport(
        [
            http_response(
                headers=(("Content-Type", "text/html"), ("Content-Encoding", "gzip")),
                body=b'<form method="get"><input type="password"></form>',
            )
        ]
    )
    report = auditor(transport).run(AuditConfig(parse_target_url("https://local.test")))
    assert not any(finding.check_id.startswith("form.") for finding in report.findings)
    assert any(finding.check_id == "response.encoded" for finding in report.findings)
