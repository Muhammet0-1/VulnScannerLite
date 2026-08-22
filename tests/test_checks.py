from __future__ import annotations

from vulnscanner_lite.checks import audit_response
from vulnscanner_lite.config import parse_target_url
from vulnscanner_lite.models import FormInfo, HTTPResponseData, Severity


def response(*headers: tuple[str, str], body: bytes = b"") -> HTTPResponseData:
    return HTTPResponseData("https://example.com/", 200, "OK", headers, body, False, 1.0)


def ids(findings: list[object]) -> set[str]:
    return {finding.check_id for finding in findings}  # type: ignore[attr-defined]


def test_hardened_headers_avoid_missing_header_findings() -> None:
    findings = audit_response(
        response(
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "geolocation=()"),
        ),
        parse_target_url("https://example.com"),
        (),
    )
    assert not any("missing" in finding.check_id for finding in findings)


def test_missing_headers_and_http_transport_are_observed() -> None:
    findings = audit_response(
        response(),
        parse_target_url("http://example.com"),
        (),
    )
    assert "transport.http" in ids(findings)
    assert "header.csp.missing" in ids(findings)
    assert "header.hsts.missing" not in ids(findings)


def test_cookie_attributes_are_checked_without_echoing_values() -> None:
    findings = audit_response(
        response(("Set-Cookie", "session=super-secret; Path=/")),
        parse_target_url("https://example.com"),
        (),
    )
    assert {"cookie.secure.session", "cookie.httponly.session", "cookie.samesite.session"} <= ids(
        findings
    )
    assert all("super-secret" not in (finding.evidence or "") for finding in findings)


def test_password_and_cross_origin_forms_are_reported() -> None:
    forms = (
        FormInfo(1, "https://other.example/login", "get", ("pw",), True),
        FormInfo(2, "javascript:alert(1)", "post", (), False),
    )
    findings = audit_response(response(), parse_target_url("http://example.com"), forms)
    assert "form.1.password-http" in ids(findings)
    assert "form.1.password-get" in ids(findings)
    assert "form.1.action.cross-origin" in ids(findings)
    assert "form.2.action.invalid" in ids(findings)


def test_cors_wildcard_is_not_misreported_as_credentialed_access() -> None:
    findings = audit_response(
        response(
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ),
        parse_target_url("https://example.com"),
        (),
    )
    cors = next(finding for finding in findings if finding.check_id == "header.cors.wildcard")
    assert cors.severity is Severity.INFO
