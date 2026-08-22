"""Conservative passive checks that report observations, not exploit claims."""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from urllib.parse import urljoin

from .config import TargetURL, parse_target_url
from .errors import ConfigurationError
from .models import Finding, FormInfo, HTTPResponseData, Severity


def audit_response(
    response: HTTPResponseData,
    target: TargetURL,
    forms: tuple[FormInfo, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_transport_checks(response, target))
    findings.extend(_header_checks(response, target))
    findings.extend(_cookie_checks(response, target))
    findings.extend(_form_checks(forms, target))
    return findings


def _transport_checks(response: HTTPResponseData, target: TargetURL) -> list[Finding]:
    findings: list[Finding] = []
    if target.scheme == "http":
        findings.append(
            _finding(
                "transport.http",
                Severity.MEDIUM,
                "Unencrypted HTTP transport",
                (
                    "The audited page is served without TLS, so traffic can be observed or "
                    "modified in transit."
                ),
                "Serve the application over HTTPS and redirect HTTP requests to HTTPS.",
            )
        )
    if response.truncated:
        findings.append(
            _finding(
                "response.truncated",
                Severity.INFO,
                "Response body was truncated",
                "The response exceeded the configured body limit, so HTML analysis was partial.",
                "Increase --max-body-bytes only if the larger response is expected and authorized.",
            )
        )
    encoding = response.header("Content-Encoding")
    if encoding and encoding.lower() not in {"identity", "none"}:
        findings.append(
            _finding(
                "response.encoded",
                Severity.INFO,
                "Server ignored the identity encoding request",
                (
                    "The response body is encoded and was not decompressed, so HTML analysis "
                    "was skipped."
                ),
                (
                    "Review headers manually or configure the server to honor "
                    "Accept-Encoding: identity."
                ),
                evidence=_clean(encoding),
            )
        )
    return findings


def _header_checks(response: HTTPResponseData, target: TargetURL) -> list[Finding]:
    findings: list[Finding] = []
    csp = response.header("Content-Security-Policy")
    if not csp:
        findings.append(
            _finding(
                "header.csp.missing",
                Severity.LOW,
                "Content-Security-Policy header is missing",
                "No enforced CSP header was observed on the audited response.",
                "Deploy a restrictive, tested Content-Security-Policy response header.",
            )
        )
    if target.scheme == "https" and not response.header("Strict-Transport-Security"):
        findings.append(
            _finding(
                "header.hsts.missing",
                Severity.LOW,
                "Strict-Transport-Security header is missing",
                "The HTTPS response does not advertise an HSTS policy.",
                "Add HSTS after confirming that the domain and intended subdomains are HTTPS-only.",
            )
        )
    if not response.header("X-Content-Type-Options"):
        findings.append(
            _finding(
                "header.xcto.missing",
                Severity.LOW,
                "X-Content-Type-Options header is missing",
                "The response does not explicitly disable MIME sniffing.",
                "Set X-Content-Type-Options: nosniff.",
            )
        )
    frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    if not frame_ancestors and not response.header("X-Frame-Options"):
        findings.append(
            _finding(
                "header.framing.missing",
                Severity.LOW,
                "No framing restriction was observed",
                "Neither CSP frame-ancestors nor X-Frame-Options was present.",
                "Set CSP frame-ancestors; retain X-Frame-Options where legacy support is needed.",
            )
        )
    for name, check_id, title in (
        ("Referrer-Policy", "header.referrer-policy.missing", "Referrer-Policy is missing"),
        (
            "Permissions-Policy",
            "header.permissions-policy.missing",
            "Permissions-Policy is missing",
        ),
    ):
        if not response.header(name):
            findings.append(
                _finding(
                    check_id,
                    Severity.INFO,
                    title,
                    f"The audited response did not include {name}.",
                    f"Define an explicit {name} appropriate for the application.",
                )
            )

    allow_origin = response.header("Access-Control-Allow-Origin")
    if allow_origin is not None and allow_origin.strip() == "*":
        findings.append(
            _finding(
                "header.cors.wildcard",
                Severity.INFO,
                "Wildcard CORS policy observed",
                "Access-Control-Allow-Origin permits every origin on this response.",
                "Restrict allowed origins when cross-origin access is not intentionally public.",
                evidence="Access-Control-Allow-Origin: *",
            )
        )

    for name, check_id in (("Server", "header.server"), ("X-Powered-By", "header.powered-by")):
        value = response.header(name)
        if value:
            findings.append(
                _finding(
                    check_id,
                    Severity.INFO,
                    f"{name} disclosure observed",
                    f"The response exposes the {name} header.",
                    "Remove unnecessary technology disclosure where operationally practical.",
                    evidence=f"{name}: {_clean(value)}",
                )
            )
    return findings


def _cookie_checks(response: HTTPResponseData, target: TargetURL) -> list[Finding]:
    findings: list[Finding] = []
    for raw_cookie in response.headers_all("Set-Cookie")[:50]:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except CookieError:
            continue
        for name, morsel in cookie.items():
            safe_name = _clean(name, limit=64)
            if target.scheme == "https" and not morsel["secure"]:
                findings.append(
                    _finding(
                        f"cookie.secure.{safe_name}",
                        Severity.LOW,
                        "Cookie lacks the Secure attribute",
                        "A cookie set over HTTPS was not marked Secure.",
                        "Mark security-sensitive cookies Secure.",
                        evidence=f"cookie={safe_name}",
                    )
                )
            if not morsel["httponly"]:
                findings.append(
                    _finding(
                        f"cookie.httponly.{safe_name}",
                        Severity.LOW,
                        "Cookie lacks the HttpOnly attribute",
                        "A response cookie is accessible to client-side scripts.",
                        "Mark cookies HttpOnly unless client-side access is explicitly required.",
                        evidence=f"cookie={safe_name}",
                    )
                )
            if not morsel["samesite"]:
                findings.append(
                    _finding(
                        f"cookie.samesite.{safe_name}",
                        Severity.INFO,
                        "Cookie has no explicit SameSite policy",
                        "A response cookie does not declare SameSite.",
                        "Choose Lax, Strict, or None according to the intended cross-site flow.",
                        evidence=f"cookie={safe_name}",
                    )
                )
    return findings


def _form_checks(forms: tuple[FormInfo, ...], target: TargetURL) -> list[Finding]:
    findings: list[Finding] = []
    for form in forms:
        prefix = f"form.{form.index}"
        if form.has_password and target.scheme == "http":
            findings.append(
                _finding(
                    f"{prefix}.password-http",
                    Severity.MEDIUM,
                    "Password form is served over HTTP",
                    "A password input was observed on an unencrypted page.",
                    "Serve the page and submission endpoint exclusively over HTTPS.",
                )
            )
        if form.has_password and form.method == "get":
            findings.append(
                _finding(
                    f"{prefix}.password-get",
                    Severity.MEDIUM,
                    "Password form uses GET",
                    (
                        "Password values submitted with GET can appear in URLs, logs, and "
                        "browser history."
                    ),
                    "Submit credentials with POST over HTTPS.",
                )
            )
        if form.method == "other":
            findings.append(
                _finding(
                    f"{prefix}.method",
                    Severity.INFO,
                    "Form uses an unrecognized method",
                    "The form method was neither GET nor POST.",
                    "Confirm that the form method is intentional and supported.",
                )
            )
        action = form.action or target.url
        try:
            destination = parse_target_url(urljoin(target.url, action))
        except ConfigurationError:
            findings.append(
                _finding(
                    f"{prefix}.action.invalid",
                    Severity.LOW,
                    "Form action is not a valid HTTP(S) URL",
                    "The form action could not be interpreted as a safe HTTP(S) destination.",
                    "Review the form action and remove script or non-HTTP destinations.",
                )
            )
        else:
            if not target.same_origin(destination):
                findings.append(
                    _finding(
                        f"{prefix}.action.cross-origin",
                        Severity.LOW,
                        "Form submits to a different origin",
                        "The form action points outside the audited origin.",
                        "Verify that the cross-origin submission is intended and trusted.",
                        evidence=f"destination_origin={_clean(destination.origin)}",
                    )
                )
    return findings


def _finding(
    check_id: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    evidence: str | None = None,
) -> Finding:
    return Finding(check_id, severity, title, description, recommendation, evidence)


def _clean(value: str, limit: int = 200) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit]
