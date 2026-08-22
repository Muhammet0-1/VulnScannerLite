"""Bounded audit orchestration with same-origin redirect handling."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin

from .checks import audit_response
from .config import AuditConfig, TargetURL, parse_target_url
from .errors import AuditError, ConfigurationError
from .htmlforms import extract_forms
from .models import AuditReport, Finding, FormInfo, HTTPResponseData, ResolvedEndpoint, Severity
from .resolution import TargetResolver
from .transport import HTTPTransport

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class Auditor:
    """Run one conservative audit against a DNS-pinned endpoint."""

    def __init__(
        self,
        *,
        resolver: TargetResolver | None = None,
        transport: HTTPTransport | None = None,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._resolver = resolver if resolver is not None else TargetResolver()
        self._transport = transport if transport is not None else HTTPTransport()
        self._wall_clock = (
            wall_clock if wall_clock is not None else (lambda: datetime.now(timezone.utc))
        )
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._token_factory = (
            token_factory if token_factory is not None else (lambda: secrets.token_urlsafe(18))
        )

    def run(self, config: AuditConfig) -> AuditReport:
        started_at = self._wall_clock().astimezone(timezone.utc).isoformat()
        started = self._monotonic()
        reflection_token = self._new_reflection_token() if config.active_reflection else None
        endpoints = self._resolver.resolve(config)
        selected = endpoints[0]

        response, final_target, redirect_findings, request_count = self._follow_redirects(
            config.target, selected, config
        )
        content_encoding = response.header("Content-Encoding")
        forms: tuple[FormInfo, ...] = ()
        if not content_encoding or content_encoding.lower() in {"identity", "none"}:
            forms = extract_forms(response.body, response.header("Content-Type"))

        findings = audit_response(response, final_target, forms)
        findings.extend(redirect_findings)

        if config.active_reflection:
            assert reflection_token is not None
            reflection_findings, reflection_requests = self._check_reflection(
                final_target, selected, config, reflection_token
            )
            findings.extend(reflection_findings)
            request_count += reflection_requests

        findings.sort(key=lambda item: (-item.severity.rank, item.check_id))
        return AuditReport(
            target_url=config.target.url,
            final_url=final_target.url,
            started_at=started_at,
            duration_seconds=max(0.0, self._monotonic() - started),
            status=response.status,
            endpoints=endpoints,
            selected_endpoint=selected,
            request_count=request_count,
            active_reflection=config.active_reflection,
            findings=tuple(findings),
        )

    def _follow_redirects(
        self,
        target: TargetURL,
        endpoint: ResolvedEndpoint,
        config: AuditConfig,
    ) -> tuple[HTTPResponseData, TargetURL, list[Finding], int]:
        current = target
        findings: list[Finding] = []
        request_count = 0

        while True:
            response = self._transport.fetch(current, endpoint, config)
            request_count += 1
            location = response.header("Location")
            if response.status not in REDIRECT_STATUSES or not location:
                return response, current, findings, request_count

            if request_count > config.max_redirects:
                findings.append(
                    _redirect_finding(
                        "redirect.limit",
                        Severity.INFO,
                        "Redirect limit reached",
                        "The response requested another redirect after the configured limit.",
                        "Review the redirect chain or increase the bounded limit if authorized.",
                    )
                )
                return response, current, findings, request_count

            try:
                destination = parse_target_url(urljoin(current.url, location))
            except ConfigurationError:
                findings.append(
                    _redirect_finding(
                        "redirect.invalid",
                        Severity.LOW,
                        "Invalid redirect destination blocked",
                        "The Location header was not a valid absolute or relative HTTP(S) URL.",
                        "Correct or remove the invalid redirect target.",
                    )
                )
                return response, current, findings, request_count

            if not config.target.same_origin(destination):
                findings.append(
                    _redirect_finding(
                        "redirect.cross-origin",
                        Severity.LOW,
                        "Cross-origin redirect was not followed",
                        "The audit stopped before contacting a different origin.",
                        "Audit the destination separately after confirming authorization.",
                        evidence=f"destination_origin={destination.origin}",
                    )
                )
                return response, current, findings, request_count
            current = destination

    def _check_reflection(
        self,
        target: TargetURL,
        endpoint: ResolvedEndpoint,
        config: AuditConfig,
        token: str,
    ) -> tuple[list[Finding], int]:
        query = parse_qsl(target.query, keep_blank_values=True)
        query.append(("vsl_probe", token))
        try:
            probe_target = parse_target_url(
                TargetURL(
                    target.scheme,
                    target.hostname,
                    target.port,
                    target.path,
                    urlencode(query),
                ).url
            )
        except ConfigurationError:
            return [
                Finding(
                    check_id="reflection.skipped-url-limit",
                    severity=Severity.INFO,
                    title="Reflection canary was not sent",
                    description=(
                        "Adding the inert query canary would have exceeded the URL safety limit."
                    ),
                    recommendation="Shorten the target URL before retrying the optional check.",
                )
            ], 0

        response = self._transport.fetch(probe_target, endpoint, config)
        findings: list[Finding] = []
        if token.encode("ascii") in response.body:
            findings.append(
                Finding(
                    check_id="reflection.query-canary",
                    severity=Severity.INFO,
                    title="Inert query canary was reflected",
                    description=(
                        "A random plain-text token appeared in the response body. Reflection alone "
                        "does not demonstrate XSS or another vulnerability."
                    ),
                    recommendation=(
                        "Review the output context and encoding manually; do not treat this result "
                        "as exploit proof."
                    ),
                    evidence="parameter=vsl_probe; payload=inert-random-token",
                )
            )
        return findings, 1

    def _new_reflection_token(self) -> str:
        raw_token = self._token_factory()
        if (
            not isinstance(raw_token, str)
            or not 1 <= len(raw_token) <= 64
            or not raw_token.isascii()
            or not all(character.isalnum() or character in "-_" for character in raw_token)
        ):
            raise AuditError("reflection token factory returned a non-inert token")
        return f"vsl-{raw_token}"


def _redirect_finding(
    check_id: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    evidence: str | None = None,
) -> Finding:
    return Finding(check_id, severity, title, description, recommendation, evidence)
