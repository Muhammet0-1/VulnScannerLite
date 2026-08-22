from __future__ import annotations

import socket
import ssl

import pytest

from vulnscanner_lite import transport as transport_module
from vulnscanner_lite.config import AuditConfig, parse_target_url
from vulnscanner_lite.errors import ConfigurationError, TransportError
from vulnscanner_lite.htmlforms import MAX_FORMS, extract_forms
from vulnscanner_lite.models import ResolvedEndpoint
from vulnscanner_lite.transport import USER_AGENT, HTTPTransport


class FakeResponse:
    status = 200
    reason = "OK"

    def __init__(self, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
        self._body = body
        self._headers = headers or []
        self.read_size = 0

    def read(self, size: int) -> bytes:
        self.read_size = size
        return self._body[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers


class FakeConnection:
    def __init__(self, response: FakeResponse, failure: BaseException | None = None) -> None:
        self.response = response
        self.failure = failure
        self.request: tuple[str, str, bool, bool] | None = None
        self.headers: list[tuple[str, str]] = []
        self.closed = False

    def putrequest(
        self, method: str, target: str, *, skip_host: bool, skip_accept_encoding: bool
    ) -> None:
        self.request = (method, target, skip_host, skip_accept_encoding)

    def putheader(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def endheaders(self) -> None:
        if self.failure:
            raise self.failure

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _endpoint() -> ResolvedEndpoint:
    return ResolvedEndpoint(socket.AddressFamily.AF_INET, "127.0.0.1")


def test_transport_sends_one_honest_bounded_get() -> None:
    response = FakeResponse(b"x" * 2048, [("Content-Type", "text/html")])
    connection = FakeConnection(response)
    times = iter((1.0, 1.025))
    transport = HTTPTransport(
        connection_factory=lambda *_args: connection,  # type: ignore[arg-type]
        monotonic=lambda: next(times),
    )
    config = AuditConfig(parse_target_url("http://localhost:8080/a?q=1"), max_body_bytes=1024)
    result = transport.fetch(config.target, _endpoint(), config)
    assert connection.request == ("GET", "/a?q=1", True, True)
    assert ("Host", "localhost:8080") in connection.headers
    assert ("User-Agent", USER_AGENT) in connection.headers
    assert ("Accept-Encoding", "identity") in connection.headers
    assert response.read_size == 1025
    assert len(result.body) == 1024
    assert result.truncated is True
    assert result.elapsed_ms == pytest.approx(25)
    assert connection.closed is True


def test_environment_proxies_cannot_change_direct_pinned_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://proxy.invalid:9999")
    connection = FakeConnection(FakeResponse(b"ok"))
    calls: list[tuple[object, ...]] = []

    def factory(*args: object) -> FakeConnection:
        calls.append(args)
        return connection

    transport = HTTPTransport(connection_factory=factory)  # type: ignore[arg-type]
    config = AuditConfig(parse_target_url("https://local.test"))
    transport.fetch(config.target, _endpoint(), config)
    assert calls[0][0] == config.target
    assert calls[0][1] == _endpoint()
    assert connection.request == ("GET", "/", True, True)


def test_transport_rejects_unverified_tls_context() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ConfigurationError, match="hostname verification"):
        HTTPTransport(ssl_context=context)


def test_absolute_request_deadline_shrinks_and_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimeoutRecorder:
        _vsl_deadline = 10.0
        timeout: float | None = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

    client = TimeoutRecorder()
    monkeypatch.setattr(transport_module.time, "monotonic", lambda: 9.25)
    transport_module._refresh_deadline(client)  # type: ignore[arg-type]
    assert client.timeout == pytest.approx(0.75)

    monkeypatch.setattr(transport_module.time, "monotonic", lambda: 10.0)
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        transport_module._refresh_deadline(client)  # type: ignore[arg-type]


def test_transport_closes_and_wraps_network_failures() -> None:
    connection = FakeConnection(FakeResponse(b""), OSError("offline"))
    transport = HTTPTransport(connection_factory=lambda *_args: connection)  # type: ignore[arg-type]
    config = AuditConfig(parse_target_url("http://localhost"))
    with pytest.raises(TransportError, match="pinned endpoint"):
        transport.fetch(config.target, _endpoint(), config)
    assert connection.closed is True


def test_extract_forms_reads_metadata_without_submission() -> None:
    forms = extract_forms(
        (
            b'<form action="/login" method="post"><input name="user">'
            b'<input type="password" name="pw"></form>'
        ),
        "text/html; charset=utf-8",
    )
    assert len(forms) == 1
    assert forms[0].action == "/login"
    assert forms[0].method == "post"
    assert forms[0].field_names == ("user", "pw")
    assert forms[0].has_password is True


def test_extract_forms_ignores_non_html_and_handles_unknown_charset() -> None:
    assert extract_forms(b"<form></form>", "application/json") == ()
    assert extract_forms(b"<form></form>", "text/plain; note=html") == ()
    assert len(extract_forms(b"<form></form>", "text/html; charset=does-not-exist")) == 1


def test_form_parser_caps_form_count() -> None:
    body = ("<form><input name='x'></form>" * (MAX_FORMS + 20)).encode()
    assert len(extract_forms(body, "text/html")) == MAX_FORMS
