"""Pinned, proxy-free HTTP transport with verified TLS and bounded bodies."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Callable
from typing import Any

from .config import AuditConfig, TargetURL
from .errors import ConfigurationError, TransportError
from .models import HTTPResponseData, ResolvedEndpoint

USER_AGENT = "VulnScannerLite/1.0 (+https://github.com/Muhammet0-1/VulnScannerLite)"


class _DeadlineSocket(socket.socket):
    """Refresh the socket timeout against one absolute request deadline."""

    _vsl_deadline: float

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        _refresh_deadline(self)
        return super().recv_into(buffer, nbytes, flags)


class _DeadlineSSLSocket(ssl.SSLSocket):
    """TLS socket variant that preserves the absolute body/header deadline."""

    _vsl_deadline: float

    def recv_into(self, buffer: Any, nbytes: int | None = None, flags: int = 0) -> int:
        _refresh_deadline(self)
        return super().recv_into(buffer, nbytes, flags)


def _refresh_deadline(client: socket.socket) -> None:
    deadline = getattr(client, "_vsl_deadline", None)
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTP request deadline exceeded")
    client.settimeout(remaining)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: TargetURL, endpoint: ResolvedEndpoint, timeout: float) -> None:
        super().__init__(host=target.hostname, port=target.port, timeout=timeout)
        self._endpoint = endpoint

    def _open_pinned_socket(self) -> _DeadlineSocket:
        client = _DeadlineSocket(int(self._endpoint.family), socket.SOCK_STREAM)
        try:
            if self.timeout is None:
                raise ConfigurationError("pinned connection requires a finite timeout")
            client._vsl_deadline = time.monotonic() + self.timeout
            _refresh_deadline(client)
            client.connect(self._endpoint.socket_address(self.port))
        except BaseException:
            client.close()
            raise
        return client

    def connect(self) -> None:
        self.sock = self._open_pinned_socket()


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def __init__(
        self,
        target: TargetURL,
        endpoint: ResolvedEndpoint,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(target, endpoint, timeout)
        self._context = context

    def connect(self) -> None:
        client = self._open_pinned_socket()
        wrapped: ssl.SSLSocket | None = None
        try:
            deadline = client._vsl_deadline
            wrapped = self._context.wrap_socket(
                client,
                server_hostname=self.host,
                do_handshake_on_connect=False,
            )
            wrapped._vsl_deadline = deadline  # type: ignore[attr-defined]
            _refresh_deadline(wrapped)
            wrapped.do_handshake()
            self.sock = wrapped
        except BaseException:
            (wrapped or client).close()
            raise


ConnectionFactory = Callable[
    [TargetURL, ResolvedEndpoint, float, ssl.SSLContext], http.client.HTTPConnection
]


class HTTPTransport:
    """Issue one GET to an already resolved endpoint without environment proxies."""

    def __init__(
        self,
        connection_factory: ConnectionFactory | None = None,
        ssl_context: ssl.SSLContext | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connection_factory = (
            connection_factory if connection_factory is not None else _default_connection_factory
        )
        self._ssl_context = ssl_context if ssl_context is not None else ssl.create_default_context()
        if (
            self._ssl_context.verify_mode != ssl.CERT_REQUIRED
            or not self._ssl_context.check_hostname
        ):
            raise ConfigurationError(
                "TLS context must require certificates and enable hostname verification"
            )
        self._ssl_context.sslsocket_class = _DeadlineSSLSocket
        self._monotonic = monotonic

    def fetch(
        self,
        target: TargetURL,
        endpoint: ResolvedEndpoint,
        config: AuditConfig,
    ) -> HTTPResponseData:
        started = self._monotonic()
        connection = self._connection_factory(
            target,
            endpoint,
            float(config.timeout),
            self._ssl_context,
        )
        try:
            connection.putrequest(
                "GET", target.request_target, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", target.host_header)
            connection.putheader("User-Agent", USER_AGENT)
            connection.putheader("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
            connection.putheader("Accept-Encoding", "identity")
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()
            body = response.read(config.max_body_bytes + 1)
            truncated = len(body) > config.max_body_bytes
            if truncated:
                body = body[: config.max_body_bytes]
            return HTTPResponseData(
                url=target.url,
                status=response.status,
                reason=str(response.reason or ""),
                headers=tuple((str(key), str(value)) for key, value in response.getheaders()),
                body=body,
                truncated=truncated,
                elapsed_ms=max(0.0, (self._monotonic() - started) * 1_000.0),
            )
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            raise TransportError(
                f"HTTP request failed for the pinned endpoint ({type(exc).__name__})"
            ) from exc
        finally:
            connection.close()


def _default_connection_factory(
    target: TargetURL,
    endpoint: ResolvedEndpoint,
    timeout: float,
    context: ssl.SSLContext,
) -> http.client.HTTPConnection:
    if target.scheme == "https":
        return _PinnedHTTPSConnection(target, endpoint, timeout, context)
    return _PinnedHTTPConnection(target, endpoint, timeout)
