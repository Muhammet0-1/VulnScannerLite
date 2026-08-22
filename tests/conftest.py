from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import NoReturn

import pytest

from vulnscanner_lite import transport as transport_module


@pytest.fixture(autouse=True)
def deny_real_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail every test that accidentally attempts real DNS or socket I/O."""

    def blocked(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("tests must not perform real DNS or network I/O")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(transport_module, "_DeadlineSocket", blocked)
    yield
