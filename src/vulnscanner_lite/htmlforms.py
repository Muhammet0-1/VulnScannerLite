"""Bounded passive HTML form extraction; forms are never submitted."""

from __future__ import annotations

from html.parser import HTMLParser

from .models import FormInfo

MAX_FORMS = 100
MAX_FIELDS = 1_000


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[FormInfo] = []
        self._current_action = ""
        self._current_method = "get"
        self._current_names: list[str] = []
        self._current_has_password = False
        self._inside_form = False
        self._field_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "form" and not self._inside_form and len(self.forms) < MAX_FORMS:
            self._inside_form = True
            self._current_action = attributes.get("action", "")
            method = attributes.get("method", "get").lower()
            self._current_method = method if method in {"get", "post"} else "other"
            self._current_names = []
            self._current_has_password = False
            return
        if not self._inside_form or self._field_count >= MAX_FIELDS:
            return
        if tag.lower() in {"input", "textarea", "select"}:
            self._field_count += 1
            name = attributes.get("name", "")
            if name:
                self._current_names.append(name[:128])
            if tag.lower() == "input" and attributes.get("type", "text").lower() == "password":
                self._current_has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or not self._inside_form:
            return
        self.forms.append(
            FormInfo(
                index=len(self.forms) + 1,
                action=self._current_action[:2_048],
                method=self._current_method,
                field_names=tuple(self._current_names),
                has_password=self._current_has_password,
            )
        )
        self._inside_form = False

    def close(self) -> None:
        super().close()
        if self._inside_form and len(self.forms) < MAX_FORMS:
            self.handle_endtag("form")


def extract_forms(body: bytes, content_type: str | None) -> tuple[FormInfo, ...]:
    """Decode only declared HTML responses and cap parser input at the transport body limit."""

    if content_type is None:
        return ()
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type not in {"text/html", "application/xhtml+xml"}:
        return ()
    charset = _charset_from_content_type(content_type)
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    parser = _FormParser()
    parser.feed(text)
    parser.close()
    return tuple(parser.forms)


def _charset_from_content_type(content_type: str) -> str:
    for item in content_type.split(";")[1:]:
        name, separator, value = item.strip().partition("=")
        if separator and name.lower() == "charset":
            return value.strip(" \"'") or "utf-8"
    return "utf-8"
