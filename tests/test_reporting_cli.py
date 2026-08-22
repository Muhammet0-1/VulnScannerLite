from __future__ import annotations

import json
import socket

import pytest

from vulnscanner_lite import cli
from vulnscanner_lite.models import AuditReport, Finding, ResolvedEndpoint, Severity
from vulnscanner_lite.reporting import render_report

ENDPOINT = ResolvedEndpoint(socket.AddressFamily.AF_INET, "127.0.0.1")


def report(*findings: Finding) -> AuditReport:
    return AuditReport(
        target_url="https://local.test/",
        final_url="https://local.test/",
        started_at="2026-08-22T12:00:00+00:00",
        duration_seconds=0.125,
        status=200,
        endpoints=(ENDPOINT,),
        selected_endpoint=ENDPOINT,
        request_count=1,
        active_reflection=False,
        findings=findings,
    )


FINDING = Finding(
    "header.example",
    Severity.LOW,
    "Example observation",
    "Observed safely.",
    "Review it.",
    "name=value",
)


def test_json_report_has_schema_and_counts() -> None:
    data = json.loads(render_report(report(FINDING), "json"))
    assert data["schema_version"] == 1
    assert data["counts"] == {"info": 0, "low": 1, "medium": 0}
    assert data["selected_endpoint"]["address"] == "127.0.0.1"


def test_jsonl_report_is_one_record_per_line() -> None:
    records = [json.loads(line) for line in render_report(report(FINDING), "jsonl").splitlines()]
    assert [record["type"] for record in records] == ["audit", "finding", "summary"]


def test_text_report_is_plain_and_contains_recommendation() -> None:
    text = render_report(report(FINDING), "text")
    assert "[LOW] Example observation" in text
    assert "Recommendation: Review it." in text
    assert "\x1b" not in text


def test_text_report_neutralizes_control_sequences_and_line_injection() -> None:
    unsafe = Finding(
        "header.example\nforged",
        Severity.LOW,
        "Title\x1b[31m",
        "line one\nline two",
        "review\rnow",
        "evidence\x00value",
    )
    text = render_report(report(unsafe), "text")
    assert "\x1b" not in text
    assert "\x00" not in text
    assert "line one line two" in text
    assert "header.example forged" in text


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_machine_reports_reject_non_finite_numbers(output_format: str) -> None:
    unsafe = report()
    object.__setattr__(unsafe, "duration_seconds", float("nan"))
    with pytest.raises(ValueError, match="JSON compliant"):
        render_report(unsafe, output_format)


def test_unknown_report_format_is_rejected() -> None:
    with pytest.raises(ValueError):
        render_report(report(), "xml")


class FakeAuditor:
    current_report = report()

    def run(self, _config: object) -> AuditReport:
        return self.current_report


def test_cli_requires_authorization_acknowledgement() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["--url", "http://127.0.0.1"])
    assert error.value.code == 2


def test_cli_semantic_configuration_errors_use_exit_two() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "--url",
                "ftp://127.0.0.1",
                "--acknowledge-authorization",
            ]
        )
    assert error.value.code == 2


def test_cli_outputs_json_and_returns_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "Auditor", FakeAuditor)
    result = cli.main(
        [
            "--url",
            "http://127.0.0.1",
            "--acknowledge-authorization",
            "--format",
            "json",
        ]
    )
    assert result == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1


def test_cli_fail_on_threshold_returns_three(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Auditor", FakeAuditor)
    FakeAuditor.current_report = report(FINDING)
    try:
        assert (
            cli.main(
                [
                    "--url",
                    "http://127.0.0.1",
                    "--acknowledge-authorization",
                    "--fail-on",
                    "low",
                ]
            )
            == 3
        )
    finally:
        FakeAuditor.current_report = report()


def test_cli_converts_domain_errors_to_exit_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FailingAuditor:
        def run(self, _config: object) -> AuditReport:
            from vulnscanner_lite.errors import ResolutionError

            raise ResolutionError("offline")

    monkeypatch.setattr(cli, "Auditor", FailingAuditor)
    assert cli.main(["--url", "http://127.0.0.1", "--acknowledge-authorization"]) == 1
    assert "error: offline" in capsys.readouterr().err
