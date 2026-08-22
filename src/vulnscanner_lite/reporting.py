"""Stable text and machine-readable report formatting."""

from __future__ import annotations

import json

from .models import AuditReport


def render_report(report: AuditReport, output_format: str) -> str:
    if output_format == "text":
        return _render_text(report)
    if output_format == "json":
        return (
            json.dumps(
                report.to_dict(),
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    if output_format == "jsonl":
        return _render_jsonl(report)
    raise ValueError(f"unsupported output format: {output_format}")


def _render_text(report: AuditReport) -> str:
    counts = report.counts
    lines = [
        "VulnScannerLite HTTP Security Posture Report",
        f"Target: {_safe_text(report.target_url)}",
        f"Final URL: {_safe_text(report.final_url)}",
        f"HTTP status: {report.status}",
        f"Pinned endpoint: {_safe_text(report.selected_endpoint.address)}",
        f"Requests: {report.request_count}",
        f"Findings: medium={counts['medium']} low={counts['low']} info={counts['info']}",
        "",
    ]
    if not report.findings:
        lines.append("No configured observations were reported.")
    for finding in report.findings:
        lines.extend(
            [
                f"[{finding.severity.value.upper()}] {_safe_text(finding.title)} "
                f"({_safe_text(finding.check_id)})",
                f"  Observation: {_safe_text(finding.description)}",
                f"  Recommendation: {_safe_text(finding.recommendation)}",
            ]
        )
        if finding.evidence:
            lines.append(f"  Evidence: {_safe_text(finding.evidence)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_jsonl(report: AuditReport) -> str:
    base = {
        "schema_version": 1,
        "target_url": report.target_url,
        "final_url": report.final_url,
        "started_at": report.started_at,
        "duration_seconds": round(report.duration_seconds, 3),
        "endpoints": [endpoint.to_dict() for endpoint in report.endpoints],
    }
    records: list[dict[str, object]] = [{"type": "audit", **base}]
    records.extend({"type": "finding", **finding.to_dict()} for finding in report.findings)
    records.append(
        {
            "type": "summary",
            "status": report.status,
            "request_count": report.request_count,
            "active_reflection": report.active_reflection,
            "counts": report.counts,
            "selected_endpoint": report.selected_endpoint.to_dict(),
        }
    )
    return "".join(
        json.dumps(record, allow_nan=False, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )


def _safe_text(value: str, limit: int = 4_096) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit]
