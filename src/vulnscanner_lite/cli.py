"""Command-line interface for authorized HTTP posture auditing."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .config import AuditConfig, parse_target_url
from .errors import ConfigurationError, VulnScannerLiteError
from .models import Severity
from .reporting import render_report
from .scanner import Auditor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscanner-lite",
        description="Bounded HTTP security posture auditor for explicitly authorized targets.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--url", required=True, help="one absolute HTTP(S) URL")
    parser.add_argument(
        "--acknowledge-authorization",
        action="store_true",
        help="confirm that you own the target or have explicit permission to audit it",
    )
    parser.add_argument(
        "--allow-public-target",
        action="store_true",
        help=(
            "permit a globally routable destination (local/private targets are allowed by default)"
        ),
    )
    parser.add_argument(
        "--active-reflection",
        action="store_true",
        help="send one additional GET with an inert random query token; never submits forms",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP transaction deadline (after DNS resolution), 0.1-30s",
    )
    parser.add_argument(
        "--max-body-bytes", type=int, default=1_048_576, help="response body cap, 1024-5242880"
    )
    parser.add_argument(
        "--max-redirects", type=int, default=3, help="same-origin redirect cap, 0-5"
    )
    parser.add_argument("--format", choices=("text", "json", "jsonl"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium"),
        default="none",
        help="exit 3 when a finding meets this severity threshold",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.acknowledge_authorization:
        parser.error("--acknowledge-authorization is required")

    try:
        config = AuditConfig(
            target=parse_target_url(args.url),
            allow_public_target=args.allow_public_target,
            timeout=args.timeout,
            max_body_bytes=args.max_body_bytes,
            max_redirects=args.max_redirects,
            active_reflection=args.active_reflection,
        )
        report = Auditor().run(config)
        sys.stdout.write(render_report(report, args.format))
        sys.stdout.flush()
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("audit interrupted", file=sys.stderr)
        return 130
    except ConfigurationError as exc:
        parser.error(str(exc))
    except VulnScannerLiteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    threshold = {"low": Severity.LOW, "medium": Severity.MEDIUM}.get(args.fail_on)
    if threshold is not None and any(
        finding.severity.rank >= threshold.rank for finding in report.findings
    ):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
