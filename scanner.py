"""Backward-compatible entry point for VulnScannerLite."""

from vulnscanner_lite.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
