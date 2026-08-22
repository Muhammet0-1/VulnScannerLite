# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-08-22

### Changed

- Rebuilt the script as an installable, typed Python package.
- Reframed the project as an HTTP security posture auditor with evidence-bounded findings.
- Made local/private targets the default and required an explicit flag for public targets.
- Replaced form submission and exploit payloads with passive inspection.
- Removed browser impersonation and unsupported WAF-bypass claims.

### Added

- DNS resolution pinning, direct proxy-free transport, verified TLS, and same-origin redirects.
- Strict URL, address-class, timeout, redirect, and response-size validation.
- Optional inert query reflection canary that is not presented as XSS proof.
- Passive header, cookie, transport, and form observations.
- Text, JSON, and JSONL output plus configurable severity exit status.
- Network-free tests, strict type checking, linting, packaging checks, and Python 3.10-3.13 CI.
