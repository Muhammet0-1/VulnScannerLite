# Contributing

Contributions that improve defensive auditing, correctness, accessibility, or documentation are welcome.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy
pytest
python -m build
```

Tests must remain deterministic and network-free. Inject fake resolvers and transports instead of contacting
real systems. New checks must report only what the collected evidence supports.

## Safety requirements

- Never add credential guessing, exploit payloads, form submission, crawling, or evasion behavior.
- Keep all network work bounded and scoped to the explicitly supplied origin.
- Do not weaken TLS verification, DNS pinning, address classification, or resource limits.
- Use documentation-only example targets and do not commit secrets or live scan results.

Open a focused pull request with tests and a clear explanation of the behavior change.
