# Contributing

Thanks for contributing to `ida-pro-mcp`.

## Before You Start

- Read `README.md` for setup and runtime model.
- Read `ARCHITECTURE.md` for module boundaries and risky areas.
- Keep changes focused; avoid mixing refactors and behavior changes in one PR.

## Development Setup

```bash
python install.py
```

or for editable mode:

```bash
pip install -e .
```

## Running Tests

The suite is pytest-based. Most tests run without live IDA (host fakes,
`FakeIDB`-style stubs); only `tests/integration/` requires a real IDA
installation. The runner writes scratch files under the pytest basetemp, and
the repo's `/tmp` tmpfs can fill — always pass
`--basetemp=/home/alex/.tmp/pytest` (repo convention).

Targeted tests:

```bash
.venv/bin/pytest tests/test_docs_sync.py --basetemp=/home/alex/.tmp/pytest
.venv/bin/pytest tests/host/test_swarm_p14_stale_docs.py --basetemp=/home/alex/.tmp/pytest
```

Per-directory layouts:

```bash
.venv/bin/pytest tests/ --basetemp=/home/alex/.tmp/pytest       # host + docs + contract tests
.venv/bin/pytest tests/host --basetemp=/home/alex/.tmp/pytest    # host-server fakes (no live IDA)
.venv/bin/pytest tests/ida_mcp --basetemp=/home/alex/.tmp/pytest # IDA-side tool logic (fakes)
```

Full suite:

```bash
.venv/bin/pytest --basetemp=/home/alex/.tmp/pytest
```

Live-IDA integration lives in `tests/integration/`; run it explicitly and do
not count it as part of the fast suite.

## Pull Request Guidelines

- Keep public tool contracts backward compatible where possible.
- Include tests for behavior changes.
- For schema changes, update docs and compatibility aliases when needed.
- Prefer additive fields over removing/renaming existing fields.
- Use clear commit messages describing intent and scope.

## Code Style and Structure

- Keep host orchestration in `src/ida_pro_mcp/host/server_*.py` mixins.
- Keep IDA runtime tool logic in `src/ida_pro_mcp/ida_mcp/tools/*.py`.
- Avoid introducing new giant handlers; extract helper functions early.
- Return structured errors with hints instead of raising opaque exceptions.

## Reporting Issues

When opening an issue, include:

- tool name and action,
- minimal reproducible call,
- expected vs actual result,
- environment notes (OS, IDA version, Python version),
- relevant logs/error payloads.
