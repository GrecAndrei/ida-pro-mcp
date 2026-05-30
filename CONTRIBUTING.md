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

Targeted tests:

```bash
python -m unittest tests.test_host_wiki_and_hardening
python -m unittest tests.test_linux_support
python -m unittest tests.test_session_features
```

Full suite:

```bash
python -m unittest discover tests
```

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
