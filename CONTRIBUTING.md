# Contributing

Thanks for contributing to `ida-pro-mcp`.

## Before You Start

- Read `AGENTS.md` for repository-wide conventions and required checks.
- Read `README.md` for setup and runtime model.
- Read `docs/guide/architecture.md` for module boundaries and risky areas.
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
the repo's temporary directory can fill — use a project-local scratch path
with `--basetemp=.pytest_tmp` when running large suites.

Targeted tests:

```bash
python -m pytest tests/test_docs_sync.py --basetemp=.pytest_tmp
python -m pytest tests/host/test_swarm_p14_stale_docs.py --basetemp=.pytest_tmp
```

Per-directory layouts:

```bash
python -m pytest tests/ --basetemp=.pytest_tmp       # host + docs + contract tests
python -m pytest tests/host --basetemp=.pytest_tmp    # host-server fakes (no live IDA)
python -m pytest tests/ida_mcp --basetemp=.pytest_tmp # IDA-side tool logic (fakes)
```

Full suite:

```bash
python -m pytest --basetemp=.pytest_tmp
```

Live-IDA integration lives in `tests/integration/`; run it explicitly and do
not count it as part of the fast suite.

## Benchmarks

Use the scope-based runner instead of creating one-off benchmark scripts or
checking in local measurements:

```bash
python benchmarks/run.py --scope contract host blackboard
python benchmarks/run.py --scope retrieval \
  --corpus /path/to/functions.json --queries /path/to/queries.json \
  --backend native
```

See `benchmarks/README.md` for corpus format, live-IDA scope requirements, and
report fields. Store generated reports outside the repository or under the
ignored `benchmark-results/` directory.

## Pull Request Guidelines

- Keep public tool contracts backward compatible where possible.
- Include tests for behavior changes.
- For schema changes, update docs and compatibility aliases when needed.
- Prefer additive fields over removing/renaming existing fields.
- Use clear commit messages describing intent and scope.

## Code Style and Structure

- Keep host orchestration in `src/ida_pro_mcp/host/server_*.py` mixins.
- Keep IDA runtime tool logic in `src/ida_pro_mcp/ida_mcp/tools/*.py`.
- Keep durable investigation-memory changes in
  `src/ida_pro_mcp/host/stores/blackboard_store.py` with an idempotent schema
  migration and retrieval regression tests.
- Avoid introducing new giant handlers; extract helper functions early.
- Return structured errors with hints instead of raising opaque exceptions.

## Reporting Issues

When opening an issue, include:

- tool name and action,
- minimal reproducible call,
- expected vs actual result,
- environment notes (OS, IDA version, Python version),
- relevant logs/error payloads.
