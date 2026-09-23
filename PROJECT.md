# Project: Repository-Wide 90% Real Test Coverage (PR 71)

## Architecture & Strategy
This project establishes comprehensive, authentic test coverage (>=90%) across all Python modules in `src/`, `scripts/`, and `installer/` on PR 71 (branch `codex/coverage-90-percent-split`).

### Key Principles
1. **Real Execution**: All tests execute real application logic against genuine local objects or a unified fake IDA SDK harness (`tests/fakes/ida_fake.py`).
2. **Zero Dummy/Mock Bypass**: No tautological assertions (`assert True`), no testing the mock instead of the implementation, no dummy bypass stubs.
3. **Guardrail Compliance**: All tests pass offline (`pytest --ignore=tests/integration`), `ruff check .` passes with 0 errors, schema integrity and tool skills doc generators exit 0 with 0 drift.

## Coverage Metrics
### Historical baseline (Survey Phase 0 — stale, do not cite as current)
- **Total Repository Statements**: 58,114
- **Covered Statements**: 37,349
- **Missed Statements**: 20,765
- **Baseline Line Coverage**: 64.27%
- **Original Target**: >= 90.0% (>= 52,303 covered statements; <= 5,811 missed statements)

### Current live (offline suite, 2026-09-23 EEST)
- **Suite**: 5362 passed, 7 skipped, ~6m15s, exit 0 (`pytest --ignore=tests/integration`)
- **Overall (incl. tests)**: ~95.99% (140,836 stmts / 3,930 miss)
- **`src/` only**: 94.55% (54,720 stmts / 2,289 miss) — **>=90% target met**
- **Remaining miss pile**: ~2.3k `src/` statements

## Feature Inventory
> **Note (2026-09-23):** Aggregate offline `src/` coverage already meets the >=90%
> target (94.55%). Rows below keep **historical Survey Phase 0 Baseline %** and
> original milestone labels for traceability. Do **not** treat Baseline % or
> IN_PROGRESS/PLANNED status as current per-subsystem measurements — those were
> not re-measured in the live run. Remaining work is miss-pile reduction (~2.3k
> `src/` statements) and a blocking CI coverage gate (M5), not inventing fresh
> subsystem percentages.

| # | Feature / Subsystem | Description | Baseline % (Phase 0) | Milestone | Source | Status (vs aggregate `src/` target) |
|---|---------------------|-------------|:----------:|:---------:|:------:|:------:|
| 1 | `tests/fakes/ida_fake.py` | Unified fake IDA SDK simulation harness unblocking authentic offline testing | N/A | M1 | Survey 2 | DONE (95%) |
| 2 | `scripts/` CLI & Tooling | Comprehensive unit tests for all 14 repository maintenance/build scripts | 0.00% | M1 | Survey 1 | DONE (85-98%) |
| 3 | `src/ida_pro_mcp/installer/` | Installer discovery, runtime download, clients config, CLI entrypoints | 76.13% | M2 | Survey 1 | Covered under met `src/` target; Baseline % historical |
| 4 | `src/ida_pro_mcp/host/server/` | Host daemon server, client lifecycle, health, protocol, embeddings pipeline | 77.04% | M2 | Survey 1 | Covered under met `src/` target; Baseline % historical |
| 5 | `src/ida_pro_mcp/host/stores/` | Blackboard store migrations (v1/v2->v3), symbol_db, knowledge_graph, truncation | 87.79% | M2 | Survey 3 | Covered under met `src/` target; Baseline % historical |
| 6 | `src/ida_pro_mcp/host/intelligence/` & `native/` | Core process lifecycle, embeddings, native ctypes C-ABI bridge & fallbacks, scanners | 80.53% | M2 | Survey 3 | Covered under met `src/` target; Baseline % historical |
| 7 | `ida_mcp/tools/` (Analysis & Nav) | `analysis.py`, `funcs.py`, `modify.py`, `segments.py`, `emulate.py`, `_common.py` | ~45% | M3 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 8 | `ida_mcp/tools/` (Code & AST) | `code.py`, `ctree.py`, `code_helpers.py`, `stack_analysis.py` | ~42% | M3 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 9 | `ida_mcp/tools/` (Types & IDB) | `types.py`, `idb.py`, `calc.py`, `annotation.py`, `batch.py` | ~45% | M4 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 10| `ida_mcp/tools/search/` | Basic, advanced, combinators, code, meta, refs, semantic, unified query engine | ~48% | M4 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 11| `ida_mcp/tools/` (Advanced & Know) | `gadgets.py`, `firmware.py`, `imports_deep.py`, `memory.py`, `knowledge.py`, `wiki.py` | ~44% | M4 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 12| `ida_mcp/` (Protocols & ZeroMCP) | `zeromcp/*`, `rpc.py`, `mcp_http.py`, `error_handling.py`, `compat.py` | ~65% | M4 | Survey 2 | Covered under met `src/` target; Baseline % historical |
| 13| CI Guardrails & Acceptance | Blocking repository-wide >=90% CI gate plus pytest/ruff/schema/skills sync | N/A | M5 | Prompt | PLANNED (aggregate `src/` already >=90%; gate not installed) |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Fake SDK Harness & Scripts Suite | `tests/fakes/ida_fake.py` + `tests/test_scripts/` (all 14 scripts) | none | DONE |
| M2 | Host, Stores, Intelligence & Installer Suite | `src/ida_pro_mcp/host/`, `stores/`, `intelligence/`, `installer/` | M1 | DONE for aggregate `src/` target (Baseline % rows above are historical) |
| M3 | IDA Tools: Analysis, Code & Decompilation | `analysis.py`, `funcs.py`, `modify.py`, `segments.py`, `emulate.py`, `code.py`, `ctree.py`, `code_helpers.py`, `stack_analysis.py` | M1 | DONE for aggregate `src/` target (Baseline % historical) |
| M4 | IDA Tools: Types, Search, Advanced & Protocols | `types.py`, `idb.py`, `calc.py`, `annotation.py`, `batch.py`, `search/*`, `gadgets.py`, `firmware.py`, `zeromcp/*`, `rpc.py` | M1 | DONE for aggregate `src/` target (Baseline % historical) |
| M5 | Final Repository-Wide Hardening & CI Guardrail Gate | Blocking CI >=90% gate, remaining miss-pile reduction, ruff, schema integrity, generate_tool_skills, forensic audit | M1–M4 | PLANNED (gate + miss-pile; not a claim that `src/` is still under 90%) |

## Code Layout & Ownership
- Fake SDK Fixtures: `tests/fakes/ida_fake.py`
- Scripts Tests: `tests/test_scripts/test_*.py`
- Host & Installer Tests: `tests/test_host/test_*.py`, `tests/test_installer/test_*.py`
- IDA Tools Tests: `tests/test_ida_mcp/test_tools_*.py`, `tests/test_ida_mcp/test_search_*.py`, `tests/test_ida_mcp/test_zeromcp_*.py`
- Existing regression tests in `tests/ida_mcp/` remain untouched and preserved.

## Interface Contracts
- `tests/fakes/ida_fake.py`:
  - `FakeDatabase`: in-memory segments, functions, instructions, types, flowcharts, ctree ASTs, snapshots.
  - `install_fake_idb(...) -> FakeDatabase`: installs simulated IDA SDK modules into `sys.modules`.
  - Compatible with `tests/conftest.py` `_isolate_sys_modules` snapshotting.
