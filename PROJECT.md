# Project: Repository-Wide 90% Real Test Coverage (PR 71)

## Architecture & Strategy
This project establishes comprehensive, authentic test coverage (>=90%) across all Python modules in `src/`, `scripts/`, and `installer/` on PR 71 (branch `codex/coverage-90-percent-split`).

### Key Principles
1. **Real Execution**: All tests execute real application logic against genuine local objects or a unified fake IDA SDK harness (`tests/fakes/ida_fake.py`).
2. **Zero Dummy/Mock Bypass**: No tautological assertions (`assert True`), no testing the mock instead of the implementation, no dummy bypass stubs.
3. **Guardrail Compliance**: All tests pass offline (`pytest --ignore=tests/integration`), `ruff check .` passes with 0 errors, schema integrity and tool skills doc generators exit 0 with 0 drift.

## Baseline Metrics (Survey Phase 0)
- **Total Repository Statements**: 58,114
- **Covered Statements**: 37,349
- **Missed Statements**: 20,765
- **Baseline Line Coverage**: 64.27%
- **Target Coverage**: >= 90.0% (>= 52,303 covered statements; <= 5,811 missed statements)

## Feature Inventory
| # | Feature / Subsystem | Description | Baseline % | Milestone | Source | Status |
|---|---------------------|-------------|:----------:|:---------:|:------:|:------:|
| 1 | `tests/fakes/ida_fake.py` | Unified fake IDA SDK simulation harness unblocking authentic offline testing | N/A | M1 | Survey 2 | DONE (95%) |
| 2 | `scripts/` CLI & Tooling | Comprehensive unit tests for all 14 repository maintenance/build scripts | 0.00% | M1 | Survey 1 | DONE (85-98%) |
| 3 | `src/ida_pro_mcp/installer/` | Installer discovery, runtime download, clients config, CLI entrypoints | 76.13% | M2 | Survey 1 | IN_PROGRESS |
| 4 | `src/ida_pro_mcp/host/server/` | Host daemon server, client lifecycle, health, protocol, embeddings pipeline | 77.04% | M2 | Survey 1 | IN_PROGRESS |
| 5 | `src/ida_pro_mcp/host/stores/` | Blackboard store migrations (v1/v2->v3), symbol_db, knowledge_graph, truncation | 87.79% | M2 | Survey 3 | IN_PROGRESS |
| 6 | `src/ida_pro_mcp/host/intelligence/` & `native/` | Core process lifecycle, embeddings, native ctypes C-ABI bridge & fallbacks, scanners | 80.53% | M2 | Survey 3 | IN_PROGRESS |
| 7 | `ida_mcp/tools/` (Analysis & Nav) | `analysis.py`, `funcs.py`, `modify.py`, `segments.py`, `emulate.py`, `_common.py` | ~45% | M3 | Survey 2 | PLANNED |
| 8 | `ida_mcp/tools/` (Code & AST) | `code.py`, `ctree.py`, `code_helpers.py`, `stack_analysis.py` | ~42% | M3 | Survey 2 | PLANNED |
| 9 | `ida_mcp/tools/` (Types & IDB) | `types.py`, `idb.py`, `calc.py`, `annotation.py`, `batch.py` | ~45% | M4 | Survey 2 | PLANNED |
| 10| `ida_mcp/tools/search/` | Basic, advanced, combinators, code, meta, refs, semantic, unified query engine | ~48% | M4 | Survey 2 | PLANNED |
| 11| `ida_mcp/tools/` (Advanced & Know) | `gadgets.py`, `firmware.py`, `imports_deep.py`, `memory.py`, `knowledge.py`, `wiki.py` | ~44% | M4 | Survey 2 | PLANNED |
| 12| `ida_mcp/` (Protocols & ZeroMCP) | `zeromcp/*`, `rpc.py`, `mcp_http.py`, `error_handling.py`, `compat.py` | ~65% | M4 | Survey 2 | PLANNED |
| 13| CI Guardrails & Acceptance | Repository-wide >=90% verification, pytest, ruff, schema integrity, skills sync | N/A | M5 | Prompt | PLANNED |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Fake SDK Harness & Scripts Suite | `tests/fakes/ida_fake.py` + `tests/test_scripts/` (all 14 scripts) | none | DONE |
| M2 | Host, Stores, Intelligence & Installer Suite | `src/ida_pro_mcp/host/`, `stores/`, `intelligence/`, `installer/` | M1 | IN_PROGRESS |
| M3 | IDA Tools: Analysis, Code & Decompilation | `analysis.py`, `funcs.py`, `modify.py`, `segments.py`, `emulate.py`, `code.py`, `ctree.py`, `code_helpers.py`, `stack_analysis.py` | M1 | PLANNED |
| M4 | IDA Tools: Types, Search, Advanced & Protocols | `types.py`, `idb.py`, `calc.py`, `annotation.py`, `batch.py`, `search/*`, `gadgets.py`, `firmware.py`, `zeromcp/*`, `rpc.py` | M1 | PLANNED |
| M5 | Final Repository-Wide Hardening & CI Guardrail Gate | Full repository coverage >=90% audit, ruff, schema integrity, generate_tool_skills, forensic audit | M1, M2, M3, M4 | PLANNED |

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
