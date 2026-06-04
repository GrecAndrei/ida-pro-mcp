## Goal
- Reduce overlap in `ida-pro-mcp` tool surface: complete Target C (misc grab-bag split) and Target D (graph ↔ xref_analysis collapse), with CI never failing.

## Constraints & Preferences
- Don't restrict to minimal changes — rewrite poorly integrated systems completely
- Make merged tools more useful, not pointless
- Do not create new tools; create new actions under existing ones
- Commit+push constantly; edit/add tests as you go
- Use `git mv` for renames; commit immediately after each change
- **EVERY VOERA REF MUST BE REMOVED**
- **NO hardcoded tool counts anywhere** — master sync script required
- **Plugin is dead code, NOT to be deleted**: `ida_mcp/` package is BACK (tests depend on it; TO BE REMOVED LATER) — user emphatic "DO NOT FUCKING REMOVE THE ENTIRE MCP JUST TO REMOVE THE LEGACY PLUGIN"
- **Legacy proxy is dead code**: `src/ida_pro_mcp/server.py` is unused but kept; entry points repointed to `host.server`
- **Standalone server IS the server** — `ida_pro_mcp.host.server:main` is the canonical entry
- **CI must never fail** — verify at every commit with `python scripts/check_schema_integrity.py && python scripts/generate_tool_skills.py && git diff --exit-code -- .agents/skills .agents/tool-docs`
- LSP noise is pre-existing, not blocking

## Progress
### Done
- **Plugin-removal refactor** (commits 812f796, 39084dc, 33bc7b8):
  - User repointed `src/ida_pro_mcp/__main__.py` and `src/ida_pro_mcp/cli.py._server_cmd` to `ida_pro_mcp.host.server` (clean fix; proxy still exists but unused)
  - `src/ida_pro_mcp/host/truncation.py` (moved from `ida_mcp/`)
  - `src/ida_pro_mcp/host/blackboard_store.py` (extracted; 1091 lines, pure SQLite)
  - `pyproject.toml`: `ida-pro-mcp = "ida_pro_mcp.host.server:main"`; removed `idapro` dep, `idalib-mcp` script
  - `opencode.json`: `python -u -m ida_pro_mcp.host.server`
  - CI precheck + tool count sync (`TOOLS=66 ADVERTISED=63 HIDDEN=3`)
- **Target C: misc grab-bag split** (commit ecc7db8, 16 files):
  - `health` → `session` (host handler `_handle_session_health`, renamed from `_handle_misc_health`)
  - `plugin_run` → `analysis` (host handler `_handle_analysis_plugin_run` — forwards to live IDA RPC port)
  - `read_file`/`write_file` → `memory` (host handler `_handle_memory_filesystem` — pure-Python path-based I/O)
  - `misc` keeps: `python`, `idc`, `load_sig`, `cache_stats`, `plugin_list`
  - Updated `policy.py`: `LOCAL_CODE_EXEC_ACTIONS`, `FILESYSTEM_WRITE_ACTIONS`, `FILESYSTEM_READ_ACTIONS`, `READ_ONLY_ACTIONS` now point to new (tool, action) pairs
  - Updated schemas/args: `path`/`content`/`encoding` on `memory`; `name`/`arg` on `analysis`; `verbose` on `session`
  - `git mv tests/test_misc_health_catalog.py tests/test_session_health_catalog.py`
  - All 1351 tests pass
- **Target D: collapse graph ↔ xref_analysis overlap** (commit aa6bb72, 25 files, +68/-146):
  - Removed 6 bogus `graph` TOOL_ACTIONS entries (`down, up, both, json, dot, mermaid` — parameter values, not actions; plugin only handled 4 real actions)
  - Added 10 real `xref_analysis` actions to `graph`: `call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions`
  - `graph` actions now: 14 total (4 original + 10 from xref_analysis, plus the singular `dominator` joins `dominators`)
  - `xref_analysis` removed from TOOLS (was hidden); preserved as `BASE_TOOL_ALIASES["xref_analysis"] = "graph"`
  - Also updated: `xfer_analysis` (typo), `xref`, `xrefs`, `strings_xref` all → `graph`
  - `_TOOL_CATEGORY_SECURITY` dropped `xref_analysis` (graph is in `_TOOL_CATEGORY_ADVANCED`)
  - 11 host/ source files updated to reference `graph` instead of `xref_analysis` (predictor, blackboard, threat_hunt, intelligence_context, server_workflow, server_response, server_predictor, server_blackboard, server_threat_hunt, auto_nudge, session, session_skills, usage_intelligence, intelligence_api_patterns, server_script)
  - `tests/probes/tool_sweep_probe.py` uses `graph` for `dependency_graph` call
  - `test_host_wiki_and_hardening.py`: `test_tool_alias_generation_covers_all_tools` exception list includes `xref_analysis`
  - `test_server_blackboard_working_memory.py`: `_DummyDispatchServer` accepts both `xref_analysis` and `graph` (alias back-compat coverage); evidence strings updated
  - Counts: TOOLS=65, ADVERTISED=63, HIDDEN=2 (was 66/63/3)
  - 1351 tests pass; CI precheck clean

### In Progress
- (none — both targets C and D complete; awaiting next direction from user)

### Blocked
- (none)

## Key Decisions
- **Plugin-removal fix**: keep `ida_mcp/` source files alive (TO BE REMOVED LATER); repoint `__main__.py`/`cli.py` to `host.server`; keep `server.py` proxy as unused dead code
- **Target C routing**: 
  - `session(health)` → host handler (no plugin needed)
  - `memory(read_file|write_file)` → host handler (no IDA needed)
  - `analysis(plugin_run)` → host handler that forwards to live IDA session RPC port
- **Target C back-compat**: clean break, all moved actions only accessible via new tool paths
- **Target D back-compat**: `xref_analysis`, `xfer_analysis`, `xref`, `xrefs`, `strings_xref` all aliased to `graph` via `BASE_TOOL_ALIASES` + `_EXTRA_TOOL_ALIASES`; resolution via `_resolve_tool_alias()` in `schemas.py:249`
- **`kill_ida_processes` is a true orphan** — no caller in `installer/main.py`; functions remain in `installer/runtime.py` (kept for now)
- **`graph` actions enum**: `["callgraph", "cfg", "dominators", "xref_graph", "call_chain", "common_callers", "common_callees", "hub_functions", "leaf_functions", "recursive", "dominator", "influence", "dependency_graph", "dead_functions"]` (14 actions, no bogus direction/format values)
- **Test stubs**: `_DummyDispatchServer` in `test_blackboard_policy_dispatch.py` gained `_handle_session` stub to delegate to `_handle_session_health`; `_DummyServer` in `test_server_blackboard_working_memory.py` accepts both `xref_analysis` and `graph` tool names

## Next Steps
1. Awaiting user direction on next target (potential: data_ops ↔ bulk overlap, classify ↔ annotate, etc.)
2. After all targets done: revisit `ida_mcp/` package removal (legacy plugin code)
3. After all targets done: revisit `server.py` proxy removal (legacy entrypoint)

## Critical Context
- **Current local baseline**: 1351 tests pass (CI env, 57 skipped, 15 subtests)
- **Run command (std)**: `python -m pytest tests/ --ignore=tests/test_session_features.py --ignore=tests/test_revamp.py --ignore=tests/test_evidence_bootstrap.py --ignore=tests/test_host_wiki_and_hardening.py --ignore=tests/test_bugfixes.py --ignore=tests/benchmarks -q --no-header`
- **Run command (CI)**: `IDA_MCP_DISABLE_RATE_LIMIT=1 IDA_MCP_POLICY_MODE=permissive python -m pytest -q --no-header`
- **CI precheck (must pass before commit)**: `python scripts/check_schema_integrity.py && python scripts/generate_tool_skills.py && git diff --exit-code -- .agents/skills .agents/tool-docs`
- **Remote**: `https://github.com/GrecAndrei/ida-pro-mcp`, branch `master`; git push works
- **Recent commits on master** (newest first): `aa6bb72` (Target D graph↔xref_analysis), `ecc7db8` (Target C misc split), `33bc7b8` (regen tool docs post-merge), `39084dc` (sync tool counts 66/63), `812f796` (main plugin-removal + fixups→segments), `ae23a49` (CI test fix)
- **Tools surface counts (post-Target-D)**: TOOLS=65, ADVERTISED=63, HIDDEN=2 (HIDDEN: `colorize`, `schemaboot`)
- **Tool action counts**: `graph` 14, `session` 57, `memory` 15, `analysis` 7, `misc` 5 (post-Target-C/D)
- **MCP entrypoint**: `python -u -m ida_pro_mcp.host.server` (via `__main__.py` or `ida_mcp_stdio.py` shim); `ida_pro_mcp.server` exists but is dead code
- **MCP probe wrapper**: `scripts/mcp_probe.py` — usage: `python scripts/mcp_probe.py --call segments --args '{"action":"list","_qol_mode":"tiny"}' --pretty`
- **CI workflow** (`.github/workflows/*.yml`): runs `check_schema_integrity.py`, `generate_tool_skills.py`, then `git diff --exit-code -- .agents/skills .agents/tool-docs` — failing any of these breaks CI
- **Reinstall cmd**: `pip install -e . --no-deps --no-build-isolation` (needed after schema edits to refresh `.venv` install)
- **HIDDEN_TOOLS_IN_LIST def**: `src/ida_pro_mcp/host/schemas.py:166` — `HIDDEN_TOOLS_IN_LIST = {t for t in TOOLS if t not in ADVERTISED_TOOLS}`
- **TOOL_ALIASES def**: `src/ida_pro_mcp/host/schemas.py:280` — `TOOL_ALIASES = _build_tool_aliases(TOOLS, {**BASE_TOOL_ALIASES, **_EXTRA_TOOL_ALIASES})`
- **WRAPPER_ACTIONS**: `src/ida_pro_mcp/host/schemas.py:154` — `("grep", "pick", "head", "tail", "next", "stats")` — cross-tool meta-actions
- **Env-touched 0-byte diffs** (NOT TO COMMIT): `ARCHITECTURE.md`, `CONTRIBUTING.md`, `HARDENING_ROADMAP.md`, `LICENSE`, `README.md`, `SAFETY_MODEL.md`, `SECURITY.md`, `USE_CASES.md`, `client_configs.json`, `ida_mcp_stdio.py`, `install.bat`, `install.py`, `uv-package.sh`, `uv.lock` — `git checkout -- <files>` to revert
- **Untracked file to ignore**: `install-report.json`
- **LSP noise**: pre-existing on `tests/test_search_callers_callees_dedup.py`, `tests/benchmarks/benchmark_firmware_heuristics.py`, `tests/test_new_smart_features.py`, etc.

## Relevant Files
- `src/ida_pro_mcp/host/schemas_data.py`: 65 tools, all `TOOL_ACTIONS` lists and per-tool schemas; edit TOOL_ACTIONS for tool merges
- `src/ida_pro_mcp/host/schemas.py:154-166, 249, 280`: `WRAPPER_ACTIONS`, `ADVERTISED_TOOLS`, `HIDDEN_TOOLS_IN_LIST`, `_resolve_tool_alias`, `TOOL_ALIASES` defs
- `src/ida_pro_mcp/host/server_dispatch.py`: 
  - Line 114: `_handle_session_health` (renamed from `_handle_misc_health`)
  - Line ~195: `_handle_memory_filesystem` (read_file/write_file)
  - Line ~265: `_handle_analysis_plugin_run`
  - Line ~1056: dispatch routes for `session`, `memory(read_file|write_file)`, `analysis(plugin_run)`
- `src/ida_pro_mcp/host/server_session.py:120-126`: `_handle_session` entry; routes `action == "health"` to `_handle_session_health`
- `src/ida_pro_mcp/host/policy.py:150-172`: `LOCAL_CODE_EXEC_ACTIONS`, `FILESYSTEM_WRITE_ACTIONS`, `FILESYSTEM_READ_ACTIONS`, `READ_ONLY_ACTIONS` (all updated to new (tool, action) pairs)
- `src/ida_pro_mcp/ida_mcp/tools/xref_analysis.py`: LEGACY plugin code (dead, will be removed later) — handles `call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions` (these actions are now also in `graph` schema)
- `src/ida_pro_mcp/ida_mcp/tools/graph.py:13-19`: LEGACY plugin code (dead) — `graph` plugin only handles 4 actions (`callgraph, cfg, dominators, xref_graph`)
- `src/ida_pro_mcp/ida_mcp/`: RESTORED package — keep as dead code; user said remove later, not now
- `src/ida_pro_mcp/server.py`: dead-code proxy; 810 lines, still imports from `ida_mcp.ida_mcp.zeromcp`; no callers since `__main__.py`/`cli.py` repointed
- `src/ida_pro_mcp/__main__.py`: `from ida_pro_mcp.host.server import main` (user's fix)
- `src/ida_pro_mcp/cli.py:120`: `_server_cmd` returns `[sys.executable, "-m", "ida_pro_mcp.host.server"]`
- `src/ida_pro_mcp/installer/main.py`: removed `install_ida_plugin()` and plugin phase; `kill_ida_processes` import kept but unused (orphan)
- `src/ida_pro_mcp/installer/runtime.py:34`: `kill_ida_processes`/`ida_processes_running` orphaned
- `tests/test_session_health_catalog.py`: renamed from `test_misc_health_catalog.py` via `git mv`
- `tests/test_runtime_dispatch_resilience.py:23-37`: `test_session_health_runtime_liveness_uses_process_poll` (was `test_misc_health_*`)
- `tests/test_policy.py:45,84,108-112`: tests `memory(write_file)`, `analysis(plugin_run)`, `session(health)` (was `misc(*)`)
- `tests/test_mcp_comprehensive.py:244,316,331,628`: `TestMiscTool.test_session_health`, workflow `audit_plan`/`execute_plan`, `test_compact_vs_full_mode` (use `session` not `misc` for health)
- `tests/test_host_wiki_and_hardening.py:213,215,311,486`: `test_tools_list_keeps_wiki_tool_slot` (asserts new tool split), `test_session_health_requires_no_session` (was `test_misc_health_*`), `test_tool_alias_generation_covers_all_tools` (excludes `xref_analysis` from "must have alias")
- `tests/test_bugfixes.py:328-336`: `test_plugins_registered` asserts `plugin_run` in `analysis`, `health` in `session`, `read_file`/`write_file` in `memory`
- `tests/test_revamp.py:375-408`: `TestMemoryReadWriteFile` (renamed from `TestMiscReadWriteFile`)
- `tests/test_blackboard_policy_dispatch.py:189-198`: `test_dispatch_policy_allows_session_health_without_ack`; `_DummyDispatchServer._handle_session` stub added
- `tests/test_server_blackboard_working_memory.py:144-148`: `_DummyServer._execute_tool` accepts both `xref_analysis` and `graph`
- `tests/probes/tool_sweep_probe.py:180`: uses `graph` for `dependency_graph` call
- `scripts/sync_tool_counts.py`: master sync for hardcoded tool counts
- `scripts/check_schema_integrity.py`: validates schema; required by CI
- `scripts/generate_tool_skills.py`: regenerates `.agents/skills` and `.agents/tool-docs`; required by CI
- `tools/sync_tool_counts.py`: entry point `python -m tools.sync_tool_counts` — what CI/precheck calls
