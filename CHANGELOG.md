# Changelog

All notable changes to `ida-pro-mcp`. Dates in YYYY-MM-DD. Versions are not tag-stamped yet — each release maps roughly to a wave of improvements announced here.

## Unreleased — search quality + bindiff/export

### Search
- Unified response envelope: `results`+`matches`, always `items[].addr` via `normalize_search_result`.
- `find`: demangled names, comments, smart skip of insn scan for identifier queries.
- Stronger `resolve_target` (unique substring, demangle, broader blackboard).
- `symbol` demangle matching + structured items; `api` always returns items with addr.
- Removed dead post-return heuristic in unified semantic path; `query_lang` in SEARCH_ACTIONS.

## Unreleased — bindiff + export that actually work

### Fixed / improved
- **export**: real file writes; `binexport` uses `BinExportBinary(path)` and verifies artifact; headers emit C decls; SARIF is blackboard findings only (no invented per-function noise); redact takes `text=`; full TOOL_ARG_SCHEMAS admitted.
- **bindiff**: `path=` on snapshot for durable fingerprints; load snapshot from path/JSON/dict; metadata (md5/imagebase); string-ref matching pass; IDA9-safe is_code; `include_full` for in-band dumps.
- Host tests for redact helper, resolve_snapshot, and arg admission.

## 0.9.0 — contract honesty, tier surface, restore pins (2026-07-08)

Honest alpha cut. Not a 1.0.

### Breaking / contract
- **Unknown RPC kwargs now hard-fail** with `MCPError.INVALID_ARGS` instead of being silently stripped before IDA RPC. Tuned calls that previously “worked” with defaults will now error until schemas admit the keys (or callers stop sending them).
- **Version `1.0.0` → `0.9.0`**, classifier Alpha. Package was not product-mature at 1.0 numbering.
- **`tools/list` Tier A only** (~17 tools). Full `TOOLS` remain callable by exact name. See `docs/ROADMAP.md`.
- **Compact action enums** (`ADVERTISED_ACTIONS`) for session/search/intelligence/blackboard/code/funcs/misc in lean/ultra schema mode. Full `TOOL_ACTIONS` still accepted at call time.
- Removed broken console entry `sideband-capsule` (module did not exist).

### Cuts
- **Removed standalone `filter` tool** (Context Guillotine / JQ meta-tool). It duplicated host wrappers (`pick`/`grep`/`head`/`tail`/`stats`) and response compaction; was not on the Tier A core path. Use those instead.
- Extracted pure `prepare_rpc_args()` for admission (tested without a live server).
- Fixed pytest `testpaths` so root-level contract tests actually run in CI.

### Search / funcs
- Removed first-class `search.semantic` / `search.smart_bundle`; NL/behavior live in `search/semantic.py` via `nl` / `behavior`.
- Registered `symbol`, `symbol_info`, `demangle`, `xrefs_to_string` on search actions.
- Admitted previously stripped kwargs (search: `mode`, `recipe`, `intent`, `semantic_min_score`, `constraints`, …; funcs tuning knobs; misc `module`/`modules` for reload).
- `funcs.create` overlap/code-carve helpers extracted; ARM Thumb path cleaned up.
- `misc(action='reload')` for dev hot-reload of IDA tool modules (not in compact enum).

### Tests / docs
- Restored a **curated** host/integration pin set (policy, RPC retry, phase gates, session reuse, schema admission, embedder fail-open, …). Not a return of the ~84k-line deleted suite.
- **Historical note:** older changelog lines that claim “1353 tests pass” / paths under `tests/host/…` refer to suites that were largely deleted in `968ae11`. Do not treat those numbers as current CI truth. Current gate is `pytest` on the files present on the tree.
- QuickStart rewritten to Tier A core path; `docs/ROADMAP.md` added; ghost wiki pages (`static_trace`, `trace`, `vuln_scan`) retargeted; ARCHITECTURE phantoms removed.

### Host
- Extended `LONG_RUNNING_ACTIONS` for search full-binary ops and bindiff.
- Blackboard remains the **canonical durable notebook**; wiki = docs; knowledge = chip/symbol KB.

## Hotfix — replace heuristic scanners with proper IDA analysis + harden embedding layer

### Changed
- **Replaced ~20 heuristic/keyword-scanning tools with proper IDA-backed analysis.** The codebase had widespread "naive heuristics" — hardcoded keyword recipes, API-name→severity dicts, statistical threshold rules — that produced high false-positive rates and had no basis in actual program analysis. Each was replaced with the proper IDA technique:
  - `search(action='vulnerable')` — was a flat list of dangerous API calls with static severity labels. Now traces call-chain reachability from taint sources (recv/read/ioctl) to dangerous sinks via BFS on the IDA call graph. Only APIs reachable from untrusted input are reported.
  - `search(action='hunt')` — had 15 hardcoded keyword recipes (backdoor, c2, anti_vm, license_check, etc.). Deleted the 10 pure-string-grep recipes. Kept only the 5 that verify import+API structure (anti_debug, crypto, network_io, file_io, process_injection).
  - `classify(action='binary')` — was threshold counting (`network>5 AND crypto>2 → "malware"`). Removed the fake type labels. Now reports raw structural facts (function count, category distribution, import modules) for the analyst to interpret.
  - `classify(action='initializers')` — was name-substring matching (`"init" in fname`). Now uses IDA segment analysis (`.init_array`, `.ctors`, `.CRT*XCU`) to find functions referenced from initialization segments.
  - `classify(action='error_handlers')` — was name-substring matching. Now verifies error-API calls in function callees.
  - `search_structured` (string→tag) — was hardcoded `("http://" in s → "network")` keyword scanning.
  - `digest_developed` complexity — was `pseudocode.count("(") // 2` for call count. Absurd.
  - `threat_hunt` severity + vuln_db_pass — were substring severity mapping and 20-entry `VULN_PATTERNS` grep list.
  - `_detect_encoding_in_func` — was `xor_count >= 3` → "encrypted".
  - `_TFIDFEmbedder` + `derive_synonyms_from_corpus` + token-alias bonus — deleted.

- **Embedding layer production-hardened.** The `BgeCodeEmbedder` + `BehaviorClassifier` had three problems that made it unsuitable for production:
  1. **Silent degradation.** When llama-server or the model was unavailable, the embedder silently fell back to a TF-IDF hash-bucket embedding, giving callers garbage vectors without telling them. Fixed: `embed()` now returns an `_EmbedResult` with `ok=False` when the model is unavailable. No silent fallback. Callers must check `result.ok` and surface the degradation.
  2. **Token-alias bonus contaminated scores.** `BehaviorClassifier.classify()` added a keyword-match bonus (`_ANCHOR_TOKEN_BONUS_WEIGHT = 0.18`) on top of the cosine similarity, making confidence scores uncalibrated and meaningless. Removed the entire bonus system. The cosine similarity IS the confidence.
  3. **Uncalibrated confidence.** Raw cosine similarity was presented as "confidence" with no grounding. The `backend` field is now included in every classify result so callers know whether the score came from `bge-code-v1` or `unavailable`.
  - Added `embed_vector()` convenience wrapper returning `list[float] | None` for callers that just need the vector.
  - Fixed anchor preload thread crash (`dict changed size during iteration`) by snapshotting keys.
  - Updated ~25 callers across the codebase to use the new `_EmbedResult` contract.
  - Updated 6 test files to match the new API; deleted 2 test files that only tested the removed fallback (`test_synonym_extension.py`, `test_synonym_bootstrap.py`).

### Earlier commits in this wave (previously uncommitted)
- **All 17 `addr` parameter descriptions now explicitly state "Hex address string (e.g. "0x356f8") or function name. Pass verbatim from search results — no mental math, no decimal conversion."** Previously most had `{"type": "string"}` with no description, causing LLMs to guess at address format and often convert hex→decimal incorrectly (e.g. 0x356f8 → 217848 instead of 218872). Committed as `c4c8ff7`.

## Hotfix — phase gate respects opt-in + orphan idat cleanup

### Fixed
- **Phase gate was firing on every write tool in prove phase, ignoring both the opt-in env var AND `_risk_ack`.** Symptom: the LLM had to write a blackboard `decision_card` + run `trace_ingest`/`trace_run` before it could call `funcs.create` / `modify` / `segments` / `bulk` / `annotation`, even when `IDA_MCP_PHASE_GATES` was unset and `_risk_ack=true` was passed. The LLM transcript reads like a confused agent thrashing through governance. Two distinct bugs caused this:
  - `server_blackboard.py:_phase_preflight_for_tool` did not check `_phase_gates_enabled` (default off). The followup-injection in `server_response.py` already gated on it (lines 45, 77), but the preflight gate was always on. Fixed: early-return None when the flag is False, matching the followup gate.
  - `server_dispatch.py` read `args.get('_risk_ack')` at the phase gate, but `args` had `_risk_ack` already popped at line 1271 by the policy block. So the check was always False, the gate always fired. Fixed: capture `_risk_ack` into `_risk_ack_passed` at the top of `_execute_tool_inner`, before the pop, and use the captured variable in both the phase preflight AND the strict bb-policy preflight. The preflight comment block was correct in intent but wrong in code.
  - Live verified: after the fix, `funcs(action='create', _risk_ack=true)` succeeds in prove phase under default config. New pins: `tests/integration/test_phase_gates_optin.py` (8 cases). 1353 tests pass, 94 skipped. 0 regressions.

- **Smoke runs left orphan idat children on the same binary.** Every smoke invocation called `session(action='create', processor='metapc', bitness=64, endian='little')`. The host's `_session_action_create` reused an existing session only when the caller did NOT pass preload options. With preload present, it always created a new session (and spawned a new idat child), even when the existing session had identical architecture. Across crashed/killed smoke runs this left 6+ idat children pinned on the same binary (~150 MB each).
  - Host fix: `_session_action_create` now compares requested preload options against the existing session's `analysis_options`. If they match, it reuses the existing session. `force_new=true` still always creates a new one.
  - Smoke fix: `scripts/smoke_mcp_all_tools.py` now (a) closes the created session in `finally` so the idat child dies before `cli.stop()` kills the host, (b) calls `session(action='close', session_id=X)` inside `restart()` (the TIMEOUT/CRASH recovery path) so each restart is leak-free, (c) calls `session(action='idle_purge', idle_seconds=1, prune_orphans=True)` after each create to nuke any other live sessions for this binary left behind by previous (killed) smoke runs.
  - Live verified: smoke run → 0 orphan idat children. New pins: `tests/integration/test_session_create_reuse.py` (11 cases). 1346 tests pass, 94 skipped. 0 regressions.

## Hotfix — session lifecycle hardening + dead-code removal

### Fixed
- **`idalib_server.py` was dead code masquerading as the IDA-side entry point.** It had a `main()` function, `if __name__ == "__main__"`, and argparse — but nothing ever imported it (not in `pyproject.toml.scripts`, not imported by any module). Worse, it contained active bugs: `ida_diskio.save_database("")` (that module doesn't exist; correct API is `ida_loader.save_database`), and `if open_database(): raise` which raises on the success return value. The `_auto_reanalyze_text_segments` code added in earlier commits only worked after being moved into the real entry point (`server_script.py`). **Deleted the file entirely.** Also purged the GHOST_CHAINS dead comment from `host/server/server.py` and the "see HACKING" reference from `server_response.py` (the HACKING doc never existed).

- **`server_runtime.py` never set `IDA_MCP_IDB_PATH`**, making the canonical-IDB-save branch in `server_script.py` dead code. The IDB was silently saving next to the source binary, so the session metadata's `idb_path` never matched what was on disk — `idb_exists: false` after a successful analysis, breaking session reuse detection. Now the env var is set in both `_build_ida_command` call sites.

- **Three misleading docstrings replaced.** `response_signals.py` claimed to expose 6 functions that don't exist; rewritten. `response_enrichment.py` referenced a dropped `GHOST_CHAINS` module; rewritten. `session.py:142` and `server_session.py:956` referenced the deleted `idalib_server`; rewritten.

- **`server_runtime.py:1768` timeout hint named the wrong env var** — told users to set `IDA_MCP_STARTUP_TIMEOUT_SEC` which doesn't exist. The real name is `IDA_MCP_STARTUP_TIMEOUT`. Fixed.

### Earlier commits in this wave (previously unchangeloged)
- **`session(action='create')` now blocks until IDB is analyzed.** Fresh-session spawn calls `_ensure_runtime_and_idb()` → `_wait_for_idb()` which polls until the IDB file appears. The caller no longer gets back a "ready" session that has no analysis. Reused sessions also block on the same check. `_wait_for_idb()` detects IDBs in 3 layouts: `session.idb_path`, `<binary>.i64` next to source, and legacy component files (`.id0`/`.nam`/`.til`).
- **Session reuse skips mixed-arch sessions for the same binary.** `find_sessions_by_path()` picks the candidate whose architecture matches the request; prevents aarch64/metapc cross-contamination when the same binary was loaded twice under different preloads.
- **Startup ping timeout raised 90s→240s** (`IDA_MCP_STARTUP_TIMEOUT` default) so the main-thread analysis block has time to finish on large ARM ELFs.
- **`log_ev()` call site corrected** — the function takes a single string, not printf-style args. `save_database` calls use the correct `ida_loader.save_database(path, 0)` API.
- **`server_script.py` now blocks on the main thread** for `auto_wait()` + reanalysis + save before `run_server()` starts accepting RPCs. Background-thread approach was unsafe (IDA SDK `auto_wait` is main-thread-only).

### Tests
- 1347–1349 passing, 94 skipped, 0 regressions from this session. (One pre-existing failure: `test_blackboard_policy_dispatch.py` import cycle, broken before this session.)

## Hotfix — `.text` reanalysis + `analysis.wait` coverage diagnostic

### Fixed
- **"Loader finished but `.text` was never analyzed" failure mode.** On stripped ARM aarch64 ELF binaries (most Android NDK arm64-v8a shared libraries, e.g. `libidmservicemgr.so`), IDA's loader creates 8-byte PLT stubs for the dynamic symbols but never enqueues work for `.text`. The classic symptom: 219 "functions" (all PLT stubs), `defined_code_bytes = 0`, `code_coverage_pct = 0.0%`, yet `analysis_complete = true` because the auto-analysis queue is empty. From the host's point of view the IDB looks fully analyzed but contains nothing useful. The fix:
  - New `_auto_reanalyze_text_segments()` helper walks executable segments, **skips PLT/INIT/FINI/GOT and small (<0x100B) LOAD trampolines**, and schedules `ida_auto.plan_range` for each. Reports a full before/after coverage diff so callers can see the upgrade. Live verified against `libidmservicemgr.so`: 219 → 9065 functions, 0 → 1.48 MB defined code, 0% → 86.79% coverage.
  - New `_ensure_entry_point_functions()` creates functions for any ELF entry point the auto-analyzer missed (JNI exports, native helpers). Returns `{entry_points_total, created, skipped_already_func, failed}`.
   - `server_script.py:640-698` (the active IDA-side entry point) now runs both helpers immediately after `ida_auto.auto_wait()` and **saves the IDB** so subsequent restarts don't re-run the expensive reanalysis. (Earlier commits put this code in `idalib_server.py` which was dead code — never imported, never called. The code only started working after being moved to the real entry point.)
  - `analysis(action='analyze', blocking=True)` without an explicit range routes through the new helper (was: `plan_range(min_ea, max_ea)` which was a no-op on these binaries). The `reanalyze` sub-dict in the response reports the full upgrade.
  - `analysis(action='analyze', start, end)` (explicit range) still does a direct `plan_range` + `auto_wait` for backwards compat.
  - `analysis(action='wait')` now reports `coverage` and `coverage_failed: bool`. When the auto queue is empty but `defined_code_bytes == 0` over a non-trivial `total_code_bytes`, `coverage_failed = true` and the `note` points the caller at `analysis(action='analyze', blocking=True)`. New pins: `tests/host/test_auto_reanalyze_text_segments.py` (10 cases). 1321 tests pass, 94 skipped.

## Hotfix — `analysis(action='wait')` no longer hangs by default

### Fixed
- **`_handle_analysis_wait` host default was `max_wait=300` (5 min)** when the caller passed no argument. The host's polling loop kept running past the caller's per-call budget (e.g. the 120s smoke budget) whenever the loaded binary was actively auto-analyzing. Symptom: every `analysis(action='wait')` call hit the caller's recv timeout, the MCP client retried, and the host's polling never got a chance to return. Now defaults to `max_wait=0` — single round-trip, returns current state immediately. Caller is responsible for passing `max_wait` / `timeout` if they want polling. A local wall-clock cap (`max(max_wait+30s, 30s)`, never above `IDA_MCP_RPC_HARD_WALLCLOCK_SEC`) prevents a wedged IDA round-trip from pinning the MCP client. Per-poll socket `recv_timeout` trimmed 15s→10s. Live verified: full 1193-action smoke sweep now runs in 2m18s (was 3m8s with 1 TIMEOUT) → `OK 425, CLEAN 592, CRASH 0, TIMEOUT 0, OTHER 0, SKIP 176, TOTAL 1193`. New pins: `tests/host/test_analysis_wait_default_nonblocking.py` (5 cases). 1275 tests pass, 94 skipped.

- **Install path was the actual problem** — the opencode MCP install uses `/home/alex/.local/share/ida-pro-mcp/.venv/...` (the installed package copy, not the working tree). Local source changes are inert until `python install.py --only runtime --yes` refreshes the install. Now remembered as a hard rule for every fix: edit + run smoke + reinstall.

## Unreleased — reliability, envelopes, hang-sentinel

This wave traded nine live-IDA crash bugs and several nondeterministic
failure modes for canonical error envelopes and three layers of hang
protection.

### Added

- **`session(action='idle_purge')`** — TTL-based live-runtime teardown. Sibling of `cleanup_stale`: lists sessions, drops any whose `last_used` is older than `idle_seconds` AND that still own a live IDA runtime, prunes orphans whose binary + idb are both gone. Envelope: `{closed_sids, orphan_sids, skipped_sids, ...}` mirroring `cleanup_stale` shape. Args validated up front to `MCPError.INVALID_ARGS`. Companion to cleanup_stale (which owns db-only stale rows).
- **`code(action='disasm', window=N)`** — centered ±N instruction slice around the input address. Defaults to function-bounded disassembly when omitted. Output ordered oldest→newest so callers can read top-to-bottom around the focus address. Response carries `"window": N` so cache consumers and formatters can verify which slice they got. Negative / non-int `window` rejected with `MCPError.INVALID_ARGS` envelopes.
- **Hang-sentinel trio on the dispatcher:**
  - `_LONG_RUNNING_ACTIONS` — module-level whitelist (41 entries) of full-program walks (`analysis.*`, `summarize.binary`, `summarize.report`, `intelligence.index_batch`, `intelligence.semantic_search`, `search.semantic`, `search.path`, `firmware_view.smart_carve` / `multi_region_campaign` / `campaign` / `segment_sweep`, `funcs.metrics` / `suggest_names`, `session.idle_purge` / `cleanup_stale`, `threat_hunt.*`, `workflow.execute_plan`, …) that get an extended socket recv timeout.
  - **`IDA_MCP_RPC_MAX_RECV_TIMEOUT`** (env, default `600`) — hard cap on socket recv timeout. Caller-supplied timeouts get `+30s` buffer on top of the `120s` floor but are always clamped to the cap. No caller can pin the dispatcher open.
  - **`IDA_MCP_RPC_HARD_WALLCLOCK_SEC`** (env, default `900`) — wall-clock watchdog on the entire `call_tool` path. Past the cap, the dispatcher terminates the IDA process (escalate to `SIGKILL` after 2s) and surfaces `MCPError.IDA_TIMEOUT, recoverable=True`. The next call re-spawns IDA fresh.
- **`data(action='functions', min_xrefs=N)` and `funcs.list(min_xrefs=N)`** — pre-filter on xref count before the `total` counter so the reported total reflects the filtered set. Trims the long tail of one-off thunks without client-side postprocessing.
- **`ToolResultCache.get(..., with_age=True)`** — returns `(result, age_seconds)`. The `@idaread` wrapper now annotates every cached dict with `_cache_hit: true` and `_cache_age_seconds: <int>`. Consumers that don't care can ignore the keys; consumers that want freshness visibility get it.
- **RPC retry on transient failures** — `_send_rpc_with_retry` retries connection-layer failures (`ConnectionRefusedError`, `EOFError`, `ConnectionResetError`, `ConnectionAbortedError`) with linear backoff over up to `IDA_MCP_RPC_MAX_RETRIES` (default 2). `socket.timeout` / `TimeoutError` / `OSError` are deliberately NOT retried — they propagate so the dispatcher can still tell "IDA was busy" from "IDA went away".

### Changed

- **Canonical error envelope contract** — every tool returns `{ok, ...}` on success or `{error: True, code, category, message, hint, recoverable?, details?}` on failure. Internally consistent across `host/intelligence/yara_scanner.py`, `host/server/server_session.py`, `host/server/server_dispatch.py`, `host/server/server_runtime.py`, and the `ida_mcp` tools layer.
- **`MCPError` catalog expanded** — added: `YARA_COMPILE_ERROR`, `YARA_SCAN_ERROR`, `YARA_DISABLED`, `NO_RESULTS`, `DECOMPILER_FAILED`, `PHASE_GATE`, `POLICY_DENIED`, `TOOL_NOT_FOUND`, `IDA_ERROR`, `IDA_TIMEOUT`, `IDA_CRASHED`, `RPC_CONNECTION_ERROR`. Each maps to an `ErrorCategory` (`USER` / `RUNTIME` / `POLICY` / `INTERNAL`) with a hint string keyed under `MCPError.<CODE>`.
- **Phase/policy gates default off** — set `IDA_MCP_PHASE_GATES=1` to opt back in. The gates were quietly blocking every tool call by default; flipping them off restores the natural request/response flow.
- **`funcs.list` and `data(functions, structured=true)`** now expose a `structured=True` toggle for callers that want raw row dicts instead of the LLM-friendly text-blob summary.
- **`session(action='cleanup_stale')`** now also prunes orphans whose binary + idb paths no longer exist on disk, when `prune_orphans=True` (default).

### Fixed

- **9 live-IDA crash bugs killed** — all surfaced by the action-by-action smoke harness. Pinned by `tests/live_smoke_pins/`. Coverage includes the `analysis.wait` 20s headless-startup timeout (not a bug; documented as expected under `-A`).
- **MCP registry aligned to source** — `TOOL_ACTIONS` and the JSON-schema-derived advert lists now match each tool's actual `Literal[...]` action enum. The `dominators` action was missing from `graph.py`'s docstring (had 3, literal has 4); fixed.
- **`yara_hunt` is now fully enveloped** — bare `{"error": "rule_compile_failed"}` strings replaced with `make_error(MCPError.YARA_COMPILE_ERROR, ...)`, `MCPError.YARA_SCAN_ERROR`, `MCPError.YARA_DISABLED`, `MCPError.NO_RESULTS`, plus per-file `MCPError.FILE_NOT_FOUND` envelopes with `details` carrying `namespace`, `path`, `errno`, and `exception_type`.
- **`intelligence.{structural_*, evidence_card}`** — bare error dicts → `MCPError.NO_RESULTS`, `MCPError.IDB_NOT_FOUND`, `MCPError.ANALYSIS_INCOMPLETE`, `MCPError.ADDRESS_INVALID`. Db errors funnel through `handle_error` so the envelope includes `details.sql_error` / `details.db_unavailable`.
- **`debug._get_reg_dict`** — bare `bool(rc)` → `MCPError.DEBUGGER_NOT_RUNNING` / `MCPError.DEBUGGER_REGISTER_ERROR` envelopes.
- **`misc.py`** — 22 legacy inline error returns (`return {"error": ..., "code": ...}`) replaced with `make_error(...)`. `import traceback` removed from the tool path so a `sys.last_traceback` swap can no longer leak through the wall.
- **`code.py`** — bulk decompile uses `make_error(MCPError.DECOMPILER_FAILED, ...)` for per-address failures and propagates the same shape through the response.
- **`struct_recover`** — was returning `MCPError.INTERNAL` for decompiler failures; now returns `MCPError.IDA_ERROR` (the canonical code).
- **`session.idle_purge` clears `current_session`** when purging the active session, so the next tool call dispatches to a re-spawned runtime instead of a now-dead one.
- **`IDA_TIMEOUT` envelope hint** now tells the caller how to recover: "The process is still alive; the call likely needs more time. Retry, or raise IDA_MCP_RPC_TIMEOUT."

### Tests

- **1179 → 1314 passing, 0 failures, ruff clean** — all on every CI commit.
- 8 new test files pinning the contract: `tests/test_tool_cache.py` (cache), `tests/test_data_min_xrefs_filter.py` (min_xrefs), `tests/test_pagination_consistency.py` (envelope shape), `tests/host/test_send_rpc_with_retry.py` (RPC retry), `tests/host/test_dispatch_crash_vs_timeout.py` (timeout vs crash distinction), `tests/test_disasm_window_param.py` (window), `tests/test_session_idle_purge.py` (idle_purge), `tests/test_rpc_hang_sentinel.py` (hang trio), plus `tests/other/test_misc_envelope_cleanup.py` and `tests/live_smoke_pins/` for the 9 crash regressions.

## Cleanup pass (preceding wave)

Earlier commits pruned verified-orphan methods (`intelligence.py` −223 lines), tightened the action registry, and replaced the policy/phase tuple-writing helper with the new `PolicyDecision` enum.

## Migration notes

- **If you call `funcs.list` or `data(functions)`** — pass `min_xrefs=<int>` to filter; `total` reflects the filtered set.
- **If you call `code(action='disasm')`** — `window=N` gives ±N lines around the focus; the response now carries `"window": N`.
- **If you ever set `IDA_MCP_PHASE_GATES=1`** — blackboard followups and phase gating activate; default is `0`.
- **If you script `session(action='cleanup_stale')`** — `prune_orphans=True` is the new default; both `binary_path` AND `idb_path` must be missing for orphan pruning.
- **If you read envelopes** — match on `code` (uppercase, machine-readable) rather than `message` (free text). Look for `category` to decide `USER` vs `RUNTIME` vs `POLICY` vs `INTERNAL` recovery.
