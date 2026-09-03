# Changelog

All notable changes to `ida-pro-mcp`. Dates in YYYY-MM-DD. Versions are not tag-stamped yet — each release maps roughly to a wave of improvements announced here.

## 2026-09-02 — PR-work coverage continuation

 - Added offline boundary coverage for host response helpers, policy and audit
   paths, blackboard trace handling, installer runtime modes, download guards,
   platform process selection, venv recovery, and bundled-runtime setup.
 - Added cross-mode coverage for IDA analysis controls, raw entry seeding,
   bounded auto-analysis, snapshot/undo fallbacks, search compatibility, type
   helpers, and host runtime protocol boundaries.
 - Added debugger/emulation fallback matrices and IDA bridge startup,
   authentication, protocol, and main-thread dispatch coverage, including
   order-independent fake-IDB setup for the cross-mode round-trip tests.
 - Added IDB metadata/state/register compatibility matrices and firmware
   shaping boundary coverage for raw ranges, load-base hypotheses, MMIO/RTOS
   scans, segment carving, audit tails, and degraded SDK modes.
 - Added search metadata truncation/error coverage and FindCrypt extraction
   safety tests for archive links, oversized or symlinked rules, destination
   rollback, and cache discovery fallbacks.
 - Added IDA 9.3/9.4 compatibility coverage for segment/function mutation,
   flow-chart constructor fallbacks, stack-frame resolution, and degraded
   prototype/type surfaces.
 - Hardened semantic and behavior search so unavailable persisted documents
   and optional insight indexes degrade to recall/classifier results instead
   of aborting the request; added coverage for backend, expansion, rerank,
   timeout, and classifier edge modes.
 - Added memory boundary coverage for scalar/string and endian failures,
   wildcard-search engine fallbacks, integer-width limits, compare algorithms,
   cyclic struct walks, region caps, and governed-write error envelopes.
 - Added intelligence lifecycle coverage for status and anchor actions,
   classification/decompilation guards, fast/full/range indexing filters,
   retry cursors, semantic/blackboard/family actions, document shaping, and
   unavailable optional-service modes.
 - Added legacy blackboard boundary coverage for damaged and partial SQLite
   files, migration/raw-copy fallbacks, candidate discovery, machinery/link
   routing, and path-confinement failures.
 - Added orchestration boundary coverage for durable machinery/task failures,
   malformed payloads, queue shutdown and deadline behavior, crawler lifecycle
   fallbacks, frontier RPC selection, and trace claim/error paths.
 - Added IDA-side boundary coverage for plugin restart/platform/port handling,
   ctree action and visitor modes, and shared utility fallbacks for address,
   type, prototype, decompiler, and stack-frame helpers.
 - Added semantic-index coverage for current-session resolution, embedding-first
   cache warmup, malformed persisted vectors, per-row embedding failures,
   lexical fallback, empty indexes, and unusable source payloads.
 - Added graph coverage for real-function cycles, function-less targets, raw
   code scans, CFG call/branch classification, empty dominator charts, xref
   directions, traversal limits, validation errors, and formatter edge cases.
 - Added workflow-batch coverage for fast-path eligibility, policy/session and
   rate-limit fallbacks, malformed RPC responses, truncation/post-processing,
   chaining references, payload limits, and wrapped versus unwrapped failures.
 - Added offline BRON corpus coverage for download-size and checksum guards,
   manifest drift, archive member safety, materialization failures, strict
   verification, partial sources, and empty corpus outcomes.
 - Added batch-manager coverage for executor rejection/recovery, cooperative
   cancellation, shutdown races, result/error states, history trimming,
   persistence debounce and truncation, corrupt reloads, and disk failures.
 - Added server-argument coverage for scope isolation, malformed action
   payloads, noisy scalar/list wrappers, positional aliases, and continuation
   token boundary handling.
 - Added complete offline coverage for the IDA-side blackboard bridge,
   including RPC and direct-IDA crawler probes, optional embedder fallbacks,
   parser limits, and standalone import error paths.
 - Added offline governance coverage for every rule family, ontology threshold
   and inference boundary, custom-rule failures, statistics, singleton helpers,
   and standalone MCP fallback actions.
 - Added shared error-layer coverage for timeout classification, IDA 9.4
   address/image fallbacks, mapped/code/function validation, debugger states,
   path safety, action suggestions, and missing-SDK behavior.
 - Added offline search-code coverage for instruction sequence, text, operand,
   and comment scans across relaxed ranges, context/offset handling, limits,
   timeout exits, malformed ranges, and IDA iteration sentinels.
 - Added deep offline coverage for basic byte, string, immediate, symbol, and
   raw data-value searches across legacy/modern IDA paths, packed literals,
   endian and pointer-width modes, pagination, timeouts, and malformed inputs.
 - Added deep offline coverage for shared search-core caches, segment and code
   iteration, target resolution ranking/fallbacks, and IDA API compatibility
   shims.
 - Added deterministic host rate-limit coverage for partial refills, refunds,
   global denials, and reservation rollback.
 - Added offline host-server coverage for environment normalization, stdio and
   daemon lifecycle/error paths, PID cleanup, native bootstrap handling, and
   legacy batch dispatch.
 - Added integrated session-skills coverage for malformed persistence,
   bootstrap dependency failures, readiness trends, embedding/global
   suggestions, dead-end detection, and triage limits.
 - Added deep offline coverage for advanced search candidate planning, bounded
   intelligence expansion, constant scans, decompiled search modes, and
   structured-index result shaping.
 - Added offline r2 host coverage for memory-root failures, active-session
   fallback, default disassembly windows, and malformed hypothesis inputs.
 - Added offline knowledge-bridge coverage for lazy store fallback, function
   fingerprinting, string-reference limits, and import/export error paths.
 - Isolated the non-interactive reranker installer test from real client
   configuration writers by stubbing both path discovery and client updates.

## 2026-09-02 — Multi-agent configuration and skill system redesign

 - Expanded client configuration support for 8 additional AI coding agent environments:
   OpenClaw (JSON5 nested `mcp.servers`), Pi Coding Agent (`mcpServers`), Hermes
   Agent (YAML `mcp_servers`), Prime Agent (`mcpServers`), modern Cursor paths,
   ZCode (`mcpServers`), Kimi Code (`mcpServers`), and MiniMax Code (`mcpServers`).
 - Added YAML configuration parser/updater (`update_yaml_config`) and nested key
   support to `src/ida_pro_mcp/installer/clients.py`, along with client removal logic.
 - Redesigned skill distribution in `installer/skills/__init__.py` to follow the open
   Agent Skills specification, automatically populating universal discovery targets
   (`~/.agents/skills/`, `~/.claude/skills/`, `~/.codex/skills/`, `~/.openclaw/`, and `~/.pi/`).
 - Added bundled runtime detection and executable launcher shims (`bin/ida-pro-mcp`)
   to `installer/runtime.py`.
 - Added `--auto` non-interactive installation and clean `--uninstall` support in
   `installer/main.py`.
 - Added dedicated `docs/releases/` folder with `docs/releases/v1.0.0a1.md` detailing
   the genesis alpha release.
 - Reorganized documentation into structured subfolders (`docs/releases/`, `docs/operations/`,
   `docs/reference/`, `docs/guide/`) and removed loose root markdown files.
 - Updated the release workflow (`alpha-release.yml`) to automatically resolve
   `docs/releases/${RELEASE_TAG}.md` when publishing, ensured PYTHONPATH includes `src`,
   added `attestations: write` permission, and package `install.sh`, `install.bat`,
   and standalone Linux installer executables into release assets.
 - Synchronized user guides, client setup, and cross-references to the official external
   GitHub Wiki repository (`https://github.com/GrecAndrei/ida-pro-mcp/wiki`).
 - Added mandatory release description template (`docs/releases/TEMPLATE.md`) and
   updated release checklist in `docs/guide/versioning.md`.
 - Updated `AGENTS.md` instructions with current codebase layout, 22+ agent client
   formats, auto-installers, routine checks, and release template safeguards.

## 2026-09-02 — PR-work coverage checkpoint

 - Declared the development tokenizer dependency required by the occupancy
   report tests and standalone CI collection.
 - Made the embedding timeout recycling test deterministic on freshly booted
   CI runners by explicitly placing it outside activation grace.
 - Fixed PR CI lint failures in the session-gate and IDA-side RPC surface
   tests.
 - Expanded cross-mode offline coverage for dispatch continuations,
   annotation/comment management, code-helper scanners, and architecture
   inference.
 - Added remaining cross-mode boundary coverage for session actions and search
   combinators.
 - Expanded installer runtime and CLI coverage across process failures,
   archive safety, signature staging, venv source modes, wizard choices,
   embedder doctor outcomes, and packaged client configuration.
 - Expanded runtime lifecycle, ownership, diagnostics, macro, archive, and
   checkpoint boundary coverage.
 - Added search-combinator parser, cache, index, and degradation-mode tests.
 - Added blackboard governance, filesystem, evidence, memory, and proposal
   lifecycle boundary tests.
 - Added type-library member-editing and compatibility failure-mode tests.
 - Expanded code-helper coverage for sparse disassembly windows, conservative
   API prefilters, detector safety limits, and SDK failure fallbacks.
 - Expanded server-script coverage for startup budgets, authenticated loading,
   and degraded pre-analysis behavior.
 - Expanded session-host coverage for state caching, runtime observability,
   cleanup, and declarative action fallbacks.
 - Added session analysis-gate coverage for watcher confirmation, teardown
   races, background spawn errors, architecture inference, and switch paths.
 - Added dispatch coverage for RPC timeout/connection failures, wall-clock
   termination, policy/guardrail faults, post-processing failures, and path
   safety boundaries.
 - Expanded client-state coverage for runtime-table failures, connection
   teardown and adoption, stale leases, and SSO scope/lifecycle rejection.
 - Expanded runtime-lease coverage for signal races, process-tree identity
   failures, heartbeat transitions, shutdown faults, and registration errors.
 - Added response-pipeline coverage for bounded address collection, malformed
   output filters, session-scoped blackboard lookup, and enrichment fallbacks.
 - Added server-state coverage for request properties, scoped insight-cache
   eviction, persistence failures, and uninitialized gate registries.
 - Expanded compact-response coverage for semantic flags, table conversion,
   dropped values, and opaque batch entries.
 - Expanded bootstrap lifecycle coverage for mitigation, autopilot,
   calibration, disputes, reweighting, and persisted outcome paths.
 - Expanded code-helper coverage for dataflow, firmware signals, decompiler
   diagnostics, structured disassembly, argument tracing, and detector scans.
 - Added deeper code-helper coverage for indirect ctree calls, computed sizes,
   constant-load string fallbacks, and disassembly recovery paths.
 - Added code-helper boundary coverage for nested ctree safety checks,
   pcrel string materialization, and tight-window recovery.
 - Expanded session administration coverage for narrative limits, validation,
   bulk tagging/deletion cleanup, snapshots, merges, macro registry behavior,
   conditional workflow branches, and recent-workset options.
 - Expanded session-state coverage for open-argument conflicts and aliases,
   analysis polling, enriched open results, discovery/get/note visibility, and
   legacy coverage-cache parsing and eviction.
 - Expanded support-helper coverage for GGUF scalar/array parsing and profile
   aliases, Sigma rule filtering and archive handling, and audit hashing,
   redaction, rotation, pruning, and serialization failure paths.
 - Expanded runtime coverage for live-process snapshots, state/RPC gates,
   checkpoint failures, teardown lock handling, IDA argument fallbacks, and
   backup/sidecar cleanup errors.
 - Expanded multi-session coverage for malformed persisted groups, cache-write
   failures, export/import aliases, cross-session resolution and decompilation,
   deep xrefs, detailed status, and uninitialized helper state.
 - Expanded session coverage for fresh/reused opens, inferred architecture
   recommendations, runtime failure envelopes, skill and triage actions,
   analogy application, activity and hypothesis tracking, macro execution,
   workflow validation, and recent-workset boundaries.
 - Expanded fake-ctree vulnerability coverage for allocator and format
   argument conventions, prototype mismatches, UAF/NULL handling, call
   injection patterns, CFG reachability, stack-frame findings, writable
   globals, suspicious shared strings, shellcode markers, and processor modes.
 - Expanded gadget coverage across architecture-specific pivot catalogs,
   RISC-V parser and decoder fallbacks, public dispatch modes, raw/head scans,
   mitigation persistence, classifier failures, and exploit-chain blackboard
   safeguards.
 - Added offline architecture coverage for RISC-V GP reference repair,
   stale/unmapped target handling, processor-option fallback, reanalysis
   scheduling, and signed immediate detection.
 - Added offline type-action coverage for public aliases, parser and apply
   failures, struct/enum validation, inference/read/vtable guards, and TIL
   lifecycle errors.
 - Added offline search-combinator coverage for boolean composition, call-graph
   path and reachability, direct outlier fallbacks, semantic and vulnerability
   guards, and detector primitive limits.
 - Added offline emulation coverage for backend absence and fallback
   selection, debugger event pumping, architecture register helpers,
   rejected lifecycle operations, memory byte fallback, and teardown errors.
 - Added offline coverage for code-helper decompiler diagnostics, firmware
   constant/string fallbacks, annotation comment recovery, and detector
   metadata failure and limit paths.
 - Expanded deterministic offline coverage across the host/IDA bridge, public
   operation dispatch, response handling, type and analysis surfaces, gadget
   discovery, retrieval, and cross-mode test isolation. The corrected PR branch
  current branch-aware source coverage snapshot measures 87.25%;
  installer discovery, installer mode contracts, and bridge startup/runtime
  failure paths received another focused test pass. Opt-in live-IDA tests
   remain separately gated.
 - Added cross-mode tests for context indexing, persistence, telemetry,
   housekeeping, enrichment failure handling, compaction, and singleton
   lifecycle behavior.
 - Added analysis-helper coverage for raw-binary detection, mapped-range
   fallbacks, executable-segment scoring, auto-analysis scheduling, and entry
   point bootstrapping.
 - Added session-action coverage for bulk lifecycle operations, skills,
   analogies, hypotheses, activity, recent worksets, macros, and conditional
   workflow steps.
 - Hardened installer state discovery, runtime lease identity checks, bounded
   metadata reads, enum compatibility, and constant-scan progress handling
   while keeping this PR focused on coverage and stability.
 - Added focused offline matrices for debug symbols, deep imports, query
   parsing/execution, semantic matching, synchronization/cache behavior,
   batch macros, bootstrap-session validation, and gadget architecture,
   mitigation, and dispatch modes, plus function-management, decompiler
   helper, and compositional-search paths. Also fixed comparison aliases such
   as `neq` being parsed as the shorter `ne` operator.
 - Added offline coverage for the public type operation's inspection,
   declaration, local/global/function application, inference, structured reads,
   propagation, dependency graphs, vtables, member editing, enum editing, and
   TIL carry paths, including IDA 9 fallback behavior and explicit failures.
 - Added offline coverage for analysis option rebasing, processor and endian
   selection, loader-option persistence, code/data conversion, analysis flags,
   offset creation, bounded reanalysis, raw mapped-range discovery, executable
   segment scoring, and scoped auto-analysis waits.
 - Added host-runtime coverage for framed localhost RPC, auth-token injection,
   fragmented responses, queue contention, bounded retries, payload limits,
   process termination, library-init diagnosis, IDA discovery, backend command
   construction, safe rendering, and IDB backup paths.
 - Hardened the memory filesystem boundary by rejecting symlink components before
   path canonicalization, and added dispatch coverage for filesystem,
   bookmark, truncation, plugin, policy, and strict-gate modes.
 - Isolated the expanded fake-IDB coverage modules so their temporary SDK
   imports cannot affect unrelated tests in the full suite.
 - Restored the shared compatibility module after import-surface fixtures so
   fake segment lookups cannot leak across IDA-side test modes.
 - Extended the central test isolation boundary to restore compatibility
   helpers alongside SDK stubs for the complete offline suite.
 - Made the TIL export error-path fixture remove both supported ordinal-count
   API spellings, keeping it valid with the complete fake-IDB harness.
 - Added offline CLI boundary coverage for stdio framing, daemon ownership,
   background jobs, raw JSON-RPC, and actionable process/socket failures.
 - Added native-backend coverage for ctypes loading, availability selection,
   cache generations, and failure recovery, plus r2 coverage for parser,
   environment, subprocess, disassembly, bininfo, and pointer-scan boundaries.
 - Added reranker lifecycle coverage for state/profile resolution, lease
   identity rejection, malformed responses, cache waiters, deadline handling,
   and subprocess recovery paths.
 - Added threat-corpus boundary coverage for malformed and normalized CWE,
   ATT&CK, and YARA inputs, source download/build failures, cache fallbacks,
   and singleton recheck behavior.
 - Added cross-platform runtime coverage for process-tree failure handling,
   psutil filtering, Windows WMIC fallback, Linux `/proc` discovery, and
   live-runtime protection.
 - Added intelligence-core coverage for GPU and model discovery fallbacks,
   shared embedder lease probing, idle shutdown state, and classifier cache
   generation edges.
 - Added gadget-discovery boundary coverage for cross-architecture terminators,
   raw/head scan selection, write-where and stack-pivot shapes, pivot-chain
   fallbacks, and exploit-assessment modes.
 - Added intelligence-core coverage for model/state discovery fallbacks,
   conservative lease validation and retirement, Windows lock handling, GPU
   startup selection, embedding-cache waiters, and classifier cache/report
   behavior.
 - Added embedding-index coverage for document/token boundary handling,
   corrupt-row reloads, fail-soft metadata access, vector/search edge cases,
   structured API filtering, and lexical-only hybrid results.

## 2026-09-01 — documentation, contribution policy, and alpha artifacts

- Reworked the README around installation, first use, investigation workflow,
  safety, privacy, and troubleshooting instead of implementation detail.
- Added readable task-oriented wiki pages and published them to the project
  GitHub wiki.
- Added contributor guidance with required `[minor]`, `[relevant]`, `[major]`,
  or `[PR-work]` commit prefixes and sparse-commit rules.
- Added immutable GitHub Actions pins, dependency review, commit/workflow
  policy checks, and a manually protected alpha release-artifact workflow.

## 2026-09-01 — expanded coverage and test stability

- Expanded offline and opt-in live coverage across the public and legacy MCP
  surfaces, and stabilized batch-history and client-path tests.

## 2026-09-01 — checkout-backed skill installation

- Reuse the Codex skill symlink when it points to the active checkout, while
  continuing to reject unrelated symlink redirects.

## 2026-08-27 — 1.0.0a1 repository cleanup and retrieval foundations

- Centralized the package, MCP handshake, CLI, and benchmark version in
  `src/ida_pro_mcp/_version.py` using a documented PEP 440 alpha scheme.
- Moved maintained guides under `docs/guide/`, added a documentation index and
  versioning guide, and removed the stale radare2 research audit.
- Replaced checked-in workstation benchmark results and ad hoc runners with
  `benchmarks/run.py`, covering contract, host, blackboard, retrieval, and
  opt-in live-IDA scopes with reproducibility metadata.
- Fixed native llama.cpp retrieval batching to split by total token capacity;
  long corpus batches no longer abort inside `llama_decode`.
- Matched native embedding tokenization to llama-server's EOS handling and
  made F16 KV the default for vector parity; Q8 KV is an explicit
  memory/speed tradeoff. The HTTP backend now preserves the configured
  per-slot context instead of being silently clamped by a smaller microbatch.
- Tuned the default CPU rerank pool from 12 to 8: the bundled 12-query corpus
  measured recall@1 0.9167 → 1.0, MRR 0.9583 → 1.0, with all 12 rerank scores
  discriminating, while removing one-third of the cross-encoder passes.
- Improved blackboard retrieval with query/document embedding purposes,
  embedding identity and dimension checks, structured document text, full
  lexical fallback coverage, and explainable hybrid ranking.
- Removed personal installation paths from tests, smoke tooling, and native
  build documentation; native builds now require explicit external paths.

## 2026-08-13 — full-surface live integration suite + 9.3/9.4 API-drift fixes

- **Expanded live integration coverage** — two new opt-in suites
  (`tests/integration/`): `test_agent_surface_catalog_live.py` runs every
  public `ida_*` operation from `AGENT_OPERATIONS` against a real stdio
  server + real IDA (101 ops: must answer correctly with the documented
  example, or fail with a coded error), and
  `test_agent_surface_behavior_live.py` proves 66 deep behaviors (exact
  decompile/disasm shapes, calc semantics, type round-trips incl. TIL
  export/import, findings lifecycle, mutation→verify→restore, undo
  transactions, snapshots, batch bindings/chaining, r2 sidecar, firmware
  heuristics, python tool). The full 217-test integration package now
  passes on idalib 9.3 and 9.4.
- **`FlowChart` construction fixed on 9.4 (unbreaks indexing)** —
  `compat.get_flow_chart` now cascades through the range overload, the
  idalib 9.4 pythonized ctor (`FlowChart(f=None, bounds=(start, end))`),
  and the legacy title-based ctor; `_build_range_chart` gets the same
  fallback. Previously every function's index metadata collection crashed
  on 9.4 (`qflow_chart_t` TypeError), so background indexing reported "No
  embeddings were created" and indexing was broken in production. Also
  fixed `func_entry_info_t.flags` (absent on 9.4) in index metadata and
  function info via `compat.get_func_flags`.
- **Undo/snapshot/entry fixes (9.3 + 9.4)** — `undo_begin`/`undo_end`
  feature-detect `ida_undo.undo_begin` → `ida_bytes.undo_begin` →
  `create_undo_point` fallback (the transaction API moved out of the Python
  surface on 9.x), reporting the `mechanism`; `restore_snapshot` accepts
  `snapshot_id`/`snapshot_name`/`ordinal` with LIFO pops (capped) and gains
  the `snapshot_id` param; `add_entry` derives the entry ordinal
  automatically instead of requiring one.
- **Types rework** — `declare`/`apply_type` retry parsing with a trailing
  `;` and verify saves via `get_named_type` (never trust `set_named_type`'s
  return); `_parse_member_type` resolves named types, maps
  `char`/`int`/`short`/etc. to fixed-width aliases, and builds `char[N]`
  via `create_array`; `struct_member_set_type` falls back to delete-tail +
  re-add when a retype overlaps trailing members; `til_export` emits
  parseable C via `print_tinfo` (typedefs skipped) and `til_import` parses
  native-format headers per-declaration with struct-name rewriting,
  falling back to `parse_decls` for foreign headers.
- **Other fixes** — `save_idb` treats an empty path as in-place (9.4
  rejects `save_database("")`); register classes are synthesized via
  `get_reg_name` + `ph_get_reg_*_sreg` accessors; `load_sig` falls back to
  `idc.plan_to_apply_idasgn`; `set_segment_attrs perm` accepts `"rwx"`
  strings; declaration-like args (`decl`/`type_str`/`declaration`/
  `prototype`) no longer lose their trailing `;` to wrapper stripping, and
  `struct_member_add` keeps its semantic `offset`.
- **Docs** — TOOLS_REFERENCE/SKILL.md regenerated; wiki updated (edit:
  undo/snapshot/add_entry, types: declare/member/TIL invariants);
  LIVE_IDA_TESTING.md documents all three live suites.

## 2026-08-12 — idalib runtime backend (opt-in) + 9.4 memory_model/GP closure

- **idalib backend (`IDA_MCP_RUNTIME=idalib`)** — sessions run inside the
  IDA kernel via the idapro whl instead of spawned idat processes.  The
  worker (`ida_pro_mcp/idalib_worker.py`) imports `idapro` first (it must
  be the first IDA import — hence a top-level module, not under `ida_mcp`,
  whose package `__init__` imports `sync`/`ida_kernwin`), opens the
  database with `enable_history=True`, then executes `server_script.py`'s
  `__main__` unchanged — the RPC listener, startup analysis and main-thread
  dispatch loop are byte-identical, so the host treats the worker exactly
  like an idat runtime (same env, port handoff, ping protocol, leases,
  teardown).  Shutdown runs `close_database(save=True)` (flush on exit).
  **Verified live: the full integration suite passes under idalib on both
  9.3.260421 and 9.4.260714 (42 passed / 8 skipped each)**; the runtime
  matrix (`run_ida_matrix.py --idalib`) runs all four legs and the
  self-hosted workflow passes `--idalib`.
- **Snapshot/undo mapping** — idalib has no `ida_loader.save_snapshot`/
  `restore_snapshot`; `analysis(snapshot/restore_snapshot)` feature-detects
  this and falls back to `ida_undo.create_undo_point`/`perform_undo`
  (LIFO restore), with `mechanism` reported in the response.  Verified live
  on 9.4 (rename → undo → restored).
- **Host seam** — `_preload_ida_args(session)` extracted from
  `_build_ida_command` so idat and idalib load with identical architecture
  flags; `_build_idalib_command` passes them via `IDA_MCP_IDALIB_OPEN`
  (`-o` only for new databases — idalib refuses an existing output with
  rc=2, surfaced with a diagnostic hint).  `--ida-runtime`-style selection
  is host-env driven (`IDA_MCP_RUNTIME`), validated per launch.
- **Installer** — wizard section "IDA session runtime backend" (idat
  recommended / idalib experimental) with idapro detection + activation
  (`py-activate-idalib.py -d <install>`), `--ida-runtime {idat,idalib}`
  flag, `find_idalib_python_dir`/`activate_idalib` helpers, and
  `IDA_MCP_RUNTIME` written into the generated client config env.
- **Regression fixed during the port** — `_build_idalib_command`'s
  PYTHONPATH root is the import root three levels above `host/server/`
  (the matrix only passed earlier runs because the host's cwd happened to
  be the repo root).
- Earlier 2026-08-12 items closed in this wave: headless RISC-V
  GP-relative xref resolution (`set_gp`), `get_arch()` on 9.4, and the
  `memory_model`/`processor_options` pre-analysis TODO (see the
  ida-9.4-migration research doc + wiki).  The GP `sreg_set` wiki seam was
  removed (RISC-V registers zero segment registers — live-probed).
- Not implemented (documented in `docs/research/idalib-runtime.md`):
  two concurrent sessions on one idalib worker (DB-swap + per-IDB state
  reset); the current model is one worker per session, preserving
  spawn-idat crash isolation.

## 2026-08-11 — IDA 9.4 support: compat layer + migration inventory

IDA 9.4 (build 9.4.260714) deprecates ~118 pointer-based IDAPython APIs in
favor of EA-based variants that avoid returning IDA-allocated pointers. The
old names still work (one DeprecationWarning per process each) but the
replacements are 9.4-only, so compatibility is handled by runtime branching
against the install the user selected in the installer — not a floor bump.

- **`ida_mcp/compat.py`** (new): import-time feature detection per API
  family (`HAS_EA_FUNCS` / `HAS_EA_DECOMPILE` / `HAS_EA_SEGMENT` /
  `HAS_DECOMPILER`) plus wrappers that prefer the 9.4 EA-based entry point
  and fall back to the legacy one on <= 9.3. Self-heals across point
  releases; deleted when the supported floor rises to 9.4.
- **`decompile_func` → `decompile_function` migration** (worked example):
  `utils.refresh_decompiler_ctext` and both `code_helpers` decompile paths
  (including the auto-analysis nudge + retry) go through
  `compat.decompile_function`.
- **`tests/ida_mcp/test_compat.py`**: fake 9.3/9.4 ida_* surfaces pin that
  each side selects the right underlying call.
- **`docs/research/ida-9.4-migration.md`**: full migration inventory (~300
  deprecated-API call sites: 193 `get_func`, 46 `getseg`, 29
  `get_segm_name`, ...), new-surface adoption candidates (`ida_indexer`,
  `ida_dscu`, idalib `execute_sync()`), and the RISC-V validation plan
  (9.4 fixes the eager `auipc` merge and several decoding bugs; raw-blob
  arch/GP inference stays ours).
- Installer discovery verified unchanged against 9.4:
  `detect_ida_installs()` reports both side-by-side installs with correct
  version/build strings.

Follow-up commits the same day complete the mechanical migration:

- **Segment family** (37 sites / 13 files, then the rest): all
  `get_segm_name`/`get_segm_class`/`set_segm_name`/`move_segm`/
  `get_segm_by_name` call sites plus every pure attribute-read `getseg`
  site migrated; `compat` gained `get_segment`, name/class/set/move
  wrappers, `get_segment_ea_by_name`, first/next segment iteration, and
  the `get_segment_perm/type/align/bitness` accessors (9.4's
  `segment_info_t` exposes those only via `get_*()` methods).
- **Function family** (~168 of ~193 `get_func` sites / 26 files):
  `get_func_start` / `get_func_info` / `get_func_flags` /
  `set_func_flags` / `get_prev_func_start` / `get_next_func_start`
  wrappers; both `update_func` sites became the flags composition; the
  `_get_prev_func`/`_get_next_func` helpers are EA-or-None on all
  versions. 25 sites remain legacy by design (they hold `func_t *` for
  FlowChart / get_prototype / get_frame / thunk APIs) — tracked in the
  migration doc as the next audit batch.
- `idc.get_func_cmt`/`idc.set_func_cmt` verified already EA-based and not
  deprecated — no migration needed there.
- Suite stays at 2820 passed / ruff-clean throughout; test fixtures that
  exercise migrated code gained dual-surface `sys.modules` wiring for the
  call-time module resolver.

Final commit of the day closes out the mechanical migration entirely:

- **`func_t`-holding remnant** (25 sites): FlowChart accepts an
  `ea_range_t` in place of `func_t *` on every supported version, so
  `_compat.get_flow_chart` builds charts from function bounds;
  `calc_thunk_func_target` → `calc_thunk_function_target`
  (func_entry_info_t-based), `ida_frame.get_spd` → `get_func_spd`,
  `pfn.frame` → `func_entry_info_t.get_frame_id()`, and our own
  `utils.get_prototype(fn)` → `_compat.get_prototype_string(ea)`.
- **Segment mutation**: `update_segm` is not deprecated and
  `segment_info_t` has full `set_*` methods, so `_compat.set_segment_attr`
  (set_segment_info on 9.4) and `_compat.add_segment` (add_segment_ex on
  9.4) close the last `getseg`/`add_segm_ex`/`move_segm` sites in
  segments.py and firmware.py; `get_segment_comb`/`get_segment_color`
  accessors complete the read surface.
- A sweep over all 118 deprecated names finds zero real call sites outside
  compat.py. Only deferral left: the struc-based stack-frame member walk
  (`ida_frame.get_frame` was *removed* in 9.4, not deprecated) needs a
  `get_func_frame_ea` + `udt_type_data_t` rewrite; both sites degrade
  gracefully in the meantime.
- Suite: 2831 passed / ruff clean (21 compat dispatch tests).

### 2026-08-12 — 9.4 validation closes every remaining work item

- **Live runtime matrix (9.3 + 9.4)**: `scripts/run_ida_matrix.py` runs
  `tests/integration` against every detected install; the self-hosted
  `ida-runtime-matrix.yml` workflow is the CI form (dispatch-only,
  guard-tested). **42 passed / 8 skipped on both 9.3.260421 and
  9.4.260714 live** — the EA-API migration is end-to-end validated.
- **RISC-V on 9.4**: fixture decode byte-identical to 9.3 except the
  documented `c.` compressed-instruction prefix; auipc sites unchanged;
  `lui`/`%hi/%lo` constant recovery identical. GP-relative resolution
  remains unreachable headless on both versions (`idc.set_processor_options`
  absent from the idat runtime; sreg seams don't drive the plugin) —
  documented in the wiki with a truthful-error note.
- **Bug found by validation**: `modify` `create_strlit` passed an end
  address as the length arg to `ida_bytes.create_strlit(start, len,
  strtype)` (defined strings to segment end, or failed); fixed, fakes
  updated to the real signature.
- **`ida_list_strings`**: API unchanged on 9.4 (`get_strlist_qty`/
  `get_strlist_item` live-verified); `get_strlist_item_ex` +
  `decompiler_string` is an additive watch-item only.
- **`ida_indexer` not adopted**: `ENABLE_INDEXER` is disabled under batch
  mode (confirmed live), so the indexer can't serve headless `ida_find`.
- **idalib not adopted**: design doc at
  `docs/research/idalib-runtime.md` (verified idapro whl/activation/API
  facts, acceptance criteria); spawn-idat stays default.
- **Installer**: `python_environment_kind()` classifies uv/conda/
  homebrew/pyenv/asdf interpreters and the wizard warns on 9.4+ installs,
  mirroring IDA's own libpython-mismatch awareness.
- Suite: 2836 passed / ruff clean (24 compat dispatch tests, 19 installer
  host tests, 3 CI-guard tests).

### 2026-08-12 — RISC-V GP-relative xrefs resolve headless; get_arch fixed for 9.4

- **`set_gp` now works headless**: `arch_utils._riscv_gp_fix_refs()`
  re-points GP-relative data refs. IDA decodes `ld rd, disp(x3)` as
  `o_displ(reg=GP)` and creates refs against an implicit GP of 0 (raw
  displacement — `ld a3, -7FFFFFE0h` ref'd 0xffffffff80000020). The scan
  computes `target = GP + disp` (XLEN-masked) and re-points stale refs via
  `del_dref`/`add_dref` (dr_R loads, dr_W stores); unmapped targets
  skipped, existing correct refs untouched, previous-GP refs cleaned on
  re-set. Response reports `refs_fixed`/`refs_skipped`; reanalysis is only
  queued on the GUI directive path (neither `set_processor_options` nor a
  usable `process_config_directive` exists in idat — verified live).
  **Validated on real 9.3 and 9.4**: fixture refs re-pointed to
  0x40/0x48/0x50, `xrefs_to` resolves, GP re-set moves and cleans refs.
- **`get_arch()` 9.4 regression fixed**: `idaapi.get_inf_structure` was
  removed in 9.4, silently degrading arch detection (and everything gated
  on it) to "unknown"; now prefers
  `ida_ida.inf_get_procname`/`inf_get_app_bitness` (both 9.3/9.4) with
  legacy fallbacks. Confirmed live (`riscv` → `riscv64`).
- Host tests: 9 new scripted-IDA dispatch tests (ref re-pointing, unmapped
  skip, idempotency, non-GP operand rejection, previous-GP cleanup, XLEN
  masking, non-RISC-V no-op, 9.4 inf-API arch detection, headless apply
  path). Suite: 2845 passed / ruff clean; live matrix PASS on 9.3 + 9.4.
- **`memory_model` TODO resolved**: the option is documented in the
  open_binary contract but IDA 9.x removed the memory-model attribute
  entirely (no `ida_ida.inf_set_mtype`, no `INF_MTYPE`, no
  `idainfo.mtype`; MT_* constants gone — verified live on 9.3 and 9.4).
  `_apply_pre_analysis_options` now applies it via `inf_set_mtype` with
  the host→MT_* mapping (0→MT_FLAT, 1→MT_16, 2→MT_32) when a future IDA
  reintroduces the setter, and otherwise emits an explicit warning instead
  of silently dropping it.  The `processor_options` path also gained the
  `ida_idp.process_config_directive` fallback (the only processor-option
  API that exists in the 9.3/9.4 idat runtime).  Open-binary schema
  descriptions updated; generated docs refreshed.  Live probe on 9.4:
  `processor_options` applies via the directive fallback; `memory_model`
  yields the explicit "not supported" warning.
- **Wiki corrected**: RISC-V registers zero segment registers (live probe:
  `get_sreg_names` empty; `split_sreg_range`/`set_default_sreg_value_ea`
  reject x3), so the previously documented
  `ida_segments(action="sreg_set", reg="GP")` seam does not exist — the
  section now directs users to `set_gp`, marks the sreg recipe as
  unsupported, and scopes the reanalysis-queue claim to the directive path.

## 2026-08-09 — settle wave: q05 tool verification, h02 runtime lifecycle, arch auto-apply

Settle/integration pass over the completed feature waves: the q05 analysis-surface
directives are verified and pinned, the session-lifecycle revamp's runtime layer
gains a real shutdown bridge, opaque-blob architecture auto-apply lands, and the
repo is landed ruff-clean.

### q05: calc / graph / gadgets / imports / data / memory
- **calc**: all address-context tokens route through the shared
  `parse_address_canonical` (symbol-first, hex-by-default in-image bare tokens,
  `ADDRESS_INVALID` for ambiguous/unmapped, crisp `no file mapping` on
  headerless blobs). `calc deref` `type="string"` now falls back to a bounded
  printable-run scan when no string literal is defined (raw blobs), mirroring
  `memory read type="string"`.
- **graph**: `cfg` and `dominators` report pre/post truncation counts
  (`nodes_before_truncation` / `edges_before_truncation` / `truncated`) and
  `dominators` now honors `max_items` (the dominator tree is still computed over
  the full block list so idoms stay correct). `callgraph` reports
  function-less-target placeholders + count; raw-blob fallbacks auto-note.
- **gadgets**: new optional `raw=True` opt-in (byte-level linear sweep);
  `rop`/`jop`/`cop`/`syscall` auto-fall back to the sweep on headless exec
  regions and carry a `note`. RISC-V register-indirect branches are classified
  through the shared `arch_utils` classifier — `jalr t0, 0(ra)` is now a JOP
  jump (not a ROP return), compressed `c.jr`/`c.jalr` terminators appear in the
  finders, and RISC-V write_what_where excludes `sp`/`fp` frame saves. The host
  `TOOL_ARG_SCHEMAS["gadgets"]` now advertises `raw` so it reaches the handler.
- **imports_deep / data / memory / misc / symbols**: verified and regression-
  pinned (ELF PLT/GOT thunk resolver, `no import table` note, `string_xrefs`
  zero-ref scoring, memory read/write split riding `@idaread`/`@idawrite`).

### h02: runtime lifecycle bridge
- **server_script**: the `__main__` join loop now waits for the listener thread
  to exit instead of returning on the shutdown event — the handler's
  best-effort `save_database` completes and the shutdown response is delivered
  before the process exits (daemon threads are not joined at interpreter exit).
  The RPC listener answers pings (`analyzing: true`) while startup analysis is
  still gated; shutdown is auth-checked and reachable mid-analysis.
- **runtime**: a fresh spawn retires a crashed runtime's log fds and stale
  port/auth token first; auto-restart is refused only while a close/delete is
  actually running; `_terminate_ida_processes_for_path` matches the IDB path as
  an exact argv argument; spawn envelope reports `indexing_state="disabled"`;
  periodic analysis checkpoints (`checkpoint_save_seconds`) persist a marker and
  a resume warns when it is stale; watcher/checkpoint threads stop cleanly.
- **arch auto-apply**: high-confidence non-ambiguous opaque-blob inferences
  (Cortex-M conf 0.92, RISC-V rv64c with a definite bitness call) are applied
  into the spawn options and surfaced in the open response; ambiguous
  rv32c/rv64 near-ties and sub-0.9 guesses are never forced.
- **leases**: the heartbeat keeps a lease while the idat launcher exited but an
  ida-named analysis child is still alive; stale-lease cleanup tree-kills the
  launcher's process group (taskkill `/T` on Windows) so orphaned children that
  hold `.id0`/`.id1` open are freed; shutdown stops watchers/spawns first.

### Blocker fixes
- `code_helpers._function_may_reference_apis` is now a conservative superset:
  an inconclusive cheap scan (register-indirect call with no resolvable operand)
  returns True so the ctree API-chain detector runs instead of silently dropping
  the function.
- `tests/conftest.py` `_isolate_sys_modules` snapshots and restores `sys.path`
  per test, fixing the `q07 → t19` import-cache and `q07 → q01` collisions
  (server_script inserts src dirs at module scope); the q04 deadline test now
  restores the real `time.time`/`time.monotonic` so the shared module is never
  left frozen.
- `batch_manager` parks its ThreadPoolExecutor when the queue goes idle, so
  `batch-*` worker threads are reclaimed instead of lingering; `shutdown()` is
  idempotent.

### Ruff cleanup
- Repo-wide sweep to zero findings (`ruff check .` passes): lambda inlining in
  tests, `UP031` → f-strings, `SIM103`/`SIM114`/`SIM105`/`E731`/`PLR1714`/
  `C416`/`PIE808`, unused imports. The cross-arch set duplicates in
  `arch_utils` (beq/bne/blt/bge, li/lui, addi/add/mul) are intentional shared
  encodings and are kept with targeted `# noqa: B033` comments.
- Docs regenerated (`scripts/generate_tool_skills.py`); schema integrity check
  passes (33 legacy tools, 103 agent operations).

## 2026-08-09 — blackboard analysis-memory redesign

The findings workspace and the legacy blackboard are merged into one SQLite
store (per binary digest under `cache/blackboards/`), with analyst memory,
machinery, embeddings, links, code anchors, and events in one schema and a
single `{proposed, open, confirmed, resolved, rejected}` status column.
`resolved`/`contradicted`/`conflicts_with` are now derived at read time.

### Store & schema
- One store: `findings` (memory), `bb_tasks`/`bb_machinery` (machinery owned by
  the orchestrator), `findings_embeddings`, `links`, `code_anchors`,
  `finding_events`. `rejected_reason` replaces `contradiction_reason`.
- Idempotent migration runner (`PRAGMA user_version`) with a compat `blackboard`
  VIEW over `findings` plus an INSTEAD OF UPDATE trigger, so legacy readers and
  the seeding seam keep working. Fixed the legacy-migration INSERT whose VALUES
  clause carried one too many `?` placeholders (silent fallback on old IDBs).
- Host dispatch is dict-driven: `server_blackboard.py` routes each action to a
  `_bb_action_*` handler through `_BLACKBOARD_ACTIONS`; the IDA-side
  `tools/blackboard.py` is a thin bridge (store subclass + `related_by_behavior`
  + `CrawlerProbe` adapter).

### Tool/action surface (design contract changes)
- `blackboard` tool drops the legacy KG actions and kwargs: `propagate_labels`,
  `quest_board`, `quest_complete`, `semantic_index`, `semantic_rebuild`, the KG
  family (`kg_add_system`, `add_struct`/`add_gap`/`add_state_machine`/
  `add_peripheral`/`add_attack_surface`, `fill_gap`, `kg_*` queries,
  `export_symbols`, `related_by_behavior`) and the 17 legacy kwargs (`members`,
  `entry_points`, `exit_points`, `size_bytes`, `hints`, `gap_type`,
  `binary_type`, `gap_id`, `filled_by`, `state_var`, `states`, `periph_type`,
  `drivers`, `reachable_from`, `input_type`, `call_stack`, `resolved`).
- `ADVERTISED_ACTIONS['blackboard']` curated to the 27 live actions: write,
  read, list, search, update, delete, stats, coverage, next_target, frontier,
  workspace_brief, decision_card, mark_examined, recall, conflicts, stale,
  export, publish_findings, import_annotations, memory_compile, phase_status,
  policy_status, state_health, start_crawler, crawler_status, proposal_list,
  trace_status. Policy read-exemption for `quest_board` removed; the
  `semantic_rebuild` long-running marker removed.
- `trace_run` is now async (returns `{ok, enqueued, task_ids, status}`);
  `trace_status` reads task rows; governance blocks return the
  `POLICY_DENIED` envelope.
- Agent-operation status enum gains `proposed` (blackboard accepts it; the 10
  `ida_*` agent-op enums are unchanged).

### Orchestration & crawler
- `BlackboardOrchestrator` owns machinery DB access, a bounded `TaskPool` with
  `drain()`, the evidence-gravity snapshot, and the frontier crawler that writes
  real proposed entries; the host probe slot routes through the in-process tool
  dispatch (`_execute_tool("code", smart_decompile)`), superseding the
  standalone-interpreter `CrawlerProbe` fallback.

### Docs & tooling
- `.agents/skills/` SKILL.md/operations.md and `docs/TOOLS_REFERENCE.md`
  regenerated from the curated action surface; investigation/frontier wiki pages
  document the new status lifecycle, derived conflicts, and coverage honesty.
- Smoke script, schema-admission tests, and the trace/coverage/policy test
  suites updated to the async contract and the curated action list.
- `scripts/check_schema_integrity.py` passes (33 legacy tools, 103 agent
  operations).

## 2026-08-09 — unified registration, r2 sidecar seam, firmware shaping, policy tiers

Registration wave that makes every new tool/action produced by the feature
orders first-class on the agent surface and inside the risk-policy engine.
Agent operation count grows from 67 to 103.

### Tool/action registration
- **New `r2` tool** (Rizin/radare2 sidecar engine, default-off): `status`,
  `bininfo`, `load_hints`, `disassemble_hypothesis`, `vxrefs` — pre-IDA triage
  on raw binaries without an IDB.
- **`firmware` tool resurrected** (headerless raw-blob shaping): `detect_vector_table`,
  `detect_load_base`, `detect_mmio`, `rtos_scan`, `carve`.
- **Action-list extensions**: `segments` gains `sreg_get`/`sreg_set`/`sreg_list`;
  `modify` gains `create_data`/`create_strlit`/`undo_begin`/`undo_end`;
  `analysis` gains `add_entry`/`snapshot`/`restore_snapshot`/`auto_wait`;
  `idb` gains `events`/`registers`; `search` gains `data_value`/`query_lang`;
  `types` gains the `struct_member_*`/`enum_member_*` editors plus `til_delete`,
  `til_export`, `til_import`.
- **36 new agent operations** exposed on the agent surface: sreg triage/set,
  raw-blob authoring (`create_data`/`create_strlit`) and reversibility primitives
  (`undo_begin`/`undo_end`), entry-point marking and IDB snapshots, struct/enum
  member editing and TIL carry, event/register inspection, raw-value and
  query-language search, the full r2 sidecar family, dangerous-API marking, and
  firmware shaping. `ida_batch` gains an optional `bindings` map.
- `schemas_data.TOOL_ARG_SCHEMAS` now admits the previously-open `modify`,
  `types`, `annotation` tools and the new `r2`/`firmware` tools, so every param
  reaches the handler instead of being silently stripped.

### Policy tiers
- `firmware` joins `WRITE_IDB_TOOLS`; `carve` stays WRITE_IDB while the
  `detect_*`/`rtos_scan` probes classify READ.
- New `NETWORK_OR_PROCESS_ACTIONS` set (forward-declared `r2 start`/`r2 attach`)
  with a `NETWORK_OR_PROCESS` check in `classify_tool_action`.
- All `modify`/`analysis`/`types`/`segments` write actions and `til_export`
  (filesystem write) / `til_import` (filesystem read) are explicitly tiered.

### Docs & prompts
- `QUICKREF_TEXT` gains a **Raw Firmware Triage** section pointing at
  `ida_r2_bininfo`/`ida_r2_load_hints`, `search data_value`, and the firmware
  `detect_*` ops.
- `README` operations table and count updated; `docs/TOOLS_REFERENCE.md` and
  `.agents/skills/` regenerated from the 103-op registry.

## 2026-08-09 — opaque-binary (RISC-V) analysis polish

Focused pass on headerless raw `.bin` device firmware — the "MCP gets confused"
case — plus search/speed/reliability seams that radare2-style triage depends on.
Opaque RISC-V blobs now get first-class arch/bitness/load-base inference,
operand-aware RISC-V instruction classification, GP/entry bootstrap at open, and
crisp "arch unverified" warnings instead of confident-wrong metapc decoding.

### RISC-V on opaque raw blobs
- **`arch_profile` gains riscv32/riscv64 as first-class candidates**: opcode
  density (auipc/lui/jal/jalr/c.jr/c.jalr/ecall-CSR) plus an RV32C/RV64C
  instruction-validity scan, bitness inferred (RV64 ld/sd/lui-hi20 density vs
  RV32), absolute-signal confidence (no inflated best-of-N), and a populated
  `load_base` (Cortex-M reset vector & ~1, dominant lui/auipc base, SoC bases
  0x80000000/0x10000000). `riscv64/rv64/riscv32/rv32/riscv` resolve to the
  canonical IDA `riscv` module with implied bitness.
- **Operand-aware RISC-V return classification**: `jalr rd,imm(rs1)` is a return
  only when `rd==x0` AND `rs1==ra`; `c.jr` returns only when `rs1==ra`; `c.jalr`
  is a call. ABI (zero/ra) and numeric (x0/x1) register names both accepted.
  RISC-V mnemonic sets (beq/bne/blt/bge, slt*/sltu*, addi/add/sub/mul*, lui/li/
  la/xori/andi/ori/xor) feed funcs metrics, query_lang MATCH routing, and branch
  annotation. `detect_riscv_gp` handles the lui+addi gp prologue and falls back
  to the raw image base with a crisp "GP not found" hint.
- **Entry/exec bootstrap for headerless blobs**: open-time bootstrap seeds reset
  `j`/`jal`/`auipc+jalr` and ISR pointer tables into entry points; reanalyze and
  text-segment search fall back to the whole mapped range with a "no executable
  segments; set perms with segments set_perms" warning instead of silent no-op.
  `segments(add)` derives perm from sclass (CODE→READ|EXEC) so added segments
  are actually analyzed as code.

### Tool quality (symbol-poor firmware)
- **`code`**: `decompile_all` pagination (`offset`/`mode='listing'`), operand-
  based `xrefs_to_field` (decoded displacement, not `+0x10` substrings), and a
  constant-load string fallback in `strings_in_func` with GP-unresolved note.
  `explain` adds firmware signals (ecall/CSR/MMIO) and a "no libc APIs detected —
  bare-metal firmware?" note.
- **`types` propagate** applies types only at genuine data items and records call
  sites without mutating. **`ctree`** nesting is CV_PARENTS-based (correct under
  CV_FAST) with honest truncated/returned counts. **`stack_analysis`** store
  detection is arch-aware (RISC-V compressed/float stores, ARM64 stp).

### Search + semantic speed
- **RISC-V constant recovery**: `search_immediate`/`search_constants` reconstruct
  adjacent lui+addi/addiw pairs into full 32-bit constants (both insn addresses
  reported).
- **Whole-binary scans get a bounded default timeout** (8s) reporting
  `timed_out` + partial results; `timeout_ms=0` remains the explicit no-limit.
  Exec-gated scans fall back to non-exec bytes with a note on raw blobs.
- **`search_text` is index-time persisted**: token columns written at index time,
  ea-range + token filters pushed into SQL, IDF cached per index build — no more
  full-table SELECT + per-row regex tokenization per query.
- **Rerank pool sized to recall** (`min(RERANK_MAX_CANDIDATES, candidate_limit)`)
  with a deadline check; expired → `rerank_meta['reason']='timeout'`. NL search
  degrades to lexical ranking with a "degraded — embedding backend unavailable"
  note instead of hard-erroring; cold-anchor behavior search reports
  "classifier cold, run index first". Auto-named `sub_*` functions get an opcode
  histogram + instruction-bigram lexical fingerprint so embeddings discriminate
  name-less firmware.

### Reliability / speed / contract
- **One shared address parser** (`parse_address_canonical`): bare all-digit
  tokens parse as HEX when they map inside the image, else `ADDRESS_INVALID` with
  a "use 0x prefix" hint — this is a deliberate change from the old decimal
  default (silent-wrong-EA on RISC-V bases like `80000000` is worse than a
  documented parse policy). calc, segments, funcs, and any tool using
  `parse_address_safe` inherit it.
- **@idawrite no longer clears the whole read cache**: invalidation is narrowed
  to the written-address family; the explicit `invalidate_all()` physical-clear
  contract is preserved. Cache keys canonicalize numeric-string args and sort
  address lists so LLM rephrasing hits the LRU.
- **Error envelopes**: every wire error (bridge-originated too) carries
  `category` + `recoverable`; exception-type dispatch yields
  DECOMPILER/EMULATION/SEARCH/RPC_TIMEOUT instead of blanket UNKNOWN_ERROR;
  bridge serialization failures become crisp INTERNAL envelopes instead of a
  dropped connection (which the host read as "IDA crashed").
- **Policy config parsed once per (mtime,size)** instead of 2-5 disk reads per
  call; `ida_batch` sends one list-shaped RPC and fans responses out; pure-PP
  page slices forward `offset`/`count` to natively-paging tools; post-processing
  runs before truncation; cheap host-only tools exempt from rate-limit buckets;
  batch persistence debounced.
- **Semantic index** rebuild is single-flight with persisted float32 vectors
  (rebuild no longer recomputes unchanged gadgets); audit records are
  hash-failure-proof with coalesced flush.

## 2026-08-08 — swarm/agent-blitz integration: host-seam reconciliation

Integration pass that resolved the 10 cross-package host-side seams surfaced by
the agent-blitz fixer wave (handoffs.json), reconciled the tool registry against
the IDA-side `action:` Literal contract, and re-verified docs/op-count parity.

### Policy tiering
- **`firmware_view/bootstrap`** (segment reclassification / range creation) and
  **`calc/persist`** (durable blackboard write) now classify `WRITE_IDB` and
  require ack; `calc` otherwise remains a read-only tool.
- **`misc/reload`** (re-executes arbitrary tool-module source via
  `spec.loader.exec_module`/`importlib.reload` and re-points the live TOOLS
  registry) classifies `LOCAL_CODE_EXEC`, on par with `misc/python|idc|plugin_run`.

### Dispatch / timeouts
- **`firmware_view/detect_mmio`**, **`firmware_view/rtos_scan`** (unbounded
  full-binary scans) and **`search/constants`** added to `LONG_RUNNING_ACTIONS`
  so the host extends the RPC timeout instead of applying short-op heuristics.

### Tool registry ↔ IDA Literal contract
- **`analysis/plugin_run` removed from the analysis action list**: the IDA-side
  `analysis` Literal correctly has no `plugin_run` (the host routes
  `analysis/plugin_run` to the `misc` tool via the dispatch shim), and the
  committed contract tests require `plugin_run` to live only on `misc`. The
  routing shim itself is unchanged, so the convenience path still works.
- **`gadgets/semantic_find` reconciled across the registry↔Literal contract**:
  the action is host-intercepted (served by `server_semantic`, never an IDA
  RPC), so the registry and the IDA-side `gadgets` `action:` Literal must agree
  for `TestIdaSideLiteralContract` (the read_bytes-class guard). Both now
  declare `semantic_find`: the host registry advertises it (so the MCP surface
  exposes the feature, with `(gadgets, semantic_find)` tiered READ), and the
  IDA-side `gadgets` Literal admits the same value with a defensive handler that
  returns a clear "host-intercepted" error if the RPC is ever called directly
  (the dispatch shim at `server_dispatch.py:1861` routes it to the host first,
  so this path only fires with host interception disabled).

### Arg schema admission
- **`code` schema admits `arg_index` / `max_callers_per_level`** so
  `trace_argument_origin` knobs reach the handler instead of being dropped by
  `prepare_rpc_args`.
- **`memory` schema admits `governed`** for governed-memory scan/walk semantics.

### Cross-package consistency
- **`compile_smart_pattern` honors `case_sensitive` on the glob path**
  (`fnmatch` was lowercasing unconditionally whenever the pattern contained
  `*`/`?`).
- **`blackboard_store.next_target` accepts a `strategy` kwarg** (validated
  against `STRATEGIES`), so `frontier`-style calls no longer raise `TypeError`.
- **Tool-cache resolution unified**: `intelligence._invalidate_tool_cache` and
  `misc.cache_stats` now call `sync._tool_cache` (the canonical
  `ida_mcp.ida_mcp.cache → cache → ida_pro_mcp.ida_mcp.cache` chain), so index
  invalidation and cache stats always hit the same singleton the readers use
  (previously a different import path yielded a second `TOOL_CACHE` instance and
  invalidation silently no-opped).
- **`query_lang` folds compact-text `data` results** (functions/strings/imports)
  into records before condition matching — previously it iterated the joined
  text (characters) and `_match_conditions` raised `AttributeError`.

### Docs / surface
- `docs/TOOLS_REFERENCE.md` + `.agents/skills` regenerated from
  `host/agent_operations.py` (no drift); README op-count (67) verified against
  the 67 exported `ida_*` AgentOperations.

### Notes
- Host suite runs with `--basetemp` on `/home` (the `/tmp` tmpfs fills, `ENOSPC`).
- `tests/ida_mcp/test_swarm_t11_intel_tools.py` fixture re-resolves the
  `blackboard` module at call time: the conftest purges `ida_mcp.tools.*`
  submodules between tests, so the collection-time module object went stale and
  `mark_examined` recorded to a real store instead of the recording fake in
  full-suite runs (pass-in-isolation order-dependence). Fixed by patching the
  module the tool's `from .blackboard import` resolves to.

## 2026-08-08 — swarm/session-blitz: session ownership/isolation, runtime & dispatch hardening

A 19-agent fixer wave over `host/` (session ownership & isolation, runtime leases,
response attribution, blackboard per-session state, dispatch integrity) plus an
integration pass that reconciled cross-package handoffs and left the host suite
green. Branch `swarm/session-blitz`.

### Session ownership & isolation
- **Ownership guard applied across the session surface**: declarative mutators
  (rename/duplicate/archive/unarchive/tag/untag/add_note/clear_notes) and the
  diff/note paths enforce `_ensure_client_owns_session` via `_run_session_spec`,
  so a multiplexed connection can never mutate another connection's live session.
  Foreign-session reads/mutates return the `FILE_LOCKED` envelope.
- **Semantic gadgets are ownership-scoped**: `_resolve_session_from_idb_ref` now
  routes through the ownership guard before reading a cached per-session index,
  and the rebuild path is covered too.
- **Truncation tokens carry real session/owner scoping** instead of empty
  placeholders; symbol-db queries and blackboard phase/policy state are
  per-session rather than host-global.

### Runtime & response
- **Usage intelligence is no longer double-fed**: `_record_activity` kept
  last-activity tracking and the auto-nudge fallback but stopped calling
  `UsageIntelligence.observe` (the dispatch path already feeds the rich
  latency+error observation once per call), fixing diluted error-rate / halved
  latency drift signals and false STUCK_LOOP trips.
- **Runtime lease hygiene**: recycled-pid verification, heartbeat clamp, and
  cross-process batch persistence reconciled with per-instance tests.
- **Response enrichment / audit attribution** now key off the session the call
  actually executed against (idb-resolved), not the shared active default.

### Dispatch & policy integrity
- **`gadgets(action='semantic_find')` is now fully registered**: added to
  `_TOOL_ACTIONS['gadgets']`, its arg schema enum (derived), and classified as a
  read-tier policy action instead of UNKNOWN.
- **`analysis(action='plugin_run')` is advertised**: added to the analysis
  action list so the schema enum and tool list admit it.
- **Policy gaps closed**: `multi_session/group_create|group_link`, the
  `session/bootstrap_*` skills mutators, and `session/log_activity` classify
  WRITE_IDB; the blackboard read-only overrides (`working_set`, `state_health`,
  `quest_board`, `conflicts`, `stale`, `recall`, `workspace_brief`,
  `campaign_summary`, `phase_status`) are read-tier. `session/sso_activate`
  deliberately stays READ (gating it breaks the SSO realm lifecycle).
- **Dead code removed**: orphaned `config.validate_path` and its exports, and
  the unused `ARG_SCHEMAS`/`ARG_ALIASES`/`ACTION_ALIASES` stubs in
  `tool_registry.py` (real schemas live in `schemas_data.py`/`schemas.py`).

### Reconciliation
- The bootstrap plan matrix lists only implemented methods so the readiness gate
  can reach 100% (phantom blended-strategy names removed); `bootstrap_snapshot`
  returns a graceful uninitialized dict (consistent with `bootstrap_status`)
  whose hint references the reachable `bootstrap_init` action.

### Notes
- Host suite runs with `--basetemp` on `/home` (the `/tmp` tmpfs fills, `ENOSPC`).

### Regression fix
- **install.py crash (`can only concatenate str (not "bytes") to str`)** — the
  IDA version scanner carried its chunk-boundary overlap as a decoded `str`
  while concatenating it onto the next raw `bytes` chunk. Introduced by the
  agent-blitz merge (`ca9aee9`). Now carries the raw tail bytes
  (`data[-overlap:]`), so version strings split at a chunk boundary still
  resolve. `python install.py` completes end-to-end again (IDA 9.3 detected,
  14 clients configured, exit 0).

### CI fixes (pre-merge green, 2026-08-09)
- **Standalone Tests ruff `UP037` (16×)** on `types.py`'s
  `Annotated[Literal[...]]` action enum: the strings are VALUE members of the
  IDA dispatch contract, not forward refs. The dev group floats `ruff>=0.15.0`,
  so CI drifted to a release that flags them under `from __future__ import
  annotations` (added by agent-blitz). UP037 is now in the documented ruff
  ignore list rather than scattered noqa.
- **Standalone Tests Python 3.11/3.12 collection** — `TestCtreeDecompileFailure`
  failed importing `ctree` because `utils.py`'s `get_prototype(fn:
  ida_funcs.func_t)` annotation is evaluated eagerly on py<=3.13 against the
  test's bare `ida_funcs` stub (no `func_t`). Local verify ran on 3.14, where
  PEP 649 defers annotations by default, so the failure only surfaced in CI.
  Root fix: `from __future__ import annotations` in `utils.py`.
- **CodeQL "3 new alerts"** — two were `hashlib.md5` content fingerprints in
  `host/intelligence/{context,embeddings}.py` (pre-existing on master, re-flagged
  because the wave shifted surrounding lines); swapped to `sha256` (identical at
  the `[:16]` truncation width, no crypto semantics). The third was
  `test_swarm_f10_stores.py`'s `(a+)+$`, an *intentional* catastrophic pattern
  used to assert `search_truncated` rejects ReDoS — dismissed as a false
  positive.

## 2026-08-08 — swarm/agent-blitz: contract hardening, security, coverage (67-agent wave)

~360 audit findings verified and fixed across a 17-agent fixer fleet (disjoint file
ownership), 16 cross-package integration handoffs, and a 5-package testbench/scripts/
CI/docs pass. Branch `swarm/agent-blitz`.

### Security & hardening
- **Bridge session-token auth is now mandatory**: `server_script.py` previously
  accepted tool calls when no token was configured, leaving arbitrary tool
  execution (incl. python code exec) open to any local process that could reach
  the RPC socket. An unconfigured bridge now refuses every tool call with
  `UNAUTHORIZED`.
- **Tool loader can no longer clobber stdlib imports**: `tools/types.py` and
  `tools/code.py` were registered flat in `sys.modules`, shadowing stdlib
  `types`/`code` and silently breaking later `from types import UnionType`
  imports. The loader snapshots and restores shadowed modules.
- **MCP HTTP hardening** (`ida_mcp/zeromcp/mcp.py`): 60s socket timeout against
  slowloris/stalled clients; non-numeric/negative `Content-Length` → clean 400;
  `send_error` closes the connection so an over-limit body can't desync a
  kept-alive connection; SSE session is validated *before* dispatch so a bogus
  session id can never execute a tool; notification `202` returns a valid empty
  body; URI-template matching `re.escape`s literal parts.
- **Failed IDA calls surface as MCP errors**: the zero-mcp layer detects the
  `{error: True, ...}` envelope and returns `isError: true` with
  `structuredContent`, so clients branching on `isError` see failures instead of
  a "successful" call.
- **Pre-analysis options now reach the IDA side**: `stack_size` and
  `processor_options` from `IDA_MCP_PRE_ANALYSIS_OPTS` are applied post-load
  (`inf_set_ssize` / `set_processor_options`); `memory_model` left as a documented
  TODO until the host encoding → `MT_*` mapping is validated live.

### Correctness
- **STUCK_LOOP drift detector no longer hard-blocks by default**: the
  `is_running()` activation gated legitimate repeated reads; the block is now
  opt-in via `IDA_MCP_STUCK_LOOP_BLOCK=1`, with the drift signal/notification
  staying advisory.
- **Blackboard publish ack restored**: `_publish_findings` requires `_risk_ack`,
  but the dispatcher popped it before routing — the ack gate now reaches the
  handler; `blackboard/coverage` is implemented host-side and classified as a
  read-tier action.
- **Tool-result caches no longer poisoned**: `_elapsed_ms` injection and
  `@idaread`/`@idawrite` cache reads now copy the dict, so caller mutation can't
  leak into later cache hits.
- **Stack-analysis heuristics**: store-type mnemonic allowlist (a
  `cmp [rbp-8], 0` read no longer marks a local initialized); shared
  buffer/array size heuristics so `buffers`/`arrays`/`summary` agree on the same
  frame.
- **Session actions rewired**: `rate_skill`, `list_skills`, `suggest_triage`,
  `suggest_strategy`, `get_phase`, `dashboard` wired into the dispatch surface
  with thin session-manager handlers; dead `_ANALYSIS_PHASES` and stale
  LONG_RUNNING_ACTIONS entries removed.
- **Policy gaps closed**: `types/import_header` + `types/propagate` classify as
  WRITE_IDB; `ida_batch` classifies WRITE_IDB (was UNKNOWN); blackboard reads
  are read-tier; `modify` governance doc updated (executable-segment patches are
  blocked unless acknowledged).
- **~400 lines of dead code removed** (`ida_mcp/utils.py` unreferenced TypedDicts
  and helpers); `annotation.py` danger-API lookup is now case-insensitive.

### Tests & coverage
- 21 new test files + expansions across host dispatch, policy classification,
  session fixes, runtime leases/recovery, response formatting, skills, workflow
  batch, blackboard, and intelligence (embeddings, threat corpus, truncation,
  patterns, symbol DB).
- Live-agent-surface integration tests now pass `risk_ack` where
  `ida_close_session` requires it.
- Test-quality pass (wave B): `test_auto_reanalyze_text_segments` now exercises
  the *live* `analysis.py` helpers instead of a stale exec'd copy; ephemeral
  ports replace hard-coded ones in RPC concurrency tests; busy-wait loops
  replaced with `threading.Event` in batch-manager tests.

### Scripts, benchmarks, CI, docs (wave B)
- Smoke/report scripts hardened (`smoke_core_path`, `smoke_mcp_all_tools`,
  `smoke_mcp_all_actions`, `test_live_ida_crystallize`, occupancy reports);
  benchmark scripts fixed; `pyyaml` added to dev deps so `test_ci_workflows` runs
  on CI; docs content updated (ROADMAP, LIVE_IDA_TESTING, POLICY, wiki tools).
  A proposed CI coverage gate was measured (39% — dominated by IDA-runtime code)
  and deliberately rejected as arbitrary churn.

### Notes
- Test suites should use a project-local `--basetemp=.pytest_tmp` directory so
  scratch files do not depend on a particular workstation's filesystem.

## 2026-08-07 — intelligence control-plane coverage + reranker busy-queue fix

- **Reranker lock contention retired a healthy shared server**: the
  inter-process lock raises `EmbeddingQueueTimeout`, but the reranker's
  handlers caught `RerankQueueTimeout` — unrelated classes.  A busy queue
  fell through to the generic error path, was misclassified as a request
  timeout, and recycled the shared reranker.  `_RerankInterProcessLock`
  now translates the shared lock's timeout into `RerankQueueTimeout`, so
  contention returns `None` cleanly without retiring the server.
- **`ContextAssembler` control plane was ~22% covered**: new
  `tests/host/intelligence/test_context_assembler.py` +
  `test_context_enrichment.py` drive the tuning/threshold/circuit-breaker
  math and the full `assemble()` pipeline with fake embedder/classifier/
  blackboard doubles (decompile enrichment, search enrichment, next-target
  suggestion, related-address graph, housekeeping).  `context.py` now 81%.
  Also fixed a stats-cache aliasing bug: `_session_retrieval_stats`
  returned shallow copies, so a caller mutating a bucket corrupted the
  cache; store/read are now deep-copied.
- **`Reranker` lifecycle was 26% covered**: `tests/host/intelligence/
  test_reranker_lifecycle.py` covers discovery (env/state/HF cache),
  lease matching/retirement, idle shutdown, recycling limits, the
  subprocess start path (mocked `Popen` + health), request parsing,
  chunked `rerank()` index offsetting, and singleton/reset/status.
  `rerank.py` now 86%.
- **Threat-corpus holder + cache pipeline untested**: `tests/host/
  intelligence/test_threat_corpus.py` covers `ThreatCorpus` indexes and
  lookups, serialization + V1 migration, the per-source cache manifest
  round-trip, legacy-file backup, and the lazy singleton (build from
  sources, auto-download, invalidation).  `threat_corpus.py` now 84%.
- **`insight_paths` / `scope_window` were 0% covered**: path-resolution
  fallbacks and half-open address-window helpers now have unit tests.

## 2026-08-07 — threat-corpus + scanner test coverage wave

- **`parse_cwe_xml` missed `Technical_Impact` scopes**: the consequence
  whitelist only matched `Scope`, `Consequence_Scope`, and the nonexistent
  `Technical_Impact_Scope` — the real CWE catalog uses
  `Technical_Impact`, so every CWE entry lost its technical-impact scopes.
  Fixed in `threat_corpus.py`.
- **Threat-corpus source parsers were 0% covered**: `tests/
  host/intelligence/test_threat_sources.py` drives every `SourceParser`
  (`attack`, `cwe`, `lolbas`, `sigma_rules`, `urlhaus`, `findcrypt`,
  `yara`, `yara_rules_extra`) with local fixtures — STIX bundles, CWE XML,
  LOLBAS JSON, Sigma YAML, URLhaus JSON, YARA trees — plus the base-class
  `download`/`fingerprint` contract and zip-extraction hooks.  Coverage
  went 0% → 61–93% per module.
- **`yara_scanner` was 28% covered**: `tests/host/intelligence/
  test_yara_scanner.py` covers compile/load/cache, byte/file/address-range
  scans (chunking, base offsets, read failures, byte budget), rule-file
  iteration, and the `YaraScanner` lifecycle.  Now 75%.
- **`ContextDensityOptimizer` compaction paths untested**: `tests/host/
  test_context_density.py` extended to cover hex-dump/xref/string
  compaction, address bucketing, budget-driven list truncation with
  critical-key preservation, the legacy `optimize` shim, and density edge
  cases.  Coverage 34% → ~90%.

## 2026-08-07 — CI + reproducibility hardening

- **CI ran the live-IDA integration suite**: `standalone-tests.yml` invoked
  `pytest` over the whole tree, and with a C compiler present
  `test_ida_live_integration.py` is not skipped — each of its five classes
  then waited out its 120s server-startup timeout in a CI runner that has no
  licensed IDA. The workflow now ignores `tests/integration` (the suite is
  exercised locally against live sessions, per AGENTS.md).
- **Live harness hung on a dead server process**:
  `MCPIntegrationClient.start()` polled its stderr queue until the timeout
  even after the stdio server exited (e.g. no IDA installed). It now fails
  fast the moment the process dies before printing the ready line.
- **llama.cpp pin lived only in a workflow comment**: the native-build CI
  claimed the commit was documented in `mcp_llama.cpp`, which never
  contained it. The canonical `LLAMA_CPP_COMMIT` default now lives in
  `scripts/build_native_llama.sh` (with a git-HEAD mismatch warning), and
  CI fails if the workflow env drifts from it.
- **New `tests/test_ci_workflows.py`**: two local guard rails — the
  standalone workflow ignores `tests/integration`, and the native-build
  workflow's llama.cpp pin matches the build script's canonical default.

## 2026-08-07 — search-analyze scopes + code-detect reachability

- **`search analyze` outlier `tiny`/`huge` were dead code**: the metrics were
  advertised and schema-validated, but only `size|complexity|bb_count` were
  ever checked, so `tiny`/`huge` fell through to an empty call-graph result.
  Both are now index-backed via `func_size` with threshold/order, and a
  direct-IDA fallback (`_outlier_rows_from_ida`) keeps `size`/`tiny`/`huge`/
  `bb_count` working with no embedding index; `complexity` returns a clear
  NOT_FOUND telling the caller to index first.
- **Call-graph edges only scanned the function's first byte**:
  `_func_callees` collected xrefs from `XrefsFrom(func.start_ea)` alone, so
  nearly every function looked like a leaf — callers/callees, reachability,
  paths, and the vulnerable scope all under-reported. Edges are now collected
  from every instruction in the body, and call targets that are not yet
  functions (PLT stubs mid-analysis) resolve by name to the import function.
- **`search analyze vulnerable` skipped the interesting part of the binary**:
  it iterated every function, missing the taint-reachable sink unless it was
  globally dangerous-looking. It now walks only functions reachable from taint
  sources, bridges PLT stubs and import functions that share a base name
  (`.read` vs `read`), and normalizes stub names before the dangerous-API
  match. Live fixture: `read` → `memcpy` in `rich_taint_path` is surfaced.
- **`search/combinators.py` referenced an undefined `_coerce_ea`** (imported
  from `.advanced` but not exported there), which would NameError at runtime
  in the similar/semantic/vulnerable paths. Import fixed.
- **`code(action='detect')` was unreachable through MCP**: the host arg
  admission rejected every detector parameter (`rule_type`, `apis`, `chain`,
  `strict_order`, `pattern`, `string`, `type_pattern`, `type`, `name`,
  `rule_name`, `register`, `rule`, `list_detectors`, `delete_detector`,
  `function`) plus `search.scope`, and the action itself was gated behind the
  `addrs` pre-check ("Address is required"). The schema now admits them,
  `detect` runs before the address gate, and the named `target` parameter is
  folded back into the detector kwargs so `caller_of`/`callee_of` work.
- **Detector helpers broke on IDA 9.3**: `_iter_all_functions` called
  `idaapi.get_next_func` (returns a `func_t` object in 9.x — `int()` blew up),
  and `_detect_string_refs` used the nonexistent `idautils.Strings().count`.
  Both now use the 9.x-safe iteration helpers proven in the `data` tool.
- **Live-suite hardening**: the fixture gained `rich_taint_path` (read then
  memcpy) and an 11-byte `rich_tiny`; a new `TestSearchAnalyzeIntegration`
  class asserts real match content; the vulnerable test waits for observable
  hits instead of the unreliable watchdog verdict, and the module declares a
  900s pytest-timeout so analysis-backed setUpClass calls are not killed by
  the global 30s default.

## 2026-08-07 — per-candidate embedding latency fix

- **`search(action='find')` and name resolution embedded every candidate**:
  `semantic_score()` ran one native llama embedding per matched name, string,
  import, comment, and instruction — tens to hundreds of sequential 6–10s
  inferences, so a `find` on a 21-function fixture took ~3.5 minutes.  Scoring
  is now two-phase: a deterministic subword/ngram pass ranks the whole pool
  instantly, then a single batched call re-embeds only the top candidates
  (capped at 24 for find, 64 elsewhere) for phrase-like queries.  A
  decisive-winner gate skips embedding entirely when the deterministic score
  already dominates; identifier-like queries never embed (exact/substring
  matching is decisive there).  Live fixture `find("fixture_entry")` dropped
  from ~3.5 min to ~0.3 s.
- **Embedding cache at the native backend**: `NativeEmbedder` now caches
  (purpose, text) -> vector (bounded FIFO, 4096 entries) so repeated queries,
  candidates, and anchor texts never pay a second inference in one session.
- **Deterministic scorer understands identifiers**: snake_case/camelCase names
  are split into subwords, and substring + edit-similarity bonuses restore the
  ranking signal typo'd and compound names used to get only from embeddings.
- **Consistent rerank context default**: `IDA_MCP_RERANK_CTX` now defaults to
  1024 on both the HTTP and native backends (was 2048 vs 1024); docs and the
  installer wizard note the rerank pool/budget/context knobs.
- **Installer wrote no rerank env to client configs**: `build_stdio_config()`
  emitted `IDA_MCP_RERANK_MODEL` / `IDA_MCP_RERANK_PROFILE` only when the
  backend forced them; the installer now passes both through in the Gemini
  and native paths so Claude Desktop / Cursor / VS Code blocks carry the
  chosen reranker, and the wizard surfaces the rerank pool/budget/context
  knobs.
- **Legacy live suite is now self-sufficient**: `test_ida_live_integration.py`
  auto-builds a detector-rich fixture (XOR-heavy code, string refs, malloc/free
  chain, globals, call graph) when `IDA_MCP_TEST_BINARY` is unset, and the
  caller_of/callee_of tests now actually invoke the detector rules.  10/10
  against a real IDA session.

## 2026-08-07 — semantic-search latency/consistency fixes

- **Quick-mode searches silently forced the cross-encoder**: `search(action='nl')`
  forwarded `rerank=bool(kwargs.get('rerank', True))`, so an absent `rerank`
  defaulted to `True` and every quick-mode search re-scored up to 12 documents
  on the CPU native backend — a multi-minute burn the host RPC timeout then
  reported as a hang. The dispatcher now forwards a tri-state (absent -> `None`
  = auto: on in expand, off in quick; explicit true/false force/skip), and the
  live agent-surface suite's quick-mode search dropped from 10+ minutes to ~11s.
- **Rebuilt indexes kept serving stale vectors**: `FunctionEmbeddingIndex`
  cached vectors in RAM, and `search/nl` only refreshed when the cache was
  empty — so after `index_batch` upgraded an index from fast to decompile
  quality, searches ranked against the pre-rebuild generation (the suite saw
  `puts`, a libc stub, rank top for a fixture query). The index now detects a
  rewritten DB via the newest mtime across the DB and its WAL/SHM sidecars and
  reloads at the vector-read choke point; `get_backend()` refreshes eagerly
  when the DB changed.
- **Cached search responses survived index rebuilds**: indexing is not an
  `@idawrite`, so `@idaread`-cached search results were never invalidated and a
  repeated query after a rebuild returned the stale payload in 0s. Indexing
  actions (`index_function`, `index_batch`/`fast`/`range`, `refresh_anchors`)
  now invalidate the tool cache — via the exact import path the `idaread`
  wrapper uses, since a differently-imported `cache` module is a second
  singleton and invalidation would silently no-op.
- **`misc(action='reload')` did not re-point the server registry**:
  `server_script.load_tools()` stores direct function references in `TOOLS`, so
  reloading a module kept serving the old function object (and its old action
  `Literal`). Reload now re-executes flat tool files under the same loader the
  server uses, reloads package tools in place, and swaps the fresh function
  into every `TOOLS` registry it finds.
- **Regression tests**: dispatcher rerank tri-state forwarding, reader
  auto-refresh after a rebuild replaces rows, plus the existing Literal
  contract and rerank-pipeline suites. Live agent-surface suite: 8/8 passing.

## 2026-08-07 — action-Literal contract fixes + live-suite repair

- **`read_bytes` was unreachable**: `data(action='read_bytes')` had a handler
  branch and a registry entry but was missing from the IDA-side `action`
  `Literal`, so every call (including the public `ida_read_bytes` operation)
  was rejected with "Unknown action" before reaching the handler. Added it to
  the `Literal`, the action description, and the docstring; verified live
  against IDA 9.3.
- **`funcs(action='list')` was unreachable** for the same reason (handler +
  registry entry existed, `Literal` did not). Added to the `Literal`.
- **`memory` advertised ghost actions** `read_file`/`write_file` — they are
  implemented in `misc`, not `memory`, and would fail at runtime. Removed from
  the registry, the tool description, and policy classification.
- **`code(action='trace_argument_origin')` was implemented but never
  advertised** — added to the registry so the host admits the call.
- **New contract test** (`test_tool_registry.py::TestIdaSideLiteralContract`):
  every action the host advertises for an IDA-side tool must exist in that
  tool's `action` `Literal`, and vice versa (modulo dynamic wrapper actions).
  This is the regression guard for the `read_bytes`/`funcs list` bugs.
- **CLI fixes + coverage**: `raw '<json>'` now accepts the JSON-RPC object as
  the documented second positional argument (previously only the third slot
  worked, contradicting the epilog); fixed a mis-indented epilog line; added
  `main(argv=...)` for testability and a 24-test suite for the CLI.
- **Live integration harness repair**: `test_ida_live_integration.py`
  computed `PROJECT_ROOT` one level too shallow, so it spawned a nonexistent
  shim and every test timed out and skipped. The stdio/daemon servers now also
  emit a `... server ready` line on stderr so readiness-based harnesses can
  synchronize instead of waiting out a full timeout.

## 2026-08-05 — removed the deprecated `ida://` MCP resource surface

The `ida://` MCP resources (`resources/list`, `resources/read`, and
`resources.py` / `ResourceResolver`) are removed. They were application-driven
— the client UI had to attach them, so agents could not read them
autonomously. The state they exposed is now produced by the real tool
`ida_session_state` (its payload-building logic moved into the session mixin);
hints that pointed at resources now point at `ida_session_state`.

## 2026-08-04 — batched native decode + Q4_K_M models (retrieval speed)

Native-backend decode is now **batched across sequences** and the models are
**Q4_K_M** — the two big levers for CPU retrieval speed.

- **True batched decode** (`mcp_llama.cpp` `encode_batched`): instead of one
  sequence per `llama_decode` (KV cache cleared, weights streamed, per call),
  sequences are packed into greedy batches of distinct `seq_id`s — up to
  `n_seq_max` (16) per decode, each with its own KV stream — and the KV is
  cleared once per batch.  Pooled embeddings are read per-sequence after the
  decode via `llama_get_embeddings_seq`.  Because the decode graph runs over
  n_ubatch-token slices, packing several short documents into one decode
  fills the ubatch (weights streamed once for ~512 slots instead of ~150
  useful ones) — the dominant cost for a bandwidth-bound 0.6B Q8/Q4 model.
  Long documents see the win through fewer per-call overheads.
- **Quantized KV cache** (`type_k/type_v = Q8_0`): halves the ~28 KiB/token KV
  a 0.6B Qwen3 needs in f16, so a 16 × 2048-token batch fits in ~0.5 GiB.
- **Head-first truncation**: over-long sequences now keep the **head** (query
  + document prefix) instead of the tail — the old tail-keeping could drop
  the query for long rerank pairs.  Matches the HTTP server's truncation.
- **Q4_K_M models** (`mcp_quantize`): a minimal `llama_model_quantize` driver
  built against the same static libs (no llama-common), so the embed and
  rerank GGUFs drop from ~639 MiB to ~396 MiB (~1.6×) — ~1.6× fewer weight
  bytes to stream on the bandwidth-bound decode.  Model discovery now prefers
  `Q4_K_M` over `Q8_0` when both exist (`IDA_MCP_Q4=0` to force Q8), and the
  installed state now points the embedder at the Q4 file (backup saved).
- Benchmarking is now centralized in `benchmarks/run.py`, with explicit scopes
  and run-time metadata instead of checked-in workstation measurements.
- Correctness verified under load: batched rerank scores (relevant 0.8909 vs
  noise 0.0005, deterministic) and batched embed vectors (distinct, nonzero
  per document) match the single-sequence path; 126 intelligence tests pass.

## 2026-08-04 — in-process native llama.cpp retrieval backend (embed + rerank)

Replaces the two full `llama-server` HTTP subprocesses with **one in-process
native library** (`libmcp_llama.so`) built from a trimmed llama.cpp and loaded
by Python via **ctypes** — no subprocess, no HTTP, no JSON, no lease/lock
files, one `llama_decode` per document instead of per-chunk round trips.

- **`src/ida_pro_mcp/native/mcp_llama.cpp`** — minimal C-ABI driver over the
  public `llama.h`: `mcp_embed_encode` (pooled embeddings, query prefix
  applied Python-side via the model profile) and `mcp_rerank_score`
  (cross-encoder relevance via the model's `rerank` chat template).  Two
  correctness lessons from matching the HTTP server byte-for-byte:
  - `llama_encode` passes a **null memory context** and Qwen3's decoder graph
    builds attention-KV unconditionally → segfault.  The server uses
    `llama_decode` with the KV cache (`llama_memory_clear` per sequence); the
    driver does the same.
  - Embeddings must be read via `llama_get_embeddings_seq` (the **pooled**
    classifier output — for RANK that's the 2-class softmax), not
    `llama_get_embeddings_ith` (raw 1024-dim hidden state).  Rerank scores
    now match the HTTP server to within float noise.
- **`src/ida_pro_mcp/host/intelligence/native.py`** — `NativeEmbedder` and
  `NativeReranker`, drop-in for `BgeCodeEmbedder` / `Reranker`, loaded via
  `ctypes` (stdlib, no build against Python headers).  Embeds are
  L2-normalized like the HTTP path.
- **Routing** — `BgeCodeEmbedder()` and `Reranker()` resolve to native when
  the library is present (host bootstrap sets `IDA_MCP_NATIVE=1`); HTTP is
  the fallback.  `IDA_MCP_BACKEND=native|http` pins explicitly.  Every
  existing call site works unchanged; `reranker_status` reports
  `backend: native-llama`.
- **`scripts/build_native_llama.sh`** — builds the trimmed llama.cpp (server /
  UI / tools / mtmd / SSL off, CPU + OpenMP + llamafile on, `-fPIC`) then
  compiles the driver into one self-contained `libmcp_llama.so`.
- Native vs HTTP comparisons run through the portable retrieval pipeline with
  the backend selected explicitly at invocation time.
- HTTP backend and its 800+ tests are untouched; tests never set
  `IDA_MCP_NATIVE`, so they keep exercising the HTTP path.

## 2026-08-04 — semantic-index false-failure fix (partial index preserved on batch failure)

Found while working a real session: a background semantic-index job over libgpu_aux.so reported **`IDA_ERROR "No embeddings were created; semantic search is unavailable"` and aborted even though it had already indexed 30 of 40 functions.** Root cause: when a pass's *first* batch failed entirely (embedder timeout → `index_many` returns `{indexed: 0, failed: N, resume_after_ea: None}`), the handler's `if count == 0:` check fired before considering the `retry_required` flag, converting a resumable partial index into a total failure.

- **`intelligence.py`**: the fatal `count == 0` error now only fires when `not retry_required`. On a failed first batch, the handler falls through and returns the normal result carrying `retry_required=True` and the resume cursor, so the background orchestrator resumes from before the failed batch instead of aborting — the 30 already-indexed functions are kept.
- **`server_batch.py` (host)**: the resume loop previously had no bound — an embedder that kept failing at the same cursor would spin forever (the existing `pass_attempted == 0` guard is skipped when a batch was attempted but all candidates failed). Now the loop counts consecutive no-forward-progress passes and, after 3, returns a `stalled: true` result with `complete: false` and the resume cursor — preserving accumulated progress and leaving the job resumable via `start_after` instead of spinning.
- New regression tests in `tests/host/test_semantic_index_jobs.py` cover both: a partial index surviving a totally-failed final pass, and the stall bound terminating a never-recovering embedder.

## 2026-08-04 — rerank RSS floor correction + live-reload dev loop

- **Rerank RSS floor 4 GiB → 5 GiB.** The 12-query full rerank benchmark exposed a wrong floor assumption: with `--parallel 2` + `ubatch 2048` + 8-doc chunks, RSS *ratchets* with request size (llama.cpp allocates a fresh compute buffer per distinct larger batch and never frees the old one), climbing to ~4.15 GiB on the varied corpus — over the old 4 GiB floor, recycling a healthy server mid-run. Verified with a fixed-size control (12 identical requests → flat 1752 MiB plateau, zero recycles). `_rss_limit_bytes` is now `max(5 GiB, model_size*5 + 1 GiB)`, giving ~0.85 GiB of headroom over the measured peak while the differential growth check still catches true leaks. Comment rewritten to record the measurement, not the old assumption.
- **Live-reload dev loop (no reinstall / no restart).** The venv is now an editable install with `site-packages/ida_pro_mcp` symlinked to `src/ida_pro_mcp`. Because the host server imports intelligence modules lazily inside handler bodies, editing `src/` is picked up by the *already-running* MCP server on its next lazy import — no `install.py` refresh, no user restart. Verified against the running server. (Non-lazy-imported modules like `host/server.py` still need a restart.)
- **Full-run rerank benchmark recorded** (12 queries, 16-candidate pools): MRR@10 0.9583 → 1.0, recall@1 0.9167 → 1.0, 12/12 discriminating queries, ~6.4 s/pair.

## 2026-08-03 — embedding/rerank hardening (CPU default, memory bounds)

- **CPU is now forced, not assumed.** A Vulkan-enabled llama.cpp build auto-selects the GPU when no `--device` is given, so on this box the embed server silently loaded `libggml-vulkan` + `libvulkan_intel` and ran on the pathological Intel UHD 620 iGPU even though offload is opt-in (`IDA_MCP_EMBED_GPU=1`). Both the embedder and reranker now pass `--device none` unless the GPU env var is set — the same fix the reranker already had, now applied to the embedder.
- **Recycle no longer kills healthy servers mid-run.** The RSS-growth check compared current RSS against the *startup* baseline, so the first batch's legitimate one-time compute-graph allocation (measured 0.9 GB → 1.6 GB, then flat) tripped it and recycled a healthy server — the benchmark indexed only 16/33 corpus functions for exactly this reason. Growth is now measured *differentially* (since the previous request), which catches true leaks without punishing one-time graph allocation. Absolute RSS floors were raised to match the real plateau: embed 3 GB, rerank 4 GB.
- **Rerank memory is bounded by chunking.** llama.cpp sizes its compute buffers for the whole request batch, so a 64-document pool ballooned to ~5.4 GB RSS on a 0.6B model (OOM territory on a 15 GB laptop). `rerank()` now scores documents in chunks (`IDA_MCP_RERANK_CHUNK`, default 8) and merges indices, so peak memory tracks the chunk, not the pool.
- **Rerank context 8192 → 2048.** The profile's `max_context` (8192) sized the KV cache and physical batch for 8k tokens when every pair under the 6000-char document cap is ≤ ~2100 tokens. `--ctx-size 2048` covers every capped pair while cutting peak memory roughly in half.
- **Rerank uses `--parallel 2`.** The `--parallel 1` score-collapse build bug was confirmed to be specific to a value of 1 — parallel 2 returns full distinct scores (verified) with lower peak memory than the no-parallel default.
- The canonical benchmark runner now reports retrieval metrics and runtime metadata without checking machine-specific results into the repository.

## 2026-08-03 — cross-encoder reranking + function families

- **Two-stage retrieval (Stage 2)**: semantic search now re-scores the recalled candidate pool with a **cross-encoder reranker** — full attention between the query and each candidate's full document, so the top of the list is *correct* instead of merely nearby. The reranker runs on its own `llama-server --rerank` process (llama.cpp serves `--embedding` and `--rerank` as mutually exclusive modes) with the same lifecycle as the embedder: lease file, idle shutdown, activation grace, request lock, RSS/request recycling.
- **Rerank profiles** (`host/intelligence/rerank_profiles.py`): `qwen3-reranker-0.6b` (default, ggml-org), `qwen3-reranker-4b` (opt-in precision), `bge-reranker-v2-gemma` (middle tier — the known public conversion is *headless* and returns constant scores; flagged), `bge-reranker-v2-m3` (opt-in compat). Discovery scans Downloads/install/HF-cache and falls back to any installed reranker.
- **Reranker manager** (`host/intelligence/rerank.py`): model switch at runtime via `Reranker.reset(model_path)` (used by the benchmark), `ida_reranker_status(probe=True)` reports installed model/readiness.
- **Document text persisted in the index**: a `document_text` column (additive migration) stores the bounded decompilation that was embedded, so reranking and function families read the full document instead of the short lexical signature. Legacy rows re-index or fall back to live decompile.
- **Graceful degradation**: if no rerank model is installed, or the model is non-discriminating (identical scores for every input — the headless-conversion symptom), recall order is preserved and the response's `rerank` block reports `applied: false`. Reranking is a quality boost, never a hard gate.
- **`ida_function_families`**: clusters lookalike functions by embedding cosine (deterministic connected-components, numpy-only). Each family returns a centroid summary, a named representative (the one to read), per-member `+token`/`-token` deltas, and optional grouped `mark_examined` so the agent reads one function per family instead of all N.
- **Two llama.cpp build bugs worked around** (verified empirically): passing `--parallel 1` collapses `/rerank` to one identical score per document, and passing `top_k` in the request body shifts the returned indices by one. The reranker sends neither.
- Installer: `--rerank-profile`, `--rerank-model`, `--download-rerank-model`; `write_embedder_state` accepts a `rerank` subsection pinned in the same `embedder.json`.

## 2026-08-03 — embedding layer overhaul

- **Vectorized semantic search**: `helpers.batch_cosine_similarity` runs the k-NN scan as a single NumPy matrix multiply (~4× faster than the per-pair Python loop on a 20k×1536 index, exact agreement to float precision), with a pure-Python fallback when NumPy is absent. The function index (`similar_vec`, `similar`), the context assembler's `similar_functions` enrichment, and the blackboard's `semantic_search` all route through it.
- **Removed duplication**: `FunctionEmbeddingIndex.similar` now embeds the query then delegates to `similar_vec` (one scoring path, one ranking rule) instead of re-implementing the scan. The context assembler's hand-rolled cosine scan was replaced with the shared `similar_vec` call. `decomp_document_chars` is a single shared `decomp_document_char_budget` helper used by both the local and cloud embedders.
- **Fixed `verify_metadata` staleness bug**: index metadata was snapshotted from the embedder the index was *built* with, not the embedder being verified against — so a changed `embedding_format` never triggered a rebuild. The snapshot now takes the candidate embedder explicitly.
- **Stripped dead code**: removed the unused `compact_policy_blob` / `prune_policy_store` policy-store helpers; hoisted inline helper imports; removed a redundant `socket` re-import.
- **Test coverage**: new tests for `batch_cosine_similarity` (NumPy + fallback parity, zero-norm/dimension-mismatch edges), the `BehaviorClassifier` scoring path (previously untested), `similar_vec` / `similar` / `hybrid_search` ranking semantics, and the blackboard vector-search path.

## 2026-08-03 — opt-in Gemini cloud embedding backend

- New **opt-in cloud embedder**: `gemini-embedding-2` (or `gemini-embedding-001`) through the Google API, selected only when the user sets `IDA_MCP_EMBED_BACKEND=gemini` or writes `embedder.json` `{"backend": "gemini"}` — never automatically, even when GCP/Gemini env vars are present. The local llama-server path (`bge-code-v1` / `zembed-1`) is unchanged and still the default.
- `GeminiEmbedBackend` (`host/intelligence/gemini.py`) implements the same duck-typed interface as `BgeCodeEmbedder`, so the function index, context assembler, semantic server, and behavior classifier work against it unchanged. Supports Google AI Studio (`GEMINI_API_KEY` / `GOOGLE_API_KEY`) and Vertex AI (bearer token, or ADC via the optional `google-auth` package), batched `batchEmbedContents`, `outputDimensionality`, per-purpose `taskType`, retry on transient errors, and a one-shot degradation when the API rejects `task_type`.
- **Privacy:** the cloud backend uploads the *compact behavioral signature* of each function — never the full decompilation. It is opt-in and network-facing by design.
- Index persistence stays stable: `embedding_format` for Gemini is `gemini:v1:<model>:<dim>:<task_mode>`, so restarting the server does not force a semantic-index rebuild. The API key is never written to `embedder.json`.
- Installer: interactive wizard now asks for the **embedding backend** (local / local / cloud), then the Gemini route (AI Studio key or Vertex project+region), and offers to install `google-auth` for Vertex ADC. New CLI flags: `--embed-backend`, `--gemini-access`, `--gemini-api-key`, `--gemini-vertex-project`, `--gemini-vertex-location`, `--gemini-model`, `--gemini-dim`, `--gemini-install-auth`. `--embedder-doctor --embed-backend gemini` verifies a cloud setup without opening IDA.

## 2026-08-02 — agent SSO for subagents

- New `session` actions `sso_activate`, `agent_login`, `agent_logout` give subagents a **per-agent identity** over a shared MCP connection. Previously every subagent was indistinguishable: one shared active session, shared ownership, and a connection close that tore down *everyone's* runtimes. The orchestrator activates a one-shot realm with an allowlist of agent names, each subagent logs on with an HMAC-signed ticket (`mint_agent_ticket` in `host/server/server_client_state.py`), and every session-scoped call carries an `agent=<name>` tag.
- **Per-agent active session**: `current_session` resolves to the bound agent's own session, so agent A creating a binary never clobbers agent B's active target on the same connection.
- **Agent-scoped ownership**: while an agent is actively running a session, a sibling agent gets `FILE_LOCKED` if it tries to grab it. Ownership is recorded under the agent, not the raw connection.
- **Per-agent teardown**: `agent_logout` (and connection close) releases only that agent's runtimes and leases — a dead subagent can no longer orphan its idat fleet or hold another agent's IDB locks.
- Truncation tokens are scoped `connection:agent`; the `agent` tag is validated against the logged-in identity on the current connection and never forwarded to IDA. Calls without an `agent` tag behave exactly as before.
- The `agent` tag is accepted on all tools (popped at the protocol layer before policy/RPC schema validation).

## 2026-08-02 — session targeting for arbitrary code execution

- `ida_python` now accepts `idb=<session_id>` (or an IDB/binary path) to target a specific session on a shared MCP connection. Previously it always executed against the connection-wide active session, so on a connection shared by several agents, Python ran in whichever binary opened last — mixing analyses from different binaries (e.g. the same function name resolving to a different base).
- The safe-mode gate now tests the session a call is aimed at (via `idb`), not the shared active default. Targeting a completed session no longer gets spuriously blocked because another session on the same connection is still analyzing, and a still-analyzing target is blocked regardless of which session happens to be active.
- Every `ida_python`/`misc` code-execution response now carries a `_executed_in` block (`session_id`, `idb_path`, `image_base`), so a call that ran in the wrong session is visible instead of silently returning addresses from another binary. The image base comes from the runtime cache or a fast lookup; it is never fabricated.

## 2026-08-01 — relocation handling and session lifecycle fixes

### Relocations
- `ida_open_binary(baseaddr=..., rebase_to=...)` silently dropped the load address when given as a hex string like `"0x400000"` (`int("0x400000")` raised and the `-b`/`-R` flags were skipped). Both flags now parse base-0 values, and `entry_point` ints are hex-formatted (IDA would have misread decimal as hex).
- `analysis(action='set_options', baseaddr=...)` computed the rebase delta *after* `set_inf_attr(INF_BASEADDR)`, so the delta was always 0: segments stayed at the old base while INF_BASEADDR claimed the new one. The delta is now computed before any mutation, `rebase_program` is the only thing that moves segments, and non-page-aligned deltas return an actionable error instead of a generic failure.
- Response enrichment no longer fabricates an image base: `_get_session_imagebase` used a hardcoded `0x140000000` default, so every 32-bit address (e.g. `0x401000`) was treated as an RVA and "rebased" to garbage (`0x140401000`). Unknown image bases now skip enrichment instead of inventing offsets, and the value is resolved from the target session's options or a live RPC.
- `memory` relocation introspection actually runs now: `ida_fixup` was never imported into the tool namespace (the check lived inside `except Exception: pass`), so relocation flags never fired in production. `struct_walk` now reports `fixup_type`/`fixup_name`/`fixup_base`/`fixup_off`, and the `pointers` action flags relocation slots.
- Firmware bootstrap accepts a string `load_base` (e.g. `"0x120000"`); it previously dropped it with a strict `isinstance(int)` gate.

### Session lifecycle
- Session metadata (watchdog analysis verdicts, stall state, apply transcripts, indexing state) was written to disk via `_save_metadata` but never serialized, so it vanished on restart. `metadata` now round-trips through `to_dict`/`from_dict`.
- Metadata writes no longer `fsync` every watchdog tick, and unchanged `_update_session_indexing_metadata` calls skip the disk write entirely.
- `cleanup_stale`/`auto_prune_if_over_budget` no longer delete sessions that still own a live IDA runtime (previously they could orphan the idat process and leave the IDB lock held forever).

### Investigation workspace persistence
- The blackboard workspace was keyed by `sha256-{binary}-{session_id}.db`, so every new session of the same binary started from an empty notebook and findings appeared lost. The workspace is now binary-scoped (`sha256-{binary}.db`): all sessions of the same binary — including byte-identical copies — share one investigation, and findings survive session close, rebuild, and new sessions.
- Workspaces from previous releases are adopted exactly once: per-session `sha256-{digest}-{sid}.db` files (newest first) and the legacy `<idb>.blackboard.db` sidecar are seeded into the shared db with `INSERT OR IGNORE` so nothing is duplicated or overwritten.

### Session cache layout
- Each session now lives in its own directory: `cache_dir/sessions/SID_<sid>/` holding `metadata.json`, the IDB, `bookmarks.json`, `snapshots.json`, `notebook.md`, `skills.json`, a `logs/` subdirectory for the IDA runtime logs, and the runtime port handoff files. The cache root no longer accumulates `SID_*` flat files and per-session logs.
- Legacy flat-layout sessions (`SID_<sid>_metadata.json`, sidecar IDB, cache-root logs) are migrated into the per-session directory on first load; the recorded `idb_path` is updated in place. Deleting a session removes the whole directory.

### Session discovery and reuse
- `ida_session_list` (and the legacy discover action) gained a `binary_name` filter that matches the analyzed file's name, and the free-text query now also matches `auto_name`, tags, and notes.
- A restarted MCP client reloads its old sessions: a recorded session that nobody is actively running (no live IDA runtime, no live foreign lease) is adopted and reuses the recorded IDB instead of silently creating a fresh session and re-analyzing from scratch. Sessions with a live idat remain locked to their owner (`FILE_LOCKED`).

### Large-binary handling
- `ida_open_binary` now warns for binaries at or above `IDA_MCP_LARGE_BINARY_MB` (default 50 MiB) and suggests background loading instead of blocking on upfront analysis.
- New operation `ida_open_background` (session action `create_background`): creates/reuses the session and starts the IDA runtime on a daemon thread, returning immediately; poll `ida_session_status` for progress (`is_running`, `analysis_ready`, and `background_error` on failure).

### idat RPC concurrency
- The per-session RPC lane keeps serializing requests to one IDA bridge (it executes one SDK request at a time), while different sessions stay fully parallel. The queue is now bounded: after `IDA_MCP_RPC_QUEUE_TIMEOUT` seconds (default 300, `0` = unlimited) a queued call fails fast with a recoverable `IDA_BUSY` error instead of piling up threads behind a stuck request — distinct from `IDA_TIMEOUT` (socket recv deadline) and `IDA_CRASHED` (process exited).
- `ida_session_health` reports per-session RPC queue depth (`rpc_queued_calls`, and per-runtime `rpc_queued` in verbose mode).

### Auto-background loading and safe mode
- `ida_open_binary` no longer blocks on upfront analysis of large binaries: at or above `IDA_MCP_LARGE_BINARY_MB` (default 50 MiB) it auto-routes to the background path and returns immediately with `background`, `auto_backgrounded`, and `safe_mode` flags, telling the agent to poll `ida_session_status`. Small binaries and reuses of an already-completed IDB still open synchronously.
- While a session's IDA auto-analysis is running, the session is in **safe mode** (`safe_mode: true` in open/status/state/list responses): full-binary analysis (`analysis` set_architecture/reanalyze/run/analyze), decompile-everything indexing (`intelligence` index_*/semantic_search/similar_functions), firmware bootstrap, whole-program workflow runs, symbol loads, segment analysis, and arbitrary script execution (`ida_python`/idc/plugin_run — which could invoke `auto_wait`) are blocked with a recoverable `SAFE_MODE` error. Manual small-area operations stay available: disassembly, reads, strings, xrefs, per-function decompilation, comments/renames, blackboard findings. Auto-enrichment (digests, session resume) is suppressed until safe mode lifts.
- Safe mode lifts only when a live runtime explicitly confirms `analysis_complete`. For background-loaded sessions the runtime is then **reloaded against the fully analyzed IDB** (the "auto move to the new one" step) and the next response for the session carries a one-shot `analysis_complete` warning. A runtime that dies mid-build does not lift the gate — the interruption is surfaced as `background_error` and safe mode stays on.
- Escape-vector hardening: re-opening the same binary (reuse or `force_new`) re-enters pending state, `session(action='rebuild')` re-enters safe mode, and a missing/ambiguous `analysis_complete` in the state RPC never counts as complete.
- Tuning: `IDA_MCP_SAFE_MODE_POLL_SEC` (default 5) controls the completion-watcher poll interval, `IDA_MCP_SAFE_MODE_WATCH_SEC` (default 6 h) caps it.

### Blackboard export in the findings format
- New `ida_export_findings` operation (findings category) exports the investigation workspace in the new findings format — kind, status, confidence, priority, tags, evidence, conflicts, staleness. JSON mode returns a full-fidelity `ida-findings-v1` snapshot (machine-readable, internal storage fields stripped); markdown mode renders a grouped report by kind → status with content and evidence bullets. Pass `path` to write a file; otherwise content is returned inline. Filters: kind/status/category/tag/address/min_confidence/include_resolved/include_contradicted/limit.
- Backed by a new `blackboard(action='export')` action (registered in the legacy tool too); it reads the binary-scoped SQLite workspace, so it works without an IDA runtime and is safe-mode compatible.
- The legacy lane-brief export `blackboard(action='notes_export')` is removed: it rendered a few lanes as truncated briefs and dropped evidence, kind, status, and conflicts. `notes_import` stays for ingesting hand-written markdown.

### Installer: frozen runtime by default
- The installer's `--runtime-source auto` resolved to `local` for any
  checkout, writing a `ida_pro_mcp_dev.pth` into the install venv so the
  deployed server imported the **live source tree**. That made every running
  MCP daemon's behavior depend on when it started relative to the last
  edit, and broke installed servers whenever the checkout changed. `auto`
  now resolves to a new **`snapshot`** mode: the checkout is copied to
  `install_root/runtime-src-<stamp>` (old snapshots pruned) and pip-installed
  from that frozen copy, so the venv holds a fixed package in site-packages.
  `local` remains only as an explicit, labeled dev mode (`--runtime-source
  local`). CLI choices and the interactive prompt are updated accordingly.
- The wiki is rewritten around the current `ida_*` operation surface: 22
  stale pages for removed legacy tools and all legacy `tool(action=...)`
  pages are gone; `core/` documents sessions/safe mode, the investigation
  workspace, frontier strategies, and intelligence; `tools/` documents every
  operation by category. Workflow playbooks were removed.

### Per-session targeting on shared MCP connections
- `ida_session_status` and `ida_session_state` now accept `idb=<session_id>`
  to report a named session instead of the connection-wide active one (which
  reflects whoever opened a binary last). Several agents multiplexed over one
  MCP connection (opencode subagents share the connection; MCP carries no
  per-agent identity) can therefore each steer status/state at their own
  session. Naming a session makes it the connection's active session for
  subsequent calls, subject to the existing ownership guard (a session with a
  live foreign runtime is rejected with FILE_LOCKED). Analysis operations
  already accepted `idb`; this closes the gap for the polling operations.

## 2026-07-31 — dead legacy tools removed

25 legacy tools were unreachable from every surface: never advertised in `tools/list` (legacy mode included), never exposed as `ida_*` operations, never called by any host service. ~18,000 lines of dead IDA-side code are gone.

- Removed tools: `abi`, `binary_info`, `bindiff`, `bulk`, `cfg_analysis`, `classify`, `compare`, `coverage`, `data_ops`, `debug`, `emulate`, `export`, `fixups`, `history`, `lumina`, `microcode`, `nav`, `patterns`, `project`, `security`, `string_ops`, `struct_recover`, `summarize`, `trace_analysis`, `xref_analysis`.
- Registry now holds 32 legacy tools (was 57); the 47 public `ida_*` operations are unchanged.
- Cleaned all references: `tool_registry.py`, `schemas_data.py` (TOOLS, descriptions, arg schemas, alias and threat-route tables), `policy.py` risk tiers, `schemas.py` tool categories, usage-intel tool sets, `server_workflow.py` step plans and category maps, session skill suggestions, legacy `prompts.py`, and batch templates.
- Kept six tools that initially looked dead but have live call sites: `annotation` (blackboard rename proposals), `ctree`/`stack_analysis`/`imports_deep` (multi-session linking), `knowledge`/`firmware_view` (session bootstrap).
- `shannon_entropy` moved from `string_ops` into `_common.py` (used by `memory` and `intelligence`).
- Deleted `tests/test_bindiff_export_helpers.py` and the `security`/`summarize` source-scan tests in `test_taint_consolidation.py`.

## 2026-07-31 — the agent surface stops teaching the legacy API

Error hints and recovery guidance are the one place models were still being steered to `tool(action=...)`. The default surface is `ida_*`, and the hints are now written that way at the source.

- Rewrote all model-facing error hints (IDA-side `error_handling.py`, host-side `errors.py`, session/bookmark dispatch, `ida_overview` next-actions) to reference public `ida_*` operations; operations without a public equivalent (debugger, bookmarks, plugins) point at `ida_python` instead of the hidden legacy API.
- Host error `recovery` recipes now ship public-first (`ida_open_binary`, `ida_disassemble`, `ida_calc_convert`, ...); the public-surface adapter passes already-public recipes through instead of dropping them.
- README operations table and count now match the registry (47 operations) and are pinned by docs-sync tests.

## Unreleased — the blackboard becomes an investigation workspace

The store was write-only in practice. A model recorded findings and then had to *choose* to query them back, which it rarely did; the only automatic recall was three bare titles injected inside a bare `except Exception: pass`. Negative results were unrecordable, nothing ever invalidated, and disagreement was silently merged into whichever claim had higher confidence. `blackboard_store.py` is rewritten around four behaviours it did not have.

### Added — recall without being asked
- Every address-bearing response now carries `_recall`: prior findings, examination verdicts, and open questions for that address, produced by a new deterministic `BlackboardStore.recall()` — exact address matches, no embeddings, bounded work.
- Result sets carry `_already_examined`: which of the returned addresses were previously read and dismissed, so a search does not re-offer work that was already thrown away.
- Failures set `_recall_error` on the payload instead of being swallowed. A recall path that silently does nothing is indistinguishable from one that was never wired up, which is how the previous version decayed.

### Added — negative results
- New operation `ida_mark_examined(address, verdict, note)` and store method `record_examination()`. Records "I read this, it's a CRT wrapper, skip it" in one line. Re-examining replaces the verdict and keeps the change in the event log.
- Coverage counts appear in `ida_analysis_brief` and `stats()`.

### Added — claims that notice they are out of date
- New `code_anchors` table. Every response that renders code for an address records a digest of it; findings written at that address are anchored to that digest.
- When the code changes, claims anchored to the old text are marked `stale` with a reason — including examination verdicts, since "boring" is also a claim about code that just changed. Staleness annotates; it never deletes or rewrites a claim.
- Revising an entry re-anchors it and clears the flag. `ida_next_target(strategy="stale")` lists what needs re-checking. Whitespace-only reformatting is not drift.

### Added — disagreement is kept, not merged
- Recording an opposed status (a rejection over a confirmation, or the reverse) on the same claim now stores both rows and links them via `conflicts_with`, returning a `conflict` block naming what it contradicts. Previously `upsert_finding` merged them and took `max(confidence)`, so a rejection at 0.2 landing on a confirmation at 0.9 left the confirmation untouched and produced no signal at all.
- `auto_merge` and `prune` refuse to touch conflicting or stale rows: they are low-confidence precisely because they need attention.
- Merging a repeat observation now takes the **newest** confidence, not the highest. Restating a claim is not evidence for it, and the old ratchet meant confidence only ever rose.

### Added — the IDB round-trip
- `ida_publish_findings(risk_ack=true)` writes confirmed, non-stale, non-conflicting findings into the database as repeatable comments, and renames functions IDA still auto-named. The IDB is the artifact an analyst opens; a conclusion that lived only in a side database was a conclusion nobody outside this tool ever saw.
- It never overwrites a symbol someone else applied — an existing name is either an analyst's own work or a library signature match, and a slug of a finding title is not worth either. Skips are reported with the reason. `dry_run=true` previews without `risk_ack`; a rename that fails still leaves the comment and says so rather than reporting the entry as published. Publishing is idempotent: an entry is written once unless it changes.
- `ida_import_annotations` adopts existing IDB names and comments as confirmed findings at confidence 0.5, since this tool did not verify them and cannot distinguish an analyst's rename from a FLIRT match. A session inherits whatever the last analyst left behind.
- Published comments carry an `[mcp:<id>]` marker and the import side skips them, so a publish/import round trip does not turn one claim into a second, independent-looking corroboration of itself.
- New `data(action="annotations")` on the IDA side. Comments were writable through the tool surface but never readable, so understanding recorded in the IDB was invisible to the host.

### Changed — the brief reads like a case file
- `ida_analysis_brief` renders Established / Open / Contested / Needs re-checking with a next step chosen from the actual state — reconcile conflicts, re-read stale claims, take an unblocked item, or expand the frontier — instead of emitting counts plus three arrays and raw event rows.

### Changed — target selection explains itself
- `ida_next_target` takes `strategy`: `unresolved`, `stale`, `conflict`, `coverage`, `frontier`. Every candidate carries a `reason` string ("12 callers, never examined"; "code at 0x401000 changed since this was recorded").
- This replaces a six-coefficient blended score — priority term, adaptive half-life, dependency factor, category prior, xref sigmoid, entropy sigmoid — that was never calibrated against whether the suggestion paid off, and that nobody could debug.
- `coverage` prefers auto-named functions but falls back to named ones on a symbolised binary rather than returning nothing, and says which it did.
- A `query` now reorders candidates by keyword overlap and never drops them; the previous blend could hide work behind a weak semantic match.

### Fixed
- **The entire semantic path was dead code.** `_pack_vec`/`_unpack_vec`/`_cosine` imported from `.intelligence.helpers` — one dot too few from `host/stores/`, resolving to the non-existent `host.stores.intelligence`. Every call raised `ModuleNotFoundError` into an `except Exception: return None`, so no embedding was ever stored, `vector` was always NULL, and `semantic_search` silently ran lexical-only forever. Fixed; `semantic_search` results now carry `match: "semantic" | "lexical"` so the fallback is visible.
- `_row_to_dict` cached column names on the instance (`_col_cache`) and could serve a stale layout after a migration. The store now uses `sqlite3.Row` throughout.
- Addresses are normalised through `normalize_addr` on every write and lookup, so `0X00401000` and `0x401000` are one address rather than two.
- `exists_similar` derived its match threshold from the quantiles of the very sample it was testing, so a set of uniformly dissimilar titles produced a low gate and reported a match. Fixed threshold now.
- `semantic_rebuild` reported `rebuilt` counts that included entries whose embedding failed; it now reports `skipped` and why.

### Removed
- `auto_tag_propagate` — copied tags from any entry above 0.8 confidence to every other entry at the same address, which manufactures agreement between unrelated claims. Replaced in the action registry by `mark_examined`, `recall`, `conflicts`, and `stale`.

### Tests
- `tests/host/test_workspace_memory.py` (30), `tests/host/test_workspace_recall_injection.py` (16), and `tests/host/test_workspace_idb_roundtrip.py` (20). Conflict preservation, anchor staleness, the confidence ratchet, the dispatch-path wiring, the rename guard, the `risk_ack` gate, the marker skip, and publish idempotence were each mutation-tested: reverting the fix fails its test. The injection suite drives the real `_prepare_response_payload` with the production MRO, so unwiring the hooks fails rather than degrading into a workspace nobody reads.

## Unreleased — dead-code cut + host safety fixes

### Cuts
Roughly 6.9K lines removed. None of it was reachable from any client.
- **Removed the analysis-engine cluster** (`analysis_engine.py`, `analysis_engine_kg.py`, `gap_engine.py`, `narrative_engine.py`, `analysis_proposal_store.py`). `AnalysisEngine` was never instantiated — `_analysis_engines` was declared and never written to. With it go the `proposals` resource and the `blackboard` `accept_proposal`/`reject_proposal` actions, which could only ever return "no analysis engine running". `accept_proposal` also called `_apply_proposal`, which is not defined anywhere.
- **Removed `server_threat_hunt.py` and `yara_hunt.py`** — no importers, absent from `TOOLS`, `_TOOL_ACTIONS`, and `schemas_data.py`, so no client could reach them. `threat_corpus` and `intelligence/sources/` are kept: the installer populates them for FindCrypt and the taint signatures.
- **Removed `mbagcn_engine.py`** — re-exported by `services.py`, imported from there by nothing. It also contained no GCN: no message passing, no learned weights, and a "Johnson-Lindenstrauss projection" that mapped 96 dimensions up to 4096.
- **Removed `.test-registry.json` and `scripts/test_registry_check.py`** — the magic-header test ceremony `AGENTS.md` forbids. No test carried the header and nothing ran the checker.
- **Removed three test files**: `test_send_rpc_with_retry.py` (all 7 tests `read_text()` the production source and grep for substrings, never executing `_send_rpc_with_retry`), `test_phase_gates_optin.py` (imports nothing from the project; its 8 tests assert against gate logic written inline, so deleting the production module leaves them green), and `test_analysis_engine.py` (covered the deleted engine).

### Known gaps
- `tests/host/test_dispatch_postprocess.py` still defines its own 22-line `_execute_tool_inner`, shadowing the 350-line production one its docstring claims to exercise. Left in place rather than deleted, but it does not test what it says it tests.
- Roughly 26K lines of IDA tool modules stay registered but hidden from `tools/list`, so no client can discover them. Promote or cut is still an open decision.

### Fixed — safety
- **Policy could be switched off by request.** `session(action='create')` accepted an undeclared `policy_mode`, session mode outranked the operator's env/config setting, and `("session","create")` classifies as a read — so one unacknowledged call disabled the policy engine, blackboard gate, and phase gate for the session. The operator baseline now wins and a session may only tighten it (`policy.strictest`); the create argument is gone.
- **Ownership checks could fail open.** Three mixins reached `_ensure_client_owns_session` through `getattr(self, ..., None)`, skipping it on any object that had not inherited it, while `server_dispatch` called it directly and raised `AttributeError`. The check now lives on `ServerClientStateMixin` and is inherited everywhere.
- **`session(action='health')` could crash.** It iterated `session_runtimes` without `_runtime_lock`, so a concurrent teardown raised `RuntimeError` from the call meant to report runtime state.
- **A failed kill reported success.** `session(action='kill')` returned `{"ok": true}` even when the process survived SIGTERM and SIGKILL. It now returns a structured error with the pid. The post-SIGTERM wait no longer swallows non-timeout errors.
- **Ownership leases had a TOCTOU window.** The lease was created empty and written afterwards; a claimer reading that window saw no owner, removed the file, and both processes believed they held the IDB. Leases are now published by hard-linking a fully written temp file.
- **Confidence decay defeated itself.** `decay_stale_confidence` wrote `updated_at`, making a decayed entry the most recently updated row in every `ORDER BY updated_at DESC` listing and resetting its own age so it could never decay twice. It now records `decayed_at` (additive column) and measures elapsed time from the later of the two.

### Fixed — CI
- **`pytest` was red on master** (8 failures). Four came from `_ensure_client_owns_session` drift, four from `ida_mcp.rpc` importing the vendored `zeromcp` as a top-level module, which fails outside IDA's flat `sys.path`. Shared SDK stubs also gained the `ida_kernwin`/`idaapi` sync constants that `ida_mcp.sync` reads at import time.
- Added `tests/host/test_safety_invariants.py`. Each fix above was mutation-tested: reverting it fails its test.

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
- **`tools/list` Tier A only** (~17 tools). Full `TOOLS` remain callable by exact name. See `docs/guide/roadmap.md`.
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
- QuickStart rewritten to Tier A core path; `docs/guide/roadmap.md` added; ghost wiki pages (`static_trace`, `trace`, `vuln_scan`) retargeted; architecture phantoms removed.

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

- **Install path was the actual problem** — client configurations use the
  packaged install tree rather than an arbitrary working checkout. Refresh the
  runtime after packaging changes with `python install.py --only runtime --yes`.

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
