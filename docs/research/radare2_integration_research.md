# radare2/Rizin Integration Research — ida-pro-mcp

**Scope:** A comprehensive, exhaustive research paper synthesizing 11 agent journals (Track A: 6 project-edge maps including the unimplemented-IDA-API map; Track B: 5 radare2/Rizin analyses including overlap-elimination and viability verdict). Mission context: the user analyzes OPAQUE device binaries — raw headerless `.bin` firmware, especially RISC-V — and wants the MCP to be more reliable, faster, and more useful than radare2.

**Tree status:** The working tree is on branch `swarm/session-blitz` and is being concurrently edited by two implementation waves (56+ files modified at the time of writing). Every claim below was anchored to files actually read at this moment. Areas in flux: `host/analysis/arch_profile.py`, `host/agent_operations.py`, `host/schemas_data.py`, `host/policy.py`, `host/server/*.py`, `src/ida_pro_mcp/ida_mcp/tools/*.py`. Re-anchor against current HEAD before acting on any recommendation.

---

## 1. Executive Summary — the 5 things a decision-maker must know

**1. The MCP already covers ~85% of the classic radare2 command surface — natively, structurally, and often better.** `axt/axf` ↔ `ida_xrefs_to` + `code(xrefs_from)`; `agf/agg` ↔ `ida_callgraph` + `graph(callgraph/cfg/dominators)`; `iz/izz` ↔ `ida_list_strings` + `memory(strings)` + `search(string)`; `/x`/`/e` ↔ `search(bytes/regex)`; `t/td` ↔ `ida_declare_type`/`get_type`/`list_types`; `wx/wa` ↔ `ida_patch_bytes`/`modify(patch_bytes)`; `z-zignatures` ↔ `funcs(find_similar)` + FLIRT. The MCP's equivalents are richer (structured JSON, xref counts, semantic search, CFG evidence, mermaid callgraphs) and operate on the authoritative analyzed IDB. **Any r2/Rizin integration that re-implements these is a mistake.** The honest value of a customized r2/Rizin engine is NOT as an IDA replacement but as a cheap, headless, **no-IDA-license subprocess co-processor** for the four things the MCP genuinely cannot do today: (a) pre-IDA file triage (arch/base/endian/strings/entropy) in milliseconds without spawning `idat`; (b) raw-data-word pointer xrefs (`/v`) that `search(immediate)` cannot produce on headerless blobs; (c) decoder cross-validation and multi-arch hypothesis disassembly; (d) deterministic lightweight CPU emulation (ESIL/unicorn) for opaque RISC-V firmware.

**2. The single biggest dynamic gap in the MCP is emulation/debugging — it is entirely absent.** There is zero execution capability in the public surface. The evidence is vestigial and contradictory: `tools/memory.py:346` documents `debug(action='write_mem')` for "debugger memory" that does not exist; `host/schemas_data.py:172` claims an `emulate` tool "in TOOLS" that is not registered anywhere; `host/errors.py` and `ida_mcp/error_handling.py` carry full `DEBUGGER_*`/`EMULATION_*` error codes with no implementing tool; the two prior attempts (a Unicorn `emulate.py` and a `debug.py`) were deleted in commit b191581 for having no public op and never being advertised. **Verified on this box:** r2 6.1.6 ESIL emulates RV32 straight-line + stack code correctly (a0=0x2a after 7 steps) but does **not** resolve RISC-V `jalr` indirect jumps (pc stays 0); stock r2 has no unicorn compiled (`asm.emu=false`, no `-U`); `e esil.maxsteps` defaults to 0 (unbounded) and `aecu`/`aesu` hang without a reachable breakpoint. The robust engine for opaque RISC-V emulation must therefore be unicorn-backed (Rizin bundles it), and every emulation op must set `esil.maxsteps` + a wall-clock cap. **The single most important design lesson from Track B:** the previous emulation/debug tools died because they had no advertised public surface — any new engine must ship registered, advertised `ida_*` ops + a workflow, or it will be removed again.

**3. License is a green light, not a blocker.** The MCP is GPL-3.0-only (pyproject). GPL-3.0 is compatible with radare2 (GPL-3.0) and Rizin (LGPL-3.0). Driving an externally-installed engine as a **subprocess** (exactly how proprietary IDA is driven today) creates zero bundling/relink/conveyance obligations. The dangerous paths: (a) bundling r2/Rizin binaries inside the wheel (GPL §5/§6 source-offer and LGPL §4(d) relinkable-object duties); (b) linking `librizin` in-process via ctypes (LGPL §4(d) + in-process untrusted-parse security). Non-negotiable rules: **subprocess-only, never bundle in the wheel, never `import` unicorn into `ida_pro_mcp/**` (unicorn-engine is GPL-2.0-only + commercial dual license), never let r2 output write the IDB** ("r2 proposes, IDA disposes").

**4. Recommended decision: ADOPT Architecture A — an optional, default-off, host-side `r2`/`ida_r2_*` subprocess engine namespace — and REJECT Architecture B (independent full query backend, two symbol namespaces, divergent indexes) and Architecture C (in-process librizin: LGPL relink obligations + in-process parsing risk).** Architecture A slots into the existing host dispatch seam (mirroring the `_handle_bookmarks`/`_handle_memory_filesystem`/`_handle_analysis_plugin_run` host-side branches in `server_dispatch.py:_execute_tool_inner`), reuses the length-prefixed JSON-RPC + session-token auth + port-file handoff pattern from `server_script.py`, the process lifecycle from `server_runtime.py`, and the policy/registry/error-envelope/compaction/batch machinery wholesale. It works even while IDA is mid-auto-analysis (safe_mode) or down — it only needs the raw binary path plus the session's resolved arch/bitness/base. **Phase order:** (0) decision doc; (1) hermetic fake-r2 tool + 2-3 ops (`load_hints`, `disassemble_range`, `bininfo`/`strings`/`entropy`), CI can run real `rz`; (2) load-hint feedback into `open_binary`; (3) ESIL/unicorn emulation as advertised ops; (4) hypothesis-tier blackboard ingestion.

**5. The firmware capability story is real but mid-flight and must be reconciled before anything else.** The `firmware_view` tool (20 actions: `detect_load_address`, `detect_vector_table`, `detect_mmio`, `rtos_scan`, `pointer_sweep`, `smart_carve`, `auto_retype`) and `support/firmware_heuristics.py` were **deleted from source** (and their tests `test_p12_firmware_tools.py`, `test_swarm_t04_firmware.py`), yet vestigial traces still advertise the concept: `ida_mcp/prompts.py:255` `WORKFLOW_FIRMWARE`, `host/policy.py:307` `firmware_analysis` purpose, `ida_mcp/tools/idb.py:127` emits `firmware_detected`, and `server_session.py:1952`/`server_response_compact.py:310` consume it. **Simultaneously, the replacement relocation has landed RISC-V raw-blob inference in `host/analysis/arch_profile.py`** — the current tree has `riscv` as a raw-candidate (opcode-density scoring with `c.jr ra`/`c.jalr ra` strongest signals), `riscv32`/`riscv64` prototype embeddings, a `_riscv_bitness` RV64-vs-RV32 evidence function, and a `riscv_instruction_validity` gate (this **resolves** the Track A2 claim that "a raw RISC-V .bin cannot be auto-detected" — the waves closed it). What is NOT yet visible in the tree: a replacement for vector-table/RTOS/pointer-sweep/carve. **Decision needed:** resurrect the firmware-shaping capabilities as `ida_*` ops (the mission's core differentiator vs radare2) or strip the vestigial traces so "firmware" is not advertised-but-absent. And there is still **zero raw/opaque `.bin` fixture, fake, test, or doc anywhere in the repo** — every opaque-blob reliability claim is unvalidated against the mission's actual input.

---

## 2. Project Surface Map — every edge of the project

The project has four layers: (1) the IDA-side analysis surface (`src/ida_pro_mcp/ida_mcp/`), (2) the standalone host server (`src/ida_pro_mcp/host/`) that runs without IDA, (3) support/plumbing shared by both, and (4) the meta-surface (tests/docs/skills/scripts/CI/packaging). Within each there is an "agent surface" (67 exact-schema `ida_*` ops in `host/agent_operations.py`, the current contract) and a "legacy surface" (31 tools / 388 actions in `schemas_data.py`/`tool_registry.py`, reachable only via `IDA_MCP_TOOL_SURFACE=legacy` or `ida_python`).

### 2.1 IDA-side tool surface (`src/ida_pro_mcp/ida_mcp/tools/`)

The IDA side is a set of 26 action-parameterized `@tool` dispatchers over a thin infra layer (`rpc.py` registry + zeromcp JSON-RPC schema gen; `sync.py` `@idaread`/`@idawrite` execute_sync serialization with an LRU result cache invalidated on every write; `error_handling.py` `make_error` envelope with ~176 MCPError codes + LLM hints; `mcp_http.py` localhost CORS/DNS-rebind-guarded config page). The tool modules, with completeness:

| Module | Purpose | Completeness / notes |
|---|---|---|
| `idb.py` | Overview, meta, state, bookmarks (read-only), segments info, architecture profile | Strong. Bookmarks are **read-only** (no create/delete/jump). Emits `firmware_detected` (vestigial, machinery deleted). |
| `code.py` | decompile, disasm, xrefs, callers/callees, smart_decompile, blocks | Strong; the core read surface. `disasm` injects a RISC-V GP note (commit a7dd37c). |
| `data.py` | strings, globals, exports, arrays, string_xrefs, **export** action | Partial. Export is shallow (named functions + types only). Raw-string min-length bumps present. |
| `funcs.py` | list/info/create/change/delete/set_flags/find_similar/metrics/suggest_names; `_try_map_raw_runtime_addr`; `_set_thumb_mode` (internal) | Strong. No function-tail chunk surgery. |
| `search/` | bytes/string/immediate/name/insns/mnemonic/instruction/text/operand/comment/data_ref/code_ref/regex/func_by_sig/find/callers/callees/api/vulnerable/constants/decompiled/structured/type/export/summary/**query_lang**/nl/behavior/bool/analyze/neighborhood/outlier/fingerprint/path/reach/noreach/symbol/symbol_info/demangle/xrefs_to_string | Very strong, the widest surface. `query_lang` (MATCH…WHERE DSL) is **legacy-only** (search action), 90%-built but orphaned. |
| `types.py` | declare, import_header, apply, propagate, list/get, enum_values (read), diff, infer, vtable | Partial. Full authoring via whole-C declaration; **no per-member edit, no TIL deletion, no TIL export/import**. |
| `segments.py` | add/delete/set_attr/set_perms/move/list/info/analyze/find_code/find_data/compare/merge | Strong. No segment-register seam (`ida_segregs`), no sreg defaults. |
| `analysis.py` | reanalyze/run/analyze, set_gp, set_architecture, set_loader_options, get_af/set_af; `_bootstrap_raw_entry_points`, `_auto_reanalyze_text_segments`, `_ensure_entry_point_functions` | **Strongest firmware seam.** Raw-blob entry bootstrap + RISC-V GP (x3) auto-config via simulated auipc/addi prologue, netnode-persisted + queued reanalysis. |
| `gadgets.py` | rop/jop/cop/syscall/mitigations/stack_pivot/write_what_where + `_classify_riscv_jalr` | Strong on RISC-V gadget classification; **mitigations is PE/ELF/Mach-O-only** (raw blobs → `{format: unknown}`). |
| `stack_analysis.py` | frame/buffers/canary/alignment/spills/usage/variables/arrays/uninitialized/summary | Partial. **Canary detection is name/symbol-dependent**; no instruction-pattern fallback. |
| `memory.py` | read/write/hexdump/strings/search/entropy/histogram/pointers/struct_walk/compare | Strong byte-view surface. **Docstring references nonexistent `debug(action='write_mem')`**; entropy is one region number (no per-block profile). |
| `modify.py` | patch_bytes, patch_asm, rename_local, governed=True pre-checks | Partial. Patches have **no undo/diff/restore**. |
| `misc.py` | python/idc/read_file/write_file/load_sig/list_sigs/find_plugin/run_plugin/cache_stats | **`python`/`idc` is an ungated arbitrary-code-execution escape hatch** (governance only via modify.py). FLIRT **apply** side present; **authoring absent**. |
| `symbols.py` | list/rename/export, load_pdb/load_dwarf/load_and_run_plugin | Partial. Export has **no import/restore** counterpart. |
| `imports_deep.py` | thunks/delay/forwarded/ordinal/api_sets/resolve | PE-centric; ELF PLT deep resolution unaddressed. |
| `graph.py` | callgraph/cfg/dominators/xref_graph | Strong (uses `ida_gdl.FlowChart`). |
| `ctree.py` | get/traverse/find_*/logic_flow/dominance_map/var_dependency_graph | **Read-only traversal; no ctree surgery, no decompiler-option toggling.** |
| `batch.py` | deterministic multi-op execution | Strong. |
| `blackboard.py` | thin IDA-side bridge (`BlackboardStore` subclass + `related_by_behavior` + crawler-probe adapter); the host owns the action dispatcher, crawler, phase machine, and policy gate | The 40-action IDA-side dispatcher, `_BackgroundCrawler`, `propagate_labels` stub, and KG/export branches were removed in the analysis-memory redesign. |
| `intelligence.py` | semantic search bridge, function_families, similar_functions | Strong (host-side engine). |
| `knowledge.py` | export_session fingerprints / import_symbols | **Function-only** cross-session transfer; no structs/comments. |
| `wiki.py`, `governance_engine.py` | wiki docs; modify pre-check governance | Gov engine real; wiki legacy. |
| `_common.py` | shared validation/helpers | Plumbing. |

**Policy is NOT an unsafe-set.** `MCP_UNSAFE` is defined in `rpc.py` but nothing ever registers (`@unsafe` unused), so the config page's "Disable unsafe" control is inert. Gating is instead: `@idawrite` cache invalidation, `modify.py` governed=True pre-checks through `governance_engine`, explicit `risk_ack` on host-side tools, and a firmware-blind OWL ontology (R001 NoImportTablePatch; **R002 PII redaction rewrites hardcoded C2 IPs/domains in IDB comments to `[IP_REDACTED]` — direct friction for firmware IOC note-taking**; R003–R006).

**Weak edges cluster:** Windows/PE libc bias (semantic tagging, dangerous-API/magic-constant catalogs, imports_deep, mitigations), symbol-name dependence (canary detection), write-only/shallow export + cross-session transfer (no restore, function-only), absent fine control (per-member struct/enum editing, TIL deletion, decompiler-option toggling, patch undo/diff).

### 2.2 Host/server/session/dispatch surface (`src/ida_pro_mcp/host/`)

`host/` is a mature, defensive mixin-composed `IDAMCPServer` (`server/server.py`) covering: JSON-RPC dispatch with safe-mode gating (`server_dispatch.py`), per-runtime serialized RPC lanes with retry + hard wall-clock watchdog (`server_runtime.py`), per-connection client state + agent SSO + cross-host IDB leases (`server_client_state.py`, `server_runtime_leases.py`), token-bucket rate limiting (`rate_limit.py`), background task pool with cooperative cancel + persisted sliced semantic-index jobs (`server_batch.py`, `batch_manager.py`), analysis pipelines (`analysis/arch_profile.py`, `analysis/patterns.py`, `analysis/context_density.py`), response post-process filter pipeline + truncation continuation tokens (`server/postprocess.py`, `stores/truncation.py`), agent-UX enrichment (`server_response.py`, `response_enrichment.py`), multi-session groups with persisted cross-binary link tables (`server_multi_session.py`), workflow plan/audit/estimate/execute (`server_workflow.py`, `server_workflow_batch.py`), blackboard workspace (`server_blackboard*.py`), session skills + bootstrap policy learner (`session_skills*.py`), semantic asm gadget index (`server_semantic.py`), and the registry/schema/policy contracts (`tool_registry.py`, `schemas_data.py`, `schemas.py`, `policy.py`, `agent_operations.py`).

| Host module | Purpose | Completeness / notes |
|---|---|---|
| `agent_operations.py` (1950 lines) | The 67-op single source of truth: schemas, examples, backend maps, help, docs, skill | **Fully wired + CI-pinned.** Regenerates `docs/TOOLS_REFERENCE.md`, `.agents/skills/`, `ida_help`, `tools/list`. Categories: session 9, discovery 14, code 8, findings 10, edit 14, calculation 8, types 4, segments 3, signatures 2, support 3, workflow 1. |
| `server/server_dispatch.py` | `_execute_tool_inner` (line 1687) dispatch: host-side branches (`_handle_session_health`, `_handle_memory_filesystem`, `_handle_bookmarks`, `_handle_analysis_plugin_run`, `_handle_truncation`, `_handle_next_continuation`) + IDA RPC fallthrough; safe-mode gate; wall-clock caps | **The seam where a host-side `r2` tool slots in.** Strong and defensive. |
| `server/server_runtime.py` | idat subprocess lifecycle: `_send_rpc_raw/_with_retry`, `_kill_process_tree`, orphan/DB-lock recovery, `IDA_MCP_RPC_HARD_WALLCLOCK_SEC=900` | Strong. 900s wall-clock terminates IDA on one long call — no soft-exceed path. |
| `server/server_session.py` | session create/reuse, analysis watcher, **~20 session actions implemented but NOT registered in `_SESSION_ACTIONS`** (line ~2637 comment) | Partial-by-design. Unregistered: `export_session`, `import_session`, `stats`, `narrative`, `validate`, `bulk_delete`, `bulk_tag`, `merge`, `suggest_analogy`, `apply_analogy`, `macro_set/get/list/delete/run`, `track/confirm/refute_hypothesis`, `recent_workset`. **`macro_run` → `_run_workflow_sequence` is the ONLY output-chaining pipeline ($param + step{i}_{key}) in the codebase — unreachable.** |
| `server/server_batch.py` + `batch_manager.py` | submit/status/cancel/result/list/wait; ThreadPoolExecutor max_workers=4; cooperative cancel (1s grace); sliced index jobs; exact-binary index reuse | Partial. **No pause/priority; cancel cannot abort a running slice; in-flight cursor lost on host restart.** |
| `server/server_workflow.py` + `server_workflow_batch.py` | 5 named workflows; plan/audit/compose/prioritize/estimate/execute; `_handle_batch` (sequential, static args) | Partial. **No output→input chaining; static args only.** |
| `server/server_multi_session.py` | SessionGroup, groups.json, group_create/list/link/remove, cross_resolve/decompile/xrefs | Partial. `group_link` first-provider-wins ("could be made configurable"); **no cross-binary diff action registered**. |
| `server/server_response.py` + `response_enrichment.py` | workspace recall injection, code-anchor staleness, address calculations, context packs, pointer notes, `_validate_address_lockstep` | Strong; the "analyst that never forgets" UX. Some pieces env-gated off by default. |
| `server/server_blackboard.py` + `_idb` + `_phase` + `_trace` | findings workspace CRUD, publish_findings → IDB round-trip, import_annotations, phase machine, trace ingest | Strong. The novel "memory that is used". |
| `server/session_skills*.py` | q-table skill selection, bootstrap policy learner, dead-end detection, phase machine | Partial. `_detect_dead_end` result is discarded; bandit learner not MCP-exposed. |
| `server/server_semantic.py` | semantic asm gadget index (per-session sqlite) | Fully built. |
| `analysis/arch_profile.py` (702 lines) | **RISC-V raw-blob inference (riscv candidate, riscv32/riscv64 prototypes, `_riscv_bitness`)** + MMIO scoring + arch normalization + `infer_binary_arch_profile` | **In flux and improved.** The Track A2 "no RISC-V candidate" gap is now closed in the tree (see §1 #5). |
| `analysis/patterns.py`, `context_density.py` | byte_entropy, looks_like_code, riscv_instruction_validity, GlobalFactsDatabase, context-density compaction | Strong. IDA-free triage foundation. |
| `policy.py` (543 lines) | RiskTier (incl. **DEBUGGER, NETWORK_OR_PROCESS**), modes, purposes, audit records; `classify_tool_action`; DESTRUCTIVE/WRITE_TOOL_ACTIONS | Strong, deterministic, cannot be relaxed by a request. `firmware_analysis` purpose present. **RiskTier.DEBUGGER is defined but unused — first consumer will be emulation/debug.** |
| `tool_registry.py` + `schemas_data.py` | 31 legacy tools / 388 actions / 17 advertised / `TOOL_ARG_SCHEMAS` | Strong + CI-enforced. **8 of 31 tools have NO TOOL_ARG_SCHEMAS** (annotation, graph, imports_deep, modify, multi_session, stack_analysis, symbols, types) — open pass-through on legacy. **13 of 31 legacy tools have no agent op** (annotation, bookmarks, ctree, gadgets, governance, imports_deep, knowledge, memory, multi_session, stack_analysis, symbols, wiki, workflow). |
| `errors.py` (39 codes) | Host-side MCPError envelope | **Second, drifting code vocabulary** vs ida-side 176 codes. No EMULATION/R2 codes. |
| `config.py`, `rate_limit.py`, `stores/` (blackboard_store, symbol_db, knowledge_graph, insight_index, truncation) | Config env knobs; per-tool + one global token bucket; workspace stores | Rate limiting has **no per-session scope, no priority classes**. `insight_index.py` L1 tiering store is **dead code** (never populated). |
| `intelligence/` (core, embeddings, families, rerank, native, threat_corpus, yara_scanner, sources) | BgeCodeEmbedder (llama-server OR in-process `libmcp_llama.so`), FunctionEmbeddingIndex sidecar, Reranker, BehaviorClassifier, families, threat enrichment | Fully built + benchmarked. Retrieval validated on ELF corpus only. |

### 2.3 Support/plumbing (`src/ida_pro_mcp/ida_mcp/support/`, sync/cache/rpc/zeromcp, `server_script.py`)

| Module | Purpose | Completeness |
|---|---|---|
| `support/arch_utils.py` (1090 lines) | `get_arch`/`is_*_family` for x86/ARM/MIPS/PPC/SPARC + xtensa/tricore/avr/msp430/csky/arc/nios2/microblaze/v850/rl78/h8/mcs51/z80/pic24/pic18; RISC-V GP auto-detection + `_apply_riscv_gp` (auipc/addi prologue sim, sign-extend, `set_processor_options('gp=...')` + netnode persist + queued reanalysis); return/SP/callee-saved register maps; operand-aware return classification (`jalr x0,ra,0`, `jr $ra`, `bx lr`) | **Fully wired + the highest-leverage RISC-V module.** Weak spot: `COMPARISON_MNEMONICS` and `XOR_MNEMONICS` have **zero RISC-V entries** — null-check and XOR-obfuscation heuristics are blind on RISC-V. |
| `support/query_lang.py` (481 lines) | MATCH…WHERE DSL over the IDB | 90%-built, **orphaned**: requires WHERE, only AND (no OR/parens), `count=1000` hardcode (silent under-report >1000), legacy-only, no op/wiki/test. |
| `support/semantic_matching.py` (399 lines) | ngram + optional embedding action/symbol normalization | Fully built; legacy-surface infra. |
| `support/crypto_registry.py`, `taint_registry.py`, `_api_categories.py` | AES/SHA/MD5/ChaCha init constants; **firmware-aware taint** (HAL_UART/DMA/SPI/I2C/USB sources, HAL_FLASH_Program sink); dangerous-API/tag/magic constants | Partial. `_api_categories` and `MAGIC_CONSTANTS` are **Win32/OpenSSL-biased** — no HAL/RTOS APIs, no firmware MMIO/peripheral magic. Vestigial docstrings reference non-existent importers. |
| `sync.py` (279 lines) | `@idaread/@idawrite` execute_sync MFF_READ/WRITE serialization, 30s timeout, re-entrancy guard, `bypass_sync()` thread-local | Fully built; the thread-safety net that makes RPC-over-HTTP safe. `_tool_cache()` singleton resolves by 3 import paths (fragile). |
| `cache.py` (120 lines) | ToolResultCache LRU 256/300s, write-generation invalidation | Fully built. **Key collision risk: `default=str` in `sha256(json.dumps(...))`** collapses dict/bytes args. |
| `error_handling.py` (905 lines) | `make_error` envelope + ~176 codes + hints + validation helpers | Fully built. **Two vocabularies drift** (host 39 vs ida 176); `recoverable` emitted only when truthy (envelope asymmetry). |
| `rpc.py`, `zeromcp/` (vendored 1.4.0) | McpServer/@tool/@unsafe/@test; JSON-RPC + Streamable HTTP `/mcp` (2025-06-18) + legacy SSE `/sse` (2024-11-05); reflection schemas; 10MB cap | Fully built. `MCP_UNSAFE` empty. |
| `mcp_http.py` (430 lines) | CORS/DNS-rebind-guarded config page, per-tool enable/disable, netnode persistence | Fully built, IDA-side only. |
| `server_script.py` (810 lines) | IDA-side RPC bridge; `_apply_pre_analysis_options` (raw `.bin` → force CODE+EXEC, 32-bit addressing, Thumb T=1 on ARM32, honors `gp=...`); token auth | Fully built. `memory_model` deliberately skipped (documented TODO). IDA-side `read_file_impl`/`write_file_impl` have **no allow-root / size cap** (host-side filesystem sandbox only). |
| `ida_mcp/prompts.py` | WORKFLOW_* prompts incl. **WORKFLOW_FIRMWARE (vestigial)**, WORKFLOW_DEBUG ("drive via misc python") | Partial/stale. |

### 2.4 Meta-surface (tests/docs/skills/scripts/CI/packaging)

| Asset | Completeness / notes |
|---|---|
| Tests ~1,570 functions: `tests/` (root contract), `tests/host/` (~90 files), `tests/ida_mcp/` (per-file FakeIDB), `tests/integration/` (live-IDAL-only, excluded from CI) | Strong around the EXISTING surface. **Zero raw `.bin` fixture/fake/test/doc anywhere.** Every opaque-blob claim is unvalidated. |
| `tests/conftest.py` | Defensive: sys.modules snapshot/restore, per-test cache-dir isolation (documented real incident: tests once pruned 341 live sessions), env freezing. **The strong part.** |
| Generated-docs loop: `agent_operations.py` → `check_schema_integrity.py` + `generate_tool_skills.py` + `test_docs_sync.py` + CI git-diff gate | Fully closed and CI-enforced. **`docs/TOOLS_REFERENCE.md`, `.agents/skills/`, `installer/skills` are GENERATED — never hand-edit.** |
| `.agents/skills/ida-pro-mcp/SKILL.md` | Generated playbook; **ELF/PE-centric**, no raw-blob or RISC-V recipe. |
| CI: `standalone-tests.yml` (py3.11/3.12, ruff, docs-drift, pytest --ignore=tests/integration), `native-build.yml` (pinned llama.cpp 99111b19), `codeql.yml`, `dependabot.yml`; `test_ci_workflows.py` guards | Strong and honest. Ubuntu-only. **No job can run licensed IDA; no job can run r2 today (but rz IS installable via apt — a real end-to-end test opportunity r2 enables).** |
| Packaging: pyproject v0.9.0 GPL-3.0-only >=3.11; install.py; `installer/` (13 MCP clients, discovery version-scan fix bac266f); pure-Python wheel (native `.so` NOT shipped) | Strong. **Nothing installs a RISC-V `.sig` pack or a raw-bin fixture.** |
| Docs: `docs/wiki/*` current; `docs/ROADMAP.md`, `POLICY.md`, `TECHNICAL_REFERENCE.md`, `LIVE_IDA_TESTING.md` current; `CONTRIBUTING.md` stale (nonexistent test modules, unittest discover); `USE_CASES.md` stale (legacy workflows); `ARCHITECTURE.md` tier claim stale; `.claude/settings.local.json` whitelists legacy names | Mixed. `test_docs_sync.py` does not cover the three stale docs. |
| Benchmarks/intelligence engineering: `benchmarks/*.py` + `BENCHMARK_RESULTS.md` (native 1.8s vs 10-25s cold start, RSS 1.9 vs 3.5GiB), `scripts/llm_eval/eval_harness.py`, native `libmcp_llama.so` | Strong, honest, **ELF-corpus-only** — nothing validates retrieval on opaque firmware where function boundaries are unreliable. |
| **radare2/Rizin competitive positioning** | **Absent.** No comparison harness, no feature diff, no workflow benchmark, no radare|rizin reference anywhere. The "more useful than radare2" ambition has no measurable spec. |

### 2.5 Intelligence / analyst-memory / workflow-session skills

This is the most fully-built corner and the strongest "analyst that never forgets" story:

- **Retrieval stack:** BgeCodeEmbedder (external llama-server OR in-process `libmcp_llama.so` via `native.py`) → per-IDB `FunctionEmbeddingIndex` sidecar (`<idb>.embeddings.db`); cross-encoder Reranker auto-applied in expand-mode; BehaviorClassifier zero-shot anchors (~22 behaviors); function-families lookalike clustering; sliced background index jobs with resume cursor; asm-level semantic gadget index.
- **Findings workspace** (`stores/blackboard_store.py`, binary-scoped `<idb>.blackboard.db`): auto-anchors every decompile/disasm to a code digest; auto-marks claims stale on code change; auto-injects prior findings/verdicts into every tool response (`_inject_workspace_recall`); separates coverage (`mark_examined`) from positive claims; links opposed assertions as conflicts; explainable `next_target` strategies (unresolved/stale/conflict/coverage/frontier); `analysis_brief` turn-one case file; `publish_findings` → repeatable IDB comments + non-clobbering renames; `import_annotations` skips its own output.
- **Workflow/session skills:** deterministic workflow orchestrator (plan/audit/execute, 5 named workflows), phase machine (scout→prove→commit→finalize), bandit-style bootstrap policy learner, session skills q-table, activity log + dead-end detection (result discarded), SymbolDB cross-session hypothesis export/import (≥0.8 confidence, exact-binary-hash OR chip_family keyed).

**Gaps:** index jobs no pause/priority; in-flight cursor not durable across host restart; cross-binary memory narrow (exact-binary index reuse + hypothesis-only SymbolDB); InsightIndex L1 store dead code; workspace binary-scoped only (no per-session overlay); families O(N²) recompute capped at 4000; rerank auto-on only in expand mode with no latency budget; several bootstrap/quest/knowledge-graph systems have no MCP-exposed tools.

### Full inventory table (condensed)

| # | Edge | Layer | Completeness | Recommendation |
|---|---|---|---|---|
| 1 | 26-tool dispatcher + rpc/sync/cache/error infra | IDA-side | fully | leave |
| 2 | Raw-blob entry bootstrap (`_bootstrap_raw_entry_points`) | IDA-side | fully | **maintain/stress-test (mission core)** |
| 3 | RISC-V GP (x3) auto-config (`detect_riscv_gp`/`set_gp`) | IDA-side | fully | **maintain (highest-leverage RISC-V fix)** |
| 4 | RISC-V gadget classification (`_classify_riscv_jalr`) | IDA-side | fully | maintain |
| 5 | RISC-V raw-arch inference (`arch_profile.py`) | host | **in flux — now present** | verify feed-through |
| 6 | FLIRT sig application | IDA-side | partially | wrap-lean (host sig dir) |
| 7 | Type authoring (declare/import_header) | IDA-side | partially | implement (member edit + TIL del) |
| 8 | Patches (no undo/diff/restore) | IDA-side | partially | wrap-lean |
| 9 | Segment-register seam (`ida_segregs`) | IDA-side | absent | **implement (top firmware gap)** |
| 10 | Export surface (write-only, no restore) | IDA-side+host | partially | implement (export/import pair) |
| 11 | Semantic tagging / dangerous-API / magic catalogs | support | partially | implement (firmware registries) |
| 12 | Mitigations report | IDA-side | partially | leave (low value for raw) |
| 13 | Stack-canary detection (name-dependent) | IDA-side | partially | implement (pattern fallback) |
| 14 | imports_deep (PE-centric) | IDA-side | partially | leave |
| 15 | Cross-session knowledge transfer (function-only) | host | partially | implement (structs+comments carrier) |
| 16 | Decompiler-option toggling (`set_hexrays_options`) | IDA-side | absent | wrap-lean |
| 17 | `blackboard.propagate_labels` stub | IDA-side | removed | deleted in the analysis-memory redesign (superseded by families) |
| 18 | Bookmarks (read-only) | IDA-side | partially | leave |
| 19 | `misc.python` ungated escape hatch / inert MCP_UNSAFE | IDA-side | fully | wrap-lean (register into MCP_UNSAFE) |
| 20 | Debugger tool (absent; vestigial DEBUGGER_* codes) | all | absent | leave (misc.python covers) |
| 21 | ~20 session actions unregistered (export/import/macros/…) | host | vestigial | **implement (highest ROI single change)** |
| 22 | Output→input chaining / pipeline | host | absent | implement (register macros) |
| 23 | Background job pause/priority/preempt | host | partially | implement |
| 24 | Rate limiting per-session + priority | host | partially | wrap-lean |
| 25 | Multi-session configurable linking + diff | host | partially | implement |
| 26 | Response post-process pipeline + truncation | host | fully | leave (integration contract) |
| 27 | Safe-mode gate + watchdog | host | fully | leave |
| 28 | RPC lifecycle robustness | host | fully | leave |
| 29 | Agent-UX response enrichment | host | fully | leave |
| 30 | Semantic index jobs + families + reranker + embedder | host | fully | leave |
| 31 | Blackboard findings lifecycle + recall + targets | host | fully | leave |
| 32 | publish/import annotations IDB round-trip | host | fully | leave |
| 33 | Workflow orchestrator + phase machine + skills q-table | host | fully | leave |
| 34 | Firmware carve pipeline (`firmware_view`) | all | **deleted, vestigial traces** | **resurrect or strip** |
| 35 | Raw `.bin` fixture/fake/test/doc | tests | **absent** | **implement (top test gap)** |
| 36 | radare2/Rizin comparison harness | meta | **absent** | **implement** |
| 37 | Generated-docs pipeline + schema integrity | meta | fully | leave |
| 38 | RISC-V wiki page + real-blob e2e test | docs/tests | absent | implement |
| 39 | CI (standalone/native/codeql) | meta | fully | leave |
| 40 | Packaging/installer (13 clients, version-scan) | meta | fully | leave |
| 41 | RISC-V `.sig` pack install path | installer | absent | implement |
| 42 | query_lang (orphaned) | support | partially | implement (promote to op) |
| 43 | Emulation/debug surface | all | **absent** | **implement (see §6/§8)** |

---

## 3. Unimplemented IDA surface — exhaustive category-by-category map

The MCP exposes 67 exact-schema ops mapping to the IDA-side tools. Everything below is reachable in principle through the risk_ack-gated `ida_python` escape hatch (`misc(action=python)`), so the "not implemented" surface is **not inaccessible — it is untyped and unsafe-by-default**. Any new edge should ship with an exact schema, an `ida_help` entry, and a behavioral test (the ROADMAP promotion rule) — a real seam or nothing.

**Notable context:** `docs/reference/IDA_Headless_Scripting.txt` (the team's own 9.2 headless audit) explicitly calls out `ida_dbg` for headless unpacking and `ida_segregs` for Thumb-mode fixes — both absent from the MCP surface.

### 3.1 Debugger / dynamic (absent entirely)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_dbg` | Only error-state detection in `error_handling.py` (is_debugger_on/get_process_state) + `WORKFLOW_DEBUG` prompt steering to `misc(python)`. `memory.py:346` dangles a nonexistent `debug(action='write_mem')`. | Dynamic verification of opaque firmware: run-to-breakpoint on a reset handler to recover the real RISC-V GP at runtime, trace ecall/svc handlers, read MMIO registers, unpack a compressed boot stage — all unanswerable from static IDB bytes. | medium | **wrap-lean** — least-viable seam: start/stop, add_bpt, run_to, get_reg_value, get_bytes-on-target. But note the two prior in-IDA attempts (emulate.py, debug.py) died; prefer the host-side r2 engine of §8. At minimum fix the misleading `memory.py:346` docstring. |
| `ida_hexrays` fine control | Read-only ctree traversal; only mutations are `rename_local` + `types.apply(kind=local)` via `user_lvar_modifier_t` + `refresh_decompiler_ctext`. | lvar rename/type covers the 95% case. Decompiler-options toggling (array/struct heuristics) is niche; AST surgery fragile (decompiler re-derives tree). | high | **leave** (rename/type is the right size). Optional: `hexrays_options_t`+`set_options` as options get/set pair (wrap-lean). |

### 3.2 Type authoring / TIL (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_struct`/`ida_enum`/`ida_typeinf` member editing | `declare`/`import_header` author whole types; `list/get`/`enum_values` read-only. **No add/del_struc_member, set_member_tinfo, enum member add/rename/revalue, del_named_type, TIL open/save/merge/export.** | Firmware peripheral/register structs are discovered iteratively: add/rename/retarget ONE field of an existing MMIO struct without re-declaring across 100s of sites. A persistent firmware type-library (TIL export/import, or netnode-attached types) would let analysis survive sessions and be shared with a GUI analyst. | low | **implement** (thin SDK wrappers). `types.diff`/`types.propagate` (≤5000 sites) already exist. |

### 3.3 Reanalysis control / auto_wait (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_auto` | Non-blocking schedule + poll (`auto_mark_range(AU_FINAL)`, `auto_is_ok`, `auto_make_step`); deliberately avoids `auto_wait()` (socket-timeout risk). | Raw-blob bootstrap + targeted text-segment reanalysis is right, but `make_code`/patch flows requeue and return "analysis scheduled", forcing agent polling. A bounded `auto_wait` (hard timeout → "still-running") would make patch→verify loops deterministic. | low | **wrap-lean** — expose bounded wait + queue depth/auto state. |

### 3.4 Bytes / data-item authoring + undo (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_bytes` create_data/undo | `get/read_bytes`, `patch_bytes`, `del_items(DELIT_SIMPLE)`, `bin_search`, flags, `get_byte/word/…`. **No create_data/create_byte/word/dword/qword; no undo_begin/undo_end; no set_ptr_flag; no 'reproduced instruction' probe.** | Defining a region as an array of dwords/pointers lets an LLM read vector tables and MMIO tables without redeclaring types. undo_begin/undo_end = safety net before batch patching (esp. with `ida_batch` running 10+ mutations). | low | **wrap-lean** — create_data with a size/type enum + a single undo pair. |

### 3.5 Xrefs (deeper modes) (absent)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_xref` typed/first-next | All xrefs via `idautils.XrefsTo`/`CodeRefsTo`/`DataRefsFrom`. No first/next, no flow-vs-data distinction, no add_cref/add_dref. | Large firmware: first/next is markedly faster (9.2 xref-tree optimization); distinguishing code/data/flow refs matters when walking millions of refs in big ROMs. `add_dref` from a GP-relative load to its data complements the RISC-V GP work. | low | **wrap-lean** — `xrefs` action mode='typed' returning {flow/code/data, iscode, from_ea, type} + optional add_cref/add_dref. |

### 3.6 Functions — tail chunks (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_funcs` chunk surgery | list/info/create/change/delete/set_flags/find_similar; info reports `chunk_count`. No append/remove_func_tail, no func_t field editing beyond flags. | Where IDA merges/splits functions wrongly (jump tables, interleaved data) tail-chunk editing would help — but read side already exposes the diagnostic. | medium | **leave** (keep read side; add FUNC_TAIL flags cheaply to info if needed). |

### 3.7 Stack frame authoring (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_frame` writes | `stack_analysis` reads frame/buffers/canary/spills/usage/uninitialized/summary via get_stkvar/get_spd/get_member_tinfo. No set_frame_size/change_sp_delta/set_member_name/frame_fixup. | On opaque firmware the frame is often mis-modeled; MCP can diagnose (spills, SPD deltas) but not correct. Diagnosis is usually enough — the LLM adjusts interpretation rather than rewriting IDA's model. | medium | **leave**. Cheap win: expose per-instruction SP-delta in `usage`. |

### 3.8 Segments & segment registers (partial — top gap)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_segment`/`ida_segregs`/`ida_srarea` | `segments.py` add/delete/set_attr/set_perms/move/analyze/find_code/find_data/compare/merge. **No seg-reg surface.** Internal only: `funcs.py _set_thumb_mode` (split_sreg_range T=1); RISC-V GP via `set_processor_options` + netnode, NOT via `ida_segregs`. | **HIGH for opaque firmware.** A raw ARM blob mis-disassembled ARM-vs-Thumb, an x86-16 BIOS with segment bases, or RISC-V with a wrong GP are all fixed by setting a segment register for a range — but there is no public op an LLM can call. This is the single most firmware-relevant gap in the segment area. | low | **implement** — `set_sreg(address, reg, value, sr_type)` + `get_sreg` + `list_sregs` backed by `ida_segregs.split_sreg_range/set_sreg`. |

### 3.9 Entry-point authoring (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_entry` | `idb.py`+`data.py` read entries. **No add_entry/rename_entry.** | After `_bootstrap_raw_entry_points` finds a reset vector/candidate, `add_entry` registers it properly and seeds recursive-descent from a real entry — a core "make this raw blob analyzable" primitive. | low | **wrap-lean** — add_entry(ordinal, ea, name). |

### 3.10 Name scoping (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_name` SN_* flags / set_name_exact | `modify.rename`/`symbols` use set_name(SN_FORCE); get_name/demangle in funcs. No SN_NOWARN/SN_NOCHECK/SN_NODUMMY, no set_name_exact. | Vendor SDK symbol names with dots/spaces can be forced with SN_NOCHECK. Marginal but cheap. | low | **leave** (expose SN_* as optional params if ever needed). |

### 3.11 Loader / multi-blob / snapshot (partial — high firmware value)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_loader` load_binary_file / snapshot | get_loader_name/set_loader_options(soft-fallback file), save_database, misc find/run_plugin, symbols load_pdb/dwarf. **No load_binary_file (append blob), no save_snapshot/restore_snapshot, no file-type enum detail.** | Two high-value firmware workflows: (1) composing bootloader+kernel+filesystem blobs into one segmented address space; (2) snapshot/restore to run an experimental pass (batch patches, sig apps) and roll back cleanly before `ida_publish_findings`. | medium | **implement** — snapshot/restore first (small, very safe pair); load_binary_file is a bigger lift. |

### 3.12 String authoring (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_strlist` create_strlit | `data.strings` reads via string_info_t. **No create_strlit/set_string_type.** | Forcing a table region to be a string lets the LLM read config/symbol tables auto-analysis left as raw bytes — cheap, high-frequency on headerless firmware. | low | **wrap-lean** — create_strlit(ea, size, STRTYPE). |

### 3.13 Netnode / persistent IDB data (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_nalt`/`ida_netnode` | Used internally (RISC-V GP persistence, mcp_http blob store). No public op for agent read/write. | Storing per-address analysis results in the IDB so a later GUI analyst (or another session) sees them attached to the file — findings/verdicts ride along in netnodes when `.i64` files round-trip between team members. | medium | **wrap-lean** — netnode_get/set with a namespaced key + list; keep SQLite workspace as primary store. |

### 3.14 Graph algorithms (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_gdl` find_cycles/connected-components/topo | graph.py uses FlowChart; dominators hand-computed. **No find_cycles, no graph construction (add_node/edge).** | Cycle/SCC detection for lock/loop structures in init sequences; but families uses embeddings for clones, so graph isomorphism is not the bottleneck. | medium | **leave** (add find_cycles on cfg if a "loops that never exit" workflow appears). |

### 3.15 Processor introspection / assemble (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_idp` register/CSR introspection | `patch_asm` uses ida_idp.assemble; set_processor_type; set_processor_options for GP. **No register-class/CSR listing, no get_reg_info, no ph flags.** | Listing the processor register set + CSR options helps an LLM reason about ecall/mret/CSR handlers without hallucinating. patch_asm already exists. | low | **wrap-lean** — a tiny register/CSR read seam. |

### 3.16 Event hooks (absent)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_hooks` | No usage anywhere. zeromcp has SSE push support unused for events. | Live refresh: on make_code/patch/rename, an IDB_Hooks notification auto-invalidates the tool cache and pushes "analysis finished" instead of agent polling — materially faster loops on large firmware. | medium | **implement** — narrow: auto-analysis-finished + function-created → SSE channel / cache-invalidation hook. |

### 3.17 Instruction decode probe (partial)
| IDA module | What MCP does | Bigger-picture value | Cost | Recommendation |
|---|---|---|---|---|
| `ida_ua` decode_insn/insn_t | Used internally (stack_analysis, code_helpers, modify). No public decode op returning operand types/values. | "Is this byte region code or data?" answered by decode_insn at candidate addresses; exposing the operand model (op type/value/reg/displacement) lets the LLM reason about unknown ISAs beyond RISC-V/ARM and powers a probe→define→reanalyze loop with make_code. | low | **wrap-lean** — `decode` action returning {mnemonic, length, operands}. |

### 3.18 Miscellaneous: srarea, ida_idc, sigmaker, kernwin, fixup, dirtree/allins
| IDA module | Verdict |
|---|---|
| `ida_srarea` (16-bit/x86 seg storage) | **leave** — fold into the ida_segregs seam if a 16-bit target ever appears. |
| `ida_idc` eval_idc/run_idc_script/ARGV | **leave** — eval_idc is enough; ida_python already covers scripts. |
| FLIRT authoring (sigmake/FLAIR) | **leave for runtime, wrap-lean for ops** — building a custom .sig from a vendor SDK and applying across a fleet is a real workflow, but it is a build-time toolchain concern; a host `.sig` directory (RTOS/HAL sigs) would be the cheap high-value slice. Lumina sharing is worthless for firmware. |
| `ida_kernwin` GUI | **leave** — headless-correctly excluded; only the execute_sync serialization primitive is used. |
| `ida_fixup` authoring | **leave** — read side (PIC/relocation-aware analysis) already suffices. |
| `ida_dirtree`/`ida_allins` | **leave** — folders niche; migrate mnemonic sets to ida_allins constants only if they keep growing. |

### 3.19 "Worth building in a bigger picture" — the short list
Across the unimplemented map, the items that matter for the mission and a bigger picture, ranked:

1. **Segment-register seam (`ida_segregs`)** — implement. Unblocks Thumb/RISC-V-GP/x86-16 sreg fixing as a public op; complements the RISC-V GP work. Low cost, top firmware relevance.
2. **Entry-point authoring (`add_entry`)** + **create_data variants** + **create_strlit** + **undo pair** — the four cheapest "make raw blobs analyzable + reversible" primitives, all missing.
3. **Snapshot/restore** (`ida_loader`) — reversible experiment-driven analysis before publish_findings. Small, very safe.
4. **Per-member struct/enum editing + TIL deletion + TIL export/import** — the iterate-on-a-peripheral-struct workflow; cross-session type-library carry.
5. **Export/import round-trip** (symbols.py + knowledge.py) — structs+comments carrier between firmware revisions and across sessions; pairs with the ~20 unregistered session actions (`export_session`/`import_session`).
6. **Instruction-pattern stack-canary fallback** — closes the symbol-less firmware case (GCC `-fstack-protector` inserts `__stack_chk_fail` even stripped).
7. **ida_hooks event layer** — cache invalidation + "analysis finished" push instead of polling.
8. **Register/CSR introspection seam** — cheap, prevents hallucination on exotic ISAs.
9. **FLIRT host `.sig` directory + sig-maker orchestration** — fleet auto-naming of RTOS/HAL/library calls across a target family.
10. **Bounded auto_wait** — deterministic patch→verify loops.

**Explicitly NOT worth building:** ctree AST surgery (fragile, decompiler re-derives), function-tail chunk surgery (rare, corruption-prone), full debugger in-IDA (two prior attempts died; host-side engine preferred), ida_srarea standalone, run_idc_script surface, fixup authoring.

---

## 4. Unbuilt / half-wired host features and their bigger-picture potential

### 4.1 Implemented-but-unreachable session actions (highest ROI single change)
`server_session.py` implements ~20 handlers (export_session/import_session, stats, narrative, validate, bulk_delete, bulk_tag, merge, suggest_analogy, apply_analogy, macro_set/get/list/delete/run, track/confirm/refute_hypothesis, recent_workset) that are **not registered in `_SESSION_ACTIONS`** (deliberately withheld "for internal/host use"). Two are high value: (1) `export_session`/`import_session` — carry an analyzed firmware's names/comments/findings to a colleague or a second machine, the natural complement to groups.json cross-binary linking; (2) **macros (`macro_run` → `_run_workflow_sequence`) — the only `$param` + `step{i}_{key}` output-chaining pipeline in the codebase**, i.e. the ready-made radare2/ESIL-style pipeline executor, currently unreachable. Registration + input-schema exposure, not new logic. **Bigger-picture:** this is the cheapest path to a "pipeline primitive" (§4.3).

### 4.2 Output→input chaining / pipeline execution
`_handle_batch` (server_workflow_batch.py) and `execute_plan` run planned calls sequentially with **static args** (`continue_on_error` only); no output→input binding, no conditionals/loops, no variable substitution outside the hidden macro path. **Bigger-picture:** the core r2 primitive the MCP lacks — "find candidates → deref → follow xref → filter" in one expression ("decompile every function that calls memcpy into a buffer" as one chained call). Cheapest path: register the macro actions + add explicit output-binding to execute_plan; a later wave could add conditional/loop steps. The existing postprocess pipeline (grep/head/tail/offset/limit/pick/field/next_token) is the output-shaping half already in place.

### 4.3 Background job control
`server_batch.py` exposes submit/status/cancel/result/list/wait only. No pause, no priority, and cancel is cooperative (BatchManager.cancel 1s grace; cannot abort a running sliced `index_fast` pass). A big-firmware full-quality index occupies the 4-worker pool for minutes while interactive calls queue. **Bigger-picture:** on a 34k-function opaque RISC-V `.bin`, "pause to answer an interactive question, then resume" + priority (interactive tool_call > background index) is what makes a long-lived daemon feel responsive. In-flight resume cursor is not durable across host restart.

### 4.4 Intelligence / analyst-memory gaps
- **Cross-binary memory is narrow:** exact-binary embedding-index reuse + SymbolDB export/import of ≥0.8 hypotheses keyed by exact binary_hash or chip_family. **Bigger-picture:** near-identical hashes, family-level blackboard import, findings/tasks/decisions crossing sessions, and auto-injected imported brief at session bootstrap — the seed of true "re-analysis of a firmware family starts pre-annotated".
- **InsightIndex L1 tiering store is dead code** (never populated; only get_function feeds a decompile digest). Remove or rewire.
- **Background crawler** now runs on the host task runner: it writes real `status='proposed'` entries to the binary-scoped workspace, persists visited/queue state in `bb_machinery` (restartable), and notifies with the real entry id; the 0.5s smart_decompile cadence is bounded per-tick. **Bigger-picture:** a bounded, persisted proposal pump maps an opaque `.bin`'s frontier while the agent answers interactive questions.
- **Dead-end detection** (`_detect_dead_end`) result is discarded by `log_activity`; STUCK_LOOP advisory unless `IDA_MCP_STUCK_LOOP_BLOCK=1`. Wire into next_target/notifications.
- **Workspace binary-scoped only** — no per-session overlay; parallel-wave sessions on one binary share one store.
- **Function-families** recomputes O(N²) from cache each call, capped at 4000; no incremental clustering.

### 4.5 Workflow / session-skills gaps
Named workflow plans are static and don't read workspace state. **Bigger-picture:** composing plans with `next_target` strategies + `analysis_brief` would make them adaptive (e.g. vuln_audit seeded from frontier targets). The bandit bootstrap policy learner and quest/proposal/knowledge-graph systems are built but have no MCP-exposed tools.

---

## 5. radare2/Rizin capability inventory (exact commands/APIs) with EXACT IDA/MCP equivalents

radare2 6.1.6 is installed at `/usr/local/bin/r2` (plus `rabin2`, `rasm2`, `rahash2`, `radiff2`, `rafind2`, `r2pm`). **Rizin is NOT installed** (no `rz`, `rz-bin`, `rz-pipe`), and there are **no python bindings** in `.venv`. Verified backend list (`dL`): native/gdb/bochs/qnx/rap/esil/winkd/rv32ima; **no lldb, no qemu, no unicorn** (`asm.emu=false`, no `-U`).

### 5.1 Command surface → MCP equivalent map

| r2/Rizin capability (exact command) | Exact MCP equivalent | Verdict |
|---|---|---|
| `aaa` / `aac` / `aab` (auto-analysis) | `analysis(action=reanalyze/run/analyze)` + `_auto_reanalyze_text_segments` + `_bootstrap_raw_entry_points` + `workflow(recon_sweep/triage_fast)` | **do-not** — MCP's raw-bin bootstrap (reset-vector jal/jalr/auipc decode + LE/BE u32 + c.j u16 ISR scan) is strictly more capable on opaque RISC-V. |
| `afl` / `afi` / `aflj` (function list/info) | `ida_list_functions` + `data(functions)` + `funcs(list/info/metrics)` + `segments(find_code)` | **do-not** — JSON-first output is better. |
| `axt` / `axtj` (xrefs-to) | `ida_xrefs_to` + `code(xrefs_to)` + `search(data_ref/code_ref)` + `data(string_xrefs)` | **do-not** — richer. |
| `axf` (xrefs-from) | `code(xrefs_from)` (code.py) | **do-not**. |
| `aar` / `aarx` (refs in disasm) | `code(disasm)` CFG + call-target evidence | **do-not**. |
| `agf` / `agg` / `agc` / `agCd` (call graphs) | `ida_callgraph` (format=mermaid\|dot\|json, direction=up/down/both, depth/max_nodes) + `graph(callgraph/cfg/dominators/xref_graph)` | **do-not** — mermaid is better for LLM rendering. |
| `afb` (basic blocks) | `code(blocks)` + `graph(cfg)` + `ctree(get_logic_flow/dominance_map)` | **do-not**. |
| `/x` (hex w/ wildcards) | `search(bytes)` via `ida_bytes.bin_search` compiled_binpat_vec_t | **do-not** — comparable performance. |
| `/v <value>` (value/immediate search) | `search(immediate)` + `search(constants)` + `memory(search)` int mode with pointer-width auto-widen | **partial-delta** — `search(immediate)` scans instruction immediates only, **not raw data words**; the data-word case is the `/v` gap (§7). |
| `/a` / `/A` (asm/arch-specific search) | `search(insns)` + `search(mnemonic/instruction)` | **do-not**. |
| `/r` (relative ref search) | `search(data_ref/code_ref)` + `code(xrefs_from)` | **do-not**. |
| `/e` (regex search) | `search(regex)` (per-segment, timeout-bounded) + `memory(search regex=True)` | **do-not**. |
| `/w` / `izz` (wide + all-strings) | `search(string)` via ida_strlist + `ida_list_strings` + `data(strings)` + `memory(strings)` | **partial-delta** — coverage complete; only r2's raw whole-file scan *speed* differs (`memory(strings)` caps at 1MB; `data(strings)` needs recognized strings). Fix natively if it matters. |
| `t` / `td` / `tu` (type system) | `ida_declare_type` + `ida_get_type` + `ida_list_types` + `ida_apply_type` + `types(infer/read_struct/import_header/diff/enum_values)` | **do-not**. |
| `z` / `zic` / `zg` (zignatures) | `funcs(find_similar)` (embedding) + `ida_apply_sig`/`ida_list_sigs`/`misc(load_sig)` (FLIRT) | **do-not** — zign weaker than find_similar + FLIRT. FLIRT *generation* (sigmake) is the honest gap (§3.18). |
| `wx` / `wd` / `wa` (write hex/nop/asm) | `modify(patch_bytes/patch_asm)` + `memory(write)` + `ida_patch_bytes(nop=true)` — governed | **do-not** — r2's ungoverned writes are a safety regression. |
| `p8` / `px` / `ps` / `pD` / `pC` (print hex/bytes/string/disasm/as-C) | `memory(hexdump/read)` + `ida_read_bytes` + `code(disasm)` + `ida_disassemble` + `ida_decompile` (Hex-Rays) | **do-not**. |
| `pf` / `pt` (format/parse structs/timestamps) | `types(read_struct/visualize)` + `memory(struct_walk)` + `ida_calc_deref`/`ida_calc_chain` | **do-not** — struct_walk is richer (recursive, fixup names). |
| `p==` / `pcp` (per-block entropy) | `memory(entropy)` + `memory(histogram)` (entropy_blocks + entropy_sparkline) + `segments(analyze)` | **partial-delta** — MCP has per-block histogram; r2's `p=e` whole-file sweep pre-IDA is the delta (no idat needed). |
| `s` / `f` (seek/flags cursor) | none — MCP is deliberately stateless (absolute addresses) | **do-not** — cursor is an LLM footgun; stateless is a feature. |
| `e` config / `om` memory map | address params + `segments(list)` + `analysis(set_options)` | **do-not**. |
| `u` unpack / `s+` arithmetic seek | `ida_calc_deref/chain/eval/offset/convert/align/bitops` (dedicated calc tool r2 lacks) | **do-not** — calc is strictly more LLM-friendly. |
| `ic` / `icc` (class info / vtable discovery) | `types(action=vtable)` — dumps ONE vtable by name; no whole-db class enumeration | **partial-delta** — r2 ic covers whole-blob C++ class/vtable enumeration. Niche for MCU RISC-V, real for SoC C++ images. |
| `#!pipe` / `!` shell / `-qc` scripting | `misc(python/idc)` (policy-gated) + `ida_batch` + `misc(read_file/write_file)` | **do-not** — MCP is safer. |
| `r2 -a <arch> -b <bits> -m <base> file.bin` (raw open) | `ida_open_binary(architecture={processor,bitness,endian}, input_format='bin', baseaddr)`; server_runtime maps preload to `-p/-Tbin/-b`; `analysis(set_architecture/set_processor/set_gp)` | **do-not** — MCP even aliases riscv32/riscv64→riscv (arch_profile.py:33-42). |
| `rabin2 -I` / `rz-bin -I` (binary info) | `ida_overview` + `idb(meta/summary/architecture_profile)` + `infer_binary_arch_profile` — **but all require a live idat session** | **partial-delta** — the pre-IDA, no-idat fast path is the delta. |
| `rabin2 -i/-s/-e/-E/-S/-D` (imports/symbols/entries/exports/sections/demangle) | `ida_list_imports` + `data(imports)` + `imports_deep(thunks/delay/forwarded/ordinal/api_sets/resolve)`; `search(symbol/symbol_info/name)` + `data(globals)` + `symbols(load_pdb/load_dwarf)`; `idb(entrypoints)`; `data(exports)`; `ida_list_segments`+`segments(list)`; `search(demangle)` | **do-not** — imports_deep exceeds rabin2 -i. |
| `rabin2 -zz` (whole-file raw strings w/ paddr) | `ida_list_strings` (only strings IDA chose to define) + `memory(strings)` (needs region+idat) + `search(string)` | **partial-delta** — whole-file incl. unmapped gaps, no idat, is the delta. |
| `rahash2 -a` (hash: md5/sha1/sha256/crc32/entropy) | `idb(meta)` file-level md5/sha256/crc32 only (needs idat) | **partial-delta** — region hashing / pre-IDA fingerprinting is the delta. |
| `rabin2 -S/-e/-s` sections/entry/symbols | `ida_list_segments` + `idb(segments/entrypoints)` + `search(symbol)` | **do-not** for raw `.bin` (no sections/symbols); marginal for ELF/PE. |
| `rabin2 -H/-x/-X/-r/-T` (headers/extract/relocs/TLS) | relocs surfaced only as per-slot flag in `memory(read/pointers)`; TLS not exposed; headers partial via `ida_overview` | **partial-delta** — reloc list + TLS layout + sub-file extract are niche gaps (§5.2). |
| `rabin2 -B` (magic file-type sniff) | `infer_binary_arch_profile` heuristic (opcode density, 2-gram, riscv validity) | **partial-delta** — wrapper-magic detection (ELF/FIT/uImage hidden behind a wrapper) is the delta; ~20-line stdlib addition. |
| `radiff2 -s/-c/-j` (binary diffing) | `code(action=diff_functions)` — decompile-level diff of TWO functions only; no whole-image bindiff | **partial-delta** — firmware v1-vs-v2 changed-handler discovery is a real MCP gap (§7). |
| `pdc` / `pdcp` (esil pseudo-C) | `ida_decompile` (Hex-Rays — strictly superior) | **partial-delta** — only valuable when Hex-Rays is absent for an arch (fallback). |
| `pdg` (r2ghidra Ghidra decompiler) | `ida_decompile` (Hex-Rays) | **do-not** as replacement; optional AGPL fallback only when no RISC-V Hex-Rays. |
| `ae*` / `aes` / `aec` / `aefa` / `aet` (ESIL emulation) | **none** — no emulation anywhere; nearest is `analysis(set_gp)` (static GP-relative resolution) | **adopt** — the biggest dynamic gap (§6). |
| `aaa`/`aaaa` with `asm.emu=true` (emulation-augmented analysis) | `analysis(run/analyze)` — static only, no execution | **partial-delta** — execution-derived code-path confirmation (§6). |
| RISC-V GP-relative xref resolution | `detect_riscv_gp` + `set_gp` + disasm GP notes (code.py:427) | **do-not** — MCP is strictly better than r2 here. |

### 5.2 The genuine, defensible gaps (the only places r2/Rizin adds value)
1. **Pre-IDA file triage in milliseconds without spawning idat** — `rabin2 -I` (filetype/arch/endian/bits), `rabin2 -zz` (whole-file strings incl. unmapped gaps), `rahash2` (file+block entropy/hash), `rabin2 -t/-a/-b` mystery-blob classification. Today `ida_overview`/`ida_list_strings`/`memory(entropy)` all require a licensed idat session.
2. **`/v`-style virtual xrefs** — locate every raw little/big-endian pointer-sized word equal to a target address (dispatch/vector tables, function-pointer arrays) when IDA never created data xrefs because the blob was loaded raw. `search(action=immediate)` only scans instruction immediates, not raw data words.
3. **Per-block entropy profile across the whole file** — packed/encrypted-vs-plaintext region boundaries for a raw `.bin` before deciding which slices to load into IDA.
4. **Multi-arch hypothesis disassembly + decoder cross-validation** — try rv32 vs rv64 vs thumb vs capstone on the same window; where independent decoders disagree, that offset is a likely mis-decode. Directly serves the reliability goal.
5. **Whole-image binary diffing** (`radiff2`/`rz-diff`) — firmware update analysis v1-vs-v2.
6. **Lightweight fallback decompiler** (`pdc` esil pseudo-C; `pdg` r2ghidra) — C-level output when Hex-Rays is absent for the target arch.
7. **ESIL/unicorn emulation** — resolve indirect jalr targets, validate load bases, confirm entry points, unroll packed init (§6).
8. **Sub-file/partition carve** (`rabin2 -x`) and **class/vtable whole-blob enumeration** (`ic`) — niche.

---

## 6. Emulation / dynamic analysis deep-dive — the gap analysis for opaque RISC-V firmware

### 6.1 The current state
Zero emulation, zero debugger, zero tracing in the MCP public surface. The evidence of past/failed intent: `memory.py:346` docstring (nonexistent `debug(action='write_mem')`), `schemas_data.py:172` comment (claims an `emulate` tool "in TOOLS" — it is not registered), `error_handling.py`/`errors.py` `DEBUGGER_*` (50-59) and `EMULATION_*` (110-119) codes with no implementing tool, `prompts.py WORKFLOW_DEBUG` ("drive it through misc(action=python)"). The prior Unicorn `emulate.py` and `debug.py` tools were **deleted in commit b191581** "had no public ida_* operation, were never advertised in tools/list". **The lesson: any emulation work that does not ship registered, advertised ops + a workflow will be removed again.**

### 6.2 Verified findings on this box (r2 6.1.6)
- **ESIL RV32 straight-line + stack code works.** A 9-instruction RV32 prologue + `li a0,42` + reload emulated correctly: a0=0x2a=42, pc advanced exactly 7 steps.
- **ESIL RISC-V `jalr` indirect jumps DO NOT resolve.** After `lui t0,0x20000; jalr t0`, pc stayed 0 even with the target region mapped. Interpreter ESIL is incomplete for RISC-V control flow → any indirect-branch/vtable/stub resolution **must** use a unicorn backend.
- **Stock r2 has no unicorn compiled** (`asm.emu=false`, no `-U`, no `io.emu`). Shipping Rizin (bundles unicorn) or a unicorn-enabled r2 is a hard dependency for the robust slice.
- **Hang risk:** `e esil.maxsteps` defaults to 0 (unbounded); `aecu`/`aesu` hang without a reachable breakpoint (a test had to be killed). Every emulation op MUST set `esil.maxsteps` + a wall-clock timeout.
- **Rizin is NOT installed** (`rz`, `rz-pipe`, `rz-bin`, `rz-run`, `rz-search` absent). RzIL, rz-run, and "search inside emulated space" (`rz-search -e`) are documented (Rizin book) but **not empirically verified**; the Rizin book does not document an `rz-search -e` flag — treat that specific claim as TBD-validate.
- **LLDB/QEMU backends absent** from `dL`; do not promise them.

### 6.3 What emulation answers for opaque RISC-V firmware (that static analysis cannot)
1. **Validate a candidate load base** — init PC at the reset vector, map the region, step N bounded instructions, report whether execution stays in sane code with plausible register values.
2. **Confirm an entry point** — emulate each candidate from `_bootstrap_raw_entry_points`; keep vectors whose execution decodes valid instructions and reaches a return/call.
3. **Code-vs-data disambiguation by execution touch** — addresses actually fetched as instructions during emulation are code; the rest stay data (replaces coarse 0x800-byte heuristic seeding).
4. **Resolve indirect branches / vtables / import stubs** — execute the jump; unicorn lands on the concrete target (interpreter ESIL fails here — verified).
5. **Function-argument reconstruction (`aefa`)** — emulate a function to observe the actual calling convention, which static psABI guessing gets wrong when bare-metal firmware passes args in globals/GP-relative slots instead of a0-a7.
6. **Unroll packed/self-modifying init** — record which addresses are written then executed (decryptor); report the executed-after-write region as the decrypted code. The Rizin book explicitly names encryption/decryption/unpacking as ESIL's intended domain.
7. **Search the EMULATED memory space** — after unrolling init, find decrypted strings/tables that never appear in the raw `.bin` file (static search can never find them).

### 6.4 Engine options and the recommendation
| Engine | RISC-V fidelity | License | Runtime | Verdict |
|---|---|---|---|---|
| r2 ESIL interpreter | Straight-line verified; **jalr broken** | GPL-3.0 subprocess | In r2 6.1.6 | Use for validate-base/find-entry/code-touch on straight-line code only. |
| Unicorn (via Rizin bundle, or unicorn-enabled r2, or unicorn-from-python in an isolated subprocess) | Robust incl. indirect jumps, C-ext | **GPL-2.0-only + commercial dual** — NEVER import into `ida_pro_mcp/**`; keep in subprocess | Rizin bundles it | The robust default for indirect-branch resolution. |
| Rizin RzIL (`rzil`) | Designed to replace ESIL; better control flow | LGPL-3.0 (compatible) | Rizin (not installed; unverified) | Abstraction-layer upgrade path; validate against the actual RISC-V corpus before defaulting. |
| IDA's own headless debugger (`ida_dbg`) | Full, but GUI-centric and heavy | Already licensed | idat | Prefer host-side engine for offline emulation; IDA debugger is the "hardware-in-the-loop" tier only. |

**Recommendation:** a host-side, subprocess, engine-abstracted emulation capability (`esil|unicorn|rzil` interchangeable backends behind one action surface), defaulting to unicorn for indirect-branch work and ESIL for straight-line validation, with mandatory `maxsteps` + wall-clock caps, advertised as `ida_r2_emu`/`ida_rz_trace` ops. The "r2 proposes, IDA disposes" rule applies: emulation output is hypothesis-tier and never writes the IDB without re-running IDA policy.

---

## 7. Overlap-elimination matrix

Consolidation of the Track B inventory + overlap audit (B1/B4), with the paper's synthesis. **Rule: do-not-reimplement anything the MCP already covers on an analyzed IDB.** The classic r2 surface is ~85% covered; the deltas are the value.

| Candidate feature | Exact MCP equivalent | Verdict |
|---|---|---|
| `aaa`/`aac` auto-analysis | `analysis(reanalyze/run/analyze)` + `_bootstrap_raw_entry_points` + `_auto_reanalyze_text_segments` + workflow(recon_sweep/triage_fast) | **drop** (MCP strictly better on raw RISC-V) |
| `afl`/`afi` function list | `ida_list_functions` + `funcs(list/info/metrics)` + `data(functions)` | drop |
| `axt`/`axf`/`aar` xrefs | `ida_xrefs_to` + `code(xrefs_from/callers/callees)` + `search(code_ref/data_ref)` | drop |
| `agf`/`agg`/`agc`/`agCd` call graphs | `ida_callgraph` (mermaid/dot/json) + `graph(callgraph/cfg/dominators/xref_graph)` | drop |
| `afb` basic blocks | `code(blocks)` + `graph(cfg)` + `ctree(logic_flow/dominance)` | drop |
| `/x` hex search | `search(bytes)` via native `bin_search` | drop |
| `/e` regex | `search(regex)` | drop |
| `/a`/`/A` insns search | `search(insns/mnemonic/instruction)` | drop |
| `/r` ref search | `search(data_ref/code_ref)` + `code(xrefs_from)` | drop |
| `/w`/`izz` all-strings | `search(string)` + `ida_list_strings` + `data(strings)` + `memory(strings)` | drop (note raw-scan speed delta; fix natively if needed) |
| `t`/`td`/`tu` types | `ida_declare_type/get_type/list_types/apply_type` + `types(infer/read_struct/import_header/diff)` | drop |
| `z`/`zg` zignatures | `funcs(find_similar)` + FLIRT (`ida_apply_sig`/`ida_list_sigs`) | drop (FLIRT *generation* is the real gap) |
| `wx`/`wa` writes | `modify(patch_bytes/patch_asm)` + `memory(write)` (governed) | drop (MCP governance is an improvement) |
| `px`/`p8`/`ps`/`pD`/`pC` | `memory(hexdump/read)` + `ida_read_bytes` + `code(disasm)` + `ida_decompile` | drop |
| `pf`/`pt` structs | `types(read_struct/visualize)` + `memory(struct_walk)` + `ida_calc_*` | drop |
| `p==`/`pcp` per-block entropy | `memory(entropy/histogram)` + `segments(analyze)` | drop for IDB; **adopt the pre-IDA whole-file sweep** as `ida_r2_entropy_profile` |
| `s`/`f` cursor | none (stateless by design) | drop (stateless is a feature) |
| `u`/`s+` calc | `ida_calc_deref/chain/eval/offset/convert/align/bitops` | drop |
| `rabin2 -I` | `ida_overview` + `idb(architecture_profile)` — needs idat | **adopt** the no-idat fast path as `ida_r2_bininfo` |
| `rabin2 -i/-s/-e/-E/-S/-D` | `ida_list_imports` + `imports_deep` + `search(symbol)` + `idb(entrypoints)` + `data(exports)` + `ida_list_segments` | drop |
| `rabin2 -zz` whole-file strings | `ida_list_strings`/`memory(strings)` (needs idat, only recognized strings) | **adopt** as `ida_r2_strings` (whole-file incl. unmapped, paddr-based) |
| `rahash2` | `idb(meta)` file-level only | **adopt** region hashing as small op / fold into memory |
| `rabin2 -H/-x/-X/-r/-T` | relocs = per-slot flag only; no TLS; no extract | **adopt (low)** — reloc list, TLS layout, sub-file carve (implement carve natively, ~100 lines stdlib) |
| `rabin2 -B` magic sniff | `infer_binary_arch_profile` heuristics | **adopt (low)** — wrapper-magic pre-pass (~20 lines stdlib) |
| `radiff2` whole-image diff | `code(diff_functions)` (two functions only) | **adopt** as `ida_r2_bindiff` (firmware v1-vs-v2 changed-handler discovery) |
| `pdc`/`pdg` fallback decompiler | `ida_decompile` (Hex-Rays) | **adopt (conditional)** — fallback only when Hex-Rays absent for the arch |
| `ic`/`icc` class/vtable enumeration | `types(vtable)` (one vtable by name) | **adopt (low)** — whole-blob C++ class enumeration |
| `ae*`/`aefa`/`aet` ESIL emulation | **none** | **adopt** — the top dynamic gap (§6) |
| `asm.emu=true` emu-augmented analysis | none (static only) | **adopt (conditional)** — execution-derived code confirmation; depends on unicorn |
| `r2 -a -b -m` raw open | `ida_open_binary(architecture=…, input_format='bin', baseaddr)` | drop |
| `#!pipe`/`!` shell | `misc(python/idc)` + `ida_batch` | drop (MCP safer) |
| RISC-V GP-relative xrefs | `detect_riscv_gp`/`set_gp`/GP notes | drop (MCP strictly better) |

**Consolidated verdict on the "customized engine":** a subprocess Rizin/r2 engine is worth adopting ONLY for the narrow host-side triage + loader-advisor + emulation slice. Everything else is do-not. The paper's synthesis across B1 (recommend p0 subprocess engine + /v + cross-validation), B3 (Architecture A, C milestone first), B4 (do-not bolt the whole engine on; unicorn-backed emulate for the emulation gap), and B5 (adopt Architecture A narrow) is: **one host-side `ida_r2_*` subprocess namespace** whose first ops are `bininfo`/`strings`/`entropy_profile`/`disassemble_hypothesis`/`decode_check`/`vxrefs`/`bindiff`, plus `emu`/`trace`/`status` for the dynamic gap, and a hard do-not for rop/disasm/search/strings/hexdump/zign reimplementations.

---

## 8. Integration architecture A/B/C with the EXACT seam specification

### 8.1 The three architectures
- **Architecture A — host-side subprocess engine (`ida_r2_*`).** An optional, default-off `r2` backend tool owned by the host, spawning `rz`/`r2 -q` subprocesses on the raw file path, never touching the IDB. Reuses the idat subprocess lifecycle, dispatch seam, policy, error envelope, compaction, batch, and ownership guard. Works without IDA and during safe_mode. **RECOMMENDED.**
- **Architecture B — independent full query backend.** r2 as a parallel analyst with its own state/index/symbol namespace. Forces two symbol namespaces, two indexes, blackboard conflicts, semantic-index divergence — the exact failure the blackboard contradiction machinery exists to catch. **REJECT.**
- **Architecture C — in-process librizin (ctypes/rz-bind).** LGPL §4(d) relink obligations against a GPL-3.0-ONLY host (relink/relicense conflict) + in-process parsing of untrusted `.bin` in the host's address space (periodic CVE record). **REJECT.**

### 8.2 The exact seam specification for Architecture A

**Tool namespace.** New host-side backend tool `r2` (public ops `ida_r2_*`). Host-side branches in `server_dispatch.py:_execute_tool_inner` already exist for `_handle_session_health`, `_handle_memory_filesystem`, `_handle_bookmarks`, `_handle_analysis_plugin_run` — add `if tool_name == 'r2': return self._handle_r2(args)` before the `call_tool` RPC fallthrough (**mandatory**, else it forwards to IDA which has no `r2` tool).

**Subprocess lifecycle.** Mirror `server_runtime.py` `_start_server_inner` Popen(idat) + `_kill_process_tree` (Windows `taskkill /T /F`) + lease + port-file handoff. New `host/r2_engine.py` with a narrow `R2Engine` interface: `start/info/command/esil/stop`. One long-lived r2 subprocess per session (r2pipe/rz-pipe transport) OR per-call stateless one-shots (`rz -q -c`, `r2 -q -qc`) — stateless one-shots are simpler and trivial to version-gate; r2pipe is the fast stateful path. **Session scoping:** r2 calls take `idb=`/session ref; host resolves via `_resolve_session_from_idb_ref` WITHOUT the runtime-alive/safe-mode-clear requirement (r2 only needs `binary_path` + the session's resolved arch/bitness/base). Standalone mode works with bare `binary_path` + `processor`/`bitness`/`baseaddr` args (no session, no IDA).

**Registration chain (all files, all must be touched):**
1. `host/server/tool_registry.py` — `_TOOL_ACTIONS['r2'] = ['bininfo','strings','entropy_profile','disassemble','decode_check','vxrefs','bindiff','emu','trace','status']`.
2. `host/schemas_data.py` — `TOOLS` + `ADVERTISED_TOOLS` + `ADVERTISED_ACTIONS['r2']` + `TOOL_DESCRIPTIONS['r2']` + `TOOL_ARG_SCHEMAS['r2']` (action enum + binary_path/addr/start/end/arch/bits/base/count/engine/max_steps + idb). Add `r2` to a category in `host/schemas.py` (`classify_tool_category`).
3. `host/agent_operations.py` — `AgentOperation` entries `ida_r2_*` with `input_schema`, `example`, `backend_tool='r2'`, `backend_action`. This regenerates `docs/TOOLS_REFERENCE.md`, `.agents/skills/`, `ida_help` via `scripts/generate_tool_skills.py` (never hand-edit generated artifacts).
4. `host/policy.py` + `docs/POLICY.md` — classify read-only `(r2, bininfo/strings/entropy/disassemble/decode_check/vxrefs/emu-report/status)` as `RiskTier.READ` (add `'r2'` to `READ_ONLY_TOOLS` or list pairs in `READ_ONLY_ACTIONS`); `(r2, start/attach)` → `RiskTier.NETWORK_OR_PROCESS` (ack in assist); emulation state-write → `RiskTier.DEBUGGER` (already defined, currently unused — first consumer); IDB-writing r2 paths (apply_to_idb) → `WRITE_IDB` + ack with **re-run of IDA policy on the resulting calls** so r2 output cannot bypass governance. **Never RiskTier.UNKNOWN** (would demand ack on everything).
5. `host/errors.py` — add `R2_ENGINE_START_FAILED` (runtime, recoverable=true), `R2_TIMEOUT` (runtime, recoverable=false), `R2_PROCESS_DIED` (runtime), `R2_BINARY_NOT_FOUND` (user, hint → `IDA_MCP_R2_BIN`/installer `--with-r2`); optionally `EMULATION_ERROR`/`EMULATION_TIMEOUT` to mirror the ida-side codes. `adapt_agent_error_payload` in agent_operations.py maps legacy hints to public `ida_r2_*` names.
6. `host/config.py` — `IDA_MCP_R2_BIN` (default `shutil.which('rz')` then `r2`), `IDA_MCP_R2_TIMEOUT_SEC`, `IDA_MCP_R2_ESIL_MAX_STEPS`, `IDA_MCP_R2_TRANSPORT=subprocess|inprocess` (future), `IDA_MCP_R2_PRE_ANALYSIS` (default on, degrades gracefully if binary missing).
7. `host/server/server.py` — compose `ServerR2Mixin` (host-side `_handle_r2`) into `IDAMCPServer`.
8. `host/server/server_dispatch.py` — the `if tool_name == 'r2'` branch + per-subprocess wall-clock cap (mirror `IDA_MCP_RPC_HARD_WALLCLOCK_SEC`); register long ops in `LONG_RUNNING_ACTIONS` (bindiff, trace).
9. `host/server/server_batch.py` — batch/background route through `_execute_tool` automatically once `r2` ∈ TOOLS; `background(submit, tool_call={'tool':'r2','action':'trace'})` gives long emulation jobs the existing poll surface.
10. `host/server/postprocess.py`/`stores/truncation.py` — free via the engine-agnostic PP pipeline; verify `_cache_next_page` key (tool/action) has no collision with IDA tools and compact-mode projections work on r2 payload shapes.
11. Installer — `installer/main.py` + `installer/runtime.py` `--with-r2` (pinned release + checksum + license text staging into CACHE_DIR/bin), mirroring the llama.cpp pin discipline.
12. Tests — `tests/host/test_r2_*.py` with a fake-r2 subprocess shim (fake stdout) so the base CI matrix needs no r2; **plus an optional CI job (`apt install rz`) running the same contract tests against real rz — CI can run rz today, which it cannot for IDA.** This is a genuine CI/testing win the engine brings.

**Error-envelope reuse.** Host-side `make_error` + `is_error_result` already handle both IDA and host results; the agent sees an identical `{error:true, code, category, message, recoverable, hint, details}` shape whether failure is IDA-side or r2-side. **The seamless test:** an `ida_r2_*` call must return the same envelope an agent expects from `ida_*` tools.

**Coexistence with the IDA bridge.** r2 operates on a `file_path`, keyed by file, never by IDB session; it does not touch IDB state. Safe-mode rule: r2 READ_ONLY actions allowed during safe_mode; IDB-writing r2 paths refused during safe_mode. Ownership guard: `_ensure_client_owns_session` as used by `_submit_semantic_index`. Subprocess hardening: cleared env (never leak `IDA_MCP_SESSION_TOKEN` into the r2 child), restricted cwd, timeout + wall-clock, capture stderr, `R2_NOPLUGINS` / `-e cfg.sandbox=true` (Rizin `io.sandbox`), never shell-interpolate the file path, target-path canonicalization via the existing memory allow-root logic.

**Windows support.** r2/Rizin ship official Windows builds; reuse `_kill_process_tree` (`taskkill /T /F`) + port-file handoff unchanged; verify headless `r2 -2 -i r2_worker.py`/`rz -qc` under cmd/PowerShell in a smoke test before promising it.

**Milestones (recommended order):** (0) decision doc `docs/RIZIN_INTEGRATION.md`; (1) hermetic fake-r2 tool + 2-3 ops (`bininfo`, `disassemble_hypothesis`, `vxrefs`) + optional real-rz CI job; (2) `load_hints` feedback into `open_binary`/`_build_ida_command` (explicit user `analysis_options` override r2 hints); (3) emulation (`emu`/`trace`/`status`) with engine abstraction; (4) hypothesis-tier blackboard ingestion.

---

## 9. Viability verdict

### 9.1 License (exactness)
- The MCP is **GPL-3.0-only** (pyproject, pure-Python wheel, native `.so` NOT shipped).
- **radare2 is GPL-3.0** → compatible. **Rizin is LGPL-3.0** → a GPL-3.0 work may incorporate LGPL-3.0 code (GPL satisfies LGPL §4's license-choice). **r2pipe/rzpipe are MIT/LGPL pure-Python bindings** — clean to add as pip deps.
- **Subprocess = no obligations.** Driving an externally-installed CLI over IPC (the exact precedent for proprietary IDA) is mere inter-process communication between separate programs — no conveyance, no GPL §5/§6 source-offer, no LGPL §4(d) relinkable-object duty.
- **Landmines:** (a) bundling r2/Rizin binaries inside the wheel (GPL §5/§6 + LGPL §4(d) Installation-Information duties) — reject; (b) linking `librizin` in-process via ctypes (LGPL §4(d) + in-process untrusted-parse security) — reject; (c) **unicorn-engine is GPL-2.0-only (no "or later") + commercial dual license** — keep ALL unicorn code inside the spawned r2/rizin subprocess, never `import unicorn` into `ida_pro_mcp/**`.
- **Verdict: green light**, with the absolute rules: subprocess-only; never bundle in the wheel; never link librizin in-process; never let r2 write the IDB.

### 9.2 Ops
- Feasible on all target OSes (r2 Windows installers, Linux distro/r2brew, macOS brew; Rizin Windows installers + choco, Debian≥12/Ubuntu≥24.04 `apt rz`, official installer, macOS brew; both headless `-q -c`, ~40-80MB installed — negligible vs IDA).
- The weak spot: **the engine is not on PyPI** (only bindings) → pin a documented minimum version + a CI apt/brew pin with a drift check (mirror the llama.cpp 99111b19 discipline). JSON/CLI shapes churn across majors → contract-test the adapter surface (pin 6.1.6/r0.7.x, feature-test at startup via `ida_r2_status` mirroring `ida_reranker_status`).
- **Rizin over r2 is the primary recommendation** (LGPL — cleaner, bundles unicorn for the ESIL jalr gap, `apt`/`choco`/`brew` present), r2 as fallback. RISC-V disassembly parity between capstone/rz and IDA's RISC-V module is unmeasured — a sample-corpus comparison is required before Phase 2.

### 9.3 Security
- Parsing an untrusted vendor `.bin` inside the host process via ctypes librizin puts a C parser's memory-corruption surface (periodic CVE record) in the same address space as the MCP server and the blackboard SQLite DB — **unacceptable**. Subprocess isolates the parse fault; the project already has spawn/lease/timeout/cap/structured-error machinery.
- Reuse: per-session bridge token (constant-time compare), 64MB caps, allow-root canonicalization, risk_ack tiers, wall-clock caps. The backend constructs the r2 `-c` commands itself and never passes user content as r2 script input → no script-execution surface; the `.bin` itself is data.
- Optional Linux sandbox (bubblewrap/seccomp) behind an opt-in knob matching SAFETY_MODEL "future hardening".
- **Subprocess-only is a hard security requirement, not a preference.**

### 9.4 Maintainability
- Two engines = two analysis models. Coherence is preserved by ONE rule enforced at the seam: **`ida_r2_*` tools have no `write_idb`/destructive actions; their output is hypothesis-tier / load-hint suggestions, tagged proposed, never auto-renamed, never a confirmed finding. IDA wins conflicts; r2 is labeled proposed.** If the team cannot commit to "r2 never writes the IDB", the answer flips to do-not.
- The previous emulation/debug tools died for lack of an advertised surface; Architecture A ships the registry wiring + public ops + a workflow, so it is the difference between a live feature and the next cleanup-commit victim.

### 9.5 Value
- **Real but narrow.** The marginal gain over IDA+MCP today: (1) real host-side RISC-V disasm in ms before committing to a slow idat session; (2) computing the exact load hints (processor/baseaddr/entry/code-regions) `open_binary` already accepts — kills the "loaded a raw bin at the wrong base" dead-end; (3) a cheap second opinion on ambiguous decodes (decoder cross-validation); (4) ESIL/unicorn emulation — the one capability IDA cannot offer the MCP.
- Redundant/weak (do-not): entropy, strings, hex search, histogram, function recovery, types/FLIRT/annotations (Hex-Rays dominates), everything IDA already covers on an analyzed IDB.

### 9.6 Sharp recommendation
**ADOPT Architecture A** (optional, default-off, host-side `ida_r2_*` subprocess triage + loader-advisor + emulation namespace). **DO-NOT adopt B or C.** Five hard conditions, all non-negotiable: (1) subprocess-only; (2) default-off optional extra (IDA-only path bit-identical when r2 absent); (3) no engine bundled in the wheel; (4) `ida_r2_*` never writes the IDB, hypothesis-tier; (5) explicit user `analysis_options` override r2 load hints. If any condition is dropped, fall back to do-not.

**Phased roadmap:**
- **Phase 0:** decision doc `docs/RIZIN_INTEGRATION.md` (license, scope, the five conditions).
- **Phase 1:** single `ida_r2_*` tool, 2-3 ops (`bininfo`/`load_hints`, `disassemble_hypothesis`, `vxrefs`), hermetic fake-r2 tests + optional real-rz CI job. This lands the seam.
- **Phase 2:** load-hint feedback loop into `open_binary`/`_build_ida_command` (r2 proposes, IDA disposes; explicit user override wins). **This is the single highest-value milestone for opaque RISC-V `.bin`.**
- **Phase 3:** emulation (`emu`/`trace`/`status`) with engine abstraction — unicorn default for indirect branches, ESIL for straight-line, `maxsteps`+wall-clock mandatory; validates the "unroll packed init / resolve jalr / confirm entry" workflow.
- **Phase 4:** hypothesis-tier blackboard ingestion (r2 findings → `kind='hypothesis'`, never `finding`).
- **Phase 5 (optional):** whole-image `bindiff` (firmware v1-vs-v2), class/vtable enumeration, pseudo-C fallback decompiler.

---

## 10. Appendix

### 10.1 Cross-check resolutions (contradictions between journals, resolved here)

1. **RISC-V raw-arch inference gap (Track A2) vs current tree.** A2 claimed `arch_profile.py` candidates are exactly `metapc/arm/mipsl/mipsb`, so "a raw RISC-V `.bin` cannot be auto-detected." **Verified against the current tree: this is now closed.** `_raw_arch_candidates`/`_opcode_density_scores` include a `riscv` candidate (`c.jr ra`=0x8082, `c.jalr ra`=0x9082 strongest signals, gated by `riscv_instruction_validity`), `_arch_prototype_embeddings` has `riscv32`/`riscv64`, and `_riscv_bitness` distinguishes RV64/RV32. The concurrent waves landed RISC-V inference in `arch_profile.py` since A2 was written (A4 flagged this migration as mid-flight). **Remaining to verify:** feed-through of the inferred processor/bitness/endian into `_build_ida_command` (`-priscv`, `-Trv64`), the endian hint, and whether the deleted firmware_view vector-table/RTOS/carve capability has any replacement.
2. **Emulation engine choice (B2 vs B4).** B2 recommends a host-side `rz` namespace with ESIL p0; B4 recommends a unicorn-backed host-side `emulate` tool (p0) and explicitly "do NOT bolt the whole r2/Rizin engine on." **Resolution:** the capability is the top gap (§6); the engine is a means. B2's own verified evidence (ESIL jalr failure) forces unicorn for indirect branches, and B4's unicorn-from-PyPI embedding avoids the Rizin-binary question for the emulation slice alone. The synthesis is one host-side subprocess engine with engine-abstracted actions (esil|unicorn|rzil), unicorn default for branch resolution — this satisfies both journals and keeps unicorn out of the MCP process.
3. **Emulation priority (B1/B3 "p1-p2 conditional" vs B2/B4 "p0").** Resolution: the *emulation capability* is p0-value for the mission, but the *engine seam* (Architecture A) is p0-build and emulation rides on it as the Phase-3 milestone (§9.6). B3's "ESIL after C milestone" ordering is retained because emulation without the seam is the dead-tool pattern.
4. **Whole-engine (B1 p0 subprocess) vs narrow-unicorn (B4 do-not-bolt).** Resolution: adopt the seam (B1/B3/B5), but scope it to the do-not-reimplement list of §7 so the engine stays a triage+advisor+emulation co-processor, not a parallel analyst. This is literally B5's "narrow Architecture A."
5. **RISC-V Hex-Rays availability** (B3 gap) — unconfirmed; it determines `ida_r2_pdc` priority (p2 vs p3). Verify against the user's IDA before building the fallback decompiler.
6. **Legacy tool status (A4) vs agent-surface claims (A1/A2).** 13 of 31 legacy tools have no `ida_*` op; 8 have no TOOL_ARG_SCHEMAS. These are consistent with the 67-op agent surface being the real contract and the legacy surface being a documented compatibility backend. The "unknown kwargs rejected" claim is TRUE only for the 23/31 with schemas on the legacy surface; the agent surface is safe via per-op strict schemas.
7. **Mitigations/entropy overlaps (B1 "MCP has it" vs B4 "100% overlap").** Consistent: both drop r2's version; only the pre-IDA whole-file sweep and per-block profile are deltas.
8. **`/v` (B1) vs `/v` (B4 do-not).** B4 lists `search(immediate)`+pointer-width widening as covering `/v`; B1 says `search(immediate)` scans instruction immediates only, not raw data words. **Resolution: B1 is correct** — `memory(search)` int mode + pointer-width auto-widen finds raw words matching a value, but there is no "everything pointing AT address X" scan. The `/v`-style virtual-xref scan (dispatch/vector tables) is a genuine gap and is carried as `ida_r2_vxrefs`/adopt in §7.

### 10.2 Coverage gaps — what no one mapped / needs verification after the waves settle

1. **The full feed-through of `arch_profile` inference into the load path** (does `-priscv`/`-Trv64`/endian actually reach `_build_ida_command`? is `_apply_session_options` consistent?) — A2/A4 disagree on the tree and the tree moved.
2. **Firmware carve replacement** — vector-table/RTOS/pointer-sweep/carve have no visible home after `firmware_view` deletion; verify whether `arch_profile` MMIO scoring + `infer_binary_arch_profile` actually cover `detect_load_address`/`detect_vector_table`/`rtos_scan`.
3. **The session architecture-profile contract** — `ida_r2_*` wants to inherit processor/bits/base/entry from the bound session; pin what `idb.architecture_profile`/`ida_session_state`/`session.analysis_options` actually return.
4. **RISC-V Hex-Rays presence** (affects `ida_r2_pdc`).
5. **RzIL / rz-run / rz-search -e behavior** — Rizin absent on this box; validate against a pinned Rizin build before committing those seams.
6. **ESIL/unicorn RISC-V maturity on real firmware slices** — step a real opaque RISC-V slice and confirm register/mem deltas match hand-disassembly before advertising `ida_r2_emu`.
7. **`cfg.sandbox` (r2) vs `io.sandbox` (Rizin) semantics** — unverified against this codebase's sandbox expectations.
8. **Windows host r2 worker script + PowerShell** — headless `r2 -2 -i` under cmd/PowerShell needs a smoke test.
9. **Test fakes for raw flat images** — no shared canonical FakeIda can simulate a flat single-segment raw blob; a shared fake with a 'raw flat blob' mode is the highest-value test investment.
10. **No live-IDA probe was possible (read-only research, `_FakeIda` only)** — claims about `bin_search`/strlit enumeration/FLIRT availability rest on code reading; run `scripts/smoke_core_path.py` against a real IDB before finalizing operational claims.
11. **The 8 un-schema'd legacy tools** and **the 13 legacy-only tools** — decide each: promote the valuable ones (gadgets ROP/COP/mitigations, stack_analysis, annotation.mark_dangerous, agent.* intelligence) before any legacy removal; the promotion rule in ROADMAP is the template.
12. **Vestigial references to reconcile:** `WORKFLOW_FIRMWARE` prompt, `firmware_analysis` policy purpose, `firmware_detected` overview key + consumers, `schemas_data.py:172` "emulate" comment, `memory.py:346` debug docstring, `DEBUGGER_*`/`EMULATION_*`/`BOOKMARK_*` error codes with no implementing tools, commented-out `api_enums`/`api_bookmarks`/`api_signatures`/`api_resources` in `tools/__init__.py`, stale `CONTRIBUTING.md`/`USE_CASES.md`/`ARCHITECTURE.md`/`.claude/settings.local.json`.

### 10.3 Per-agent source-journal appendix (condensed)

**Track A1 — IDA-side tool surface (26 dispatchers, infra, policy-as-gating).** Strongest: raw-blob entry bootstrap, RISC-V GP, jalr gadget classification, firmware-aware taint registry. Weak: PE/libc-biased catalogs, name-dependent canary, write-only export, no per-member type editing / TIL deletion / decompiler options / patch undo. Policy is not an unsafe-set (`MCP_UNSAFE` inert); `misc.python` is an ungated escape hatch; R002 PII redaction conflicts with IOC note-taking.

**Track A2 — host/server/session/dispatch.** Robustness + agent-UX strong (safe-mode gate, RPC lifecycle, postprocess pipeline, enrichment). Gaps: ~20 unregistered session actions incl. `export_session`/`import_session` and the only `$param`/`step{i}_{key}` chaining (macros); no output→input batch chaining; background jobs no pause/priority/preempt; group_link first-provider-wins; rate limiting no per-session scope; RISC-V arch inference (now resolved in-tree, see §10.1).

**Track A3 — unimplemented IDA API map (24 edges).** Debugger absent (vestigial codes + misleading docstring); no segment-register seam (top gap); no add_entry/create_data/create_strlit/undo; no multi-blob loading or snapshot/restore; no member-level type editing or TIL sharing; no ida_hooks events; ctree read-only (reasonable scope cut); `ida_auto` avoids `auto_wait` (polling cost); ida_python mitigates everything but untyped/unsafe-by-default. ROADMAP promotion rule is the standard for new edges.

**Track A4 — support/plumbing.** arch_utils deep RISC-V + exotic-CPU coverage but `COMPARISON_MNEMONICS`/`XOR_MNEMONICS` RISC-V-blind; query_lang orphaned (90% built); semantic_matching fine; registries partially firmware-aware; sync/cache solid (cache key `default=str` collision risk; singleton import-path fragility); two drifting MCPError vocabularies; zeromcp dual-surface; server_script bridge correct except `memory_model` skipped and IDA-side file read unsandboxed; 8 legacy tools unschema'd, 13 without ops; **firmware_view deleted mid-migration**; debugger/emulation codes reserved but absent.

**Track A5 — meta-surface.** Tests strong around existing surface but **zero raw `.bin` fixture/fake/test/doc**; firmware carve pipeline deleted leaving vestigial traces; RISC-V implemented in code bits but undocumented + never e2e-tested on a real blob; generated-docs loop fully closed and CI-enforced; installer strong (version-scan fix) but no RISC-V `.sig` pack; CI ubuntu-only, no licensed IDA; **no radare2/Rizin comparison harness exists**.

**Track A6 — intelligence/analyst-memory/workflow.** Retrieval stack fully built + benchmarked (embedder, index, reranker, classifier, families, sliced jobs); blackboard workspace novel and live (anchors, staleness, recall, coverage, targets, publish/import round-trip, durable host-side crawler + proposal lifecycle). Gaps: index jobs no pause/priority + non-durable cursor; cross-binary memory narrow (exact-hash + hypothesis-only); InsightIndex dead code; dead-end result discarded; workspace binary-scoped only.

**Track B1 — r2 inventory.** Subprocess engine p0; `/v` vxrefs + pre-IDA triage trio + cross-validation as first ops; ESIL emulation deferred to B2; r2ghidra/pdc fallbacks conditional; o+/map + radiff2 conditional; ~10 do-not rows (af*/pd/axt//x/agf/zign/t/td/rabin2 -S/etc.).

**Track B2 — emulation deep-dive.** ESIL RV32 straight-line verified; **jalr broken (verified)**; stock r2 no unicorn; `esil.maxsteps=0` hang risk (verified); Rizin not installed, RzIL/rz-run claims unverified; recommend host-side `rz` namespace with engine abstraction, unicorn default for indirect branches; **the container must ship advertised ops or repeat the b191581 dead-tool cycle**; license: keep unicorn in subprocess (GPL-2.0-only landmine).

**Track B3 — integration architecture.** Architecture A per-session r2 subprocess engine manager (p0) + worker protocol mirroring server_script.py + full registration chain + dispatch branch + policy tiers + error-envelope reuse; C-milestone (rabin2 triage→seed-IDB) first shippable; `ida_r2_esil` p1; B (in-process) p3 blocked on LGPL-vs-GPL-3.0-only + thread-safety; packaging/pinning/Windows p1; safe-mode triage p1; do-not-reimplement overlap list.

**Track B4 — overlap audit.** ~85% of classic r2 surface already covered, richer; verdict do-not for most; genuine gaps: emulation (p0, unicorn-backed host tool), sub-file carve (native ~100 lines), rahash2 region hashing, magic sniff pre-pass; pdc/pdg do-not (Hex-Rays strictly better); RISC-V GP is a strict MCP win.

**Track B5 — viability verdict.** License green light (subprocess-only rule); ops feasible but needs pin matrix; security subprocess-only hard requirement; maintainability hinges on "r2 proposes, IDA disposes" single rule; value real-but-narrow (triage + load-hints + second opinion); **ADOPT A, reject B/C**, five hard conditions + phased roadmap.

---

*End of paper. Generated by the SYNTHESIZER agent from 11 research-agent journals (Track A ×6, Track B ×5). All claims anchored to files read on branch `swarm/session-blitz` at the time of writing; the tree is under concurrent edit and in-flux areas are flagged in §10.1–§10.2.*
