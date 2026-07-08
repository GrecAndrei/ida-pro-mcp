# IDA Pro MCP - Tools Reference

Total tools: **66** | Advertised: **64**

> Single source of truth: `src/ida_pro_mcp/host/schemas_data.py`
>
> Generated: 2026-07-06

## Tool Summary

| Tool | Actions | Description |
|------|---------|-------------|
| `session` | 61 | Full session lifecycle with runtime tracking, analysis no... |
| `truncation` | 1 | Continues a previously truncated tool response to retriev... |
| `bookmarks` | 7 | Manages named address bookmarks for quick navigation and ... |
| `background` | 6 | Background batch execution for long-running analysis task... |
| `batch` | 0 | Executes multiple tool calls in a single request to reduc... |
| `analysis` | 9 | Controls IDA analysis engine settings and triggers reanal... |
| `idb` | 8 | Query top-level IDB metadata: binary info, segments, entr... |
| `code` | 19 | Decompilation, disassembly, and code analysis (≈ IDA View... |
| `data` | 9 | Retrieve core IDB data |
| `search` | 38 | Pattern, reference, and semantic search |
| `types` | 16 | Manages IDA type system: structs, enums, prototypes, type... |
| `memory` | 11 | Read, write, and inspect raw memory/bytes in the binary o... |
| `modify` | 4 | Apply edits to the IDB: rename symbols, add comments (reg... |
| `funcs` | 8 | Function boundary management (≈ IDA P/Delete keys) |
| `segments` | 12 | List, create, modify, and analyze binary segments and the... |
| `bulk` | 6 | Applies batch edits (renames, comments, types) to multipl... |
| `misc` | 9 | Utility grab-bag: run scripts (python/idc), load signatur... |
| `calc` | 8 | Safe address arithmetic and pointer resolution—use instea... |
| `nav` | 4 | Navigate the IDA cursor to addresses or semantically inte... |
| `debug` | 31 | Control the debugger: run, step, breakpoints, registers, ... |
| `coverage` | 10 | Import and analyze code coverage data to identify hit/mis... |
| `trace_analysis` | 20 | Analyzes imported execution traces for coverage, loops, A... |
| `project` | 19 | Project I/O and evidence management |
| `microcode` | 4 | Access Hex-Rays microcode IR for a function at various ma... |
| `graph` | 4 | Generate call graphs, CFGs, dominator trees, and xref gra... |
| `xref_analysis` | 10 | Cross-reference and callgraph analysis: call chains, comm... |
| `ctree` | 9 | Query and traverse the Hex-Rays decompiler ctree AST for ... |
| `entropy` | 7 | Compute entropy over regions to detect packing, encryptio... |
| `imports_deep` | 6 | Deep import analysis: thunks, delay-loads, forwarded, ord... |
| `patterns` | 9 | Generate, match, and manage FLIRT/byte pattern signatures... |
| `symbols` | 5 | Loads and manages debug symbols (PDB/DWARF) for the curre... |
| `lumina` | 6 | Interface to Hex-Rays Lumina server for collaborative fun... |
| `export` | 9 | Export IDB content in various formats for external tooling |
| `history` | 6 | Undo/redo IDB changes, create snapshots, restore, and dif... |
| `data_ops` | 8 | Change data representation at addresses (≈ IDA Edit menu ... |
| `firmware_view` | 20 | Firmware triage: region scanning, pointer sweeps, table c... |
| `hooks` | 5 | Generate dynamic instrumentation hooks (Frida, Detours) f... |
| `wiki` | 7 | Accesses built-in documentation and tool usage guides wit... |
| `yara_hunt` | 6 | Scans the binary with YARA rules and provides match conte... |
| `intelligence` | 14 | Intelligence subsystem: embedding-based classification, b... |
| `threat_hunt` | 8 | Runs automated threat-hunting passes to detect malware pa... |
| `workflow` | 13 | Executes predefined multi-step analysis workflows for com... |
| `gadgets` | 11 | Find ROP/JOP/COP gadgets, stack pivots, and classify expl... |
| `taint` | 5 | Data flow taint analysis from user-controlled sources to ... |
| `deobfuscate` | 8 | Detect and decode obfuscation: stack strings, API hashing... |
| `crypto_id` | 6 | Detect cryptographic algorithms, constants, and encoding ... |
| `abi` | 10 | Analyzes calling conventions and ABI details of functions |
| `summarize` | 11 | Structured summaries of binary components |
| `classify` | 12 | Classify functions and binaries by purpose |
| `compare` | 10 | Diff two IDB databases or functions across binaries |
| `stack_analysis` | 10 | Analyze stack frames: buffer sizes, canaries, alignment, ... |
| `protocol` | 13 | Detect and analyze network protocol structures, parsers, ... |
| `annotation` | 18 | Automatically generates and manages comments, labels, and... |
| `string_ops` | 24 | Advanced string analysis and IOC extraction |
| `cfg_analysis` | 10 | Analyzes control flow graph structure including loops, do... |
| `binary_info` | 10 | Retrieves binary metadata including PE/ELF headers, secti... |
| `blackboard` | 70 | Persistent RE knowledge base: findings, hypotheses, IOCs,... |
| `governance` | 4 | Pre-flight validation for edits: detect contradictions, P... |
| `knowledge` | 5 | Cross-session firmware knowledge base: chip family identi... |
| `packer` | 5 | Detect packers / protectors (UPX, MPRESS, VMProtect, Them... |
| `struct_recover` | 5 | Automatic struct/type recovery from field access patterns... |
| `emulate` | 5 | Unicorn-backed emulation sandbox — execute functions/slic... |
| `bindiff` | 5 | Cross-version binary diffing via serialized snapshots — f... |
| `multi_session` | 8 | Multi-binary session groups — link IDA sessions for cross... |
| `fixups` | 4 | Manage relocations/fixups (relocation table entries) in t... |

## Tool Details

### session

Full session lifecycle with runtime tracking, analysis notebook, hypothesis tracking. state: full analysis state snapshot (binary, coverage, blackboard summary, engine status, next actions) — call this at the start of every turn instead of reading the ida://state resource. logs: tail IDA stdout/stderr log files directly without an IDA RPC — use this when IDA is busy (e.g. during auto-analysis) and other tool calls time out; accepts lines= param (default 60). Actions: create/switch/close/list/status/state/logs, snapshot/restore, rate_skill/suggest_strategy/suggest_triage/suggest_analogy/apply_analogy, notebook_append/read, track_hypothesis/confirm/refute, get_phase/advance_phase, recent_workset, macro_set/run, dashboard, health, idle_purge. cleanup_stale: remove sessions older than max_age_days (default 30); with prune_orphans=True (default) also deletes sessions whose binary+idb paths are both gone. idle_purge: tear down live IDA runtimes idle longer than idle_seconds (does NOT touch the database; use cleanup_stale for DB rows). health: server, runtime, IDA, session, wiki diagnostics. Plus ~30 more actions (tag, merge, export_session, etc.) — use tools/list for the full enum.

**Actions:**

- `health`
- `create`
- `discover`
- `get`
- `list`
- `switch`
- `close`
- `status`
- `rebuild`
- `update`
- `rename`
- `duplicate`
- `export_session`
- `import_session`
- `archive`
- `unarchive`
- `tag`
- `untag`
- `find_by_tag`
- `add_note`
- `clear_notes`
- `cleanup_stale`
- `stats`
- `validate`
- `bulk_delete`
- `bulk_tag`
- `search_notes`
- `recent`
- `oldest`
- `snapshot`
- `restore_snapshot`
- `merge`
- `rate_skill`
- `list_skills`
- `suggest_strategy`
- `suggest_triage`
- `suggest_analogy`
- `apply_analogy`
- `log_activity`
- `get_activity_log`
- `notebook_append`
- `notebook_read`
- `notebook_section`
- `track_hypothesis`
- `confirm_hypothesis`
- `refute_hypothesis`
- `list_hypotheses`
- `dashboard`
- `get_phase`
- `advance_phase`
- `link_session`
- `cross_reference_sessions`
- `list_snapshots`
- `macro_set`
- `macro_get`
- `macro_list`
- `macro_delete`
- `macro_run`
- `recent_workset`
- `kill`
- `state`

### truncation

Continues a previously truncated tool response to retrieve remaining output. Actions: continue.

**Actions:**

- `continue`

### bookmarks

Manages named address bookmarks for quick navigation and milestone tracking. Actions: add, list, delete, update, clear, find, export.

**Actions:**

- `add`
- `list`
- `delete`
- `update`
- `clear`
- `find`
- `export`

### background

Background batch execution for long-running analysis tasks and IDAPython scripts. Submit scripts or tool calls to run in background threads without interrupting IDA. Actions: submit, status, cancel, result, list, wait.

**Actions:**

- `submit`
- `status`
- `cancel`
- `result`
- `list`
- `wait`

### batch

Executes multiple tool calls in a single request to reduce round trips. Pass a calls array of tool invocations.

### analysis

Controls IDA analysis engine settings and triggers reanalysis, and runs IDA plugins. Actions: get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze, run, analyze, state. Note: analysis(action='plugin_run', name='...') is a host-level alias that forwards to misc(action='plugin_run').

**Actions:**

- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`
- `run`
- `analyze`
- `state`

### idb

Query top-level IDB metadata: binary info, segments, entrypoints, bookmarks, and architecture profile guidance for raw binaries. Actions: meta, summary, segments, entrypoints, bookmarks, overview, architecture_profile.

**Actions:**

- `meta`
- `summary`
- `segments`
- `entrypoints`
- `bookmarks`
- `overview`
- `architecture_profile`
- `state`

### code

Decompilation, disassembly, and code analysis (≈ IDA View menu / F5/Tab). smart_decompile: best first call — pseudocode + behavior tags + callers/callees + crypto hints + suggested next actions. decompile: pseudocode only. disasm: assembly listing. decompile_chain: function + compact caller/callee context. semantic_decompile: pseudocode + CFG semantics + variable dependency graph. diff_functions: unified diff of two functions. trace_argument_origin: backward BFS through callers to trace where an argument value originates (returns call chain with arg expressions and types: string_literal, constant, function_call, address_of, variable). Actions: smart_decompile, decompile, disasm, decompile_chain, semantic_decompile, diff_functions, trace_argument_origin, xrefs_to, xrefs_from, callees, callers, blocks, callgraph, find_paths, strings_in_func, decomp_dataflow, export.

**Actions:**

- `smart_decompile`
- `decompile`
- `decompile_all`
- `disasm`
- `decompile_chain`
- `semantic_decompile`
- `diff_functions`
- `xrefs_to`
- `xrefs_from`
- `xrefs_to_field`
- `callees`
- `callers`
- `blocks`
- `callgraph`
- `find_paths`
- `strings_in_func`
- `decomp_dataflow`
- `export`
- `explain`

### data

Retrieve core IDB data. functions: list all functions — always includes xref count (capped 999). globals: global variables. strings: string literals — always includes xref count. imports: imported modules and functions. exports: exported entry points. lookup: resolve name↔address. bulk_query: multiple queries in one call. capability_matrix: binary capability matrix from imports + function classifications. string_xrefs: ranked string-to-function xref map with module clustering.

**Actions:**

- `functions`
- `globals`
- `strings`
- `imports`
- `exports`
- `lookup`
- `bulk_query`
- `capability_matrix`
- `string_xrefs`

### search

Pattern, reference, and semantic search. nl: NL search via bge-code-v1 embeddings (best for RE queries). find: unified search over names/strings/imports/instructions. api: all call sites of an import. decompiled: grep pseudocode across all functions. vulnerable: scan for dangerous API patterns. outlier: structurally anomalous functions (size/complexity/orphan/hub). hunt: named recipes (backdoor/c2/crypto/anti_debug — pass recipe='list'). path: shortest call-graph path between two symbols. reach/noreach: reachability from a root. symbol: resolve symbol by name (exact then fuzzy, returns demangled + alternatives). symbol_info: rich symbol inspector (type, size, xrefs, segment, flags, prototype). demangle: demangle one or more C++ mangled names (INF_SHORT_DN and INF_LONG_DN). xrefs_to_string: find all functions referencing a string literal by value or address. Actions: nl, behavior, find, semantic, smart_bundle, api, decompiled, structured, vulnerable, constants, callers, callees, bytes, string, immediate, name, insns, mnemonic, comment, regex, func_by_sig, bool, hunt, neighborhood, outlier, fingerprint, path, reach, noreach, symbol, symbol_info, demangle, xrefs_to_string.

**Actions:**

- `nl`
- `behavior`
- `find`
- `semantic`
- `smart_bundle`
- `api`
- `decompiled`
- `structured`
- `vulnerable`
- `constants`
- `callers`
- `callees`
- `bytes`
- `string`
- `immediate`
- `name`
- `insns`
- `mnemonic`
- `instruction`
- `text`
- `operand`
- `comment`
- `data_ref`
- `code_ref`
- `regex`
- `func_by_sig`
- `type`
- `export`
- `summary`
- `query_lang`
- `bool`
- `hunt`
- `neighborhood`
- `outlier`
- `fingerprint`
- `path`
- `reach`
- `noreach`

### types

Manages IDA type system: structs, enums, prototypes, type propagation, and header imports. Actions: list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header, diff, visualize, propagate, enum_values, type_graph, vtable.

**Actions:**

- `list`
- `get`
- `set_prototype`
- `parse_decl`
- `declare`
- `apply`
- `search_structs`
- `infer`
- `read_struct`
- `import_header`
- `diff`
- `visualize`
- `propagate`
- `enum_values`
- `type_graph`
- `vtable`

### memory

Read, write, and inspect raw memory/bytes in the binary or debuggee, plus host filesystem read/write helpers. Actions: read, write, hexdump, search, compare, pointers, find_pointers, entropy, strings, struct_walk, histogram, read_file, write_file.

**Actions:**

- `read`
- `write`
- `hexdump`
- `search`
- `compare`
- `pointers`
- `find_pointers`
- `entropy`
- `strings`
- `struct_walk`
- `histogram`

### modify

Apply edits to the IDB: rename symbols, add comments (regular/repeatable/anterior/posterior), set types, and patch assembly (multi-line instructions separated by semicolons). Actions: rename, comment, set_type, patch_asm.

**Actions:**

- `rename`
- `comment`
- `set_type`
- `patch_asm`

### funcs

Function boundary management (≈ IDA P/Delete keys). create: define a function at addr (≡ pressing P in IDA). delete: remove function definition. info: full function metadata — pass include_xrefs/include_prototype/include_stack for richer output. metrics: size/complexity/call counts. find_similar: structural similarity search. suggest_names: name candidates from heuristics. list: paginated function listing (like data(functions)) with structured output. Note: regex-based filters live in search, while renames and comments live on modify. Actions: create, delete, set_flags, info, metrics, find_similar, suggest_names, list.

**Actions:**

- `create`
- `delete`
- `set_flags`
- `info`
- `metrics`
- `find_similar`
- `suggest_names`
- `list`

### segments

List, create, modify, and analyze binary segments and their permissions/attributes. Actions: list, add, delete, set_attr, set_perms, move, info, analyze, find_code, find_data, compare, merge. For relocations/fixups use the dedicated `fixups` tool.

**Actions:**

- `list`
- `add`
- `delete`
- `set_attr`
- `set_perms`
- `move`
- `info`
- `analyze`
- `find_code`
- `find_data`
- `compare`
- `merge`

### bulk

Applies batch edits (renames, comments, types) to multiple addresses in one call. Actions: rename, comment, apply_type, rename_stack, import_annotations, export_annotations.

**Actions:**

- `rename`
- `comment`
- `apply_type`
- `rename_stack`
- `import_annotations`
- `export_annotations`

### misc

Utility grab-bag: run scripts (python/idc), load signatures, inspect cache stats, and read/write files on the host filesystem. Actions: python, idc, load_sig, cache_stats, plugin_list, plugin_run, read_file, write_file, health. (analysis(action='plugin_run') and memory read/write live alongside here.)

**Actions:**

- `python`
- `idc`
- `load_sig`
- `cache_stats`
- `plugin_list`
- `plugin_run`
- `read_file`
- `write_file`
- `health`

### calc

Safe address arithmetic and pointer resolution—use instead of mental math. Includes bitwise helper operations. Actions: eval, offset, convert, resolve, deref, chain, align, bitops.

**Actions:**

- `eval`
- `offset`
- `convert`
- `resolve`
- `deref`
- `chain`
- `align`
- `bitops`

### nav

Navigate the IDA cursor to addresses or semantically interesting locations. Actions: goto, cursor, interesting, semantic_goto.

**Actions:**

- `goto`
- `cursor`
- `interesting`
- `semantic_goto`

### debug

Control the debugger: run, step, breakpoints, registers, memory, threads. Actions: status, start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, add_hw_bp, add_watch, regs, set_reg, reg_diff, snapshot_regs, threads, modules, callstack, read_mem, write_mem, search_mem, stack_dump, mem_map, bp_context, trace_start, trace_stop, trace_read, mem_diff.

**Actions:**

- `status`
- `start`
- `stop`
- `continue`
- `step_into`
- `step_over`
- `run_to`
- `run_until`
- `breakpoints`
- `add_bp`
- `del_bp`
- `enable_bp`
- `add_hw_bp`
- `add_watch`
- `regs`
- `set_reg`
- `reg_diff`
- `snapshot_regs`
- `threads`
- `modules`
- `callstack`
- `read_mem`
- `write_mem`
- `search_mem`
- `stack_dump`
- `mem_map`
- `bp_context`
- `trace_start`
- `trace_stop`
- `trace_read`
- `mem_diff`

### coverage

Import and analyze code coverage data to identify hit/missed paths. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter, function_coverage, gaps, compare, merge.

**Actions:**

- `import_drcov`
- `import_lighthouse`
- `highlight`
- `report`
- `uncovered`
- `function_coverage`
- `gaps`
- `compare`
- `merge`

### trace_analysis

Analyzes imported execution traces for coverage, loops, API sequences, and anti-analysis detection. Also provides runtime execution-trace access (get/clear/set_options), static control-flow tracing (static_trace, decrypt_strings, eval_expr, prefetch_context), and emulation-driven deobfuscation (deobfuscate_emulate). Actions: import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, execution_timeline_graph, cross_run_diff, coverage_debug_plan, anti_analysis_detect, trace_entropy, api_sequence, loop_analysis, get, clear, set_options, static_trace, decrypt_strings, eval_expr, deobfuscate_emulate, prefetch_context.

**Actions:**

- `import_trace`
- `analyze_coverage`
- `find_loops`
- `extract_api_calls`
- `basic_blocks_hit`
- `execution_timeline_graph`
- `cross_run_diff`
- `coverage_debug_plan`
- `anti_analysis_detect`
- `trace_entropy`
- `api_sequence`
- `loop_analysis`
- `get`
- `clear`
- `set_options`
- `static_trace`
- `decrypt_strings`
- `eval_expr`
- `deobfuscate_emulate`
- `prefetch_context`

### project

Project I/O and evidence management. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, evidence_graph, knowledge_merge, confidence_model, replay_pipeline, hypothesis_tracker, temporal_reasoning, semantic_artifact_diff, ai_governance, knowledge_debt, casefile_export.

**Actions:**

- `save`
- `close`
- `open`
- `load_binary`
- `list_recent`
- `get_cwd`
- `set_cwd`
- `list_dir`
- `exists`
- `evidence_graph`
- `knowledge_merge`
- `confidence_model`
- `replay_pipeline`
- `hypothesis_tracker`
- `temporal_reasoning`
- `semantic_artifact_diff`
- `ai_governance`
- `knowledge_debt`
- `casefile_export`

### microcode

Access Hex-Rays microcode IR for a function at various maturity levels. Actions: get, blocks, instructions, def_use_graph.

**Actions:**

- `get`
- `blocks`
- `instructions`
- `def_use_graph`

### graph

Generate call graphs, CFGs, dominator trees, and xref graphs for visualization. Actions: callgraph, cfg, dominators, xref_graph.

**Actions:**

- `callgraph`
- `cfg`
- `dominators`
- `xref_graph`

### xref_analysis

Cross-reference and callgraph analysis: call chains, common callers/callees, hub/leaf functions, recursion detection, dominator analysis, influence reachability, dependency graphs, dead function detection. Actions: call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions.

**Actions:**

- `call_chain`
- `common_callers`
- `common_callees`
- `hub_functions`
- `leaf_functions`
- `recursive`
- `dominator`
- `influence`
- `dependency_graph`
- `dead_functions`

### ctree

Query and traverse the Hex-Rays decompiler ctree AST for a function. Actions: get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph.

**Actions:**

- `get`
- `traverse`
- `find_calls`
- `find_vars`
- `find_strings`
- `find_conditions`
- `get_logic_flow`
- `dominance_map`
- `var_dependency_graph`

### entropy

Compute entropy over regions to detect packing, encryption, or compressed data. Actions: section, region, packed_detect, crypto_detect, compare, window, summary.

**Actions:**

- `section`
- `region`
- `packed_detect`
- `crypto_detect`
- `compare`
- `window`
- `summary`

### imports_deep

Deep import analysis: thunks, delay-loads, forwarded, ordinal, and API set resolution. Actions: thunks, delay, forwarded, ordinal, api_sets, resolve.

**Actions:**

- `thunks`
- `delay`
- `forwarded`
- `ordinal`
- `api_sets`
- `resolve`

### patterns

Generate, match, and manage FLIRT/byte pattern signatures for function identification. Actions: generate, match, list_sigs, apply_sig, create_sig, matched, yara_from_func, flirt_generate, match_yara.

**Actions:**

- `generate`
- `match`
- `list_sigs`
- `apply_sig`
- `create_sig`
- `matched`
- `yara_from_func`
- `flirt_generate`
- `match_yara`

### symbols

Loads and manages debug symbols (PDB/DWARF) for the current binary. Actions: load_pdb, load_dwarf, status, apply, export.

**Actions:**

- `load_pdb`
- `load_dwarf`
- `status`
- `apply`
- `export`

### lumina

Interface to Hex-Rays Lumina server for collaborative function metadata sharing. Actions: pull, push, status, history, search, get_metadata.

**Actions:**

- `pull`
- `push`
- `status`
- `history`
- `search`
- `get_metadata`

### export

Export IDB content in various formats for external tooling. Actions: listing, html, idc, json, sarif, binexport, headers, redact.

**Actions:**

- `listing`
- `html`
- `idc`
- `json`
- `sarif`
- `binexport`
- `headers`
- `redact`
- `vtable`

### history

Undo/redo IDB changes, create snapshots, restore, and diff states. Actions: undo, redo, list, snapshot, restore, diff.

**Actions:**

- `undo`
- `redo`
- `list`
- `snapshot`
- `restore`
- `diff`

### data_ops

Change data representation at addresses (≈ IDA Edit menu / D/A/O/U keys). cycle_data: step byte→word→dword→qword at addr (≡ pressing D in IDA). make_data: force a specific size. make_array: define an array. make_string: define a string literal (≡ A in IDA). undefine: undefine bytes (≡ U in IDA). make_code: convert to code (≡ C in IDA). set_repr: change display radix (hex/dec/bin/char/offset). make_ptr: mark as pointer. Actions: make_data, make_array, make_string, undefine, make_code, cycle_data, set_repr, make_ptr.

**Actions:**

- `make_data`
- `make_array`
- `make_string`
- `undefine`
- `make_code`
- `cycle_data`
- `set_repr`
- `make_ptr`

### firmware_view

Firmware triage: region scanning, pointer sweeps, table carving, deterministic detection logic, multi-region campaigns, and bootstrap orchestration. Actions: scan_region, auto_retype, pointer_sweep, recommend, table_candidates, smart_carve, rollback_last, review_contradictions, region_profile, pointer_clusters, carve_plan, campaign, segment_sweep, multi_region_campaign, detect_load_address, detect_vector_table, detect_mmio, rtos_scan, triage_snapshot, bootstrap.

**Actions:**

- `scan_region`
- `auto_retype`
- `pointer_sweep`
- `recommend`
- `table_candidates`
- `smart_carve`
- `rollback_last`
- `review_contradictions`
- `region_profile`
- `pointer_clusters`
- `carve_plan`
- `campaign`
- `segment_sweep`
- `multi_region_campaign`
- `detect_load_address`
- `detect_vector_table`
- `detect_mmio`
- `rtos_scan`
- `triage_snapshot`
- `bootstrap`

### hooks

Generate dynamic instrumentation hooks (Frida, Detours) for target functions. Actions: suggest, generate_frida, generate_detours, find_targets, inline_hooks.

**Actions:**

- `suggest`
- `generate_frida`
- `generate_detours`
- `find_targets`
- `inline_hooks`

### wiki

Accesses built-in documentation and tool usage guides within MCP context. Actions: list_topics, read, search, semantic_search, index, sections, suggest.

**Actions:**

- `list_topics`
- `read`
- `search`
- `semantic_search`
- `index`
- `sections`
- `suggest`

### yara_hunt

Scans the binary with YARA rules and provides match context and xref correlation. Actions: scan, compile, list_rules, match_context, extract_strings, xref_matches.

**Actions:**

- `scan`
- `compile`
- `list_rules`
- `match_context`
- `extract_strings`
- `xref_matches`

### intelligence

Intelligence subsystem: embedding-based classification, blackboard-driven indexing, and similarity search. Actions: intelligence_status, embedder_status, anchor_status, refresh_anchors, classify_text, classify_function, index_function, index_batch, index_fast, index_range, similar_functions, semantic_search, blackboard_search, export_index_summary. Supports multi-region indexing and structural pre-filtering (size, bb_count, loops, api_count, segment).

**Actions:**

- `intelligence_status`
- `embedder_status`
- `anchor_status`
- `refresh_anchors`
- `classify_text`
- `classify_function`
- `index_function`
- `index_batch`
- `index_fast`
- `index_range`
- `similar_functions`
- `semantic_search`
- `blackboard_search`
- `export_index_summary`

### threat_hunt

Runs automated threat-hunting passes to detect malware patterns, vulnerabilities, and suspicious behaviors. Actions: run, malware, vuln, tracing, findings, quick, deep, legacy.

**Actions:**

- `run`
- `malware`
- `vuln`
- `tracing`
- `findings`
- `quick`
- `deep`
- `legacy`

### workflow

Executes predefined multi-step analysis workflows for common RE tasks. audit_plan validates and scores a plan before execution. execute_plan runs a planned call list (or generated plan) through batch execution with execution metadata. prioritize reorders a dry-run plan by strategy (original/coverage/risk_first). compose merges multiple workflow plans into one deduplicated dry-run execution plan. estimate returns dry-run complexity/risk/category projections. explain returns a dry-run plan plus per-step rationale. plan previews another workflow action without executing it. catalog returns available workflows and required inputs. triage_fast auto-checks idb overview and, for firmware-like binaries, injects firmware_view(action='triage_snapshot') plus guided analysis. recon_sweep runs broader orientation + structured retrieval + protocol + security posture in one pass. Supports dry_run plan preview and include/exclude tool filtering for controlled orchestration. Actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review.

**Actions:**

- `audit_plan`
- `execute_plan`
- `prioritize`
- `compose`
- `estimate`
- `explain`
- `plan`
- `catalog`
- `triage_fast`
- `malware_deep`
- `vuln_audit`
- `recon_sweep`
- `patch_review`

### gadgets

Find ROP/JOP/COP gadgets, stack pivots, and classify exploit chains. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, classify_chain.

**Actions:**

- `rop`
- `jop`
- `cop`
- `syscall`
- `write_what_where`
- `stack_pivot`
- `shellcode_space`
- `mitigations`
- `seh_handlers`
- `pivot_chains`
- `classify_chain`

### taint

Data flow taint analysis from user-controlled sources to dangerous sinks. Actions: sources (list all taint sources: recv/read/fgets/getenv imports + blackboard IOCs), sinks (dangerous sinks reachable from a source), trace (trace forward from addr/source, write vuln entries to blackboard), paths (full call-graph paths source→sink with dataflow description), report (all sources → all reachable sinks). Example: taint(action='trace', source='recv') finds all paths from recv to memcpy/strcpy/system.

**Actions:**

- `sources`
- `sinks`
- `trace`
- `paths`
- `report`

### deobfuscate

Detect and decode obfuscation: stack strings, API hashing, dead code, anti-disasm. Actions: detect, detect_encoding, stack_strings, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt.

**Actions:**

- `detect`
- `detect_encoding`
- `stack_strings`
- `dead_code`
- `api_hashing`
- `dynamic_dispatch`
- `anti_disasm`
- `decode_attempt`

### crypto_id

Detect cryptographic algorithms, constants, and encoding routines in the binary. Actions: identify, constants, encoding, checksums, entropy_analysis, aes_ni.

**Actions:**

- `identify`
- `constants`
- `encoding`
- `checksums`
- `entropy_analysis`
- `aes_ni`

### abi

Analyzes calling conventions and ABI details of functions. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.

**Actions:**

- `detect`
- `stack_args`
- `reg_args`
- `return_type`
- `varargs`
- `struct_return`
- `tail_calls`
- `prologue`
- `epilogue`
- `abi_violations`

### summarize

Structured summaries of binary components. binary: overall binary summary. function: single function summary. segment: segment summary. imports_by_category: imports grouped by API category. strings_by_category: strings grouped by type. complexity: function complexity metrics. call_hierarchy: call tree from entry point. data_flow: data flow summary. security_posture: dangerous APIs + mitigations + risk level. statistics: binary-wide stats. report: FULL REPORT — binary + security_posture + live taint scan + blackboard findings + statistics. NOTE: the binary and function actions share names with classify.binary / classify.function but produce DIFFERENT output — summarize returns counts/structure, classify returns categories/behavior tags. Pick the one that matches the question.

**Actions:**

- `binary`
- `function`
- `segment`
- `imports_by_category`
- `strings_by_category`
- `complexity`
- `call_hierarchy`
- `data_flow`
- `security_posture`
- `statistics`
- `report`

### classify

Classify functions and binaries by purpose. function: single function — embedding-driven BehaviorClassifier (bge-code-v1). binary: overall binary type. all_functions: classify all functions — unnamed functions use BehaviorClassifier. library_code/wrappers/callbacks/initializers/error_handlers: structural classification. hot_functions: most-called functions. orphans: no-caller functions (entry points / dead code). induce_schema: structural attribute-value schema for retrieval. anchor_coverage: report per-anchor coverage over current IDB. NOTE: the binary and function actions share names with summarize.binary / summarize.function but produce DIFFERENT output — classify returns categories/behavior tags, summarize returns counts/structure. Pick the one that matches the question.

**Actions:**

- `function`
- `binary`
- `all_functions`
- `library_code`
- `wrappers`
- `callbacks`
- `initializers`
- `error_handlers`
- `hot_functions`
- `orphans`
- `induce_schema`
- `anchor_coverage`

### compare

Diff two IDB databases or functions across binaries. Actions: functions, blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog.

**Actions:**

- `functions`
- `blocks`
- `apis`
- `strings`
- `constants`
- `structure`
- `semantics`
- `batch_compare`
- `find_clones`
- `changelog`

### stack_analysis

Analyze stack frames: buffer sizes, canaries, alignment, spills, variables, and uninitialized regions. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.

**Actions:**

- `frame`
- `buffers`
- `canary`
- `alignment`
- `spills`
- `usage`
- `variables`
- `arrays`
- `uninitialized`
- `summary`

### protocol

Detect and analyze network protocol structures, parsers, endpoints, state machines, and reconstruct full protocol specs from dispatch tables. Actions: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine, reconstruct, trace_handler, export_spec.

**Actions:**

- `detect`
- `parsers`
- `serializers`
- `handlers`
- `endpoints`
- `tls_config`
- `socket_flow`
- `packet_struct`
- `magic_numbers`
- `state_machine`
- `reconstruct`
- `trace_handler`
- `export_spec`

### annotation

Automatically generates and manages comments, labels, and documentation across functions. Actions: auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate, get_context, set_structured, bulk_set, export_md, import_md, summary.

**Actions:**

- `auto_comment`
- `auto_comment_function`
- `label_loops`
- `label_branches`
- `mark_dangerous`
- `annotate_constants`
- `tag_functions`
- `document_args`
- `mark_error_paths`
- `propagate_names`
- `cleanup`
- `validate`
- `get_context`
- `set_structured`
- `bulk_set`
- `export_md`
- `import_md`
- `summary`

### string_ops

Advanced string analysis and IOC extraction. score_c2/indicators: C2 risk report — BehaviorClassifier on strings + API triads + family guess. ioc_extract: extract all IOCs (URLs, IPs, registry keys, C2 endpoints). persistence/evasion: persistence mechanisms and evasion techniques. find_urls/find_ips/find_paths/find_registry/find_emails/find_commands: pattern extraction. find_c2/find_configs/find_api_keys/find_databases/find_crypto_addrs: semantic extraction. find_stack_strings/find_base64: obfuscated string recovery. entropy_rank: rank strings by Shannon entropy. suspicious/encoding_stats/multilingual/decode_all: analysis utilities.

**Actions:**

- `score_c2`
- `indicators`
- `ioc_extract`
- `persistence`
- `evasion`
- `find_urls`
- `find_ips`
- `find_paths`
- `find_registry`
- `find_emails`
- `find_commands`
- `find_c2`
- `find_configs`
- `find_api_keys`
- `find_databases`
- `find_crypto_addrs`
- `find_stack_strings`
- `find_base64`
- `find_xrefs`
- `entropy_rank`
- `suspicious`
- `encoding_stats`
- `multilingual`
- `decode_all`

### cfg_analysis

Analyzes control flow graph structure including loops, dominators, and complexity. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.

**Actions:**

- `complexity`
- `loops`
- `branches`
- `paths`
- `dominators`
- `post_dominators`
- `back_edges`
- `natural_loops`
- `irreducible`
- `flatten_detect`

### binary_info

Retrieves binary metadata including PE/ELF headers, sections, and build info. Actions: headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay.

**Actions:**

- `headers`
- `sections`
- `relocations`
- `resources`
- `debug_info`
- `compiler`
- `linker`
- `timestamps`
- `checksums`
- `overlay`

### blackboard

Persistent RE knowledge base: findings, hypotheses, IOCs, decisions, and knowledge graph. write/read/list/search/update/delete: CRUD for findings. frontier: ranked unvisited functions — read this when choosing what to analyze next. next_target: priority queue by confidence×recency×xrefs. decision_card: record a verified claim with evidence citations (required before write-surface tools in prove phase). contradict/resolve/add_evidence/calibrate: evidence lifecycle. Actions: write, read, list, search, update, delete, clear, stats, frontier, next_target, decision_card, working_set, state_health, contradict, resolve, add_evidence, calibrate, campaign_summary, propagate_labels, start_crawler, stop_crawler, phase_set, phase_status, policy_set, policy_check.

**Actions:**

- `policy_set`
- `policy_status`
- `policy_check`
- `phase_status`
- `phase_set`
- `phase_tick`
- `quest_board`
- `quest_complete`
- `memory_compile`
- `phase_finalize`
- `trace_ingest`
- `trace_run`
- `trace_status`
- `proposal_create`
- `proposal_list`
- `proposal_accept`
- `proposal_reject`
- `decision_card`
- `working_set`
- `state_health`
- `notes_export`
- `notes_import`
- `write`
- `read`
- `list`
- `search`
- `update`
- `delete`
- `clear`
- `stats`
- `prune`
- `merge`
- `contradict`
- `resolve`
- `next_target`
- `frontier`
- `coverage`
- `propagate_labels`
- `start_crawler`
- `stop_crawler`
- `crawler_status`
- `accept`
- `reject`
- `add_evidence`
- `calibrate`
- `campaign_summary`
- `auto_tag_propagate`
- `accept_proposal`
- `reject_proposal`
- `add_system`
- `add_struct`
- `add_gap`
- `fill_gap`
- `add_state_machine`
- `add_peripheral`
- `add_attack_surface`
- `kg_summary`
- `kg_systems`
- `kg_gaps`
- `kg_structs`
- `kg_state_machines`
- `kg_attack_surface`
- `kg_peripherals`
- `export_symbols`
- `import_symbols`
- `semantic_index`
- `semantic_rebuild`
- `related_by_behavior`
- `deref`
- `chain`


### governance

Pre-flight validation for edits: detect contradictions, PII, dangerous patches. Actions: check, redact, list_rules, stats.

**Actions:**

- `check`
- `redact`
- `list_rules`
- `stats`

### knowledge

Cross-session firmware knowledge base: chip family identification, persistent symbol memory, and symbol transfer across binaries. Actions: chip_identify, symbol_lookup, import_symbols, export_session, chip_families.

**Actions:**

- `chip_identify`
- `symbol_lookup`
- `import_symbols`
- `export_session`
- `chip_families`

### packer

Detect packers / protectors (UPX, MPRESS, VMProtect, Themida, ASPack, custom) and game anti-cheat references in the current IDB. Returns indicators, classification, recommendation, and a structured workflow with concrete tool calls (static_steps) and external user actions (external_steps). Actions: detect, profile, guide, status, script. script runs Python in the packer's namespace for custom heuristics.

**Actions:**

- `detect`
- `profile`
- `guide`
- `status`
- `script`

### struct_recover

Automatic struct/type recovery from field access patterns — walks instructions for [base+offset] accesses, clusters by register, infers field types, generates C structs. Actions: recover, recover_all, propagate, preview, apply.

**Actions:**

- `recover`
- `recover_all`
- `propagate`
- `preview`
- `apply`

### emulate

Unicorn-backed emulation sandbox — execute functions/slices from the IDB without a debugger (x86/x64, ARM/AArch64, MIPS). Maps IDB segments, sets up stack and calling convention. Actions: run, slice, call, decrypt, trace. NOTE: requires `pip install unicorn`.

**Actions:**

- `run`
- `slice`
- `call`
- `decrypt`
- `trace`

### bindiff

Cross-version binary diffing via serialized snapshots — fingerprint all functions, compare against a saved baseline, find patches and security-relevant changes. Unlike compare (same-IDB), bindiff works across IDB versions. Actions: snapshot, diff, patch_analysis, function_match, summary.

**Actions:**

- `snapshot`
- `diff`
- `patch_analysis`
- `function_match`
- `summary`

### multi_session

Multi-binary session groups — link IDA sessions for cross-binary import/export resolution, cross-session decompilation, and cross-binary xref queries. Actions: group_create, group_list, group_link, group_remove, cross_resolve, cross_decompile, cross_xrefs, status.

**Actions:**

- `group_create`
- `group_list`
- `group_link`
- `group_remove`
- `cross_resolve`
- `cross_decompile`
- `cross_xrefs`
- `status`

### fixups

Manage relocations/fixups (relocation table entries) in the IDB. Actions: list, get, add, delete.

**Actions:**

- `list`
- `get`
- `add`
- `delete`

## Advertised vs Hidden

**Advertised** (64): Tools exposed to LLM clients.

`session`, `truncation`, `bookmarks`, `batch`, `wiki`, `analysis`, `idb`, `code`, `data`, `search`, `imports_deep`, `symbols`, `patterns`, `types`, `memory`, `modify`, `funcs`, `segments`, `bulk`, `misc`, `calc`, `nav`, `project`, `debug`, `graph`, `ctree`, `export`, `history`, `annotation`, `binary_info`, `threat_hunt`, `workflow`, `compare`, `firmware_view`, `blackboard`, `knowledge`, `abi`, `cfg_analysis`, `classify`, `coverage`, `crypto_id`, `intelligence`, `data_ops`, `deobfuscate`, `entropy`, `gadgets`, `governance`, `hooks`, `lumina`, `microcode`, `protocol`, `stack_analysis`, `string_ops`, `summarize`, `taint`, `trace_analysis`, `yara_hunt`, `packer`, `struct_recover`, `emulate`, `bindiff`, `multi_session`, `fixups`

**Hidden** (2): Internal tools, not in ADVERTISED_TOOLS.

`background`, `xref_analysis`
