# MCP Tools Reference

Current canonical tool surface: **68 tools** (registered in `src/ida_pro_mcp/host/schemas.py` `TOOLS`).

Generated from `schemas.py` (`TOOLS`, `TOOL_ACTIONS`, `TOOL_DESCRIPTIONS`, `build_input_schema`).

## Notes

- `session(action="create")` requires `binary_path` and does not accept `idb_path`/`use_existing`.
- `threat_hunt` is the consolidated malware/vulnerability/tracing orchestration tool and supports legacy inheritance routing for archived threat-family tools (for example `vuln_scan`). The canonical surface remains `threat_hunt`, `string_ops`, and `taint`.
- Host normalization is intentionally permissive for noisy LLM calls on `threat_hunt`, `search`, `session`, and `code` (wrapped action names, noisy arg keys, bracketed address/list values) when mapping is unambiguous.
- All tool responses containing hex addresses include `llm_address_calculation` containing pre-computed decimal values, alignment states, and offsets relative to the active session's image base address (RVA) to support automated reasoning and prevent manual arithmetic errors.

## Aliases

| Alias | Canonical |
|---|---|
| `plugins` | `misc` |
| `xfer_analysis` | `xref_analysis` |
| `comments_ai` | `annotation` |
| `emulate` | `static_trace` |
| `edit` | *(delegated to `modify`, `funcs`, `bulk`)* |

Tools not in `TOOLS` but still reachable through compatibility routing: `vuln_scan`, `diff`, `structs`.

---

## 1. Core Infrastructure

### session
Session lifecycle + analysis context hub with runtime tracking. Provides analysis notebook, hypothesis tracking, global skill registry (VOERA MemRL-inspired), dead-end detection, and federated session linking. IDB is optional: after create/switch, tools use active session.

**Actions:** discover, create, get, list, switch, close, status, rebuild, update, rename, duplicate, export_session, import_session, archive, unarchive, tag, untag, find_by_tag, add_note, clear_notes, cleanup_stale, stats, validate, bulk_delete, bulk_tag, search_notes, recent, oldest, snapshot, restore_snapshot, merge, macro_set, macro_get, macro_list, macro_delete, macro_run, recent_workset, crystallize_skill, rate_skill, list_skills, suggest_strategy, log_activity, get_activity_log, notebook_append, notebook_read, notebook_section, track_hypothesis, confirm_hypothesis, refute_hypothesis, list_hypotheses, dashboard, get_phase, advance_phase, link_session, cross_reference_sessions, list_snapshots

### truncation
Continuation helper for auto-truncated responses. Retrieves next chunk by token/field.

**Actions:** continue

### bookmarks
Enhanced session-correlated bookmarking with regex/glob/substring filtering on name, notes, tags, addr, and category.

**Actions:** add, list, delete, update, clear, find, export

### batch
Run multiple tool calls in a single request. Supports shorthand calls like `tool:action` and inline `{name, action, ...args}` objects. Returns compact per-call rows + summary.

**Actions:** run

### filter
Context Guillotine: deterministic JQ-like filtering for tool outputs. Supports path extraction, array slicing, conditional filtering, sorting, plucking, grouping, and pipe operators. Runs entirely on the MCP server to prevent context window overflow.

**Actions:** filter

### blackboard
Persistent stateful context store for analysis hypotheses and findings, now with semantic indexing/retrieval lifecycle and behavior-centric recall (`semantic_index`, `semantic_rebuild`, `related_by_behavior`).

**Actions:** policy_set, policy_status, policy_check, phase_status, phase_set, phase_tick, quest_board, quest_complete, memory_compile, phase_finalize, trace_ingest, trace_run, trace_status, proposal_create, proposal_list, proposal_accept, proposal_reject, decision_card, working_set, state_health, notes_export, notes_import, write, read, list, search, semantic_index, semantic_rebuild, related_by_behavior, update, delete, clear, stats, prune, merge, contradict, resolve, next_target, frontier, coverage, propagate_labels, start_crawler, stop_crawler, crawler_status, accept, reject, add_evidence, calibrate, campaign_summary, auto_tag_propagate, accept_proposal, reject_proposal, add_system, add_struct, add_gap, fill_gap, add_state_machine, add_peripheral, add_attack_surface, kg_summary, kg_systems, kg_gaps, kg_structs, kg_state_machines, kg_attack_surface, kg_peripherals, export_symbols, import_symbols

### governance
Deterministic governance layer for all IDB write operations. Blocks dangerous patches, redacts PII, warns on misleading renames. Zero ML, zero external dependencies.

**Actions:** check, redact, list_rules, stats

---

## 2. Analysis Configuration

### analysis
Analysis configuration and reanalysis.

**Actions:** get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze

---

## 3. Unified Query Hub

### query
Unified read-only query hub that delegates to sub-tools. Single entry point for data, search, idb, code, types, imports_deep, symbols, and patterns queries.

**Actions:** data, search, idb, code, types, imports_deep, symbols, patterns

---

## 4. Primary Data Access

### idb
Database metadata and segment information.

**Actions:** meta, summary, segments, entrypoints, bookmarks, overview

### code
Code logic, decompilation, and flow analysis. Supports semantic decompilation, decompilation dataflow, callgraph, path finding, and inter-function diffing.

**Actions:** decompile, semantic_decompile, decomp_dataflow, disasm, xrefs_to, xrefs_from, xrefs_to_field, callees, callers, blocks, analyze, callgraph, export, find_paths, strings_in_func, decompile_chain, diff_functions

### data
Function listing, global variables, strings, imports, and exports. Query patterns auto-detect regex (e.g. `^init`, `\w+alloc`), glob (`*alloc*`), or plain substring.

**Actions:** functions, globals, strings, imports, exports, lookup, bulk_query

### search
Pattern and reference search. Supports semantic matching, case sensitivity, and context inclusion. Pattern auto-detects regex, glob, or plain substring.

**Actions:** bytes, string, immediate, name, insns, mnemonic, instruction, text, operand, comment, data_ref, code_ref, regex, func_by_sig, find, semantic, smart_bundle, callers, callees, api, vulnerable, constants, decompiled, structured, type, export, summary, query_lang, nl, behavior

### types
Type Library (TIL) and prototype management.

**Actions:** list, get, set_prototype, parse_decl, declare, apply, search_structs, infer, read_struct, import_header

### memory
Direct database memory access with typed reads.

**Actions:** read, write, hexdump

---

## 5. Modification Tools

### modify
Rename, comment (regular/repeatable/anterior/posterior), set types, and patch assembly. `patch_asm` assembles instruction(s) and patches bytes, supports multi-line separated by semicolons.

**Actions:** rename, comment, set_type, patch_asm

### funcs
Function boundary management. Auto-converts bytes to code, supports end address, flags, and force deletion of overlaps. List supports regex/glob/substring query filtering.

**Actions:** create, delete, set_flags, set_name, rename, add_comment, list, info

### segments
Segment management.

**Actions:** list, add, delete, set_attr, set_perms, move, info

### bulk
Bulk rename/comment/type operations. Supports `continue_on_error` for resilient batch processing.

**Actions:** rename, comment, apply_type, rename_stack, import_annotations, export_annotations

### annotation
Intelligent bulk annotation (writes to DB, supports dry_run). Includes neuro-symbolic validation for contradiction and PII detection.

**Actions:** auto_comment, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, get_context, set_structured, bulk_set, export_md, import_md, summary

---

## 6. Utilities

### misc
Utilities including full IDAPython access, host filesystem I/O, IDA plugin management, and diagnostics. Alias: `plugins`.

**Actions:** python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health

### calc
Mathematical and address resolution with dereference chains and alignment.

**Actions:** eval, offset, convert, resolve, deref, chain, align, bitops

### nav
Navigation and triage. Jump to addresses, query cursor position, and discover interesting locations.

**Actions:** goto, cursor, interesting

---

## 7. Debugging and Tracing

### debug
Debugger control and dynamic analysis. Full process control, breakpoint management, register/memory inspection, and callstack navigation.

**Actions:** start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem

### trace
Execution tracing.

**Actions:** get, clear, set_options

### coverage
Code coverage import and analysis. Supports DrCov and Lighthouse formats.

**Actions:** import_drcov, import_lighthouse, highlight, report, uncovered, filter

### trace_analysis
Execution trace processing for coverage analysis, loop detection, API extraction, timeline graphing, cross-run diffing, and anti-analysis detection.

**Actions:** import_trace, analyze_coverage, find_loops, extract_api_calls, basic_blocks_hit, execution_timeline_graph, cross_run_diff, coverage_debug_plan, anti_analysis_detect, trace_entropy, api_sequence, loop_analysis

---

## 8. Project and File Management

### project
Project I/O and file operations. Includes advanced features: evidence_graph, knowledge_merge, confidence_model, replay_pipeline, hypothesis_tracker, temporal_reasoning, semantic_artifact_diff, ai_governance, knowledge_debt, and casefile_export.

**Actions:** save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, evidence_graph, knowledge_merge, confidence_model, replay_pipeline, hypothesis_tracker, temporal_reasoning, semantic_artifact_diff, ai_governance, knowledge_debt, casefile_export

---

## 9. Advanced Analysis

### agent
High-level analysis orchestrator with bridge-conditioned multi-hop search (`bridge_query`) and reasoning bank distillation (`reflect`). Provides context packing, rename suggestions, and similarity analysis.

**Actions:** analyze_function, explore_address, find_references, search_all, search_structs, context_pack, quick, rename_suggestions, batch_context, similar, bridge_query, reflect, cluster, fingerprint, cfg_encode, cfg_similar, cfg_stats

### intelligence
Intelligence subsystem: embedding-based function classification, indexing, similarity search, and evidence-card production. Extracted from `agent` in the dedup pass.

**Actions:** intelligence_status, embedder_status, anchor_status, refresh_anchors, classify_text, classify_function, index_function, index_batch, similar_functions, semantic_search, blackboard_search, export_index_summary, evidence_card

### microcode
Hex-Rays Microcode (IR) access with def-use graph support.

**Actions:** get, blocks, instructions, def_use_graph

### graph
Topological visualization (CFG, callgraph, xref graph).

**Actions:** callgraph, cfg, xref_graph

### ctree
Hex-Rays AST (CTree) analysis with dominance maps and variable dependency graphs.

**Actions:** get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph

### static_trace
Static control flow tracing. Supports appcall-style invocation, string decryption, and expression evaluation. Legacy alias: `emulate`.

**Actions:** static_trace, decrypt_strings, eval_expr

### entropy
Entropy and packing/crypto detection across sections and regions.

**Actions:** section, region, packed_detect, crypto_detect, compare, window, summary

---

## 10. Structure and Type Recovery

### imports_deep
Advanced import resolution supporting thunks, delay-load, forwarded APIs, ordinal imports, and API sets.

**Actions:** thunks, delay, forwarded, ordinal, api_sets, resolve

### patterns
Signature generation, matching, and FLIRT/IDA signature management.

**Actions:** generate, match, list_sigs, apply_sig, create_sig, matched

### symbols
PDB and DWARF symbol management.

**Actions:** load_pdb, load_dwarf, status, apply, export

---

## 11. Differential and Comparison

### lumina
Lumina server interaction for function metadata sharing.

**Actions:** pull, push, status, history, search, get_metadata

### compare
Function comparison and similarity analysis including side-by-side diff, semantic comparison, batch comparison, clone detection, and changelog generation.

**Actions:** functions, blocks, apis, strings, constants, structure, semantics, batch_compare, find_clones, changelog

### mbagcn
MbaGCN graph encoding for function CFG similarity. Encodes CFGs to embeddings and queries nearest neighbors.

**Actions:** encode, similar, stats

---

## 12. Export and History

### export
Database export in multiple formats.

**Actions:** listing, html, idc, json, binexport, headers

### history
Undo/redo and database snapshots with diff support.

**Actions:** undo, redo, list, snapshot, restore, diff

### colorize
Visual highlighting for functions, ranges, instructions, and patterns.

**Actions:** set_func, set_range, set_insn, get, clear, palette, highlight_pattern

### data_ops
Data type conversion (make data/array/string/code, undefine).

**Actions:** make_data, make_array, make_string, undefine, make_code

---

## 13. Instrumentation

### hooks
Hook suggestion and Frida/Detours script generation.

**Actions:** suggest, generate_frida, generate_detours, find_targets, inline_hooks

---

## 14. Documentation and YARA

### wiki
Built-in documentation system with ranked and semantic search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs.

**Actions:** list_topics, read, search, semantic_search, sections, index

### yara_hunt
YARA scanning with context and cross-reference attribution.

**Actions:** scan, compile, list_rules, match_context, extract_strings, xref_matches

---

## 15. Security & Vulnerability Analysis

### threat_hunt
Consolidated malware/vulnerability/tracing orchestration hub. Executes end-to-end pipelines across existing tools and can route legacy actions from archived tools (`vuln_scan`, etc.). Returns step-by-step status with deduplicated findings.

**Actions:** run, malware, vuln, tracing, findings, quick, deep, legacy

### predictor
Deterministic/local-ML predictive assistant for workflow guidance. Uses activity sequence modeling and local Q-value strategy ranking (MemRL-inspired). Detects stalls, suggests next addresses, and explains decisions.

**Actions:** suggest_next_tool, detect_stuck, suggest_focus, suggest_next_address, risk_of_stall, recommend_bundle, explain_decision

### workflow
Deterministic workflow façade that expands a single call into a validated multi-step batch plan. Reduces LLM prompt complexity by hiding orchestration details behind a single canonical entry point.

**Actions:** catalog, plan, explain, estimate, compose, prioritize, audit_plan, execute_plan, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review

### gadgets
ROP/JOP/COP gadget discovery for x86/x64 and ARM/AArch64. Includes semantic gadget finding.

**Actions:** rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains, semantic_find

### deobfuscate
Deobfuscation analysis including encoding detection, XOR scanning, stack strings, opaque predicates, control-flow flattening detection, API hashing, dynamic dispatch, and anti-disassembly.

**Actions:** detect_encoding, xor_scan, stack_strings, opaque_predicates, control_flow_flatten, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt

### crypto_id
Crypto algorithm identification via known constants (AES S-box, SHA-256, CRC32, etc.) and key schedule detection.

**Actions:** identify, constants, key_schedule, block_cipher, hash_detect, rng_detect, asymmetric, custom_crypto, encoding, checksums

---

## 16. ABI & Calling Conventions

### abi
ABI and calling convention analysis including detection, stack/register arg analysis, return types, varargs, struct return, tail calls, prologue/epilogue patterns, and ABI violation detection.

**Actions:** detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations

---

## 17. Summarization & Classification

### summarize
LLM-friendly summarization with compact output. Covers binary-level, function-level, segment-level, imports/strings by category, complexity, call hierarchy, data flow, security posture, and statistics.

**Actions:** binary, function, segment, imports_by_category, strings_by_category, complexity, call_hierarchy, data_flow, security_posture, statistics

### classify
Function purpose classification. Supports individual function, binary-wide, library code detection, wrapper/callback/initializer identification, error handlers, hot functions, and orphan detection.

**Actions:** function, binary, all_functions, library_code, wrappers, callbacks, initializers, error_handlers, hot_functions, orphans, induce_schema

---

## 18. Stack Analysis

### stack_analysis
Stack frame analysis including frame layout, buffer detection, canary presence, alignment, spills, variable usage, arrays, uninitialized variables, and summary.

**Actions:** frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary

---

## 19. Protocol Analysis

### protocol
Network protocol analysis. Discovers protocol parsers, serializers, handlers, endpoints, TLS config, socket flow, packet structures, magic numbers, and state machines.

**Actions:** detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine

---

## 20. Deep Cross-Reference Analysis

### xref_analysis
Deep cross-reference analysis including call chains, common callers/callees, hub/leaf function identification, recursion detection, dominator/influence analysis, dependency graphs, and dead function detection. Alias: `xfer_analysis`.

**Actions:** call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions

---

## 21. String Operations

### string_ops
Advanced string analysis, C2 scoring, and IOC extraction. Includes ML-based C2 risk assessment, entropy ranking, and comprehensive IOC extraction (URLs, paths, registry, IPs, emails, commands, API keys, configs, databases, crypto addresses).

**Actions:** decode_all, find_urls, find_paths, find_registry, find_ips, find_emails, find_commands, encoding_stats, multilingual, suspicious, find_xrefs, find_stack_strings, find_base64, find_api_keys, find_configs, find_c2, find_databases, find_crypto_addrs, entropy_rank, score_c2, indicators, persistence, evasion, ioc_extract

---

## 22. CFG Analysis

### cfg_analysis
Control flow graph metrics including cyclomatic complexity, loop/branch analysis, path enumeration, dominator/post-dominator trees, back edges, natural loops, irreducibility detection, and flattening detection.

**Actions:** complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect

---

## 23. Binary Info

### binary_info
Binary metadata analysis covering headers, sections, relocations, resources, debug info, compiler/linker identification, timestamps, checksums, and overlay.

**Actions:** headers, sections, relocations, resources, debug_info, compiler, linker, timestamps, checksums, overlay

---

## 24. LLM Helpers

### llm_helpers
LLM workflow helpers plus 50+ advanced external-expansion actions for planning, search orchestration, fusion intelligence, IDAPython orchestration, and analyst workflow systems. Includes context density optimization (`compact` action), intent-to-tool compilation, adaptive query planning, semantic chunking, behavioral signature search, cross-artifact correlation, temporal search replay, hypothesis sandboxing, function role classification, protocol reconstruction, influence mapping, API contract extraction, semantic diff explanation, dangerous pattern explanation, binary capability matrix building, execution hypothesis generation, patch impact forecasting, safe IDAPython orchestration with provenance recording, script automation, investigation playbooks, next-best-action recommendations, dead-end detection, contradiction tracking, AI edit review queues, case narrative composition, cost/latency optimization, trust verification, and learning feedback loops.

**Actions:** bootstrap, context_window, function_digest, binary_digest, explain_address, suggest_next, progress_report, focus_area, question_answer, guided_analysis, cheatsheet, compact, enrich, intent_tool_compiler, adaptive_query_planner, token_aware_context_optimizer, cross_call_variable_resolver, evidence_weighted_response_assembler, uncertainty_propagation_engine, multi_granularity_retrieval_layer, semantic_chunking_for_decompiled_code, question_type_router, interactive_clarification_protocol, behavioral_signature_search, cross_artifact_correlation_search, temporal_search_replay, search_hypothesis_sandbox, path_constrained_search, argument_semantics_search, decompile_disasm_consistency_search, near_miss_search_ranking, persistent_search_collections, auto_expansion_search_chains, function_role_classifier, protocol_format_reconstruction_assistant, global_state_influence_mapper, api_contract_extractor, interprocedural_data_lineage_graph, semantic_diff_explainer, dangerous_pattern_explainer, binary_capability_matrix_builder, execution_hypothesis_generator, patch_impact_forecaster, safe_idapython_orchestration_runtime, script_template_marketplace_layer, auto_script_synthesis_from_intent, script_output_schema_enforcer, long_running_job_manager, cross_session_script_memory, privilege_scope_guardrails_for_scripts, script_to_tool_promotion_pipeline, experiment_harness_for_script_variants, idapython_provenance_recorder, investigation_playbook_engine, next_best_action_recommender, analysis_dead_end_detector, workset_intelligence_capsules, contradiction_tracker, review_queue_for_ai_edits, case_narrative_composer, cost_latency_optimizer, trust_verification_layer, learning_feedback_loop

---

## 25. VOERA Tools

### schemaboot
Deterministic function attribute extraction and structured search (VOERA Structured Semantic Indexing). Ingests all functions into a SQLite index with instruction mix, API calls, string refs, structural metrics, and entropy. Enables instant SQL-style queries without iterating functions.

**Actions:** ingest, query, refresh, stats, delete, get

### turboquant
3-bit extreme embedding compression with PolarQuant + QJL (VOERA embedding compression). Ingests function vectors from SchemaBoot and compresses them to 3 bits per dimension (~8x memory reduction). Supports similarity search on compressed embeddings.

**Actions:** ingest, query, stats, delete

### bridge_search
Bridge-conditioned Multi-Hop Search (VOERA retrieval). Finds structurally related functions through shared bridge entities (APIs, strings, xrefs) using SchemaBoot as the bridge source. Implements tripartite scoring s(query, bridge, candidate).

**Actions:** search, bridges

### memrl
Non-parametric reinforcement learning on episodic memory (VOERA Memory-Reinforced Learning). Stores Intent-Experience-Utility triplets with learned Q-values. Two-phase retrieval: similarity recall followed by Q-value re-ranking. Updates via TD rule: Q_new = Q_old + alpha * (reward - Q_old).

**Actions:** record, update, rank, stats, top, get_q, suggest, feedback, ingest, list_suggestions, get_suggestion
