#!/usr/bin/env python3
"""
Smoke-test EVERY ACTION of EVERY ida-pro-mcp tool against real IDA Pro, over
the real MCP JSON-RPC stdio protocol.

Companion to smoke_mcp_all_tools.py (which tests one curated action per tool).
This one enumerates the `action` enum from each tool's inputSchema and drives
every action, so a silent crash in any handler branch (like the funcs.info /
packer.detect / data_ops.make_string bugs) is surfaced.

Classification is the same as the per-tool smoke:

  OK       -> {ok: true}                      (plumbing works, real data)
  CLEAN    -> {error: true, code != UNKNOWN}  (plumbing works, structured err)
  CRASH    -> {error: true, code == UNKNOWN_ERROR} (the bug class we hunt)
  TIMEOUT  -> no response within the per-call budget
  OTHER    -> unexpected payload shape

A CLEAN error (INVALID_ARGS / SESSION_REQUIRED / NOT_FOUND / GOVERNANCE_BLOCKED
...) counts as PASS for plumbing: the call reached the handler and came back as
a structured error, not a crash/traceback. Only CRASH/TIMEOUT/OTHER are failures.

Destructive / run-corrupting actions (session.close, history.undo, modify.patch_asm,
data_ops.undefine, ...) are skipped so they don't wreck the shared session for
the rest of the sweep.

Usage:
  python scripts/smoke_mcp_all_actions.py
  python scripts/smoke_mcp_all_actions.py --binary /path/to/foo.exe
  python scripts/smoke_mcp_all_actions.py --timeout 150
  python scripts/smoke_mcp_all_actions.py --only funcs,code,data_ops
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

# Reuse the per-tool smoke harness (MCP client, classifier, env, constants).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import smoke_mcp_all_tools as S  # noqa: E402

# ---- per-(tool, action) curated args for actions that need specific inputs ----
# Keys here are kwargs ONLY (the "action" key is added by the driver). Anything
# not listed falls through to the generic schema-driven fallback. Placeholders
# __ADDR__ / __ADDR2__ / __IDB__ are substituted at runtime.
ACTION_ARGS: dict[tuple[str, str], dict] = {
    # abi
    ("abi", "detect"):            {"addr": "__ADDR__"},
    # agent
    ("agent", "search_all"):       {"query": "zzzznomatchxyz", "max_items": 1},
    ("agent", "search_structs"):  {"query": "zzzznomatchxyz"},
    ("agent", "find_references"): {"addr": "__ADDR__"},
    ("agent", "explore_address"): {"addr": "__ADDR__"},
    ("agent", "analyze_function"): {"addr": "__ADDR__"},
    ("agent", "context_pack"):    {"addr": "__ADDR__"},
    ("agent", "quick"):           {"addr": "__ADDR__"},
    ("agent", "rename_suggestions"): {"addr": "__ADDR__"},
    ("agent", "similar"):         {"addr": "__ADDR__"},
    ("agent", "fingerprint"):     {"addr": "__ADDR__"},
    ("agent", "cfg_encode"):      {"addr": "__ADDR__"},
    ("agent", "cfg_similar"):     {"addr": "__ADDR__"},
    ("agent", "cfg_stats"):       {"addr": "__ADDR__"},
    # batch
    ("batch", "__none__"):        {"calls": []},
    # blackboard - read-only
    ("blackboard", "list"):       {"limit": 3},
    ("blackboard", "search"):     {"query": "zzz", "limit": 3},
    ("blackboard", "read"):       {"entry_id": "deadbeef"},
    ("blackboard", "frontier"):   {"limit": 3},
    ("blackboard", "coverage"):  {},
    ("blackboard", "stats"):      {},
    # bridge_search
    ("bridge_search", "search"):  {"query": "main", "top_k": 3},
    ("bridge_search", "bridges"): {"func_name": "main", "bridge_types": ["apis"], "top_k": 3},
    # calc
    ("calc", "eval"):            {"expr": "0x140001000 + 0x10"},
    ("calc", "offset"):          {"addr": "__ADDR__", "target": "__ADDR2__"},
    ("calc", "convert"):         {"addr": "__ADDR__"},
    ("calc", "resolve"):         {"addr": "__ADDR__"},
    ("calc", "deref"):           {"addr": "__ADDR__"},
    ("calc", "align"):           {"addr": "__ADDR__", "value": 16},
    # code
    ("code", "smart_decompile"): {"addr": "__ADDR__"},
    ("code", "decompile"):       {"addr": "__ADDR__"},
    ("code", "disasm"):          {"addr": "__ADDR__"},
    ("code", "decompile_chain"): {"addr": "__ADDR__"},
    ("code", "semantic_decompile"): {"addr": "__ADDR__"},
    ("code", "xrefs_to"):        {"addr": "__ADDR__"},
    ("code", "xrefs_from"):      {"addr": "__ADDR__"},
    ("code", "callees"):         {"addr": "__ADDR__"},
    ("code", "callers"):         {"addr": "__ADDR__"},
    ("code", "blocks"):          {"addr": "__ADDR__"},
    ("code", "callgraph"):       {"addr": "__ADDR__"},
    ("code", "find_paths"):      {"addr": "__ADDR__"},
    ("code", "strings_in_func"): {"addr": "__ADDR__"},
    ("code", "decomp_dataflow"): {"addr": "__ADDR__"},
    # compare
    ("compare", "find_clones"):  {"idb": "__IDB__"},
    ("compare", "batch_compare"): {"idb": "__IDB__"},
    ("compare", "functions"):   {"idb": "__IDB__"},
    ("compare", "strings"):     {"idb": "__IDB__"},
    ("compare", "changelog"):    {"idb": "__IDB__"},
    # ctree
    ("ctree", "get"):            {"addr": "__ADDR__"},
    ("ctree", "traverse"):        {"addr": "__ADDR__"},
    ("ctree", "find_calls"):     {"addr": "__ADDR__"},
    ("ctree", "find_vars"):      {"addr": "__ADDR__"},
    ("ctree", "find_strings"):   {"addr": "__ADDR__"},
    ("ctree", "find_conditions"): {"addr": "__ADDR__"},
    ("ctree", "get_logic_flow"): {"addr": "__ADDR__"},
    ("ctree", "dominance_map"):  {"addr": "__ADDR__"},
    ("ctree", "var_dependency_graph"): {"addr": "__ADDR__"},
    # data
    ("data", "functions"):       {"count": 2},
    ("data", "strings"):         {"count": 2},
    ("data", "imports"):         {},
    ("data", "exports"):         {},
    ("data", "globals"):         {"count": 2},
    ("data", "lookup"):          {"query": "main"},
    ("data", "bulk_query"):      {"queries": []},
    ("data", "capability_matrix"): {},
    ("data", "string_xrefs"):    {},
    # data_ops - mutating; run on a scratch data address to avoid corrupting
    # the function we decompile elsewhere. Use addr2 (second function) as scratch.
    ("data_ops", "make_string"): {"addr": "__ADDR2__", "size": 4},
    ("data_ops", "make_array"):  {"addr": "__ADDR2__", "count": 2, "size": 4},
    ("data_ops", "make_data"):   {"addr": "__ADDR2__", "size": 4},
    ("data_ops", "make_ptr"):    {"addr": "__ADDR2__"},
    ("data_ops", "make_code"):   {"addr": "__ADDR2__"},
    ("data_ops", "set_repr"):     {"addr": "__ADDR2__", "repr": "hex", "size": 4},
    ("data_ops", "cycle_data"):  {"addr": "__ADDR2__", "size": 4},
    # funcs
    ("funcs", "info"):           {"addr": "__ADDR__", "include_xrefs": True, "include_prototype": True, "include_stack": True},
    ("funcs", "metrics"):       {"addr": "__ADDR__"},
    ("funcs", "suggest_names"):  {"addr": "__ADDR__"},
    ("funcs", "find_similar"):   {"addr": "__ADDR__"},
    # graph
    ("graph", "callgraph"):      {"addr": "__ADDR__"},
    ("graph", "cfg"):            {"addr": "__ADDR__"},
    ("graph", "call_chain"):     {"src": "__ADDR__", "dst": "__ADDR2__"},
    ("graph", "common_callers"): {"addr": "__ADDR__", "addr2": "__ADDR2__"},
    ("graph", "common_callees"): {"addr": "__ADDR__", "addr2": "__ADDR2__"},
    ("graph", "dominator"):      {"addr": "__ADDR__"},
    ("graph", "influence"):       {"addr": "__ADDR__"},
    ("graph", "dependency_graph"): {"addr": "__ADDR__"},
    ("graph", "recursive"):       {"addr": "__ADDR__"},
    ("graph", "xref_graph"):      {"addr": "__ADDR__"},
    ("graph", "dead_functions"):  {},
    ("graph", "hub_functions"):    {},
    ("graph", "leaf_functions"):  {},
    # hooks
    ("hooks", "suggest"):         {"addr": "__ADDR__"},
    ("hooks", "generate_frida"):   {"addr": "__ADDR__"},
    ("hooks", "generate_detours"): {"addr": "__ADDR__"},
    ("hooks", "find_targets"):     {},
    ("hooks", "inline_hooks"):     {"addr": "__ADDR__"},
    # memory
    ("memory", "read"):          {"addr": "__ADDR__", "size": 16},
    ("memory", "hexdump"):        {"addr": "__ADDR__", "size": 16},
    ("memory", "strings"):       {"addr": "__ADDR__", "size": 64},
    ("memory", "search"):        {"pattern": "deadbeef", "addr": "__ADDR__", "size": 64},
    ("memory", "pointers"):      {"addr": "__ADDR__", "size": 64},
    ("memory", "find_pointers"):  {"addr": "__ADDR__"},
    ("memory", "entropy"):        {"addr": "__ADDR__", "size": 64},
    ("memory", "histogram"):      {"addr": "__ADDR__", "size": 64},
    ("memory", "struct_walk"):    {"addr": "__ADDR__"},
    # microcode
    ("microcode", "get"):          {"addr": "__ADDR__"},
    ("microcode", "blocks"):       {"addr": "__ADDR__"},
    ("microcode", "instructions"): {"addr": "__ADDR__"},
    ("microcode", "def_use_graph"): {"addr": "__ADDR__"},
    # modify - benign mutations on the scratch addr
    ("modify", "comment"):        {"addr": "__ADDR2__", "comment": "smoke"},
    ("modify", "rename"):         {"addr": "__ADDR2__", "name": "smoke_renamed"},
    ("modify", "set_type"):       {"addr": "__ADDR2__", "type": "int"},
    # search
    ("search", "find"):           {"query": "main", "limit": 3},
    ("search", "nl"):             {"query": "entry point"},
    ("search", "semantic"):       {"query": "entry point"},
    ("search", "smart_bundle"):   {"query": "main"},
    ("search", "api"):            {"pattern": "Write"},
    ("search", "decompiled"):     {"query": "main", "limit": 3},
    ("search", "name"):           {"pattern": "main"},
    ("search", "string"):         {"pattern": "main"},
    ("search", "bytes"):          {"pattern": "deadbeef"},
    ("search", "immediate"):     {"pattern": "0x10"},
    ("search", "callers"):        {"addr": "__ADDR__"},
    ("search", "callees"):        {"addr": "__ADDR__"},
    ("search", "constants"):      {},
    ("search", "path"):           {"src": "main", "dst": "exit"},
    ("search", "reach"):          {"src": "__ADDR__", "max_depth": 2},
    ("search", "noreach"):        {"depth": 2},
    ("search", "neighborhood"):   {"addr": "__ADDR__"},
    ("search", "outlier"):        {"metric": "size", "top": 5},
    ("search", "fingerprint"):    {"addr": "__ADDR__"},
    ("search", "behavior"):       {"query": "crypto"},
    ("search", "bool"):           {"query": "(api:Write*)"},
    ("search", "hunt"):           {"recipe": "list"},
    ("search", "vulnerable"):     {},
    ("search", "regex"):          {"pattern": "^main$"},
    ("search", "func_by_sig"):    {"query": "void main()"},
    ("search", "summary"):        {"addr": "__ADDR__"},
    ("search", "query_lang"):     {"query": "api:Write*"},
    ("search", "text"):           {"pattern": "main"},
    ("search", "operand"):        {"pattern": "main"},
    ("search", "comment"):        {"pattern": "main"},
    ("search", "data_ref"):       {"addr": "__ADDR__"},
    ("search", "code_ref"):       {"addr": "__ADDR__"},
    ("search", "mnemonic"):       {"pattern": "mov"},
    ("search", "instruction"):    {"pattern": "mov"},
    ("search", "insns"):           {"pattern": "mov"},
    ("search", "export"):         {},
    ("search", "structured"):     {"query": "main"},
    # stack_analysis
    ("stack_analysis", "frame"):   {"addr": "__ADDR__"},
    ("stack_analysis", "buffers"): {"addr": "__ADDR__"},
    ("stack_analysis", "canary"):  {"addr": "__ADDR__"},
    ("stack_analysis", "alignment"): {"addr": "__ADDR__"},
    ("stack_analysis", "spills"):  {"addr": "__ADDR__"},
    ("stack_analysis", "usage"):   {"addr": "__ADDR__"},
    ("stack_analysis", "variables"): {"addr": "__ADDR__"},
    ("stack_analysis", "arrays"):  {"addr": "__ADDR__"},
    ("stack_analysis", "uninitialized"): {"addr": "__ADDR__"},
    ("stack_analysis", "summary"): {"addr": "__ADDR__"},
    # string_ops
    ("string_ops", "find_urls"):       {},
    ("string_ops", "find_ips"):        {},
    ("string_ops", "find_paths"):     {},
    ("string_ops", "find_registry"):  {},
    ("string_ops", "find_emails"):     {},
    ("string_ops", "find_commands"):   {},
    ("string_ops", "find_c2"):        {},
    ("string_ops", "find_configs"):   {},
    ("string_ops", "find_api_keys"):  {},
    ("string_ops", "find_databases"): {},
    ("string_ops", "find_crypto_addrs"): {},
    ("string_ops", "find_stack_strings"): {},
    ("string_ops", "find_base64"):    {},
    ("string_ops", "entropy_rank"):   {},
    ("string_ops", "suspicious"):     {},
    ("string_ops", "encoding_stats"): {},
    ("string_ops", "multilingual"):  {},
    ("string_ops", "decode_all"):    {},
    ("string_ops", "ioc_extract"):    {},
    ("string_ops", "indicators"):    {},
    ("string_ops", "score_c2"):       {},
    ("string_ops", "persistence"):   {},
    ("string_ops", "evasion"):       {},
    # summarize
    ("summarize", "binary"):         {},
    ("summarize", "function"):       {"addr": "__ADDR__"},
    ("summarize", "segment"):        {},
    ("summarize", "imports_by_category"): {},
    ("summarize", "strings_by_category"): {},
    ("summarize", "complexity"):     {"addr": "__ADDR__"},
    ("summarize", "call_hierarchy"): {},
    ("summarize", "data_flow"):      {"addr": "__ADDR__"},
    ("summarize", "security_posture"): {},
    ("summarize", "statistics"):     {},
    ("summarize", "report"):         {},
    # taint
    ("taint", "sources"):  {},
    ("taint", "sinks"):    {"source": "recv"},
    ("taint", "trace"):    {"source": "recv"},
    ("taint", "paths"):    {"source": "recv"},
    ("taint", "report"):   {},
    # types
    ("types", "list"):          {},
    ("types", "search_structs"): {"query": "zzz"},
    ("types", "infer"):         {"addr": "__ADDR__"},
    ("types", "read_struct"):    {"name": "zzz"},
    ("types", "enum_values"):   {"name": "zzz"},
    ("types", "type_graph"):    {},
    # cfg_analysis
    ("cfg_analysis", "complexity"): {"addr": "__ADDR__"},
    ("cfg_analysis", "loops"):      {"addr": "__ADDR__"},
    ("cfg_analysis", "branches"):   {"addr": "__ADDR__"},
    ("cfg_analysis", "paths"):      {"addr": "__ADDR__"},
    ("cfg_analysis", "dominators"): {"addr": "__ADDR__"},
    ("cfg_analysis", "post_dominators"): {"addr": "__ADDR__"},
    ("cfg_analysis", "back_edges"): {"addr": "__ADDR__"},
    ("cfg_analysis", "natural_loops"): {"addr": "__ADDR__"},
    ("cfg_analysis", "irreducible"): {"addr": "__ADDR__"},
    ("cfg_analysis", "flatten_detect"): {"addr": "__ADDR__"},
    # classify
    ("classify", "function"):        {"addr": "__ADDR__"},
    ("classify", "binary"):          {},
    ("classify", "all_functions"):   {},
    ("classify", "library_code"):    {},
    ("classify", "wrappers"):        {},
    ("classify", "callbacks"):       {},
    ("classify", "initializers"):    {},
    ("classify", "error_handlers"):  {},
    ("classify", "hot_functions"):   {},
    ("classify", "orphans"):        {},
    ("classify", "induce_schema"):  {},
    ("classify", "anchor_coverage"): {},
    # coverage
    ("coverage", "report"):             {},
    ("coverage", "uncovered"):          {},
    ("coverage", "filter"):             {},
    ("coverage", "function_coverage"):  {},
    ("coverage", "gaps"):               {},
    ("coverage", "compare"):           {},
    ("coverage", "merge"):              {},
    # intelligence
    ("intelligence", "intelligence_status"): {},
    ("intelligence", "embedder_status"):     {},
    ("intelligence", "anchor_status"):       {},
    ("intelligence", "semantic_search"):     {"query": "entry point", "top_k": 3},
    ("intelligence", "similar_functions"):   {"addr": "__ADDR__", "top_k": 3},
    ("intelligence", "evidence_card"):       {"addr": "__ADDR__"},
    ("intelligence", "export_index_summary"): {},
    ("intelligence", "blackboard_search"):    {"query": "zzz"},
    # segments
    ("segments", "list"):    {},
    ("segments", "info"):    {"segment": ".text"},
    ("segments", "find_code"): {},
    ("segments", "find_data"): {},
    ("segments", "compare"): {"segment": ".text", "segment2": ".rdata"},
    # gadgets
    ("gadgets", "mitigations"): {},
    ("gadgets", "rop"):        {"limit": 3},
    ("gadgets", "jop"):        {"limit": 3},
    ("gadgets", "syscall"):    {},
    ("gadgets", "write_what_where"): {},
    ("gadgets", "stack_pivot"): {"limit": 3},
    ("gadgets", "shellcode_space"): {},
    ("gadgets", "seh_handlers"): {},
    ("gadgets", "pivot_chains"): {},
    ("gadgets", "classify_chain"): {},
    # protocol
    ("protocol", "detect"):        {},
    ("protocol", "parsers"):        {},
    ("protocol", "serializers"):    {},
    ("protocol", "handlers"):       {},
    ("protocol", "endpoints"):      {},
    ("protocol", "tls_config"):     {},
    ("protocol", "socket_flow"):    {},
    ("protocol", "packet_struct"):  {},
    ("protocol", "magic_numbers"):  {},
    ("protocol", "state_machine"):  {},
    # threat_hunt
    ("threat_hunt", "findings"):  {},
    ("threat_hunt", "quick"):      {},
    ("threat_hunt", "malware"):    {},
    ("threat_hunt", "vuln"):       {},
    ("threat_hunt", "tracing"):    {},
    ("threat_hunt", "run"):        {"profile": "quick", "limit": 3},
    ("threat_hunt", "deep"):      {},
    # trace_analysis
    ("trace_analysis", "get"):               {},
    ("trace_analysis", "set_options"):       {},
    ("trace_analysis", "static_trace"):      {"addr": "__ADDR__"},
    ("trace_analysis", "decrypt_strings"):   {"addr": "__ADDR__"},
    ("trace_analysis", "eval_expr"):         {"addr": "__ADDR__", "expr": "0+1"},
    ("trace_analysis", "prefetch_context"):  {"addr": "__ADDR__"},
    ("trace_analysis", "deobfuscate_emulate"): {"addr": "__ADDR__"},
    ("trace_analysis", "anti_analysis_detect"): {},
    ("trace_analysis", "trace_entropy"):     {},
    ("trace_analysis", "api_sequence"):      {},
    ("trace_analysis", "loop_analysis"):     {},
    # deobfuscate
    ("deobfuscate", "detect"):            {},
    ("deobfuscate", "detect_encoding"):   {},
    ("deobfuscate", "stack_strings"):     {},
    ("deobfuscate", "dead_code"):         {"addr": "__ADDR__"},
    ("deobfuscate", "api_hashing"):       {},
    ("deobfuscate", "dynamic_dispatch"):   {"addr": "__ADDR__"},
    ("deobfuscate", "anti_disasm"):       {"addr": "__ADDR__"},
    ("deobfuscate", "decode_attempt"):     {"addr": "__ADDR__"},
    # crypto_id
    ("crypto_id", "identify"):       {},
    ("crypto_id", "constants"):      {},
    ("crypto_id", "encoding"):       {},
    ("crypto_id", "checksums"):      {},
    ("crypto_id", "entropy_analysis"): {},
    ("crypto_id", "aes_ni"):          {},
    # entropy
    ("entropy", "summary"):        {},
    ("entropy", "section"):        {"addr": "__ADDR__", "size": 64},
    ("entropy", "region"):         {"addr": "__ADDR__", "size": 64},
    ("entropy", "packed_detect"):   {},
    ("entropy", "crypto_detect"):   {},
    ("entropy", "compare"):        {"addr": "__ADDR2__", "size": 64, "addr1": "__ADDR__", "addr2": "__ADDR2__"},
    ("entropy", "window"):         {"addr": "__ADDR__", "size": 64},
    # firmware_view
    ("firmware_view", "triage_snapshot"): {},
    ("firmware_view", "scan_region"):      {"addr": "__ADDR__", "size": 64},
    ("firmware_view", "pointer_sweep"):    {"addr": "__ADDR__", "size": 64},
    ("firmware_view", "recommend"):        {},
    ("firmware_view", "table_candidates"):  {},
    ("firmware_view", "region_profile"):    {"addr": "__ADDR__"},
    ("firmware_view", "pointer_clusters"):  {},
    ("firmware_view", "detect_load_address"): {},
    ("firmware_view", "detect_vector_table"): {},
    ("firmware_view", "detect_mmio"):       {},
    ("firmware_view", "rtos_scan"):          {},
    ("firmware_view", "bootstrap"):         {},
    # binary_info
    ("binary_info", "headers"):    {},
    ("binary_info", "sections"):   {},
    ("binary_info", "relocations"): {},
    ("binary_info", "resources"):  {},
    ("binary_info", "debug_info"): {},
    ("binary_info", "compiler"):  {},
    ("binary_info", "linker"):    {},
    ("binary_info", "timestamps"): {},
    ("binary_info", "checksums"): {},
    ("binary_info", "overlay"):   {},
    # imports_deep
    ("imports_deep", "thunks"):     {},
    ("imports_deep", "delay"):      {},
    ("imports_deep", "forwarded"): {},
    ("imports_deep", "ordinal"):    {},
    ("imports_deep", "api_sets"):   {},
    ("imports_deep", "resolve"):    {"name": "Write"},
    # annotation
    ("annotation", "summary"):     {},
    ("annotation", "get_context"):  {"addr": "__ADDR__"},
    ("annotation", "validate"):     {},
    ("annotation", "export_md"):    {},
    # bookmarks
    ("bookmarks", "list"):   {},
    ("bookmarks", "find"):   {"query": "zzz"},
    ("bookmarks", "export"): {},
    ("bookmarks", "add"):    {"addr": "__ADDR2__", "name": "smoke"},
    # history
    ("history", "list"):      {},
    ("history", "snapshot"):  {},
    ("history", "diff"):      {},
    # idb
    ("idb", "meta"):         {},
    ("idb", "summary"):      {},
    ("idb", "segments"):     {},
    ("idb", "entrypoints"):  {},
    ("idb", "bookmarks"):    {},
    ("idb", "overview"):     {},
    ("idb", "architecture_profile"): {},
    ("idb", "state"):        {},
    # knowledge
    ("knowledge", "chip_families"): {},
    ("knowledge", "chip_identify"):  {"query": "zzz"},
    ("knowledge", "symbol_lookup"):  {"query": "main"},
    ("knowledge", "export_session"): {},
    # llm_helpers
    ("llm_helpers", "bootstrap"):         {},
    ("llm_helpers", "cheatsheet"):        {},
    ("llm_helpers", "context_window"):    {},
    ("llm_helpers", "function_digest"):    {"addr": "__ADDR__"},
    ("llm_helpers", "binary_digest"):      {},
    ("llm_helpers", "explain_address"):    {"addr": "__ADDR__"},
    ("llm_helpers", "suggest_next"):        {},
    ("llm_helpers", "progress_report"):    {},
    ("llm_helpers", "focus_area"):          {},
    ("llm_helpers", "behavioral_signature_search"): {"query": "crypto"},
    # lumina
    ("lumina", "status"):   {},
    ("lumina", "history"):  {},
    ("lumina", "search"):    {"query": "main"},
    # misc
    ("misc", "plugin_list"): {},
    ("misc", "cache_stats"):  {},
    ("misc", "python"):       {"expr": "1+1"},
    ("misc", "idc"):          {"expr": "idc.get_inf_attr(idc.INF_PROC) if hasattr(idc,'get_inf_attr') else 'n/a'"},
    # nav
    ("nav", "interesting"):   {},
    ("nav", "cursor"):        {},
    ("nav", "semantic_goto"): {"query": "entry"},
    # packer
    ("packer", "detect"):  {},
    ("packer", "profile"): {},
    ("packer", "guide"):   {},
    ("packer", "status"):  {},
    # patterns
    ("patterns", "list_sigs"):  {},
    ("patterns", "match"):       {"pattern": "deadbeef"},
    ("patterns", "matched"):     {},
    ("patterns", "create_sig"):  {"addr": "__ADDR__"},
    ("patterns", "generate"):     {"addr": "__ADDR__"},
    ("patterns", "yara_from_func"): {"addr": "__ADDR__"},
    ("patterns", "flirt_generate"): {"addr": "__ADDR__"},
    ("patterns", "match_yara"):    {"rules": "rule x { strings: $a = \"deadbeef\" condition: $a }"},
    # predictor
    ("predictor", "suggest_next_tool"):  {},
    ("predictor", "detect_stuck"):        {},
    ("predictor", "suggest_focus"):       {},
    ("predictor", "suggest_next_address"): {},
    ("predictor", "risk_of_stall"):       {},
    ("predictor", "recommend_bundle"):    {},
    # project
    ("project", "list_recent"):  {},
    ("project", "get_cwd"):       {},
    ("project", "list_dir"):       {"path": "."},
    ("project", "exists"):        {"path": "."},
    ("project", "evidence_graph"): {},
    ("project", "knowledge_merge"): {},
    ("project", "confidence_model"): {},
    ("project", "hypothesis_tracker"): {},
    ("project", "temporal_reasoning"): {},
    ("project", "semantic_artifact_diff"): {},
    ("project", "ai_governance"):  {},
    ("project", "knowledge_debt"): {},
    ("project", "casefile_export"): {},
    # query
    ("query", "data"):     {"action": "functions", "count": 2},
    ("query", "search"):    {"query": "main"},
    ("query", "idb"):       {},
    ("query", "code"):      {"addr": "__ADDR__"},
    ("query", "types"):     {},
    ("query", "symbols"):   {"query": "main"},
    ("query", "patterns"):  {},
    ("query", "imports_deep"): {},
    ("query", "nl"):        {"query": "entry point"},
    # session - read-only actions only
    ("session", "list"):    {},
    ("session", "status"):   {},
    ("session", "health"):   {},
    ("session", "recent"):   {"n": 3},
    ("session", "oldest"):   {"n": 3},
    ("session", "dashboard"): {},
    ("session", "get_phase"): {},
    ("session", "list_hypotheses"): {},
    ("session", "list_skills"): {},
    ("session", "list_snapshots"): {},
    ("session", "macro_list"): {},
    ("session", "get_activity_log"): {},
    ("session", "recent_workset"): {"n": 3},
    ("session", "search_notes"): {"query": "zzz"},
    ("session", "notebook_read"): {},
    ("session", "suggest_strategy"): {},
    ("session", "suggest_triage"): {},
    ("session", "suggest_analogy"): {"context": "entry"},
    # stack_analysis covered above
    # string_ops covered above
    # symbols
    ("symbols", "status"):   {},
    ("symbols", "export"):   {},
    # summarize covered above
    # taint covered above
    # trace_analysis covered above
    # truncation
    ("truncation", "continue"): {"token": "deadbeef"},
    # types covered above
    # wiki
    ("wiki", "list_topics"):    {},
    ("wiki", "search"):          {"query": "tool"},
    ("wiki", "semantic_search"): {"query": "tool"},
    ("wiki", "index"):           {},
    ("wiki", "suggest"):         {"query": "tool"},
    # workflow
    ("workflow", "catalog"):     {},
    ("workflow", "triage_fast"):  {"dry_run": True},
    ("workflow", "recon_sweep"):  {"dry_run": True},
    ("workflow", "malware_deep"): {"dry_run": True},
    ("workflow", "vuln_audit"):   {"dry_run": True},
    ("workflow", "patch_review"): {"dry_run": True},
    ("workflow", "plan"):         {"workflow_action": "triage_fast"},
    ("workflow", "estimate"):     {"workflow_action": "triage_fast"},
    ("workflow", "explain"):      {"workflow_action": "triage_fast"},
    ("workflow", "audit_plan"):   {"planned_calls": []},
    ("workflow", "prioritize"):   {"planned_calls": []},
    ("workflow", "compose"):       {"workflow_actions": ["triage_fast"]},
    # yara_hunt
    ("yara_hunt", "list_rules"):  {},
    ("yara_hunt", "compile"):     {"rules": "rule x { strings: $a = \"deadbeef\" condition: $a }"},
    # governance
    ("governance", "list_rules"): {},
    ("governance", "stats"):      {},
    ("governance", "check"):      {"operation_type": "comment", "addr": "__ADDR__", "proposed_value": "x"},
    # bulk
    ("bulk", "export_annotations"): {},
    ("bulk", "rename"):             {"items": []},
    ("bulk", "comment"):            {"items": []},
    ("bulk", "apply_type"):         {"items": []},
    ("bulk", "rename_stack"):       {"items": []},
    ("bulk", "import_annotations"): {"path": "/nonexistent/zzz.json"},
    # analysis
    ("analysis", "get_options"):   {},
    ("analysis", "wait"):           {},
    # filter
    ("filter", "filter"):          {"data": {"functions": ["a"]}, "query": "."},
    # export
    ("export", "listing"):        {"limit": 3},
    ("export", "json"):           {"limit": 3},
    ("export", "html"):           {"limit": 3},
    ("export", "headers"):        {},
    ("export", "idc"):            {},
    ("export", "sarif"):          {},
    ("export", "binexport"):      {},
    ("export", "redact"):         {},
    # hooks covered above
    # debug - status only (no live debugger)
    ("debug", "status"):    {},
    ("debug", "mem_map"):   {},
    ("debug", "modules"):  {},
    ("debug", "threads"):  {},
    ("debug", "callstack"): {},
    ("debug", "breakpoints"): {},
    ("debug", "regs"):      {},
    ("debug", "snapshot_regs"): {},
    # bridge_search covered above
    ("bridge_search", "bridges"): {"func_name": "main", "bridge_types": ["apis"], "top_k": 3},
}

# Actions that would corrupt the shared session / IDB state for the rest of
# the sweep (or are irreversible). Skipped, not run.
SKIP_ACTIONS: set[tuple[str, str]] = {
    ("session", "create"),       # would spawn another idat / steal focus
    ("session", "switch"), ("session", "close"), ("session", "delete"),
    ("session", "kill"), ("session", "restore_snapshot"), ("session", "merge"),
    ("session", "archive"), ("session", "unarchive"), ("session", "bulk_delete"),
    ("session", "bulk_tag"), ("session", "cleanup_stale"), ("session", "duplicate"),
    ("session", "rebuild"), ("session", "update"), ("session", "rename"),
    ("session", "tag"), ("session", "untag"), ("session", "find_by_tag"),
    ("session", "export_session"), ("session", "import_session"),
    ("session", "add_note"), ("session", "clear_notes"), ("session", "validate"),
    ("session", "link_session"), ("session", "cross_reference_sessions"),
    ("session", "log_activity"), ("session", "track_hypothesis"),
    ("session", "confirm_hypothesis"), ("session", "refute_hypothesis"),
    ("session", "advance_phase"), ("session", "notebook_append"),
    ("session", "notebook_section"), ("session", "macro_set"), ("session", "macro_get"),
    ("session", "macro_delete"), ("session", "macro_run"), ("session", "tag"),
    ("history", "undo"), ("history", "redo"), ("history", "restore"),
    ("modify", "patch_asm"),           # rewrites instruction bytes
    ("data_ops", "undefine"),          # destroys definitions used elsewhere
    ("blackboard", "clear"), ("blackboard", "prune"), ("blackboard", "delete"),
    ("blackboard", "update"), ("blackboard", "write"), ("blackboard", "merge"),
    ("blackboard", "contradict"), ("blackboard", "resolve"), ("blackboard", "add_evidence"),
    ("blackboard", "calibrate"), ("blackboard", "next_target"), ("blackboard", "propagate_labels"),
    ("blackboard", "start_crawler"), ("blackboard", "stop_crawler"), ("blackboard", "accept"),
    ("blackboard", "reject"), ("blackboard", "semantic_rebuild"), ("blackboard", "semantic_index"),
    ("blackboard", "deref"), ("blackboard", "chain"),
    ("memory", "write"),                # writes bytes into the IDB
    ("debug", "start"), ("debug", "stop"), ("debug", "continue"),
    ("debug", "step_into"), ("debug", "step_over"), ("debug", "run_to"),
    ("debug", "run_until"), ("debug", "add_bp"), ("debug", "del_bp"),
    ("debug", "enable_bp"), ("debug", "add_hw_bp"), ("debug", "add_watch"),
    ("debug", "set_reg"), ("debug", "write_mem"), ("debug", "search_mem"),
    ("debug", "trace_start"), ("debug", "trace_stop"),
    ("project", "save"), ("project", "close"), ("project", "open"),
    ("project", "load_binary"), ("project", "set_cwd"),
    ("analysis", "reanalyze"), ("analysis", "run"), ("analysis", "analyze"),
    ("analysis", "set_options"), ("analysis", "set_processor"),
    ("analysis", "set_loader_options"), ("analysis", "set_architecture"),
    ("analysis", "plugin_run"),
    ("segments", "add"), ("segments", "delete"), ("segments", "set_attr"),
    ("segments", "set_perms"), ("segments", "move"), ("segments", "merge"),
    ("types", "set_prototype"), ("types", "parse_decl"), ("types", "declare"),
    ("types", "apply"), ("types", "import_header"), ("types", "propagate"),
    ("funcs", "create"), ("funcs", "delete"), ("funcs", "set_flags"),
    ("bookmarks", "delete"), ("bookmarks", "update"), ("bookmarks", "clear"),
    ("symbols", "load_pdb"), ("symbols", "load_dwarf"), ("symbols", "apply"),
    ("misc", "load_sig"),
    ("coverage", "import_drcov"), ("coverage", "import_lighthouse"),
    ("coverage", "highlight"),
    ("trace_analysis", "import_trace"), ("trace_analysis", "clear"),
    ("trace_analysis", "deobfuscate_emulate"),
    ("patterns", "apply_sig"),
    ("history", "snapshot"),  # mutates IDB history; keep list/diff only
    ("yara_hunt", "scan"), ("yara_hunt", "match_context"),
    ("yara_hunt", "extract_strings"), ("yara_hunt", "xref_matches"),
    ("governance", "redact"),
    ("hooks", "generate_frida"), ("hooks", "generate_detours"), ("hooks", "inline_hooks"),
    ("firmware_view", "smart_carve"), ("firmware_view", "carve_plan"),
    ("firmware_view", "campaign"), ("firmware_view", "segment_sweep"),
    ("firmware_view", "multi_region_campaign"), ("firmware_view", "auto_retype"),
    ("firmware_view", "rollback_last"), ("firmware_view", "review_contradictions"),
    ("blackboard", "kg_add_system"), ("blackboard", "kg_add_struct"),
    ("blackboard", "kg_add_gap"), ("blackboard", "fill_gap"),
    ("blackboard", "kg_add_state_machine"), ("blackboard", "kg_add_peripheral"),
    ("blackboard", "kg_add_attack_surface"),
    ("blackboard", "add_system"), ("blackboard", "add_struct"),
    ("blackboard", "add_gap"), ("blackboard", "add_state_machine"),
    ("blackboard", "add_peripheral"), ("blackboard", "add_attack_surface"),
    ("blackboard", "policy_set"), ("blackboard", "phase_set"),
    ("blackboard", "phase_tick"), ("blackboard", "phase_status"),
    ("blackboard", "phase_finalize"), ("blackboard", "memory_compile"),
    ("blackboard", "trace_ingest"), ("blackboard", "trace_run"),
    ("blackboard", "trace_status"), ("blackboard", "proposal_create"),
    ("blackboard", "proposal_list"), ("blackboard", "proposal_accept"),
    ("blackboard", "proposal_reject"), ("blackboard", "accept_proposal"),
    ("blackboard", "reject_proposal"), ("blackboard", "decision_card"),
    ("blackboard", "working_set"), ("blackboard", "state_health"),
    ("blackboard", "notes_export"), ("blackboard", "notes_import"),
    ("blackboard", "campaign_summary"), ("blackboard", "auto_tag_propagate"),
    ("blackboard", "export_symbols"), ("blackboard", "import_symbols"),
    ("blackboard", "related_by_behavior"),
    ("blackboard", "kg_summary"), ("blackboard", "kg_systems"),
    ("blackboard", "kg_gaps"), ("blackboard", "kg_structs"),
    ("blackboard", "kg_state_machines"), ("blackboard", "kg_attack_surface"),
    ("blackboard", "kg_peripherals"),
    ("session", "create"),
}


def actions_for_tool(schema: dict) -> list[str]:
    """Return the action enum for a tool, or [] if it has no action prop."""
    props = (schema or {}).get("properties", {}) or {}
    action_prop = props.get("action", {})
    if isinstance(action_prop, dict):
        enum = action_prop.get("enum")
        if isinstance(enum, list) and enum:
            return list(enum)
    return []


def fallback_args_for_action(schema: dict, action: str, addr: str, addr2: str, idb: str) -> dict:
    """Generic schema-driven args for an action not in ACTION_ARGS."""
    props = (schema or {}).get("properties", {}) or {}
    args: dict[str, Any] = {"action": action}
    for name, prop in props.items():
        if name in ("action", "_risk_ack"):
            continue
        typ = prop.get("type") if isinstance(prop, dict) else None
        if name in ("addr", "ea", "start", "start_ea", "target", "addr1", "func_ea", "src"):
            args[name] = addr
        elif name in ("addr2", "ea2", "end", "end_ea", "end_addr", "dst", "addr2_ea"):
            args[name] = addr2
        elif name in ("idb", "idb2", "other_idb", "db_path"):
            args[name] = idb
        elif name in ("query", "q", "text", "expr", "pattern", "uri", "name", "func_name"):
            args[name] = "main"
        elif name in ("count", "limit", "max_items", "top_k", "n", "top", "k", "max_depth", "depth"):
            args[name] = 3
        elif name in ("size", "length"):
            args[name] = 16
        elif name in ("offset", "start_i"):
            args[name] = 0
        elif typ == "boolean":
            args[name] = False
        elif typ == "integer":
            args[name] = 1
        elif typ == "array":
            args[name] = []
        elif typ == "object":
            args[name] = {}
        elif typ == "string":
            args[name] = "main"
    args["_risk_ack"] = True
    return args


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=S.DEFAULT_BINARY)
    ap.add_argument("--timeout", type=int, default=S.DEFAULT_TIMEOUT)
    ap.add_argument("--only", help="comma-separated tool names to run")
    ap.add_argument("--skip-clean", action="store_true", help="don't print CLEAN rows")
    args_cli = ap.parse_args()

    if not os.path.isfile(S.VENV_PY):
        print(f"FATAL: venv python not found: {S.VENV_PY}", file=sys.stderr)
        return 2
    if not os.path.isfile(args_cli.binary):
        print(f"FATAL: binary not found: {args_cli.binary}", file=sys.stderr)
        return 2
    if not os.path.isfile(os.path.join(S.BASE_ENV["IDADIR"], "idat")):
        print(f"FATAL: idat not found in IDADIR={S.BASE_ENV['IDADIR']}", file=sys.stderr)
        return 2

    only = set(args_cli.only.split(",")) if args_cli.only else None
    cli = S.MCPClient(timeout=args_cli.timeout)
    rows: list[tuple[str, str, str, str]] = []
    counts = {"OK": 0, "CLEAN": 0, "CRASH": 0, "TIMEOUT": 0, "OTHER": 0, "SKIP": 0}

    def restart() -> bool:
        cli.stop()
        cli.start()
        if not cli.initialize():
            return False
        payload, err = cli.tool_call("session", {
            "action": "create", "binary_path": args_cli.binary,
            "processor": "metapc", "bitness": 64, "endian": "little", "_risk_ack": True,
        })
        if err or not payload or payload.get("ok") is not True:
            return False
        return True

    try:
        cli.start()
        if not cli.initialize():
            print("FATAL: initialize handshake failed", file=sys.stderr)
            return 3
        if not restart():
            print("FATAL: could not create session / spawn IDA", file=sys.stderr)
            return 4

        # idb path for compare
        idb_path = ""
        sp = cli.call("tools/call", {"name": "idb", "arguments": {"action": "meta", "_risk_ack": True}})
        if sp and "result" in sp:
            try:
                p = json.loads(sp["result"]["content"][0]["text"])
                idb_path = p.get("idb_path") or p.get("path") or ""
            except Exception:
                pass

        # fetch two addrs
        ap2, _ = cli.tool_call("data", {"action": "functions", "count": 3, "_risk_ack": True})
        addrs = S.first_addr_from_functions(ap2 or {}, 3) if ap2 else []
        if len(addrs) < 2:
            ep, _ = cli.tool_call("idb", {"action": "entrypoints", "_risk_ack": True})
            eps = ep.get("entrypoints") if isinstance(ep, dict) else []
            for e in eps[:2]:
                if isinstance(e, dict):
                    a = e.get("ea") or e.get("address")
                    if a:
                        addrs.append(a if str(a).startswith("0x") else (hex(int(a, 16)) if isinstance(a, str) else hex(a)))
        addr = addrs[0] if addrs else "0x140001000"
        addr2 = addrs[1] if len(addrs) > 1 else addr

        tools = cli.tools_list()
        if not tools:
            print("FATAL: tools/list returned no tools", file=sys.stderr)
            return 5

        print(f"=== ida-pro-mcp ALL-ACTIONS smoke test ===")
        print(f"binary : {args_cli.binary}")
        print(f"addr    : {addr} / {addr2}  idb: {idb_path or '-'}")
        print()
        print(f"{'STATUS':7} {'TOOL':18} {'ACTION':22} RESULT")
        print(f"{'-'*7} {'-'*18} {'-'*22} {'-'*50}")

        for t in tools:
            name = t.get("name", "")
            if not name or (only and name not in only):
                continue
            schema = t.get("inputSchema") or {}
            acts = actions_for_tool(schema)
            if not acts:
                # No action enum: test the tool once with generic args.
                call_args = S.fallback_args(schema, addr)
                call_args = S.substitute(call_args, addr, addr2, idb_path)
                action_lbl = "(none)"
                payload, err = cli.tool_call(name, call_args)
                status, note = S.classify(payload, err)
                counts[status] = counts.get(status, 0) + 1
                rows.append((status, name, action_lbl, note))
                if not (status == "CLEAN" and args_cli.skip_clean):
                    print(f"{status:7} {name:18} {action_lbl:22} {note}")
                sys.stdout.flush()
                if status in ("TIMEOUT", "CRASH") and err in ("timeout", "eof"):
                    if not restart():
                        print("  (host restart failed; aborting)", file=sys.stderr)
                        break
                continue

            for action in acts:
                key = (name, action)
                if key in SKIP_ACTIONS:
                    counts["SKIP"] = counts.get("SKIP", 0) + 1
                    rows.append(("SKIP", name, action, "(destructive/run-corrupting)"))
                    if not args_cli.skip_clean:
                        print(f"{'SKIP':7} {name:18} {action:22} (skipped)")
                    continue
                if key in ACTION_ARGS:
                    kw = ACTION_ARGS[key]
                    call_args = S.substitute(kw, addr, addr2, idb_path)
                    if action != "__none__":
                        call_args["action"] = action
                else:
                    call_args = S.substitute(
                        fallback_args_for_action(schema, action, addr, addr2, idb_path),
                        addr, addr2, idb_path,
                    )
                payload, err = cli.tool_call(name, call_args)
                status, note = S.classify(payload, err)
                counts[status] = counts.get(status, 0) + 1
                rows.append((status, name, action, note))
                if not (status == "CLEAN" and args_cli.skip_clean):
                    print(f"{status:7} {name:18} {action:22} {note}")
                sys.stdout.flush()
                if status in ("TIMEOUT", "CRASH") and err in ("timeout", "eof"):
                    if not restart():
                        print("  (host restart failed; aborting)", file=sys.stderr)
                        break
            else:
                continue
            break  # if inner broke out due to restart failure, stop tools loop

    finally:
        cli.stop()

    print()
    print("=== SUMMARY ===")
    total = sum(counts.values())
    for k in ("OK", "CLEAN", "CRASH", "TIMEOUT", "OTHER", "SKIP"):
        print(f"  {k:7}: {counts.get(k,0):3}")
    print(f"  {'TOTAL':7}: {total:3}")
    failures = [r for r in rows if r[0] in ("CRASH", "TIMEOUT", "OTHER")]
    if failures:
        print()
        print("=== ATTENTION (CRASH / TIMEOUT / OTHER) ===")
        for st, nm, ac, nt in failures:
            print(f"  {st:7} {nm}.{ac}  -> {nt}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())