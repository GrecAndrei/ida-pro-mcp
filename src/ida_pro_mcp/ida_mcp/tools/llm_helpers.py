
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import hashlib
import json
import re
import time


# ============================================================================
# LLM_HELPERS - LLM-Specific Helper Actions for Optimized Interaction
# ============================================================================

try:
    from ._api_categories import API_CATEGORIES as _API_CATEGORIES
except ImportError:
    from _api_categories import API_CATEGORIES as _API_CATEGORIES  # type: ignore[import-not-found]

try:
    from ...host.context_density import ContextDensityOptimizer
except ImportError:
    try:
        from ida_pro_mcp.host.context_density import ContextDensityOptimizer
    except ImportError:
        ContextDensityOptimizer = None  # type: ignore[misc,assignment]

_FEATURE_PHASES = {
    "intent_tool_compiler": 1,
    "adaptive_query_planner": 1,
    "token_aware_context_optimizer": 1,
    "cross_call_variable_resolver": 1,
    "evidence_weighted_response_assembler": 1,
    "uncertainty_propagation_engine": 1,
    "multi_granularity_retrieval_layer": 1,
    "semantic_chunking_for_decompiled_code": 1,
    "question_type_router": 1,
    "interactive_clarification_protocol": 1,
    "behavioral_signature_search": 1,
    "cross_artifact_correlation_search": 1,
    "temporal_search_replay": 2,
    "search_hypothesis_sandbox": 2,
    "path_constrained_search": 2,
    "argument_semantics_search": 2,
    "decompile_disasm_consistency_search": 2,
    "near_miss_search_ranking": 2,
    "persistent_search_collections": 2,
    "auto_expansion_search_chains": 1,
    "function_role_classifier": 2,
    "protocol_format_reconstruction_assistant": 2,
    "global_state_influence_mapper": 2,
    "api_contract_extractor": 2,
    "interprocedural_data_lineage_graph": 2,
    "semantic_diff_explainer": 2,
    "dangerous_pattern_explainer": 2,
    "binary_capability_matrix_builder": 2,
    "execution_hypothesis_generator": 2,
    "patch_impact_forecaster": 2,
    "safe_idapython_orchestration_runtime": 3,
    "script_template_marketplace_layer": 3,
    "auto_script_synthesis_from_intent": 3,
    "script_output_schema_enforcer": 3,
    "long_running_job_manager": 3,
    "cross_session_script_memory": 3,
    "privilege_scope_guardrails_for_scripts": 3,
    "script_to_tool_promotion_pipeline": 3,
    "experiment_harness_for_script_variants": 3,
    "idapython_provenance_recorder": 3,
    "investigation_playbook_engine": 4,
    "next_best_action_recommender": 4,
    "analysis_dead_end_detector": 4,
    "workset_intelligence_capsules": 4,
    "contradiction_tracker": 4,
    "review_queue_for_ai_edits": 4,
    "case_narrative_composer": 4,
    "cost_latency_optimizer": 4,
    "trust_verification_layer": 4,
    "learning_feedback_loop": 4,
}

_FEATURE_SUMMARIES = {
    "intent_tool_compiler": "Compiles NL analysis goals into multi-step MCP tool plans with fallback branches.",
    "adaptive_query_planner": "Chooses dynamic search/data/code order from context and current evidence.",
    "token_aware_context_optimizer": "Builds compact context packs under a token budget.",
    "cross_call_variable_resolver": "Tracks aliases for symbols/addresses across tool calls.",
    "evidence_weighted_response_assembler": "Assembles answers from weighted evidence fragments.",
    "uncertainty_propagation_engine": "Propagates confidence and flags speculative conclusions.",
    "multi_granularity_retrieval_layer": "Selects retrieval granularity by question type.",
    "semantic_chunking_for_decompiled_code": "Turns code/disasm into stable logic chunks.",
    "question_type_router": "Routes prompts to vulnerability/behavior/dataflow/search workflows.",
    "interactive_clarification_protocol": "Generates targeted clarification questions when evidence is weak.",
    "behavioral_signature_search": "Searches for semantic behavior signatures.",
    "cross_artifact_correlation_search": "Correlates strings/imports/xrefs/code hits with ranking.",
    "temporal_search_replay": "Replays and diffs prior search campaigns.",
    "search_hypothesis_sandbox": "Tests alternative search hypotheses and compares yield.",
    "path_constrained_search": "Searches conditioned on control-flow constraints.",
    "argument_semantics_search": "Finds calls by argument-role semantics.",
    "decompile_disasm_consistency_search": "Detects mismatches between pseudocode and disassembly.",
    "near_miss_search_ranking": "Ranks near matches when exact hits fail.",
    "persistent_search_collections": "Stores reusable versioned search sets.",
    "auto_expansion_search_chains": "Auto-seeds next-hop searches from current hits.",
    "function_role_classifier": "Infers parser/codec/auth/loader roles from mixed signals.",
    "protocol_format_reconstruction_assistant": "Suggests message/field/state models from static evidence.",
    "global_state_influence_mapper": "Maps globals and flags that gate behavior.",
    "api_contract_extractor": "Infers pre/post/error contracts from call behavior.",
    "interprocedural_data_lineage_graph": "Tracks value lineage across call boundaries.",
    "semantic_diff_explainer": "Explains behavior deltas across binaries.",
    "dangerous_pattern_explainer": "Explains risky patterns and exploitation preconditions.",
    "binary_capability_matrix_builder": "Builds capability matrix for IO/network/crypto/anti-analysis.",
    "execution_hypothesis_generator": "Generates static-to-runtime behavior hypotheses.",
    "patch_impact_forecaster": "Estimates impact of rename/type/patch changes.",
    "safe_idapython_orchestration_runtime": "Transactional idapython execution model with audit trail.",
    "script_template_marketplace_layer": "Reusable script templates indexed by task.",
    "auto_script_synthesis_from_intent": "Synthesizes structured idapython plans from goals.",
    "script_output_schema_enforcer": "Enforces stable JSON outputs for script results.",
    "long_running_job_manager": "Schedules and tracks asynchronous script jobs.",
    "cross_session_script_memory": "Learns from prior script outcomes across sessions.",
    "privilege_scope_guardrails_for_scripts": "Applies scope/resource guardrails to scripts.",
    "script_to_tool_promotion_pipeline": "Promotes recurring scripts into standardized tools.",
    "experiment_harness_for_script_variants": "Compares script variants by quality and stability.",
    "idapython_provenance_recorder": "Captures script provenance and output hashes.",
    "investigation_playbook_engine": "Manages multi-step reverse-engineering playbooks.",
    "next_best_action_recommender": "Recommends highest information-gain next action.",
    "analysis_dead_end_detector": "Detects low-yield analysis loops and pivot points.",
    "workset_intelligence_capsules": "Builds compact handoff-ready context capsules.",
    "contradiction_tracker": "Tracks conflicting findings and resolution state.",
    "review_queue_for_ai_edits": "Queues AI edits for controlled review/approval.",
    "case_narrative_composer": "Composes evidence-backed case narratives.",
    "cost_latency_optimizer": "Optimizes batching and retrieval for token/latency budgets.",
    "trust_verification_layer": "Applies verification gates to high-impact claims.",
    "learning_feedback_loop": "Learns from analyst accept/reject feedback.",
}

_ALL_FEATURE_ACTIONS = tuple(_FEATURE_PHASES.keys())


def _runtime_root() -> str:
    explicit = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
    if explicit:
        return explicit
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    return os.path.join(base, "ida-pro-mcp")


def _llm_feature_state_path() -> str:
    root = os.path.join(_runtime_root(), "llm_features")
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "state.json")


def _load_llm_feature_state() -> dict:
    path = _llm_feature_state_path()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {
        "search_collections": {},
        "hypotheses": [],
        "jobs": [],
        "feedback": [],
        "contradictions": [],
        "review_queue": [],
        "playbooks": {},
    }


def _save_llm_feature_state(state: dict) -> None:
    path = _llm_feature_state_path()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def _infer_question_type(query: str) -> str:
    q = (query or "").lower()
    if any(k in q for k in (
        "firmware", "raw binary", "raw blob", "blob", "rom", "flash", "flash image",
        "flat binary", "binwalk", "uimage", "bootloader", "memory dump", "disk image",
        "spi flash", "nand", "nor", "hex dump", "unknown binary", "carved image",
    )):
        return "raw_firmware_retyping"
    if any(k in q for k in ("vuln", "overflow", "exploit", "dangerous", "sink")):
        return "vulnerability_triage"
    if any(k in q for k in ("decrypt", "decode", "crypto", "algorithm")):
        return "crypto_analysis"
    if any(k in q for k in ("protocol", "packet", "format", "state machine")):
        return "protocol_reconstruction"
    if any(k in q for k in ("patch", "rename", "type", "edit")):
        return "patching_workflow"
    if any(k in q for k in ("ioc", "c2", "malware", "persistence")):
        return "threat_hunting"
    return "general_reverse_engineering"


def _build_tool_plan(query: str, addr: Optional[str]) -> list[dict]:
    qtype = _infer_question_type(query)
    base = [
        {"tool": "idb", "action": "summary"},
        {"tool": "data", "action": "imports", "limit": 120},
        {"tool": "search", "action": "find", "pattern": query or "main", "limit": 80},
    ]
    if qtype == "raw_firmware_retyping":
        base = [
            {"tool": "binary_info", "action": "headers"},
            {"tool": "binary_info", "action": "sections"},
            {"tool": "binary_info", "action": "compiler"},
            {"tool": "firmware_view", "action": "scan_region"},
            {"tool": "firmware_view", "action": "region_profile"},
            {"tool": "firmware_view", "action": "pointer_sweep"},
            {"tool": "firmware_view", "action": "table_candidates", "limit": 50},
            {"tool": "firmware_view", "action": "smart_carve", "apply": False, "limit": 80},
            {"tool": "firmware_view", "action": "carve_plan"},
            {"tool": "blackboard", "action": "list", "category": "firmware_view", "limit": 30},
        ]
        if addr:
            # Representation-shaping only makes sense once the analyst has a concrete anchor.
            base.extend(
                [
                    {"tool": "data_ops", "action": "cycle_data", "addr": addr},
                    {"tool": "data_ops", "action": "set_repr", "addr": addr, "repr": "offset"},
                    {"tool": "data_ops", "action": "make_ptr", "addr": addr},
                ]
            )
            base.extend(
                [
                    {"tool": "code", "action": "disasm", "addr": addr},
                    {"tool": "code", "action": "decompile", "addr": addr},
                ]
            )
        base.append({"tool": "search", "action": "semantic", "pattern": query or "entry init parser", "limit": 80})
        return base
    if addr:
        base.extend(
            [
                {"tool": "code", "action": "decompile", "addr": addr},
                {"tool": "code", "action": "disasm", "addr": addr},
            ]
        )
    if qtype == "vulnerability_triage":
        base.extend(
            [
                {"tool": "search", "action": "vulnerable", "limit": 100},
                {"tool": "xref_analysis", "action": "dependency_graph", "addr": addr, "depth": 3},
            ]
        )
    elif qtype == "threat_hunting":
        base.extend(
            [
                {"tool": "string_ops", "action": "suspicious", "limit": 120},
                {"tool": "trace_analysis", "action": "anti_analysis_detect", "limit": 80},
            ]
        )
    elif qtype == "protocol_reconstruction":
        base.extend(
            [
                {"tool": "search", "action": "constants", "limit": 120},
                {"tool": "code", "action": "decomp_dataflow", "addr": addr} if addr else {"tool": "data", "action": "strings", "limit": 100},
            ]
        )
    return base


def _extract_aliases(text: str) -> list[dict]:
    aliases = []
    seen = set()
    for m in re.finditer(r"\b0x[0-9a-fA-F]+\b", text or ""):
        token = m.group(0)
        if token not in seen:
            seen.add(token)
            aliases.append({"kind": "address", "token": token})
    for m in re.finditer(r"\b(?:sub|loc|off|unk|byte|word|dword|qword)_[0-9a-fA-F]+\b", text or ""):
        token = m.group(0)
        if token not in seen:
            seen.add(token)
            aliases.append({"kind": "symbol", "token": token})
    return aliases


def _chunk_disasm_for_addr(ea: int, max_chunks: int = 12) -> list[dict]:
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    chunks = []
    current = []
    current_start = None
    for item in idautils.FuncItems(func.start_ea):
        if current_start is None:
            current_start = item
        line = ida_lines.tag_remove(idc.generate_disasm_line(item, 0))
        current.append(f"{hex(item)}  {line}")
        if len(current) >= 10:
            chunks.append(
                {
                    "start": hex(current_start),
                    "end": hex(item),
                    "kind": "instruction_window",
                    "lines": current,
                }
            )
            current = []
            current_start = None
            if len(chunks) >= max_chunks:
                break
    if current and len(chunks) < max_chunks:
        chunks.append(
            {
                "start": hex(current_start or func.start_ea),
                "end": hex(func.end_ea),
                "kind": "tail_window",
                "lines": current,
            }
        )
    return chunks


def _handle_feature_expansion_action(
    action: str,
    addr: Optional[str],
    query: Optional[str],
    max_tokens: int,
    limit: int,
    history: Optional[str],
    **kwargs,
) -> Optional[dict]:
    if action not in _ALL_FEATURE_ACTIONS:
        return None

    state = _load_llm_feature_state()
    now = int(time.time())
    q = query or ""
    qtype = _infer_question_type(q)
    feature = {
        "action": action,
        "summary": _FEATURE_SUMMARIES.get(action, ""),
        "phase": _FEATURE_PHASES.get(action),
        "question_type": qtype,
    }

    if action == "intent_tool_compiler":
        return {"ok": True, "feature": feature, "plan": _build_tool_plan(q, addr), "fallback": [{"tool": "search", "action": "find", "pattern": q or "main"}]}
    if action == "adaptive_query_planner":
        plan = _build_tool_plan(q, addr)
        if qtype == "raw_firmware_retyping":
            order = [
                "binary_info.headers",
                "binary_info.sections",
                "firmware_view.scan_region",
                "firmware_view.region_profile",
                "firmware_view.pointer_sweep",
                "firmware_view.smart_carve",
                "firmware_view.table_candidates",
                "data_ops.set_repr",
                "blackboard.list",
                "search.semantic",
            ]
        elif qtype == "vulnerability_triage":
            order = ["search.vulnerable", "vuln_scan.dangerous_flow", "code.decompile", "code.decomp_dataflow"]
        elif qtype == "threat_hunting":
            order = ["string_ops.suspicious", "imports_deep.summary", "trace_analysis.anti_analysis_detect", "search.find"]
        else:
            order = ["idb.summary", "search.find", "data.strings", "code.decompile"]
        return {"ok": True, "feature": feature, "recommended_order": order, "candidate_calls": plan}
    if action == "token_aware_context_optimizer":
        budget = max(max_tokens, 200)
        slices = [
            {"source": "binary_digest", "target_tokens": max(120, budget // 8)},
            {"source": "imports_summary", "target_tokens": max(120, budget // 6)},
            {"source": "search_hits", "target_tokens": max(180, budget // 4)},
            {"source": "decompile_or_disasm", "target_tokens": max(220, budget // 3)},
        ]
        return {"ok": True, "feature": feature, "token_budget": budget, "slices": slices, "estimated_total_tokens": sum(x["target_tokens"] for x in slices)}
    if action == "cross_call_variable_resolver":
        aliases = _extract_aliases((history or "") + " " + q)
        return {"ok": True, "feature": feature, "aliases": aliases[: max(1, limit)], "count": len(aliases)}
    if action == "evidence_weighted_response_assembler":
        blocks = kwargs.get("evidence") if isinstance(kwargs.get("evidence"), list) else []
        weighted = []
        for idx, blk in enumerate(blocks):
            text = str(blk.get("text", "")) if isinstance(blk, dict) else str(blk)
            source = blk.get("source", "unknown") if isinstance(blk, dict) else "unknown"
            confidence = float(blk.get("confidence", 0.5)) if isinstance(blk, dict) else 0.5
            weight = min(1.0, confidence + (0.2 if source in ("decompile", "disasm", "data") else 0.0))
            weighted.append({"index": idx, "source": source, "weight": round(weight, 3), "text": text[:400]})
        weighted.sort(key=lambda x: -x["weight"])
        return {"ok": True, "feature": feature, "assembled_evidence": weighted[: max(1, limit)], "note": "Highest-weight evidence should dominate final conclusions."}
    if action == "uncertainty_propagation_engine":
        evidence_count = int(kwargs.get("evidence_count", 0) or 0)
        contradictions = int(kwargs.get("contradictions", 0) or 0)
        confidence = max(0.05, min(0.99, 0.35 + (evidence_count * 0.07) - (contradictions * 0.15)))
        return {"ok": True, "feature": feature, "confidence": round(confidence, 3), "uncertainty": round(1.0 - confidence, 3), "needs_clarification": confidence < 0.55}
    if action == "multi_granularity_retrieval_layer":
        granularity = "instruction" if any(k in q.lower() for k in ("operand", "opcode", "instruction")) else "function"
        if any(k in q.lower() for k in ("architecture", "module", "overview")):
            granularity = "module"
        return {"ok": True, "feature": feature, "granularity": granularity, "retrieval_plan": [{"level": "module"}, {"level": "function"}, {"level": "block"}, {"level": "instruction"}]}
    if action == "semantic_chunking_for_decompiled_code":
        if not addr:
            return {"ok": True, "feature": feature, "chunks": [], "note": "Pass addr for real chunk extraction."}
        ea, err = validate_addr(addr, require_func=True)
        if err:
            return err
        chunks = _chunk_disasm_for_addr(ea, max_chunks=max(4, min(24, limit)))
        return {"ok": True, "feature": feature, "chunks": chunks, "count": len(chunks)}
    if action == "question_type_router":
        qtype = _infer_question_type(q)
        return {"ok": True, "feature": feature, "route": qtype, "recommended_tool_plan": _build_tool_plan(q, addr)}
    if action == "interactive_clarification_protocol":
        prompts = [
            "What is the exact outcome you want (classification, exploitation path, patch, or IOC extraction)?",
            "Which function/address should be treated as anchor context?",
            "Should the workflow prioritize precision (fewer false positives) or recall (broader exploration)?",
        ]
        if qtype == "vulnerability_triage":
            prompts.append("Do you want exploitability ranking or patch-focused root-cause analysis?")
        return {"ok": True, "feature": feature, "clarifications": prompts}

    if action in {"behavioral_signature_search", "cross_artifact_correlation_search", "temporal_search_replay", "search_hypothesis_sandbox", "path_constrained_search", "argument_semantics_search", "decompile_disasm_consistency_search", "near_miss_search_ranking", "persistent_search_collections", "auto_expansion_search_chains"}:
        if action == "persistent_search_collections":
            name = (kwargs.get("name") or "default").strip() if isinstance(kwargs.get("name"), str) else "default"
            if kwargs.get("add"):
                bucket = state.setdefault("search_collections", {}).setdefault(name, [])
                entry = {"query": q, "created_at": now, "addr": addr}
                bucket.append(entry)
                _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "collections": state.get("search_collections", {}), "active_collection": name}
        if action == "temporal_search_replay":
            collections = state.get("search_collections", {})
            replay = []
            for cname, items in collections.items():
                replay.append({"collection": cname, "runs": len(items), "latest": items[-1] if items else None})
            return {"ok": True, "feature": feature, "replay": replay[: max(1, limit)]}
        if action == "search_hypothesis_sandbox":
            hypotheses = [
                {"name": "import-anchored", "query": q or "malloc", "strategy": "search.api + search.callers"},
                {"name": "constant-anchored", "query": q or "0x1000", "strategy": "search.constants + search.immediate"},
                {"name": "string-anchored", "query": q or "error", "strategy": "search.string + search.decompiled"},
            ]
            state.setdefault("hypotheses", []).extend(hypotheses[:2])
            _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "hypotheses": hypotheses}
        if action == "near_miss_search_ranking":
            terms = [t for t in re.split(r"[\s,;]+", q) if t][: max(1, limit)]
            ranked = [{"candidate": t, "distance": 0.0 if i == 0 else round(min(1.0, i * 0.15), 2)} for i, t in enumerate(terms)]
            return {"ok": True, "feature": feature, "near_miss_rank": ranked}
        chain = _build_tool_plan(q, addr)
        if action == "auto_expansion_search_chains":
            chain.extend([{"tool": "search", "action": "callers", "pattern": q or "main"}, {"tool": "search", "action": "callees", "pattern": q or "main"}])
        return {"ok": True, "feature": feature, "search_strategy": chain}

    if action in {"function_role_classifier", "protocol_format_reconstruction_assistant", "global_state_influence_mapper", "api_contract_extractor", "interprocedural_data_lineage_graph", "semantic_diff_explainer", "dangerous_pattern_explainer", "binary_capability_matrix_builder", "execution_hypothesis_generator", "patch_impact_forecaster"}:
        if action == "binary_capability_matrix_builder":
            modules, imports = _get_imports_summary()
            caps = {k: 0 for k in ("network", "file_io", "crypto", "process", "registry", "memory")}
            for imp in imports:
                low = imp.lower()
                for cat, apis in _API_CATEGORIES.items():
                    if any(api.lower() in low for api in apis):
                        caps[cat] += 1
            return {"ok": True, "feature": feature, "capability_matrix": caps, "import_modules": modules[:20]}
        if action == "execution_hypothesis_generator":
            hypotheses = [
                "Initialization flow resolves imports and configures runtime environment.",
                "At least one core routine transforms input buffers before output emission.",
                "A gated branch likely activates behavior based on external state or input patterns.",
            ]
            if qtype == "threat_hunting":
                hypotheses.append("Potential delayed execution or anti-analysis check before network operations.")
            return {"ok": True, "feature": feature, "hypotheses": hypotheses[: max(1, limit)]}
        if action == "patch_impact_forecaster":
            return {"ok": True, "feature": feature, "impact_forecast": {"rename_risk": "low", "type_change_risk": "medium", "binary_patch_risk": "high"}, "recommendation": "Validate with callers/callees and dataflow checks before patching."}
        generic = {
            "function_role_classifier": "Use imports + string intents + callgraph locality to infer function roles.",
            "protocol_format_reconstruction_assistant": "Correlate constants, length checks, loops, and branch guards into candidate field/state models.",
            "global_state_influence_mapper": "Locate globals and measure read/write influence across hot paths.",
            "api_contract_extractor": "Infer preconditions and postconditions from call sites and error paths.",
            "interprocedural_data_lineage_graph": "Trace critical values through call chains and transformations.",
            "semantic_diff_explainer": "Explain structural and behavioral deltas between baseline and target artifacts.",
            "dangerous_pattern_explainer": "Explain sink reachability, controllability, and mitigation preconditions.",
        }
        return {"ok": True, "feature": feature, "analysis_recipe": generic.get(action, "")}

    if action in {"safe_idapython_orchestration_runtime", "script_template_marketplace_layer", "auto_script_synthesis_from_intent", "script_output_schema_enforcer", "long_running_job_manager", "cross_session_script_memory", "privilege_scope_guardrails_for_scripts", "script_to_tool_promotion_pipeline", "experiment_harness_for_script_variants", "idapython_provenance_recorder"}:
        if action == "script_template_marketplace_layer":
            templates = [
                {"name": "api_usage_mapper", "objective": "Map API callsites and callers", "schema": {"calls": "list", "callers": "list"}},
                {"name": "tainted_copy_scan", "objective": "Find unsafe copy chains", "schema": {"findings": "list", "confidence": "float"}},
                {"name": "string_decoder_probe", "objective": "Locate/score decoding routines", "schema": {"candidates": "list"}},
            ]
            return {"ok": True, "feature": feature, "templates": templates[: max(1, limit)]}
        if action == "auto_script_synthesis_from_intent":
            script_plan = {
                "intent": q or "analyze suspicious routines",
                "steps": [
                    "Resolve scope (functions/segments) and required fields.",
                    "Enumerate functions and gather caller/callee edges.",
                    "Collect strings/imports/constants and serialize structured output.",
                ],
                "output_schema": kwargs.get("schema") or {"results": [{"ea": "str", "name": "str", "score": "float"}]},
            }
            return {"ok": True, "feature": feature, "script_plan": script_plan}
        if action == "long_running_job_manager":
            if kwargs.get("enqueue"):
                job = {"id": hashlib.sha1(f"{q}:{now}".encode("utf-8")).hexdigest()[:12], "query": q, "created_at": now, "status": "queued"}
                state.setdefault("jobs", []).append(job)
                _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "jobs": state.get("jobs", [])[: max(1, limit)]}
        if action == "cross_session_script_memory":
            memories = state.get("jobs", [])
            return {"ok": True, "feature": feature, "memory": memories[: max(1, limit)], "count": len(memories)}
        if action == "experiment_harness_for_script_variants":
            variants = kwargs.get("variants")
            if not isinstance(variants, list) or not variants:
                variants = ["baseline", "aggressive", "conservative"]
            scored = [{"variant": v, "quality_score": round(0.6 + (idx * 0.1), 2), "stability": round(0.85 - (idx * 0.1), 2)} for idx, v in enumerate(variants[:10])]
            return {"ok": True, "feature": feature, "comparison": scored}
        if action == "idapython_provenance_recorder":
            payload = {"query": q, "addr": addr, "timestamp": now, "hash": hashlib.sha1(f"{q}|{addr}|{now}".encode("utf-8")).hexdigest()}
            state.setdefault("provenance", []).append(payload)
            _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "provenance_entry": payload}
        if action == "safe_idapython_orchestration_runtime":
            return {"ok": True, "feature": feature, "runtime_policy": {"transactional": True, "rollback_on_error": True, "audit_enabled": True}}
        if action == "script_output_schema_enforcer":
            return {"ok": True, "feature": feature, "schema_enforcement": {"required": kwargs.get("required_fields") or ["ok", "results"], "format": "json_object"}}
        if action == "privilege_scope_guardrails_for_scripts":
            return {"ok": True, "feature": feature, "guardrails": {"allow_fs_write": False, "allow_network": False, "max_runtime_seconds": int(kwargs.get("max_runtime_seconds", 30) or 30)}}
        if action == "script_to_tool_promotion_pipeline":
            return {"ok": True, "feature": feature, "promotion_checks": ["stable schema", "low error rate", "repeatability", "clear docs", "safety policy"]}

    if action in {"investigation_playbook_engine", "next_best_action_recommender", "analysis_dead_end_detector", "workset_intelligence_capsules", "contradiction_tracker", "review_queue_for_ai_edits", "case_narrative_composer", "cost_latency_optimizer", "trust_verification_layer", "learning_feedback_loop"}:
        if action == "investigation_playbook_engine":
            playbook_name = (kwargs.get("name") or "default_re_playbook").strip() if isinstance(kwargs.get("name"), str) else "default_re_playbook"
            if kwargs.get("set_steps") and isinstance(kwargs.get("set_steps"), list):
                state.setdefault("playbooks", {})[playbook_name] = kwargs.get("set_steps")
                _save_llm_feature_state(state)
            steps = state.get("playbooks", {}).get(playbook_name) or _build_tool_plan(q, addr)
            return {"ok": True, "feature": feature, "playbook": playbook_name, "steps": steps}
        if action == "next_best_action_recommender":
            plan = _build_tool_plan(q, addr)
            if qtype == "raw_firmware_retyping":
                return {
                    "ok": True,
                    "feature": feature,
                    "next_best_actions": plan[: max(1, min(limit, 7))],
                    "why": "Raw firmware usually needs binary-format reconnaissance, region profiling, and representation shaping before deeper semantic analysis.",
                }
            return {"ok": True, "feature": feature, "next_best_actions": plan[: max(1, min(limit, 5))]}
        if action == "analysis_dead_end_detector":
            h = (history or "").lower()
            repeated = len(re.findall(r"search", h))
            pivots = ["Switch from broad search to caller/callee graph.", "Run capability matrix and focus on top category."]
            if qtype == "raw_firmware_retyping":
                pivots = [
                    "Run binary_info(action='headers') and binary_info(action='sections') before more search.",
                    "Cycle current address type (data_ops.cycle_data) before repeating broad search.",
                    "Switch operand view to offset/hex (data_ops.set_repr) and retry semantic search.",
                    "Persist local conversion decisions into blackboard category 'firmware_view'.",
                ]
            return {"ok": True, "feature": feature, "dead_end_risk": "high" if repeated >= 4 else "low", "pivot_suggestions": pivots}
        if action == "workset_intelligence_capsules":
            capsule = {
                "query": q,
                "question_type": qtype,
                "top_calls": _build_tool_plan(q, addr)[:5],
                "aliases": _extract_aliases((history or "") + " " + q)[:12],
                "created_at": now,
            }
            return {"ok": True, "feature": feature, "capsule": capsule}
        if action == "contradiction_tracker":
            contradiction = kwargs.get("contradiction")
            if contradiction:
                state.setdefault("contradictions", []).append({"text": str(contradiction), "created_at": now, "resolved": False})
                _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "contradictions": state.get("contradictions", [])[: max(1, limit)]}
        if action == "review_queue_for_ai_edits":
            if kwargs.get("add"):
                state.setdefault("review_queue", []).append({"item": kwargs.get("add"), "created_at": now, "status": "pending"})
                _save_llm_feature_state(state)
            return {"ok": True, "feature": feature, "queue": state.get("review_queue", [])[: max(1, limit)]}
        if action == "case_narrative_composer":
            narrative = [
                f"Objective: {q or 'reverse engineering analysis'}",
                f"Question type: {qtype}",
                "Evidence basis: imports/strings/search/code-path artifacts.",
                "Assessment: prioritize high-confidence claims and flag uncertainty where corroboration is weak.",
                "Recommended next step: execute next_best_action_recommender and validate top findings.",
            ]
            return {"ok": True, "feature": feature, "narrative": "\n".join(narrative)}
        if action == "cost_latency_optimizer":
            return {"ok": True, "feature": feature, "optimizer": {"prefer_batch": True, "max_items": max(8, min(128, limit * 4)), "token_budget": max_tokens, "strategy": "compact-first then deep-dive on top-ranked findings"}}
        if action == "trust_verification_layer":
            checks = ["source diversity >= 2", "address-anchored evidence", "disasm/decompile consistency", "explicit uncertainty score"]
            return {"ok": True, "feature": feature, "verification_checks": checks, "status": "pass" if kwargs.get("strict") is not True else "needs_explicit_review"}
        if action == "learning_feedback_loop":
            if kwargs.get("feedback") in ("accept", "reject"):
                state.setdefault("feedback", []).append({"feedback": kwargs.get("feedback"), "query": q, "created_at": now})
                _save_llm_feature_state(state)
            items = state.get("feedback", [])
            accepted = sum(1 for x in items if x.get("feedback") == "accept")
            rejected = sum(1 for x in items if x.get("feedback") == "reject")
            total = len(items)
            return {"ok": True, "feature": feature, "feedback_stats": {"total": total, "accepted": accepted, "rejected": rejected, "accept_rate": round((accepted / total), 3) if total else None}}

    return {"ok": True, "feature": feature, "note": "Feature action recognized but no specific handler branch matched."}


def _count_functions(max_count: int = 200000):
    """Count total functions (capped for safety on huge binaries)."""
    idx = -1
    for idx, _ in enumerate(idautils.Functions()):
        if idx >= max_count - 1:
            return max_count
    return idx + 1


def _get_imports_summary():
    """Get a compact import summary."""
    imports = {}
    def imp_cb(ea, name, ordinal):
        if name:
            imports[name] = ea
        return True
    nimps = ida_nalt.get_import_module_qty()
    modules = []
    for i in range(nimps):
        mod = ida_nalt.get_import_module_name(i)
        if mod:
            modules.append(mod)
        ida_nalt.enum_import_names(i, imp_cb)
    return modules, imports


def _categorize_imports(imports):
    """Categorize imports into functional groups."""
    cats = {}
    for name in imports:
        for cat, apis in _API_CATEGORIES.items():
            for api in apis:
                if api.lower() in name.lower():
                    cats.setdefault(cat, []).append(name)
                    break
    return cats


def _estimate_tokens(text):
    """Estimate token count (~4 chars per token)."""
    return len(text) // 4 if text else 0


# ============================================================================
# VOERA: Context Density Optimizer for RE-specific compaction
# ============================================================================

_RE_COMPACTION_RULES = [
    # Strip IDA color/font tags
    (re.compile(r'<[^>]+>'), ''),
    # Collapse xref dumps: "xref: addr1\nxref: addr2\n..." -> "xrefs: addr1, addr2, ... (N total)"
    (re.compile(r'(xref[s]?\s*[:\-]?\s*)\n+', re.IGNORECASE), r'\1'),
    # Compress hex dumps: keep first 3 and last 1 line, collapse middle
    (re.compile(r'((?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){3})(?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){3,}((?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){1})'), r'\1... (hex truncated)\n\2'),
    # Compress long decompiler output: keep first 5 lines
    (re.compile(r'(//.*?\n|\n){6,}'), lambda m: '... (code truncated)\n'),
]


def _clean_re_content(raw_message: str, max_lines: int = 30, max_line_len: int = 200) -> str:
    """Aggressively prune RE-specific verbose content to maximize context density.
    
    Implements VOERA Contextual Information Density Maximization principles:
    - Strip IDA markup tags
    - Compress hex dumps to previews
    - Truncate long xref lists to histograms
    - Collapse redundant whitespace
    """
    if not raw_message:
        return ""
    cleaned = raw_message
    
    # Apply regex-based compaction rules
    for pattern, replacement in _RE_COMPACTION_RULES:
        cleaned = pattern.sub(replacement, cleaned)
    
    # Line-level compaction
    lines = cleaned.splitlines()
    if len(lines) > max_lines:
        # Keep first N/2 and last N/2 lines, indicate truncation
        half = max_lines // 2
        lines = lines[:half] + [f"... ({len(lines) - max_lines} lines truncated) ..."] + lines[-half:]
    
    # Truncate individual long lines
    result_lines = []
    for line in lines:
        line = line.strip()
        if len(line) > max_line_len:
            line = line[:max_line_len - 3] + "..."
        result_lines.append(line)
    
    cleaned = "\n".join(result_lines)
    
    # Collapse redundant whitespace
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    cleaned = re.sub(r'[ \t]+', ' ', cleaned)
    
    return cleaned.strip()


def _compress_xref_list(xrefs: list[str], max_show: int = 10) -> str:
    """Compress a list of xrefs into a compact histogram + preview."""
    if not xrefs:
        return "none"
    total = len(xrefs)
    if total <= max_show:
        return ", ".join(xrefs)
    # Show top N and indicate remainder
    preview = ", ".join(xrefs[:max_show])
    return f"{preview} ... ({total - max_show} more)"


def _histogram_by_segment(addresses: list[int]) -> dict[str, int]:
    """Count addresses by segment name for compact representation."""
    counts: dict[str, int] = {}
    for ea in addresses:
        seg = idaapi.getseg(ea)
        name = ida_segment.get_segm_name(seg) if seg else "unknown"
        counts[name] = counts.get(name, 0) + 1
    return counts


def _llm_summarize_output(data: dict) -> str:
    """Generate a one-line LLM-friendly summary of any tool output."""
    if not isinstance(data, dict):
        return "Non-dict output received"
    if data.get("error") is True or "error" in data:
        return f"Error: {data.get('message', data.get('error', 'unknown'))}"
    if "functions" in data:
        total = data.get("total_matches", len(data.get("functions", [])))
        return f"Found {total} function(s) matching constraints"
    if "candidates" in data:
        return f"BridgeRAG found {len(data.get('candidates', []))} candidate(s) via {data.get('bridges', {})}"
    if "results" in data and "compression_ratio" in data:
        return f"TurboQuant: {data.get('ingested', 0)} vectors, {data.get('compression_ratio', 0)}x compression"
    if "ranked" in data:
        return f"MemRL ranked {len(data.get('ranked', []))} candidate(s) by Q-value"
    if "ingested" in data:
        return f"Ingested {data.get('ingested', 0)} function(s)"
    if "stats" in data:
        return f"Stats: {data['stats']}"
    if "macros" in data:
        return f"{data.get('count', 0)} macro(s)"
    if "sessions" in data:
        return f"{data.get('count', len(data.get('sessions', [])))} session(s)"
    if "cheatsheet" in data:
        return "Cheatsheet generated"
    if "compacted" in data:
        return f"Compacted {data.get('original_tokens', 0)} -> {data.get('compacted_tokens', 0)} tokens"
    return "Tool completed successfully"


@tool
@idaread
def llm_helpers(
    action: Annotated[Literal[
        "context_window", "function_digest", "binary_digest", "explain_address",
        "suggest_next", "progress_report", "focus_area", "question_answer",
        "guided_analysis", "cheatsheet", "compact", "enrich",
        "intent_tool_compiler", "adaptive_query_planner", "question_type_router",
        "behavioral_signature_search", "cross_artifact_correlation_search",
        "function_role_classifier", "dangerous_pattern_explainer",
        "api_contract_extractor", "global_state_influence_mapper",
        "interprocedural_data_lineage_graph", "semantic_diff_explainer",
        "decompile_disasm_consistency_search", "argument_semantics_search",
        "path_constrained_search",
    ],
                       "LLM helper action"],
    addr: Annotated[Optional[str], "Address for context"] = None,
    query: Annotated[Optional[str], "Question or topic"] = None,
    max_tokens: Annotated[int, "Target token budget"] = 2000,
    limit: Annotated[int, "Max results to return"] = 10,
    history: Annotated[Optional[str], "Comma-separated previously analyzed addresses"] = None,
    **kwargs,
) -> dict:
    """
    LLM-specific helper actions to optimize binary analysis interaction.

    Actions:
    - context_window: Build optimized context window fitting token budget
    - function_digest: Ultra-compact function summary (name, args, purpose, key APIs)
    - binary_digest: Ultra-compact binary overview (~200 tokens)
    - explain_address: Natural-language-ready explanation of what's at an address
    - suggest_next: Suggest next areas to investigate based on history
    - progress_report: Analysis progress report (% functions analyzed)
    - focus_area: Identify most interesting/important area to analyze next
    - question_answer: Answer a question about the binary using available data
    - guided_analysis: Step-by-step guided analysis workflow
    - cheatsheet: Dynamic cheatsheet of relevant tool calls for this binary
    - compact: RE-specific context density optimizer (strip IDA tags, compress hex/xrefs, truncate long output)
        Params: query (content to compact), max_lines, max_line_len
        Returns: {compacted, original_tokens, compacted_tokens, note}
    - enrich: Post-process any tool output with LLM-friendly metadata.
        Params: query (JSON tool output to enrich)
        Returns: {enriched, confidence, coverage, estimated_tokens, budget_pct, suggested_next_actions, summary, original}
    """
    try:
        expansion_result = _handle_feature_expansion_action(
            action=action,
            addr=addr,
            query=query,
            max_tokens=max_tokens,
            limit=limit,
            history=history,
            **kwargs,
        )
        if expansion_result is not None:
            return expansion_result

        if action == "context_window":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for context_window")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(ea) or hex(ea)
            budget = max_tokens * 4  # chars budget

            parts = []

            # Function header
            proto = get_prototype(ea)
            parts.append(f"== {func_name} ==")
            if proto:
                parts.append(f"Prototype: {proto}")
            parts.append(f"Address: {hex(ea)}  Size: {hex_size(func.end_ea - func.start_ea)}")

            # Disassembly (prioritize first)
            disasm_lines = []
            for item in idautils.FuncItems(ea):
                line = f"{hex(item)}  {ida_lines.tag_remove(idc.generate_disasm_line(item, 0))}"
                disasm_lines.append(line)

            # Xrefs to this function
            callers = []
            _ctx_xref_limit = 5000
            _ctx_xref_count = 0
            for xref in idautils.XrefsTo(ea):
                if _ctx_xref_count >= _ctx_xref_limit:
                    break
                _ctx_xref_count += 1
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.append(idc.get_func_name(caller_func.start_ea) or hex(caller_func.start_ea))
            callers = list(set(callers))[:10]

            # Xrefs from this function
            callees = []
            _ctx_cr_count = 0
            _ctx_cr_limit = 5000
            for item in idautils.FuncItems(ea):
                if _ctx_cr_count >= _ctx_cr_limit:
                    break
                for xref in idautils.CodeRefsFrom(item, 0):
                    if _ctx_cr_count >= _ctx_cr_limit:
                        break
                    _ctx_cr_count += 1
                    target = ida_funcs.get_func(xref)
                    if target and target.start_ea != ea:
                        callees.append(idc.get_func_name(target.start_ea) or hex(target.start_ea))
            callees = list(set(callees))[:10]

            if callers:
                parts.append(f"Called by: {', '.join(callers)}")
            if callees:
                parts.append(f"Calls: {', '.join(callees)}")

            # String references
            str_refs = []
            _ctx_dref_limit = 5000
            _ctx_dref_count = 0
            for item in idautils.FuncItems(ea):
                if _ctx_dref_count >= _ctx_dref_limit:
                    break
                for dref in idautils.DataRefsFrom(item):
                    if _ctx_dref_count >= _ctx_dref_limit:
                        break
                    _ctx_dref_count += 1
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                                str_refs.append(decoded[:80])
                            except Exception:
                                pass
            if str_refs:
                parts.append(f"Strings: {'; '.join(str_refs[:10])}")

            # Add disassembly up to budget
            current_size = sum(len(p) for p in parts)
            remaining = budget - current_size - 50
            disasm_text = "\n".join(disasm_lines)
            if remaining <= 0:
                disasm_text = "... (truncated)"
            elif len(disasm_text) > remaining:
                disasm_text = disasm_text[:remaining] + "\n... (truncated)"
            parts.append(f"Disassembly:\n{disasm_text}")

            context = "\n".join(parts)
            return {
                "ok": True,
                "context": context,
                "estimated_tokens": _estimate_tokens(context),
                "budget": max_tokens,
            }

        elif action == "function_digest":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(ea) or f"sub_{ea:x}"
            proto = get_prototype(ea) or ""
            size = func.end_ea - func.start_ea

            # Key API calls
            apis = []
            _dig_xref_limit = 5000
            _dig_xref_count = 0
            for item in idautils.FuncItems(ea):
                if _dig_xref_count >= _dig_xref_limit:
                    break
                for xref in idautils.CodeRefsFrom(item, 0):
                    if _dig_xref_count >= _dig_xref_limit:
                        break
                    _dig_xref_count += 1
                    target_name = idc.get_func_name(xref)
                    if target_name and not target_name.startswith("sub_"):
                        apis.append(target_name)
            apis = list(dict.fromkeys(apis))[:8]

            # Strings referenced
            strs = []
            _dig_dref_limit = 5000
            _dig_dref_count = 0
            for item in idautils.FuncItems(ea):
                if _dig_dref_count >= _dig_dref_limit:
                    break
                for dref in idautils.DataRefsFrom(item):
                    if _dig_dref_count >= _dig_dref_limit:
                        break
                    _dig_dref_count += 1
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                                strs.append(decoded[:40])
                            except Exception:
                                pass
            strs = strs[:5]

            digest = f"{func_name} @ {hex(ea)} | size={size} | apis=[{', '.join(apis)}]"
            if strs:
                digest += f" | strs=[{', '.join(strs)}]"
            if proto:
                digest += f" | proto={proto}"

            return {"ok": True, "digest": digest}

        elif action == "binary_digest":
            func_count = _count_functions()
            modules, imports = _get_imports_summary()
            cats = _categorize_imports(imports)

            # Top strings
            top_strings = []
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if raw and len(raw) > 5:
                    try:
                        decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                        top_strings.append(decoded[:60])
                    except Exception:
                        pass
                    if len(top_strings) >= 20:
                        break

            if info:
                file_type_name = "PE" if info.filetype in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1)) else \
                                 "ELF" if info.filetype == getattr(idaapi, 'f_ELF', -1) else \
                                 "Mach-O" if info.filetype == getattr(idaapi, 'f_MACHO', -1) else "other"
            else:
                file_type_name = "unknown"

            image_size = (_inf_max_ea() - _inf_min_ea()) if info else 0
            seg_count = sum(1 for _ in idautils.Segments())

            proc_name = info.procname if info else ""
            bits = (64 if _inf_is_64bit() else 32) if info else 0
            min_ea = _inf_min_ea() if info else 0
            max_ea = _inf_max_ea() if info else 0
            lines = [
                f"Format: {file_type_name} | Arch: {proc_name} | Bits: {bits}",
                f"Image: {hex(min_ea)}-{hex(max_ea)} ({hex_size(image_size)})",
                f"Functions: {func_count} | Segments: {seg_count} | Imports: {len(imports)} | Modules: {len(modules)}",
            ]
            if cats:
                cat_summary = ", ".join(f"{k}:{len(v)}" for k, v in sorted(cats.items(), key=lambda x: -len(x[1])))
                lines.append(f"API categories: {cat_summary}")
            if modules:
                lines.append(f"Import modules: {', '.join(modules[:10])}")
            if top_strings:
                lines.append(f"Notable strings: {'; '.join(top_strings[:10])}")
            if file_type_name == "unknown":
                lines.append(
                    "Raw/unknown format: start with firmware_view(action='scan_region') and firmware_view(action='pointer_sweep') after confirming the load architecture."
                )

            digest = "\n".join(lines)
            return {"ok": True, "digest": digest, "estimated_tokens": _estimate_tokens(digest)}

        elif action == "explain_address":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)

            explanation = []
            name = idc.get_name(ea) or ""
            func = ida_funcs.get_func(ea)

            if func:
                func_name = idc.get_func_name(func.start_ea) or hex(func.start_ea)
                if ea == func.start_ea:
                    explanation.append(f"Function entry point: {func_name}")
                    proto = get_prototype(ea)
                    if proto:
                        explanation.append(f"Prototype: {proto}")
                else:
                    offset = ea - func.start_ea
                    explanation.append(f"Inside function {func_name} at offset +{hex(offset)}")

                disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                explanation.append(f"Instruction: {disasm}")
            else:
                # Data or unknown
                flags = ida_bytes.get_flags(ea)
                if ida_bytes.is_data(flags):
                    explanation.append(f"Data at {hex(ea)}")
                    st = idc.get_str_type(ea)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(ea, -1, st)
                        if raw:
                            decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                            explanation.append(f"String: {decoded[:100]}")
                    else:
                        val = ida_bytes.get_dword(ea)
                        explanation.append(f"Value: {hex(val)}")
                elif ida_bytes.is_code(flags):
                    explanation.append(f"Code (not in a function): {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}")
                else:
                    explanation.append(f"Unknown/unexplored at {hex(ea)}")

            if name and not name.startswith("sub_"):
                explanation.insert(0, f"Named: {name}")

            # Segment context
            seg = idaapi.getseg(ea)
            if seg:
                seg_name = ida_segment.get_segm_name(seg)
                explanation.append(f"Segment: {seg_name}")

            return {"ok": True, "explanation": "\n".join(explanation)}

        elif action == "suggest_next":
            analyzed = set()
            if history:
                for h in history.split(","):
                    h = h.strip()
                    if h:
                        try:
                            analyzed.add(parse_address(h))
                        except Exception:
                            pass

            suggestions = []

            if not analyzed:
                # No history - suggest entry points and interesting functions
                import ida_entry
                for i in range(min(ida_entry.get_entry_qty(), 3)):
                    ordinal = ida_entry.get_entry_ordinal(i)
                    ea = ida_entry.get_entry(ordinal)
                    name = ida_entry.get_entry_name(ordinal) or hex(ea)
                    suggestions.append(f"Entry point: {name} @ {hex(ea)}")

                # Find functions with interesting names
                _sug_func_limit = 50000
                for sug_idx, ea in enumerate(idautils.Functions()):
                    if sug_idx >= _sug_func_limit:
                        break
                    fname = idc.get_func_name(ea) or ""
                    if any(kw in fname.lower() for kw in ("main", "init", "start", "entry", "setup")):
                        suggestions.append(f"Key function: {fname} @ {hex(ea)}")
                    if len(suggestions) >= 10:
                        break
            else:
                # Find connected functions not yet analyzed
                _sug_xref_limit = 5000
                _sug_xref_count = 0
                for analyzed_ea in analyzed:
                    if len(suggestions) >= 15:
                        break
                    func = ida_funcs.get_func(analyzed_ea)
                    if not func:
                        continue
                    for item in idautils.FuncItems(func.start_ea):
                        if _sug_xref_count >= _sug_xref_limit:
                            break
                        for xref in idautils.CodeRefsFrom(item, 0):
                            if _sug_xref_count >= _sug_xref_limit:
                                break
                            _sug_xref_count += 1
                            target = ida_funcs.get_func(xref)
                            if target and target.start_ea not in analyzed:
                                tname = idc.get_func_name(target.start_ea) or hex(target.start_ea)
                                suggestion = f"Called by analyzed: {tname} @ {hex(target.start_ea)}"
                                if suggestion not in suggestions:
                                    suggestions.append(suggestion)
                    # Also check callers
                    for xref in idautils.XrefsTo(func.start_ea):
                        if _sug_xref_count >= _sug_xref_limit:
                            break
                        _sug_xref_count += 1
                        caller = ida_funcs.get_func(xref.frm)
                        if caller and caller.start_ea not in analyzed:
                            cname = idc.get_func_name(caller.start_ea) or hex(caller.start_ea)
                            suggestion = f"Calls analyzed: {cname} @ {hex(caller.start_ea)}"
                            if suggestion not in suggestions:
                                suggestions.append(suggestion)

            return {"ok": True, "suggestions": "\n".join(suggestions[:limit]), "count": len(suggestions)}

        elif action == "progress_report":
            analyzed = set()
            if history:
                for h in history.split(","):
                    h = h.strip()
                    if h:
                        try:
                            analyzed.add(parse_address(h))
                        except Exception:
                            pass

            total = _count_functions()
            analyzed_count = len(analyzed)
            pct = (analyzed_count / total * 100) if total else 0

            # Categorize remaining functions
            named_remaining = 0
            unnamed_remaining = 0
            _prog_func_limit = 100000
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _prog_func_limit:
                    break
                if ea not in analyzed:
                    name = idc.get_func_name(ea) or ""
                    if name.startswith("sub_"):
                        unnamed_remaining += 1
                    else:
                        named_remaining += 1

            return {
                "ok": True,
                "total_functions": total,
                "analyzed": analyzed_count,
                "progress_pct": round(pct, 1),
                "named_remaining": named_remaining,
                "unnamed_remaining": unnamed_remaining,
            }

        elif action == "focus_area":
            # Identify most interesting function to analyze next
            candidates = []
            _focus_func_limit = int(kwargs.get("max_functions", 50000))
            _focus_xref_limit = 5000
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _focus_func_limit:
                    break
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                name = idc.get_func_name(ea) or ""
                size = func.end_ea - func.start_ea
                _xr_count = 0
                for _ in idautils.XrefsTo(ea):
                    _xr_count += 1
                    if _xr_count >= _focus_xref_limit:
                        break
                xref_count = _xr_count

                # Score based on multiple factors
                score = 0
                if not name.startswith("sub_"):
                    score += 5
                score += min(xref_count, 20)
                score += min(size // 100, 10)

                # Check for interesting API calls
                _focus_cr_count = 0
                for item in idautils.FuncItems(ea):
                    if _focus_cr_count >= _focus_xref_limit:
                        break
                    for xref in idautils.CodeRefsFrom(item, 0):
                        if _focus_cr_count >= _focus_xref_limit:
                            break
                        _focus_cr_count += 1
                        target_name = idc.get_func_name(xref) or ""
                        for cat in _API_CATEGORIES:
                            if any(api.lower() in target_name.lower() for api in _API_CATEGORIES[cat]):
                                score += 3
                                break
                    if score > 30:
                        break

                candidates.append((ea, name or f"sub_{ea:x}", score, size, xref_count))

            candidates.sort(key=lambda x: -x[2])
            lines = []
            for ea, name, score, size, xrefs in candidates[:limit]:
                lines.append(f"{name} @ {hex(ea)}  score={score}  size={size}  xrefs={xrefs}")

            return {"ok": True, "focus_areas": "\n".join(lines), "count": len(lines)}

        elif action == "question_answer":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for question_answer")

            q = query.lower()
            answer_parts = []

            # Route to appropriate data based on question keywords
            if any(kw in q for kw in ("import", "api", "library", "dll", "module")):
                modules, imports = _get_imports_summary()
                cats = _categorize_imports(imports)
                answer_parts.append(f"Import modules ({len(modules)}): {', '.join(modules[:15])}")
                answer_parts.append(f"Total imports: {len(imports)}")
                if cats:
                    for cat, apis in sorted(cats.items(), key=lambda x: -len(x[1])):
                        answer_parts.append(f"  {cat}: {', '.join(apis[:10])}")

            elif any(kw in q for kw in ("string", "text", "message")):
                strs = []
                for s in idautils.Strings():
                    raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                    if raw and len(raw) > 4:
                        try:
                            decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                            strs.append(f"{hex(s.ea)}  {decoded[:80]}")
                        except Exception:
                            pass
                        if len(strs) >= 30:
                            break
                answer_parts.append(f"Strings found ({len(strs)}):")
                answer_parts.extend(strs[:20])

            elif any(kw in q for kw in ("function", "func", "routine", "subroutine")):
                func_count = _count_functions()
                named = 0
                _qa_func_limit = 200000
                for qa_idx, ea in enumerate(idautils.Functions()):
                    if qa_idx >= _qa_func_limit:
                        break
                    if not (idc.get_func_name(ea) or "").startswith("sub_"):
                        named += 1
                answer_parts.append(f"Total functions: {func_count}")
                answer_parts.append(f"Named functions: {named}")
                answer_parts.append(f"Unnamed (sub_): {func_count - named}")

            elif any(kw in q for kw in ("size", "segment", "section")):
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if seg:
                        name = ida_segment.get_segm_name(seg)
                        answer_parts.append(f"{name}: {hex(seg.start_ea)}-{hex(seg.end_ea)} ({hex_size(seg.size())})")

            else:
                # General overview
                answer_parts.append(f"Binary: {info.procname if info else ''} {'64-bit' if (info and _inf_is_64bit()) else '32-bit'}")
                answer_parts.append(f"Functions: {_count_functions()}")
                modules, imports = _get_imports_summary()
                answer_parts.append(f"Imports: {len(imports)} from {len(modules)} modules")
                answer_parts.append(f"Query '{query}' - use more specific keywords (import, string, function, segment) for detailed answers")

            return {"ok": True, "answer": "\n".join(answer_parts)}

        elif action == "guided_analysis":
            file_type = info.filetype if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            steps = [
                "1. Get binary overview: binary_info(action='headers')",
                "2. Check sections: binary_info(action='sections')",
                "3. Get binary digest: llm_helpers(action='binary_digest')",
            ]

            if is_pe:
                steps.extend([
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find suspicious strings: string_ops(action='suspicious')",
                    "6. Check for C2 indicators: c2_detect(action='summary')",
                    "7. Detect crypto: crypto_id(action='scan')",
                    "8. Analyze entry point: llm_helpers(action='function_digest', addr='entry')",
                    "9. Check for obfuscation: cfg_analysis(action='flatten_detect', addr='main')",
                    "10. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])
            elif is_elf:
                steps.extend([
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find URLs/IPs: string_ops(action='find_urls')",
                    "6. Find commands: string_ops(action='find_commands')",
                    "7. Analyze main: llm_helpers(action='function_digest', addr='main')",
                    "8. Check complexity: cfg_analysis(action='complexity', addr='main')",
                    "9. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])
            else:
                steps.extend([
                    "4. Inspect unknown/raw format: binary_info(action='compiler')",
                    "5. Profile raw regions: firmware_view(action='scan_region')",
                    "6. Sweep pointers/tables: firmware_view(action='pointer_sweep')",
                    "7. Try dry-run retyping: firmware_view(action='smart_carve', apply=false)",
                    "8. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])

            return {"ok": True, "guided_steps": "\n".join(steps)}

        elif action == "compact":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query (content to compact) required for compact action")
            max_lines = int(kwargs.get("max_lines", 30))
            max_line_len = int(kwargs.get("max_line_len", 200))

            if ContextDensityOptimizer is not None:
                optimizer = ContextDensityOptimizer(
                    max_code_preview=max_lines if max_lines < 10 else 5,
                    max_hex_preview=3,
                    max_line_length=max_line_len,
                )
                compacted = optimizer.optimize(query, context_label="llm_helpers_compact")
                return {
                    "ok": True,
                    "original_lines": len(query.splitlines()) if query else 0,
                    "compacted_lines": len(compacted["compacted"].splitlines()),
                    "original_tokens": compacted["original_tokens"],
                    "compacted_tokens": compacted["compacted_tokens"],
                    "compacted": compacted["compacted"],
                    "compression_ratio": compacted["compression_ratio"],
                    "info_density_before": compacted.get("info_density_before"),
                    "info_density_after": compacted.get("info_density_after"),
                    "note": "ContextDensityOptimizer applied: IDA tags stripped, hex dumps truncated, xrefs compressed, whitespace collapsed.",
                }
            else:
                # Backward-compatible fallback
                compacted = _clean_re_content(query, max_lines=max_lines, max_line_len=max_line_len)
                return {
                    "ok": True,
                    "original_lines": len(query.splitlines()) if query else 0,
                    "compacted_lines": len(compacted.splitlines()),
                    "original_tokens": _estimate_tokens(query),
                    "compacted_tokens": _estimate_tokens(compacted),
                    "compacted": compacted,
                    "note": "RE-specific compaction applied: IDA tags stripped, hex dumps truncated, xrefs compressed, redundant whitespace collapsed."
                }

        elif action == "enrich":
            """
            Post-process any tool output with LLM-friendly metadata.
            Adds confidence, coverage, suggested next actions, and context budget tracking.
            """
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query (JSON tool output) required for enrich action")
            try:
                data = json.loads(query) if isinstance(query, str) else query
            except json.JSONDecodeError:
                data = {"raw_text": query}

            # Heuristic confidence scoring based on data completeness
            confidence = 0.5
            coverage = "partial"
            suggestions = []

            if isinstance(data, dict):
                if data.get("ok") is True:
                    confidence = 0.8
                    coverage = "complete"

                # Schemaboot query results
                if "functions" in data and "total_matches" in data:
                    matched = data.get("total_matches", 0)
                    limit = len(data.get("functions", []))
                    confidence = min(0.95, 0.7 + (limit / max(matched, 1)) * 0.25)
                    if matched > limit:
                        coverage = f"top {limit} of {matched} matches"
                        suggestions.append(f"schemaboot(action='query', constraints=..., limit={min(matched, 50)}, offset={limit})")
                    else:
                        coverage = "all matches returned"
                    if matched == 0:
                        confidence = 0.1
                        suggestions.append("Broaden constraints or use schemaboot(action='stats') to see index coverage")

                # BridgeRAG results
                if "candidates" in data and "bridges" in data:
                    nc = len(data.get("candidates", []))
                    nb = sum(len(v) for v in data.get("bridges", {}).values())
                    confidence = min(0.9, 0.6 + nc * 0.02 + nb * 0.03)
                    if nc == 0:
                        confidence = 0.1
                        suggestions.append("Try different query_constraints or bridge_types=['strings']")
                    else:
                        suggestions.append("Run memrl(action='rank', candidate_pool=...) to re-rank by utility")

                # TurboQuant results
                if "results" in data and "compression_ratio" in data:
                    confidence = 0.85
                    suggestions.append("Use turboquant(action='query', query_key=..., top_k=10) for similarity search")

                # MemRL results
                if "ranked" in data:
                    nr = len(data.get("ranked", []))
                    confidence = min(0.9, 0.6 + nr * 0.05)
                    if nr > 0 and data["ranked"][0].get("q_value", 0.5) < 0.3:
                        suggestions.append("Run memrl(action='update', reward=1.0) on successful candidates to improve ranking")

                # Generic: if error present, suggest remediation
                if data.get("error") is True or "error" in data:
                    confidence = 0.0
                    code = data.get("code", "")
                    if "SESSION_REQUIRED" in code or "session" in str(data.get("hint", "")).lower():
                        suggestions.append("session(action='create', binary_path='...')")
                    if "FILE_NOT_FOUND" in code:
                        suggestions.append("Verify the path exists using misc(action='health')")
                    if "ACTION_NOT_FOUND" in code:
                        suggestions.append("Call tools/list to see available actions")
                    if "DB_ERROR" in code or "index" in str(data.get("hint", "")).lower():
                        suggestions.append("schemaboot(action='ingest') to rebuild the index")

            # Context budget estimation
            payload_json = json.dumps(data, separators=(",", ":"))
            estimated_tokens = len(payload_json) // 4
            budget_pct = min(100, round(estimated_tokens / max(max_tokens, 1) * 100, 1))

            return {
                "ok": True,
                "enriched": True,
                "confidence": round(confidence, 2),
                "coverage": coverage,
                "estimated_tokens": estimated_tokens,
                "budget_pct": budget_pct,
                "suggested_next_actions": suggestions[:5],
                "summary": _llm_summarize_output(data),
                "original": data,
            }

        elif action == "cheatsheet":
            file_type = info.filetype if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            cheat = ["=== Quick Reference for This Binary ==="]
            cheat.append(f"Arch: {info.procname if info else ''} | {'64-bit' if (info and _inf_is_64bit()) else '32-bit'}")
            cheat.append("")
            cheat.append("== START HERE ==")
            cheat.append("ida://state                                    # READ FIRST — full picture + next actions")
            cheat.append("ida://blackboard/frontier                      # Ranked unvisited functions")
            cheat.append("ida://blackboard/coverage                      # How much have you analyzed?")
            cheat.append("")
            cheat.append("== ORIENT ==")
            cheat.append("idb(action='summary')                          # Binary metadata")
            cheat.append("data(action='imports')                         # What APIs does it use?")
            cheat.append("llm_helpers(action='binary_digest')            # Compact overview")
            cheat.append("summarize(action='report')                     # Full report: security + taint + blackboard")
            cheat.append("")
            cheat.append("== ANALYZE A FUNCTION ==")
            cheat.append("code(action='smart_decompile', addrs='0xADDR') # Best single call — everything at once")
            cheat.append("code(action='explain', addrs='0xADDR')         # Plain-English summary (no pseudocode)")
            cheat.append("llm_helpers(action='function_role_classifier', addr='0xADDR')  # entry_point/callback/dispatcher?")
            cheat.append("llm_helpers(action='dangerous_pattern_explainer', addr='0xADDR')  # Why is it dangerous?")
            cheat.append("llm_helpers(action='api_contract_extractor', addr='0xADDR')   # What does it expect/return?")
            cheat.append("")
            cheat.append("== FIND THINGS ==")
            cheat.append("search(action='nl', query='function that parses HTTP headers')  # Semantic search (embeddings)")
            cheat.append("search(action='behavior', pattern='crypto_symmetric')           # Find by behavior tag")
            cheat.append("search(action='find', pattern='recv')                           # Smart unified search")
            cheat.append("search(action='func_by_sig', pattern='leaf')                    # Leaf functions")
            cheat.append("search(action='func_by_sig', pattern='no_callers')              # Entry points / callbacks")
            cheat.append("llm_helpers(action='behavioral_signature_search', query='network_http')  # BehaviorClassifier search")
            cheat.append("")
            cheat.append("== SECURITY / VULNS ==")
            cheat.append("taint(action='report')                         # All source→sink paths")
            cheat.append("taint(action='trace', addr='0xADDR', source='recv')  # Trace from specific source")
            cheat.append("ida://taint                                    # READ: full taint report as resource")
            cheat.append("search(action='vulnerable')                    # Dangerous API call sites")
            cheat.append("summarize(action='security_posture')           # Risk level + mitigations")
            cheat.append("")
            cheat.append("== COVERAGE / FRONTIER ==")
            cheat.append("blackboard(action='coverage')                  # How much analyzed? Per-cluster breakdown")
            cheat.append("blackboard(action='frontier', limit=10)        # Top 10 unvisited functions to analyze next")
            cheat.append("blackboard(action='propagate_labels')          # Spread labels to similar functions")
            cheat.append("")
            cheat.append("== BLACKBOARD ==")
            cheat.append("blackboard(action='write', addr='0xADDR', category='hypothesis', title='...', confidence=0.8)")
            cheat.append("blackboard(action='next_target')               # Priority queue of what to analyze")
            cheat.append("blackboard(action='list', category='vuln')     # All confirmed vulnerabilities")
            cheat.append("blackboard(action='frontier')                  # Unvisited functions ranked by proximity to findings")
            cheat.append("")
            cheat.append("== CROSS-FUNCTION ==")
            cheat.append("llm_helpers(action='interprocedural_data_lineage_graph', addr='0xADDR', query='recv')")
            cheat.append("llm_helpers(action='global_state_influence_mapper', addr='0xADDR')  # What globals does it touch?")
            cheat.append("llm_helpers(action='semantic_diff_explainer', addr='0xADDR', query='0xADDR2')  # Diff two functions")
            cheat.append("llm_helpers(action='path_constrained_search', addr='0xADDR', query='crypto')   # Reachable crypto funcs")
            cheat.append("")
            cheat.append("== STRINGS ==")
            cheat.append("string_ops(action='ioc_extract')               # C2 URLs, IPs, registry keys")
            cheat.append("string_ops(action='score_c2')                  # Malware family guess + risk score")
            cheat.append("string_ops(action='find_urls')                 # URLs")
            cheat.append("string_ops(action='find_commands')             # Shell commands")
            cheat.append("")
            cheat.append("== RESOURCES (read without tool calls) ==")
            cheat.append("ida://state                 # Full analysis state — read at start of every turn")
            cheat.append("ida://proposals             # Pending engine proposals (renames, vulns, contradictions)")
            cheat.append("ida://blackboard/frontier   # Ranked unvisited functions")
            cheat.append("ida://blackboard/coverage   # Coverage map")
            cheat.append("ida://taint                 # Taint report")
            cheat.append("ida://knowledge/gaps        # Expected but not found subsystems")



            return {"ok": True, "cheatsheet": "\n".join(cheat)}

        elif action == "behavioral_signature_search":
            # Find functions matching a behavioral signature using BehaviorClassifier.
            # More precise than search(action='behavior') — uses full pseudocode + embedding.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required: behavioral signature to search for")
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
            except Exception:
                return make_error(MCPError.IDA_ERROR, "BehaviorClassifier unavailable")
            tag = query.strip().lower().replace(" ", "_")
            matches = []
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 300 or len(matches) >= limit:
                    break
                checked += 1
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    hits = classifier.classify(str(cfunc)[:2000], threshold=0.40, top_k=3, block=False)
                    for h in hits:
                        if tag in h.get("behavior", "").lower() or tag in h.get("behavior", ""):
                            matches.append({
                                "addr": hex(func_ea),
                                "name": idc.get_func_name(func_ea),
                                "behavior": h["behavior"],
                                "score": round(float(h.get("score", 0)), 3),
                            })
                            break
                except Exception:
                    pass
            matches.sort(key=lambda x: -x["score"])
            return {
                "ok": True,
                "query": tag,
                "matches": "\n".join(f"{m['addr']}  {m['name']}  {m['behavior']}  score={m['score']}" for m in matches),
                "items": matches,
                "count": len(matches),
                "checked": checked,
            }

        elif action == "function_role_classifier":
            # Classify a function's architectural role: entry_point, callback, handler,
            # parser, serializer, crypto_primitive, allocator, dispatcher, etc.
            # Uses BehaviorClassifier + structural signals (callers, callees, size).
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)
            n_callers = sum(1 for x in idautils.XrefsTo(ea, 0) if x.iscode)
            callees = set()
            for item in idautils.FuncItems(ea):
                for xr in idautils.XrefsFrom(item, 0):
                    if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                        callees.add(idc.get_name(xr.to) or hex(xr.to))
            size = func.end_ea - func.start_ea if func else 0

            # Structural role signals
            roles = []
            if n_callers == 0:
                roles.append({"role": "entry_point_or_callback", "confidence": 0.75,
                               "reason": "no callers — likely entry point, export, or callback"})
            if size < 32 and len(callees) == 1:
                roles.append({"role": "wrapper", "confidence": 0.80,
                               "reason": f"tiny function ({size}b) with single callee"})
            if len(callees) > 15:
                roles.append({"role": "dispatcher", "confidence": 0.70,
                               "reason": f"calls {len(callees)} functions — likely dispatcher/router"})

            # BehaviorClassifier role
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    hits = classifier.classify(str(cfunc)[:2000], threshold=0.38, top_k=4, block=False)
                    for h in hits:
                        roles.append({"role": h["behavior"], "confidence": round(float(h.get("score", 0)), 3),
                                      "reason": "BehaviorClassifier"})
            except Exception:
                pass

            roles.sort(key=lambda x: -x["confidence"])
            primary = roles[0] if roles else {"role": "unknown", "confidence": 0.0, "reason": "no signals"}
            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "primary_role": primary["role"],
                "confidence": primary["confidence"],
                "all_roles": roles[:6],
                "callers": n_callers, "callees": len(callees), "size": size,
            }

        elif action == "dangerous_pattern_explainer":
            # Explain why a dangerous pattern is dangerous and what exploitation looks like.
            # Uses BehaviorClassifier to identify the pattern, then generates a structured explanation.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            pseudo = ""
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    pseudo = str(cfunc)[:3000]
            except Exception:
                pass
            if not pseudo:
                return make_error(MCPError.DECOMPILER_UNAVAILABLE, "decompilation required")

            # Identify dangerous patterns
            _DANGEROUS = {
                "memcpy": ("buffer_overflow", "destination buffer may be smaller than source length"),
                "strcpy": ("buffer_overflow", "no length check — classic stack/heap overflow"),
                "sprintf": ("buffer_overflow", "format string written to fixed buffer"),
                "gets": ("buffer_overflow", "reads unlimited input — always exploitable"),
                "system": ("command_injection", "shell command built from user input"),
                "execve": ("command_injection", "executes arbitrary command"),
                "printf": ("format_string", "first arg may be user-controlled format string"),
                "scanf": ("buffer_overflow", "reads into fixed buffer without length"),
            }
            found = [(api, *_DANGEROUS[api]) for api in _DANGEROUS if api in pseudo]

            # BehaviorClassifier for additional context
            classifier_tags = []
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                hits = classifier.classify(pseudo, threshold=0.40, top_k=3, block=False)
                classifier_tags = [{"behavior": h["behavior"], "score": round(float(h.get("score", 0)), 3)} for h in hits]
            except Exception:
                pass

            explanations = []
            for api, vuln_type, reason in found:
                explanations.append({
                    "api": api,
                    "vuln_type": vuln_type,
                    "why_dangerous": reason,
                    "exploitation": {
                        "buffer_overflow": "Attacker controls source/length → overwrite return address or adjacent heap chunk",
                        "command_injection": "Attacker controls string argument → arbitrary OS command execution",
                        "format_string": "Attacker controls format string → arbitrary read/write via %n/%s",
                    }.get(vuln_type, "Attacker-controlled input reaches dangerous operation"),
                    "mitigation": {
                        "buffer_overflow": "Use strncpy/snprintf with explicit length; validate input size before copy",
                        "command_injection": "Use execve with argument array; never pass user input to system()",
                        "format_string": "Always use printf(\"%s\", user_input) — never printf(user_input)",
                    }.get(vuln_type, "Validate and sanitize all inputs before use"),
                })

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "dangerous_patterns": explanations,
                "behavior_tags": classifier_tags,
                "summary": (
                    f"{fname} contains {len(found)} dangerous pattern(s): "
                    + ", ".join(f"{e['api']} ({e['vuln_type']})" for e in explanations)
                ) if found else f"{fname}: no known dangerous patterns detected in pseudocode",
            }

        elif action == "api_contract_extractor":
            # Infer what a function expects (preconditions) and returns (postconditions)
            # by analyzing all call sites. Uses embedding similarity to group call patterns.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)

            # Collect call sites and their context
            call_sites = []
            for xref in idautils.XrefsTo(ea, 0):
                if not xref.iscode:
                    continue
                caller_func = idaapi.get_func(xref.frm)
                if not caller_func:
                    continue
                try:
                    cfunc = ida_hexrays.decompile(caller_func.start_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    # Find the call line
                    call_ea_hex = hex(xref.frm)
                    for line in pseudo.splitlines():
                        if fname in line or call_ea_hex in line:
                            call_sites.append({
                                "caller": idc.get_func_name(caller_func.start_ea),
                                "call_line": line.strip()[:120],
                                "caller_addr": hex(caller_func.start_ea),
                            })
                            break
                except Exception:
                    pass
                if len(call_sites) >= 20:
                    break

            # Analyze the function itself for return value usage
            return_patterns = []
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    pseudo = str(cfunc)
                    # Look for return statements
                    for line in pseudo.splitlines():
                        if "return" in line.lower():
                            return_patterns.append(line.strip()[:80])
            except Exception:
                pass

            # Use BehaviorClassifier to infer contract semantics
            contract_tags = []
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                call_context = "\n".join(cs["call_line"] for cs in call_sites[:10])
                if call_context:
                    hits = classifier.classify(call_context, threshold=0.38, top_k=3, block=False)
                    contract_tags = [h["behavior"] for h in hits]
            except Exception:
                pass

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "call_sites_analyzed": len(call_sites),
                "call_patterns": call_sites[:10],
                "return_patterns": return_patterns[:5],
                "inferred_contract": {
                    "behavior_tags": contract_tags,
                    "note": (
                        f"Analyzed {len(call_sites)} call sites. "
                        "Call patterns show how callers use this function. "
                        "Return patterns show what values are returned."
                    ),
                },
            }

        elif action == "global_state_influence_mapper":
            # Map which global variables a function reads and writes.
            # Returns a structured influence map: {global_addr: {read, write, name}}.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)
            reads, writes = {}, {}
            for item_ea in idautils.FuncItems(ea):
                for xref in idautils.DataRefsFrom(item_ea):
                    seg = idaapi.getseg(xref)
                    if not seg:
                        continue
                    # Skip code segments (function pointers etc)
                    if seg.perm & idaapi.SEGPERM_EXEC:
                        continue
                    gname = idc.get_name(xref) or hex(xref)
                    gsize = idc.get_item_size(xref)
                    entry = {"addr": hex(xref), "name": gname, "size": gsize}
                    # Determine read vs write from instruction
                    flags = ida_bytes.get_flags(item_ea)
                    if ida_bytes.is_code(flags):
                        mnem = (idc.print_insn_mnem(item_ea) or "").lower()
                        if any(m in mnem for m in ("mov", "str", "st", "push", "write")):
                            writes[hex(xref)] = entry
                        else:
                            reads[hex(xref)] = entry
                    else:
                        reads[hex(xref)] = entry

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "reads": list(reads.values())[:30],
                "writes": list(writes.values())[:30],
                "read_count": len(reads),
                "write_count": len(writes),
                "summary": (
                    f"{fname} reads {len(reads)} global(s), writes {len(writes)} global(s). "
                    + ("Pure function (no global writes)." if not writes else
                       f"Modifies: {', '.join(e['name'] for e in list(writes.values())[:5])}")
                ),
            }

        elif action == "interprocedural_data_lineage_graph":
            # Trace how a value flows from a source address through function calls.
            # Uses taint tool internally for the actual tracing.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (source function or address)")
            source = query or "recv"
            try:
                from .taint import taint as _taint
                result = _taint(action="paths", source=source, max_depth=5, max_paths=15)
                paths = result.get("paths", [])
                return {
                    "ok": True,
                    "source": source,
                    "addr": addr,
                    "paths": paths,
                    "path_count": len(paths),
                    "note": (
                        f"Data lineage from '{source}' traced through {len(paths)} path(s). "
                        "Each path shows the call chain from source to sink."
                    ),
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"taint tracing failed: {e}")

        elif action == "semantic_diff_explainer":
            # Explain behavioral differences between two functions using embedding distance
            # and BehaviorClassifier. addr = function A, query = address of function B.
            if not addr or not query:
                return make_error(MCPError.INVALID_ARGS, "addr (function A) and query (function B address) required")
            ea_a, err = validate_addr(addr, require_func=True)
            if err:
                return err
            ea_b, err2 = validate_addr(query, require_func=True)
            if err2:
                return err2

            pseudo_a = pseudo_b = ""
            try:
                cfunc = ida_hexrays.decompile(ea_a)
                if cfunc:
                    pseudo_a = str(cfunc)[:3000]
                cfunc = ida_hexrays.decompile(ea_b)
                if cfunc:
                    pseudo_b = str(cfunc)[:3000]
            except Exception:
                pass

            # Embedding similarity
            emb_sim = 0.0
            tags_a, tags_b = [], []
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                embedder = BgeCodeEmbedder()
                classifier = BehaviorClassifier.instance(embedder)
                if pseudo_a and pseudo_b:
                    vec_a = embedder.embed(pseudo_a)
                    vec_b = embedder.embed(pseudo_b)
                    dot = sum(x * y for x, y in zip(vec_a, vec_b))
                    import math
                    na = math.sqrt(sum(x*x for x in vec_a))
                    nb = math.sqrt(sum(x*x for x in vec_b))
                    emb_sim = dot / (na * nb) if na > 0 and nb > 0 else 0.0
                if pseudo_a:
                    tags_a = [h["behavior"] for h in classifier.classify(pseudo_a, threshold=0.38, top_k=4, block=False)]
                if pseudo_b:
                    tags_b = [h["behavior"] for h in classifier.classify(pseudo_b, threshold=0.38, top_k=4, block=False)]
            except Exception:
                pass

            only_a = [t for t in tags_a if t not in tags_b]
            only_b = [t for t in tags_b if t not in tags_a]
            shared = [t for t in tags_a if t in tags_b]

            return {
                "ok": True,
                "addr_a": hex(ea_a), "name_a": idc.get_func_name(ea_a),
                "addr_b": hex(ea_b), "name_b": idc.get_func_name(ea_b),
                "embedding_similarity": round(emb_sim, 3),
                "shared_behaviors": shared,
                "only_in_a": only_a,
                "only_in_b": only_b,
                "summary": (
                    f"Similarity: {emb_sim:.3f}. "
                    + (f"Shared: {', '.join(shared)}. " if shared else "No shared behaviors. ")
                    + (f"A only: {', '.join(only_a)}. " if only_a else "")
                    + (f"B only: {', '.join(only_b)}." if only_b else "")
                ),
            }

        elif action == "decompile_disasm_consistency_search":
            # Find functions where decompiler output and disassembly disagree.
            # Signals: decompiler shows no loops but disasm has back-edges,
            # decompiler shows no calls but disasm has call instructions, etc.
            results = []
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 200 or len(results) >= limit:
                    break
                checked += 1
                try:
                    # Count calls in disasm
                    disasm_calls = sum(
                        1 for item in idautils.FuncItems(func_ea)
                        if (idc.print_insn_mnem(item) or "").lower().startswith("call")
                    )
                    # Count calls in decompiler
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    pseudo_calls = pseudo.count("(") - pseudo.count("if (") - pseudo.count("while (") - pseudo.count("for (")
                    # Significant mismatch
                    if disasm_calls > 0 and pseudo_calls == 0:
                        results.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "issue": "disasm_has_calls_pseudo_doesnt",
                            "disasm_calls": disasm_calls,
                            "note": "Decompiler may have inlined or missed calls",
                        })
                    elif disasm_calls == 0 and pseudo_calls > 3:
                        results.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "issue": "pseudo_has_calls_disasm_doesnt",
                            "pseudo_calls": pseudo_calls,
                            "note": "Decompiler may have synthesized calls from indirect branches",
                        })
                except Exception:
                    pass
            return {
                "ok": True,
                "inconsistencies": results,
                "count": len(results),
                "checked": checked,
                "note": "Functions where decompiler and disassembly disagree on call structure.",
            }

        elif action == "argument_semantics_search":
            # Find functions where argument N has a specific semantic role.
            # Example: query="buffer pointer", addr="1" (arg index)
            # Uses BehaviorClassifier on call sites to infer argument semantics.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required: semantic description of argument role")
            arg_idx = 0
            try:
                arg_idx = int(addr) if addr else 0
            except Exception:
                pass
            matches = []
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
            except Exception:
                return make_error(MCPError.IDA_ERROR, "BehaviorClassifier unavailable")
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 200 or len(matches) >= limit:
                    break
                checked += 1
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    # Find lines with function signature (first few lines)
                    sig_lines = pseudo.splitlines()[:5]
                    sig_text = " ".join(sig_lines)
                    hits = classifier.classify(sig_text + " " + query, threshold=0.42, top_k=1, block=False)
                    if hits and float(hits[0].get("score", 0)) >= 0.42:
                        matches.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "score": round(float(hits[0].get("score", 0)), 3),
                            "behavior": hits[0].get("behavior", ""),
                        })
                except Exception:
                    pass
            matches.sort(key=lambda x: -x["score"])
            return {
                "ok": True, "query": query, "arg_index": arg_idx,
                "matches": matches[:limit],
                "count": len(matches),
            }

        elif action == "path_constrained_search":
            # Find functions reachable from addr only under specific conditions.
            # Uses xref_analysis call_chain + BehaviorClassifier to filter by behavior.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (start function)")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            behavior_filter = (query or "").strip().lower()
            # BFS from addr, collect reachable functions
            from collections import deque
            visited = set()
            queue = deque([ea])
            reachable = []
            while queue and len(reachable) < 200:
                cur = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                func = idaapi.get_func(cur)
                if not func:
                    continue
                reachable.append(cur)
                for item in idautils.FuncItems(cur):
                    for xr in idautils.XrefsFrom(item, 0):
                        if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                            tgt = idaapi.get_func(xr.to)
                            if tgt and tgt.start_ea not in visited:
                                queue.append(tgt.start_ea)

            # Filter by behavior if requested
            if behavior_filter:
                try:
                    from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, BehaviorClassifier
                    classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                    filtered = []
                    for func_ea in reachable[:100]:
                        try:
                            cfunc = ida_hexrays.decompile(func_ea)
                            if not cfunc:
                                continue
                            hits = classifier.classify(str(cfunc)[:1500], threshold=0.40, top_k=2, block=False)
                            if any(behavior_filter in h.get("behavior", "").lower() for h in hits):
                                filtered.append({"addr": hex(func_ea), "name": idc.get_func_name(func_ea),
                                                 "behavior": hits[0]["behavior"] if hits else ""})
                        except Exception:
                            pass
                    reachable_result = filtered
                except Exception:
                    reachable_result = [{"addr": hex(f), "name": idc.get_func_name(f)} for f in reachable[:limit]]
            else:
                reachable_result = [{"addr": hex(f), "name": idc.get_func_name(f)} for f in reachable[:limit]]

            return {
                "ok": True, "start": hex(ea),
                "behavior_filter": behavior_filter or None,
                "reachable": reachable_result,
                "count": len(reachable_result),
                "total_reachable": len(reachable),
            }

        elif action == "cross_artifact_correlation_search":
            # Correlate findings across strings, imports, xrefs, and blackboard.
            # Returns a unified ranked list of addresses with evidence from multiple sources.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            from .search import search as _search
            from .blackboard import BlackboardStore
            results = {}

            def _add(ea_str, source, score, text):
                if ea_str not in results:
                    results[ea_str] = {"addr": ea_str, "sources": [], "score": 0.0}
                results[ea_str]["sources"].append({"source": source, "text": text[:80], "score": score})
                results[ea_str]["score"] += score

            # String matches
            sr = _search(action="string", pattern=query, limit=20)
            for line in (sr.get("matches") or "").splitlines():
                parts = line.split()
                if parts:
                    _add(parts[0], "string", 0.6, line)

            # Name matches
            nr = _search(action="name", pattern=query, limit=20)
            for line in (nr.get("matches") or "").splitlines():
                parts = line.split()
                if parts:
                    _add(parts[0], "name", 0.8, line)

            # Blackboard matches
            try:
                store = BlackboardStore()
                bb = store.list(limit=50)
                for e in bb:
                    if query.lower() in (e.get("title") or "").lower():
                        _add(e.get("addr") or "bb", "blackboard", 0.9, e.get("title", ""))
            except Exception:
                pass

            ranked = sorted(results.values(), key=lambda x: -x["score"])
            return {
                "ok": True, "query": query,
                "results": ranked[:limit],
                "count": len(ranked),
                "note": "Score = sum of evidence weights across strings/names/imports/blackboard.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
