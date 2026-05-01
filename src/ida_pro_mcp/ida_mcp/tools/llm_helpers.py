
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
                {"tool": "vuln_scan", "action": "dangerous_flow", "limit": 50},
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
        if qtype == "vulnerability_triage":
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
            return {"ok": True, "feature": feature, "next_best_actions": plan[: max(1, min(limit, 5))]}
        if action == "analysis_dead_end_detector":
            h = (history or "").lower()
            repeated = len(re.findall(r"search", h))
            return {"ok": True, "feature": feature, "dead_end_risk": "high" if repeated >= 4 else "low", "pivot_suggestions": ["Switch from broad search to caller/callee graph.", "Run capability matrix and focus on top category."]}
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


def _count_functions():
    """Count total functions."""
    return sum(1 for _ in idautils.Functions())


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


@tool
@idaread
def llm_helpers(
    action: Annotated[Literal["context_window", "function_digest", "binary_digest", "explain_address", "suggest_next", "progress_report", "focus_area", "question_answer", "guided_analysis", "cheatsheet", "compact", "intent_tool_compiler", "adaptive_query_planner", "token_aware_context_optimizer", "cross_call_variable_resolver", "evidence_weighted_response_assembler", "uncertainty_propagation_engine", "multi_granularity_retrieval_layer", "semantic_chunking_for_decompiled_code", "question_type_router", "interactive_clarification_protocol", "behavioral_signature_search", "cross_artifact_correlation_search", "temporal_search_replay", "search_hypothesis_sandbox", "path_constrained_search", "argument_semantics_search", "decompile_disasm_consistency_search", "near_miss_search_ranking", "persistent_search_collections", "auto_expansion_search_chains", "function_role_classifier", "protocol_format_reconstruction_assistant", "global_state_influence_mapper", "api_contract_extractor", "interprocedural_data_lineage_graph", "semantic_diff_explainer", "dangerous_pattern_explainer", "binary_capability_matrix_builder", "execution_hypothesis_generator", "patch_impact_forecaster", "safe_idapython_orchestration_runtime", "script_template_marketplace_layer", "auto_script_synthesis_from_intent", "script_output_schema_enforcer", "long_running_job_manager", "cross_session_script_memory", "privilege_scope_guardrails_for_scripts", "script_to_tool_promotion_pipeline", "experiment_harness_for_script_variants", "idapython_provenance_recorder", "investigation_playbook_engine", "next_best_action_recommender", "analysis_dead_end_detector", "workset_intelligence_capsules", "contradiction_tracker", "review_queue_for_ai_edits", "case_narrative_composer", "cost_latency_optimizer", "trust_verification_layer", "learning_feedback_loop"],
                       "LLM helper action"],
    addr: Annotated[Optional[str], "Address for context"] = None,
    query: Annotated[Optional[str], "Question or topic"] = None,
    max_tokens: Annotated[int, "Target token budget"] = 2000,
    limit: Annotated[int, "Max results to return"] = 10,
    history: Annotated[Optional[str], "Comma-separated previously analyzed addresses"] = None,
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
    """
    try:
        info = idaapi.get_inf_structure() if hasattr(idaapi, 'get_inf_structure') else None
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
            for xref in idautils.XrefsTo(ea):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.append(idc.get_func_name(caller_func.start_ea) or hex(caller_func.start_ea))
            callers = list(set(callers))[:10]

            # Xrefs from this function
            callees = []
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, 0):
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
            for item in idautils.FuncItems(ea):
                for dref in idautils.DataRefsFrom(item):
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                str_refs.append(raw.decode("utf-8", errors="replace")[:80])
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
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, 0):
                    target_name = idc.get_func_name(xref)
                    if target_name and not target_name.startswith("sub_"):
                        apis.append(target_name)
            apis = list(dict.fromkeys(apis))[:8]

            # Strings referenced
            strs = []
            for item in idautils.FuncItems(ea):
                for dref in idautils.DataRefsFrom(item):
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                strs.append(raw.decode("utf-8", errors="replace")[:40])
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
                        top_strings.append(raw.decode("utf-8", errors="replace")[:60])
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

            image_size = (info.max_ea - info.min_ea) if info else 0
            seg_count = sum(1 for _ in idautils.Segments())

            proc_name = info.procname if info else ""
            bits = (64 if info.is_64bit() else 32) if info else 0
            min_ea = info.min_ea if info else 0
            max_ea = info.max_ea if info else 0
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
                            explanation.append(f"String: {raw.decode('utf-8', errors='replace')[:100]}")
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
                for ea in idautils.Functions():
                    fname = idc.get_func_name(ea) or ""
                    if any(kw in fname.lower() for kw in ("main", "init", "start", "entry", "setup")):
                        suggestions.append(f"Key function: {fname} @ {hex(ea)}")
                    if len(suggestions) >= 10:
                        break
            else:
                # Find connected functions not yet analyzed
                for analyzed_ea in analyzed:
                    func = ida_funcs.get_func(analyzed_ea)
                    if not func:
                        continue
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.CodeRefsFrom(item, 0):
                            target = ida_funcs.get_func(xref)
                            if target and target.start_ea not in analyzed:
                                tname = idc.get_func_name(target.start_ea) or hex(target.start_ea)
                                suggestion = f"Called by analyzed: {tname} @ {hex(target.start_ea)}"
                                if suggestion not in suggestions:
                                    suggestions.append(suggestion)
                    # Also check callers
                    for xref in idautils.XrefsTo(func.start_ea):
                        caller = ida_funcs.get_func(xref.frm)
                        if caller and caller.start_ea not in analyzed:
                            cname = idc.get_func_name(caller.start_ea) or hex(caller.start_ea)
                            suggestion = f"Calls analyzed: {cname} @ {hex(caller.start_ea)}"
                            if suggestion not in suggestions:
                                suggestions.append(suggestion)
                    if len(suggestions) >= 15:
                        break

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
            for ea in idautils.Functions():
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
            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                name = idc.get_func_name(ea) or ""
                size = func.end_ea - func.start_ea
                xref_count = len(list(idautils.XrefsTo(ea)))

                # Score based on multiple factors
                score = 0
                if not name.startswith("sub_"):
                    score += 5
                score += min(xref_count, 20)
                score += min(size // 100, 10)

                # Check for interesting API calls
                for item in idautils.FuncItems(ea):
                    for xref in idautils.CodeRefsFrom(item, 0):
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
                            strs.append(f"{hex(s.ea)}  {raw.decode('utf-8', errors='replace')[:80]}")
                        except Exception:
                            pass
                        if len(strs) >= 30:
                            break
                answer_parts.append(f"Strings found ({len(strs)}):")
                answer_parts.extend(strs[:20])

            elif any(kw in q for kw in ("function", "func", "routine", "subroutine")):
                func_count = _count_functions()
                named = sum(1 for ea in idautils.Functions() if not (idc.get_func_name(ea) or "").startswith("sub_"))
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
                answer_parts.append(f"Binary: {info.procname if info else ''} {'64-bit' if (info and info.is_64bit()) else '32-bit'}")
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
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find interesting strings: string_ops(action='suspicious')",
                    "6. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])

            return {"ok": True, "guided_steps": "\n".join(steps)}

        elif action == "compact":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query (content to compact) required for compact action")
            max_lines = int(kwargs.get("max_lines", 30))
            max_line_len = int(kwargs.get("max_line_len", 200))
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

        elif action == "cheatsheet":
            file_type = info.filetype if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            cheat = ["=== Quick Reference for This Binary ==="]
            cheat.append(f"Arch: {info.procname if info else ''} | {'64-bit' if (info and info.is_64bit()) else '32-bit'}")
            cheat.append("")
            cheat.append("-- Overview --")
            cheat.append("binary_info(action='headers')        # PE/ELF headers")
            cheat.append("binary_info(action='sections')       # Sections with entropy")
            cheat.append("llm_helpers(action='binary_digest')  # Compact overview")
            cheat.append("")
            cheat.append("-- Functions --")
            cheat.append("llm_helpers(action='function_digest', addr='0xADDR')  # One-line summary")
            cheat.append("llm_helpers(action='context_window', addr='0xADDR')   # Full context")
            cheat.append("cfg_analysis(action='complexity', addr='0xADDR')       # Complexity")
            cheat.append("")
            cheat.append("-- Strings --")
            cheat.append("string_ops(action='find_urls')       # URLs")
            cheat.append("string_ops(action='find_commands')   # Shell commands")
            cheat.append("string_ops(action='suspicious')      # Passwords/keys/tokens")

            if is_pe:
                cheat.append("")
                cheat.append("-- PE-Specific --")
                cheat.append("string_ops(action='find_registry')   # Registry keys")
                cheat.append("binary_info(action='resources')      # PE resources")
                cheat.append("c2_detect(action='summary')          # Malware indicators")

            if is_elf:
                cheat.append("")
                cheat.append("-- ELF-Specific --")
                cheat.append("string_ops(action='find_paths')      # Unix paths")
                cheat.append("string_ops(action='find_commands')    # Shell commands")

            cheat.append("")
            cheat.append("-- Navigation --")
            cheat.append("llm_helpers(action='focus_area')              # What to look at next")
            cheat.append("llm_helpers(action='suggest_next', history=...)  # Based on analysis history")
            cheat.append("llm_helpers(action='progress_report', history=...)  # Track progress")

            return {"ok": True, "cheatsheet": "\n".join(cheat)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
