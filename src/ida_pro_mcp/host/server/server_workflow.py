#!/usr/bin/env python3
"""Workflow, batch, and tools list helpers extracted from the main server."""

import time

from ..config import (
    EMBEDDING_FIRST_MODE,
    _bounded_int,
    _coerce_bool,
    _parse_str_list,
)
from ..errors import MCPError, is_error_result, make_error
from .server_workflow_batch import ServerWorkflowBatchMixin
from ..schemas import (
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_DESCRIPTIONS,
    TOOLS,
    build_input_schema_lean,
    build_input_schema_ultra,
    build_tool_description_lean,
    build_tool_description_ultra,
    classify_tool_category,
    sanitize_schema_for_vertex,
)


class ServerWorkflowMixin(ServerWorkflowBatchMixin):
    def _handle_workflow(self, args: dict) -> dict:
        action = str(args.get("action") or "triage_fast").strip().lower()
        profile = str(args.get("profile") or "balanced").strip().lower()
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"
        limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=100)
        addr = str(args.get("addr") or "").strip()
        dry_run = _coerce_bool(args.get("dry_run"), False)
        include_tools = [t.strip().lower() for t in _parse_str_list(args.get("include_tools")) if t and str(t).strip()]
        exclude_tools = [t.strip().lower() for t in _parse_str_list(args.get("exclude_tools")) if t and str(t).strip()]
        include_tools = list(dict.fromkeys(include_tools))
        exclude_tools = list(dict.fromkeys(exclude_tools))

        step_plan: list[dict] = []
        workflow_meta: dict = {"version": 1, "action": action, "profile": profile}

        def _detect_firmware_mode() -> tuple[bool, str, bool]:
            """Best-effort firmware detection with fallback to IDB metadata."""
            overview_failed = False
            raw_binary_mode = False
            try:
                overview = self._execute_tool("idb", {"action": "overview"})
                if isinstance(overview, dict):
                    arch_profile = overview.get("architecture_profile") if isinstance(overview.get("architecture_profile"), dict) else {}
                    if isinstance(arch_profile, dict):
                        raw_binary_mode = bool(arch_profile.get("raw_binary_mode", False))
                    if bool(overview.get("firmware_detected")):
                        return True, "idb_overview", raw_binary_mode
                    # Keep overview as the authoritative trigger unless fallback
                    # can positively detect raw/firmware from explicit filetype metadata.
                    overview_trigger = "idb_overview"
                else:
                    return False, "idb_overview_non_dict", raw_binary_mode
            except Exception:
                overview_failed = True
            if overview_failed:
                return False, "idb_overview_error", raw_binary_mode
            try:
                meta = self._execute_tool("idb", {"action": "meta"})
                if isinstance(meta, dict):
                    ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
                    ft_name = str(
                        meta.get("file_type_effective")
                        or ft_info.get("effective")
                        or meta.get("file_type")
                        or ""
                    ).strip().lower()
                    ft_id = meta.get("file_type_id")
                    raw_binary_mode = raw_binary_mode or ft_name in {"raw", "unknown", "bin", "binary", "obj", ""}
                    if not ft_name and ft_id is None:
                        return False, overview_trigger, raw_binary_mode
                    if ft_name in {"raw", "unknown", "bin", "binary", "obj", ""}:
                        return True, "idb_meta_filetype", raw_binary_mode
                    try:
                        ft_num = int(ft_id) if ft_id is not None else None
                    except Exception:
                        ft_num = None
                    if ft_num in {0, 2, 17}:
                        return True, "idb_meta_filetype", raw_binary_mode
                    return False, overview_trigger, raw_binary_mode
                return False, overview_trigger, raw_binary_mode
            except Exception:
                return False, overview_trigger, raw_binary_mode

        def _workflow_binary_stats() -> dict:
            """Best-effort stats used to gate fragile workflow steps."""
            try:
                s = self._execute_tool("idb", {"action": "summary"})
                if isinstance(s, dict):
                    return {
                        "functions": int(s.get("functions", 0) or 0),
                        "imports": int(s.get("imports", 0) or 0),
                    }
            except Exception:
                pass
            return {"functions": 0, "imports": 0}
        if action == "audit_plan":
            calls_in = args.get("planned_calls")
            calls_raw: list = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls_raw = calls_in
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or is_error_result(compose_result):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls") if isinstance(compose_result.get("planned_calls"), list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "audit_plan requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='audit_plan', workflow_action='recon_sweep')",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "execute_plan", "audit_plan", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "audit_plan target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or is_error_result(plan_result):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls") if isinstance(plan_result.get("planned_calls"), list) else []
                    source_desc = "plan"

            normalized_calls: list[dict] = []
            invalid_calls: list[int] = []
            missing_calls: list[str] = []
            duplicate_keys: dict[str, int] = {}
            risk_hints: list[str] = []
            tool_counts: dict[str, int] = {}
            seen_keys: set[tuple[str, str]] = set()
            for idx, call in enumerate(calls_raw):
                name, call_args, normalize_err = self._normalize_batch_call(call, idx)
                if normalize_err or not isinstance(name, str) or not name.strip() or not isinstance(call_args, dict):
                    invalid_calls.append(idx)
                    continue
                n = name.strip()
                a = str(call_args.get("action") or "").strip()
                if n not in TOOL_ACTIONS:
                    invalid_calls.append(idx)
                    missing_calls.append(f"{n}.{a}" if a else n)
                    continue
                if a and a not in {str(x).strip() for x in TOOL_ACTIONS.get(n, [])}:
                    invalid_calls.append(idx)
                    missing_calls.append(f"{n}.{a}")
                    continue
                key = (n, a)
                normalized_calls.append({"name": n, "arguments": call_args})
                tool_counts[n] = int(tool_counts.get(n, 0)) + 1
                key_str = f"{n}.{a}"
                if key in seen_keys:
                    duplicate_keys[key_str] = int(duplicate_keys.get(key_str, 1)) + 1
                else:
                    seen_keys.add(key)
                if n in {"threat_hunt", "deobfuscate", "search"} and a in {"malware", "vuln", "api_hashing", "vulnerable"}:
                    risk_hints.append(f"high-risk step present: {key_str}")

            warnings: list[str] = []
            if invalid_calls:
                warnings.append(f"invalid_call_entries={len(invalid_calls)} at indexes {invalid_calls[:10]}")
            if missing_calls:
                warnings.append(f"unknown_tool_or_action: {missing_calls[:10]}")
            if duplicate_keys:
                dup = ", ".join(f"{k}x{v}" for k, v in sorted(duplicate_keys.items())[:8])
                warnings.append(f"duplicate_steps_detected: {dup}")
            if len(normalized_calls) > 100:
                warnings.append("large_plan: more than 100 executable calls")
            if not normalized_calls:
                warnings.append("no_executable_calls")

            score = max(0, 100 - len(invalid_calls) * 10 - len(duplicate_keys) * 5 - max(0, len(normalized_calls) - 50))
            health = "good" if score >= 80 else ("fair" if score >= 60 else "poor")

            return {
                "ok": True,
                "action": "audit_plan",
                "dry_run": True,
                "source": source_desc,
                "audit": {
                    "health": health,
                    "score": score,
                    "raw_call_count": len(calls_raw),
                    "executable_call_count": len(normalized_calls),
                    "invalid_call_count": len(invalid_calls),
                    "duplicate_step_count": len(duplicate_keys),
                    "tool_counts": tool_counts,
                    "warnings": warnings,
                    "risk_hints": list(dict.fromkeys(risk_hints)),
                },
                "planned_calls": normalized_calls,
                "summary": {
                    "action": "audit_plan",
                    "health": health,
                    "score": score,
                    "source": source_desc,
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "audit_plan",
                    "dry_run": True,
                    "source": source_desc,
                    "step_count": len(normalized_calls),
                },
            }
        elif action == "execute_plan":
            continue_on_error = _coerce_bool(args.get("continue_on_error"), True)
            max_steps = _bounded_int(args.get("max_steps", 50), 50, min_value=1, max_value=200)
            calls_in = args.get("planned_calls")
            calls_raw: list = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls_raw = calls_in
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or is_error_result(compose_result):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls") if isinstance(compose_result.get("planned_calls"), list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "execute_plan requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='execute_plan', workflow_action='triage_fast', continue_on_error=true)",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "execute_plan", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "execute_plan target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or is_error_result(plan_result):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls") if isinstance(plan_result.get("planned_calls"), list) else []
                    source_desc = "plan"

            normalized_calls: list[dict] = []
            for idx, call in enumerate(calls_raw):
                name, call_args, normalize_err = self._normalize_batch_call(call, idx)
                if normalize_err or not isinstance(name, str) or not name.strip() or not isinstance(call_args, dict):
                    continue
                normalized_calls.append({"name": name.strip(), "arguments": call_args})

            requested_steps = len(normalized_calls)
            truncated = False
            if len(normalized_calls) > max_steps:
                normalized_calls = normalized_calls[:max_steps]
                truncated = True

            if not normalized_calls:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "No executable calls found in plan",
                    hint="Provide planned_calls with valid tool/action entries, or use workflow_action/workflow_actions.",
                )

            step_results: list[dict] = []
            calls_out: list[dict] = []
            completed = 0
            blocked = False
            for idx, step in enumerate(normalized_calls):
                name = str(step.get("name") or "").strip()
                call_args = step.get("arguments") if isinstance(step.get("arguments"), dict) else {}
                if blocked:
                    step_results.append(
                        {
                            "index": idx,
                            "tool": name,
                            "args": call_args,
                            "outcome": "skipped",
                            "elapsed_ms": 0,
                            "recovery_hint": "Previous dependency-like step failed; rerun after fixing earlier error.",
                        }
                    )
                    continue
                t0 = time.time()
                try:
                    res = self._execute_tool(name, dict(call_args))
                except Exception as e:
                    res = {"error": True, "message": str(e)}
                elapsed_ms = int((time.time() - t0) * 1000)
                is_err = is_error_result(res)
                calls_out.append({"name": name, "arguments": call_args, "result": res})
                step_results.append(
                    {
                        "index": idx,
                        "tool": name,
                        "args": call_args,
                        "outcome": "error" if is_err else "ok",
                        "elapsed_ms": elapsed_ms,
                        "recovery_hint": (
                            "Check address/args and retry this step manually."
                            if is_err
                            else ""
                        ),
                    }
                )
                if is_err:
                    # Conservative dependency gate for clearly chained operations.
                    if name in {"query", "batch"}:
                        blocked = True
                    if not continue_on_error:
                        break
                else:
                    completed += 1

            return {
                "ok": True,
                "action": "execute_plan",
                "source": source_desc,
                "calls": calls_out,
                "step_results": step_results,
                "summary": {
                    "requested_steps": requested_steps,
                    "executed_steps": len(step_results),
                    "completed_steps": completed,
                    "error_steps": len([s for s in step_results if s.get("outcome") == "error"]),
                    "skipped_steps": len([s for s in step_results if s.get("outcome") == "skipped"]),
                    "truncated": truncated,
                    "continue_on_error": continue_on_error,
                },
                "execution_meta": {
                    "action": "execute_plan",
                    "source": source_desc,
                    "requested_steps": requested_steps,
                    "executed_steps": len(step_results),
                    "truncated": truncated,
                    "continue_on_error": continue_on_error,
                },
            }
        elif action == "prioritize":
            mode = str(args.get("priority_mode") or "coverage").strip().lower()
            if mode not in {"original", "coverage", "risk_first"}:
                mode = "coverage"
            calls_in = args.get("planned_calls")
            calls: list[dict] = []
            source_desc = "provided"
            if isinstance(calls_in, list):
                calls = [c for c in calls_in if isinstance(c, dict)]
            else:
                compose_targets = _parse_str_list(args.get("workflow_actions"))
                if compose_targets:
                    compose_result = self._handle_workflow(
                        {
                            "action": "compose",
                            "workflow_actions": compose_targets,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(compose_result, dict) or is_error_result(compose_result):
                        return compose_result
                    calls_raw = compose_result.get("planned_calls")
                    calls = [c for c in calls_raw if isinstance(c, dict)] if isinstance(calls_raw, list) else []
                    source_desc = "compose"
                else:
                    target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
                    if not target_action:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "prioritize requires planned_calls, workflow_actions, or workflow_action",
                            hint="Example: workflow(action='prioritize', workflow_action='recon_sweep', priority_mode='coverage')",
                        )
                    if target_action in {"plan", "explain", "estimate", "compose", "prioritize", "catalog"}:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "prioritize target must be executable workflow",
                            hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                        )
                    plan_result = self._handle_workflow(
                        {
                            "action": "plan",
                            "workflow_action": target_action,
                            "profile": profile,
                            "limit": limit,
                            "include_tools": include_tools,
                            "exclude_tools": exclude_tools,
                            "addr": addr,
                        }
                    )
                    if not isinstance(plan_result, dict) or is_error_result(plan_result):
                        return plan_result
                    calls_raw = plan_result.get("planned_calls")
                    calls = [c for c in calls_raw if isinstance(c, dict)] if isinstance(calls_raw, list) else []
                    source_desc = "plan"

            def _priority_key(c: dict) -> tuple[int, int, str]:
                name = str(c.get("name") or "").strip().lower()
                action_name = str((c.get("arguments") or {}).get("action") or "").strip().lower() if isinstance(c.get("arguments"), dict) else ""
                call = f"{name}.{action_name}"
                source_count = int(c.get("source_count") or 1)
                if mode == "original":
                    return (0, 0, call)
                if mode == "risk_first":
                    risk_order = {
                        "threat_hunt.malware": 0,
                        "threat_hunt.vuln": 0,
                        "search.vulnerable": 1,
                        "deobfuscate.api_hashing": 1,
                        "crypto_id.identify": 2,
                        "protocol.detect": 2,
                    }
                    return (risk_order.get(call, 50), -source_count, call)
                # coverage
                return (-source_count, 0 if name in {"idb", "data"} else 1, call)

            prioritized = list(calls)
            if mode != "original":
                prioritized.sort(key=_priority_key)

            annotated = []
            for idx, c in enumerate(prioritized):
                out = dict(c)
                out["priority_index"] = idx
                out["priority_mode"] = mode
                annotated.append(out)

            return {
                "ok": True,
                "action": "prioritize",
                "dry_run": True,
                "priority_mode": mode,
                "source": source_desc,
                "planned_calls": annotated,
                "summary": {
                    "action": "prioritize",
                    "priority_mode": mode,
                    "step_count": len(annotated),
                    "source": source_desc,
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "prioritize",
                    "dry_run": True,
                    "priority_mode": mode,
                    "source": source_desc,
                    "step_count": len(annotated),
                },
            }
        elif action == "compose":
            raw_actions = _parse_str_list(args.get("workflow_actions"))
            if not raw_actions:
                single = str(args.get("workflow_action") or args.get("target_action") or "").strip()
                if single:
                    raw_actions = [single]
            target_actions = [str(a).strip().lower() for a in raw_actions if str(a).strip()]
            target_actions = list(dict.fromkeys(target_actions))
            if not target_actions:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "compose requires workflow_actions",
                    hint="Example: workflow(action='compose', workflow_actions=['triage_fast','vuln_audit'])",
                )
            if any(a in {"plan", "explain", "estimate", "compose", "catalog"} for a in target_actions):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "compose targets must be executable workflows only",
                    hint="Use workflow_actions from: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )

            merged_calls: list[dict] = []
            seen_keys: set[tuple[str, str]] = set()
            source_map: dict[tuple[str, str], list[str]] = {}
            composed_meta: list[dict] = []

            for target_action in target_actions:
                plan_args = dict(args)
                plan_args["action"] = "plan"
                plan_args["workflow_action"] = target_action
                if not addr:
                    plan_args.pop("addr", None)
                plan_result = self._handle_workflow(plan_args)
                if not isinstance(plan_result, dict) or is_error_result(plan_result):
                    return plan_result
                calls = plan_result.get("planned_calls")
                if not isinstance(calls, list):
                    calls = []
                meta = plan_result.get("workflow_meta") if isinstance(plan_result.get("workflow_meta"), dict) else {}
                composed_meta.append(
                    {
                        "action": target_action,
                        "step_count": len(calls),
                        "firmware_detected": bool(meta.get("firmware_detected", False)),
                        "plan_diagnostics": list(meta.get("plan_diagnostics", [])) if isinstance(meta.get("plan_diagnostics"), list) else [],
                    }
                )
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    name = str(call.get("name") or "").strip()
                    args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                    action_name = str((args_obj or {}).get("action") or "").strip()
                    key = (name, action_name)
                    source_map.setdefault(key, [])
                    if target_action not in source_map[key]:
                        source_map[key].append(target_action)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    merged_calls.append(call)

            annotated_calls = []
            for idx, call in enumerate(merged_calls):
                if not isinstance(call, dict):
                    continue
                name = str(call.get("name") or "").strip()
                args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                action_name = str((args_obj or {}).get("action") or "").strip()
                key = (name, action_name)
                sources = source_map.get(key, [])
                out_call = dict(call)
                out_call["sources"] = sources
                out_call["source_count"] = len(sources)
                out_call["index"] = idx
                annotated_calls.append(out_call)

            return {
                "ok": True,
                "action": "compose",
                "requested_action": "compose",
                "planned_actions": target_actions,
                "dry_run": True,
                "dedup_enabled": True,
                "planned_calls": annotated_calls,
                "summary": {
                    "action": "compose",
                    "planned_actions": target_actions,
                    "step_count": len(annotated_calls),
                    "source_workflows": len(target_actions),
                },
                "workflow_meta": {
                    "version": 1,
                    "action": "compose",
                    "dry_run": True,
                    "composed_actions": target_actions,
                    "component_workflows": composed_meta,
                    "step_count": len(annotated_calls),
                },
            }
        elif action == "estimate":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "estimate requires workflow_action",
                    hint="Example: workflow(action='estimate', workflow_action='recon_sweep', profile='balanced')",
                )
            if target_action in {"plan", "explain", "estimate"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "estimate cannot target plan/explain/estimate",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = "plan"
            plan_args["workflow_action"] = target_action
            plan_result = self._handle_workflow(plan_args)
            if not isinstance(plan_result, dict) or is_error_result(plan_result):
                return plan_result
            calls = plan_result.get("planned_calls")
            if not isinstance(calls, list):
                calls = []

            tool_categories = {
                "idb": "orientation",
                "data": "discovery",
                "string_ops": "ioc_hunt",
                "threat_hunt": "threat_hunt",
                "deobfuscate": "deobfuscation",
                "crypto_id": "crypto",
                "yara_hunt": "signature_hunt",
                "gadgets": "exploit_surface",
                "search": "search",
                "protocol": "protocol",
                "summarize": "summary",
                "firmware_view": "firmware",
                "llm_helpers": "guidance",
                "code": "code",
                "graph": "graph",
                "compare": "diff",
            }
            category_counts: dict[str, int] = {}
            unique_tools = set()
            for c in calls:
                if not isinstance(c, dict):
                    continue
                name = str(c.get("name") or "").strip()
                if not name:
                    continue
                unique_tools.add(name)
                cat = tool_categories.get(name, "other")
                category_counts[cat] = int(category_counts.get(cat, 0)) + 1

            meta = plan_result.get("workflow_meta") if isinstance(plan_result.get("workflow_meta"), dict) else {}
            firmware_detected = bool(meta.get("firmware_detected", False))
            step_count = len(calls)
            complexity = "low" if step_count <= 4 else ("medium" if step_count <= 7 else "high")
            risk_score = 0
            plan_text = " ".join(
                f"{str(c.get('name') or '').strip()}.{str((c.get('arguments') or {}).get('action') or '').strip()}"
                for c in calls
                if isinstance(c, dict)
            ).strip()
            if EMBEDDING_FIRST_MODE and plan_text:
                try:
                    from ..intelligence.core import BgeCodeEmbedder
                    embedder = BgeCodeEmbedder()
                    qv = embedder.embed(plan_text)
                    anchors = [
                        "low risk orientation metadata summary listing imports",
                        "medium risk protocol and threat triage suspicious indicators",
                        "high risk exploit vulnerability deobfuscation patch and malware deep analysis",
                    ]
                    sims = [float(embedder.cosine(qv, embedder.embed(a))) for a in anchors]
                    if sims:
                        risk_score = int(round(max(0.0, min(1.0, max(sims))) * 100.0))
                except Exception:
                    risk_score = 0
            if risk_score <= 0:
                # Deterministic fallback by plan breadth only (no heuristic keyword weights).
                risk_score = int(round(min(100.0, (float(step_count) / 12.0) * 100.0)))
            if firmware_detected:
                risk_score = min(100, risk_score + 6)

            return {
                "ok": True,
                "action": "estimate",
                "requested_action": "estimate",
                "planned_action": target_action,
                "dry_run": True,
                "estimate": {
                    "complexity": complexity,
                    "risk_score": risk_score,
                    "step_count": step_count,
                    "unique_tool_count": len(unique_tools),
                    "firmware_detected": firmware_detected,
                    "category_counts": category_counts,
                },
                "planned_calls": calls,
                "workflow_meta": meta,
                "summary": {
                    "action": "estimate",
                    "workflow_action": target_action,
                    "complexity": complexity,
                    "risk_score": risk_score,
                },
            }
        elif action == "explain":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "explain requires workflow_action",
                    hint="Example: workflow(action='explain', workflow_action='triage_fast', profile='balanced')",
                )
            if target_action in {"plan", "explain"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "explain cannot target plan/explain",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = "plan"
            plan_args["workflow_action"] = target_action
            plan_result = self._handle_workflow(plan_args)
            if not isinstance(plan_result, dict) or is_error_result(plan_result):
                return plan_result
            calls = plan_result.get("planned_calls")
            if not isinstance(calls, list):
                calls = []

            rationale_by_call = {
                "idb.overview": "Establishes binary orientation and high-signal context before deep tooling.",
                "idb.meta": "Captures format/arch/base metadata used by downstream interpretation.",
                "data.functions": "Builds a function inventory for navigation and prioritization.",
                "data.imports": "Highlights external capability surface and potential behavior anchors.",
                "string_ops.find_urls": "Extracts direct network indicators for quick IOC triage.",
                "threat_hunt.quick": "Runs a fast heuristic pass to surface high-priority suspicious regions.",
                "string_ops.find_c2": "Targets command-and-control indicators in strings and references.",
                "deobfuscate.stack_strings": "Recovers runtime-built strings hidden from static string tables.",
                "deobfuscate.api_hashing": "Flags and resolves hashed API dispatch patterns common in malware.",
                "crypto_id.identify": "Identifies cryptographic primitives and likely key-handling hotspots.",
                "yara_hunt.list_rules": "Enumerates available rules to align hunts with known families.",
                "threat_hunt.malware": "Performs malware-focused threat hunting profile.",
                "gadgets.rop": "Maps exploit-relevant gadget surface for memory corruption risk analysis.",
                "search.vulnerable": "Finds dangerous API/use patterns tied to common vulnerability classes.",
                "protocol.detect": "Locates protocol parsers/handlers and potential attack boundaries.",
                "threat_hunt.vuln": "Performs vulnerability-focused threat hunting profile.",
                "search.structured": "Uses schema-guided retrieval to find semantically constrained candidates.",
                "summarize.security_posture": "Produces consolidated risk and mitigation posture snapshot.",
                "firmware_view.triage_snapshot": "Aggregates load/vector/MMIO hints for firmware-first orientation.",
                "llm_helpers.focus_area": "Identifies the most interesting area to analyze next.",
                "code.disasm": "Gets opcode-level view at target address for patch semantics.",
                "code.xrefs_to": "Shows inbound dependency impact into the patch location.",
                "code.xrefs_from": "Shows outbound behavior impact from patched block.",
                "graph.dependency_graph": "Summarizes near-neighbor call/data dependencies around patch.",
                "compare.functions": "Captures structural/functional differences for regression risk review.",
            }
            explained_steps = []
            for idx, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                name = str(call.get("name") or "").strip()
                args_obj = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                action_name = str((args_obj or {}).get("action") or "").strip()
                key = f"{name}.{action_name}"
                explained_steps.append(
                    {
                        "index": idx,
                        "tool": name,
                        "action": action_name,
                        "call": key,
                        "rationale": rationale_by_call.get(
                            key,
                            "Included by workflow profile as a high-value analysis step.",
                        ),
                    }
                )

            return {
                "ok": True,
                "action": "explain",
                "requested_action": "explain",
                "planned_action": target_action,
                "dry_run": True,
                "planned_calls": calls,
                "explained_steps": explained_steps,
                "summary": {
                    "action": "explain",
                    "workflow_action": target_action,
                    "step_count": len(explained_steps),
                },
                "workflow_meta": plan_result.get("workflow_meta", {}),
            }
        elif action == "plan":
            target_action = str(args.get("workflow_action") or args.get("target_action") or "").strip().lower()
            if not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "plan requires workflow_action",
                    hint="Example: workflow(action='plan', workflow_action='recon_sweep', profile='deep')",
                )
            if target_action == "plan":
                return make_error(
                    MCPError.INVALID_ARGS,
                    "plan cannot target plan",
                    hint="Use workflow_action as one of: triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
                )
            plan_args = dict(args)
            plan_args["action"] = target_action
            plan_args["dry_run"] = True
            plan_result = self._handle_workflow(plan_args)
            if isinstance(plan_result, dict):
                plan_result.setdefault("requested_action", "plan")
                plan_result.setdefault("planned_action", target_action)
            return plan_result
        elif action == "catalog":
            catalog = {
                "triage_fast": {
                    "description": "Fast binary orientation + IOC/threat quick pass; firmware-aware auto-injection.",
                    "requires_addr": False,
                    "firmware_aware": True,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "malware_deep": {
                    "description": "Deeper malware-oriented hunting with deobfuscation and crypto triage.",
                    "requires_addr": False,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "vuln_audit": {
                    "description": "Vulnerability-focused audit: gadgets, dangerous patterns, protocol surface.",
                    "requires_addr": False,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "recon_sweep": {
                    "description": "Broad recon pass combining orientation, structured retrieval, protocol, and security posture.",
                    "requires_addr": False,
                    "firmware_aware": True,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
                "patch_review": {
                    "description": "Patch-impact review focused on one address and its xref/dependency neighborhood.",
                    "requires_addr": True,
                    "firmware_aware": False,
                    "default_profile": "balanced",
                    "supports_filters": True,
                    "supports_dry_run": True,
                },
            }
            return {
                "ok": True,
                "action": "catalog",
                "workflow_catalog": catalog,
                "supports_plan_action": True,
                "supports_explain_action": True,
                "supports_estimate_action": True,
                "supports_compose_action": True,
                "supports_prioritize_action": True,
                "supports_execute_plan_action": True,
                "supports_audit_plan_action": True,
                "supported_profiles": ["quick", "balanced", "deep"],
                "supported_filters": ["include_tools", "exclude_tools"],
                "supports_dry_run": True,
            }
        elif action == "triage_fast":
            firmware_detected, firmware_detected_trigger, raw_binary_mode = _detect_firmware_mode()
            wf_stats = _workflow_binary_stats()
            has_functions = int(wf_stats.get("functions", 0)) > 0

            step_plan = [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "idb", "arguments": {"action": "meta"}},
                {"name": "data", "arguments": {"action": "functions", "count": limit}},
                {"name": "data", "arguments": {"action": "imports", "count": limit}},
                {"name": "search", "arguments": {"action": "nl" if has_functions else "find", "query": "entrypoint parser auth decode crypto", "limit": limit}},
                {"name": "string_ops", "arguments": {"action": "find_urls", "limit": limit}},
                {
                    "name": "threat_hunt",
                    "arguments": {
                        "action": "run",
                        "limit": limit,
                        "profile": profile,
                        "include_vuln": True,
                        "include_malware": True,
                        "include_tracing": True,
                    },
                },
                {"name": "blackboard", "arguments": {"action": "frontier", "limit": min(limit, 10)}},
            ]
            if firmware_detected or raw_binary_mode:
                step_plan.insert(2, {"name": "firmware_view", "arguments": {"action": "triage_snapshot"}})
                step_plan.append({"name": "llm_helpers", "arguments": {"action": "focus_area"}})
            workflow_meta["firmware_mode"] = "enabled" if (firmware_detected or raw_binary_mode) else "disabled"
            workflow_meta["firmware_detected"] = firmware_detected
            workflow_meta["raw_binary_mode"] = raw_binary_mode
            workflow_meta["trigger"] = firmware_detected_trigger
            workflow_meta["has_functions"] = has_functions
        elif action == "malware_deep":
            step_plan = [
                {"name": "string_ops", "arguments": {"action": "find_c2", "limit": limit}},
                {"name": "search", "arguments": {"action": "nl", "query": "beacon c2 command parser persistence injection", "limit": limit}},
                {"name": "deobfuscate", "arguments": {"action": "stack_strings", "limit": limit}},
                {"name": "deobfuscate", "arguments": {"action": "api_hashing", "limit": limit}},
                {"name": "crypto_id", "arguments": {"action": "identify", "limit": limit}},
                {"name": "yara_hunt", "arguments": {"action": "list_rules"}},
                {"name": "threat_hunt", "arguments": {"action": "malware", "limit": limit, "profile": profile}},
            ]
        elif action == "vuln_audit":
            step_plan = [
                {"name": "gadgets", "arguments": {"action": "rop", "limit": limit}},
                {"name": "search", "arguments": {"action": "nl", "query": "input validation memcpy strcpy length check auth bypass", "limit": limit}},
                {"name": "search", "arguments": {"action": "vulnerable", "limit": limit}},
                {"name": "protocol", "arguments": {"action": "detect", "limit": limit}},
                {"name": "threat_hunt", "arguments": {"action": "vuln", "limit": limit, "profile": profile}},
            ]
        elif action == "recon_sweep":
            firmware_detected, firmware_detected_trigger, raw_binary_mode = _detect_firmware_mode()
            wf_stats = _workflow_binary_stats()
            has_functions = int(wf_stats.get("functions", 0)) > 0

            step_plan = [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "idb", "arguments": {"action": "meta"}},
                {"name": "data", "arguments": {"action": "functions", "count": limit}},
                {"name": "search", "arguments": {"action": "nl" if has_functions else "find", "query": "dispatcher parser crypto network auth", "limit": limit}},
                {"name": "search", "arguments": {"action": "structured", "limit": limit}},
                {"name": "blackboard", "arguments": {"action": "frontier", "limit": min(limit, 10)}},
                {"name": "protocol", "arguments": {"action": "detect", "limit": limit}},
                {"name": "summarize", "arguments": {"action": "security_posture", "max_items": limit}},
                {
                    "name": "threat_hunt",
                    "arguments": {
                        "action": "run",
                        "limit": limit,
                        "profile": profile,
                        "include_vuln": True,
                        "include_malware": True,
                        "include_tracing": True,
                    },
                },
            ]
            if firmware_detected or raw_binary_mode:
                step_plan.insert(2, {"name": "firmware_view", "arguments": {"action": "triage_snapshot"}})
                step_plan.append({"name": "llm_helpers", "arguments": {"action": "focus_area"}})
            workflow_meta["firmware_mode"] = "enabled" if (firmware_detected or raw_binary_mode) else "disabled"
            workflow_meta["firmware_detected"] = firmware_detected
            workflow_meta["raw_binary_mode"] = raw_binary_mode
            workflow_meta["trigger"] = firmware_detected_trigger
            workflow_meta["has_functions"] = has_functions
        elif action == "patch_review":
            if not addr:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "patch_review requires addr",
                    hint="Provide workflow(action='patch_review', addr='0x401000')",
                )
            step_plan = [
                {"name": "code", "arguments": {"action": "disasm", "addr": addr}},
                {"name": "code", "arguments": {"action": "xrefs_to", "addr": addr, "limit": limit}},
                {"name": "code", "arguments": {"action": "xrefs_from", "addr": addr, "limit": limit}},
                {"name": "graph", "arguments": {"action": "dependency_graph", "addr": addr, "depth": 1, "limit": limit}},
                {"name": "compare", "arguments": {"action": "functions", "addr": addr, "addr2": addr}},
            ]
        else:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported workflow action: '{action}'",
                hint="Valid workflow actions: audit_plan, execute_plan, prioritize, compose, estimate, explain, plan, catalog, triage_fast, malware_deep, vuln_audit, recon_sweep, patch_review",
            )

        available_tools = sorted(
            {
                str(step.get("name") or "").strip().lower()
                for step in step_plan
                if str(step.get("name") or "").strip()
            }
        )
        unknown_include_tools = [t for t in include_tools if t not in set(available_tools)]
        unknown_exclude_tools = [t for t in exclude_tools if t not in set(available_tools)]
        conflicting_tools = [t for t in include_tools if t in set(exclude_tools)]

        if include_tools:
            step_plan = [
                step
                for step in step_plan
                if str(step.get("name") or "").strip().lower() in set(include_tools)
            ]
        if exclude_tools:
            step_plan = [
                step
                for step in step_plan
                if str(step.get("name") or "").strip().lower() not in set(exclude_tools)
            ]

        # Capability gating: prune unavailable tool/actions so workflows degrade gracefully.
        unavailable_steps: list[str] = []
        gated_plan: list[dict] = []
        for step in step_plan:
            tool_name = str(step.get("name") or "").strip().lower()
            action_name = str((step.get("arguments") or {}).get("action") or "").strip().lower()
            if tool_name not in TOOL_ACTIONS:
                unavailable_steps.append(f"{tool_name}.{action_name or '*'} (tool unavailable)")
                continue
            if action_name and action_name not in {str(a).strip().lower() for a in TOOL_ACTIONS.get(tool_name, [])}:
                unavailable_steps.append(f"{tool_name}.{action_name} (action unavailable)")
                continue
            gated_plan.append(step)
        step_plan = gated_plan

        workflow_meta["dry_run"] = dry_run
        workflow_meta["available_tools"] = available_tools
        workflow_meta["include_tools"] = include_tools
        workflow_meta["exclude_tools"] = exclude_tools
        workflow_meta["unknown_include_tools"] = unknown_include_tools
        workflow_meta["unknown_exclude_tools"] = unknown_exclude_tools
        workflow_meta["conflicting_tools"] = conflicting_tools
        workflow_meta["step_count"] = len(step_plan)
        workflow_meta["step_tools"] = [str(step.get("name") or "") for step in step_plan]
        workflow_meta["step_actions"] = [
            f"{str(step.get('name') or '')}.{str((step.get('arguments') or {}).get('action') or '')}"
            for step in step_plan
        ]
        workflow_meta["step_calls"] = [
            {
                "tool": str(step.get("name") or ""),
                "action": str((step.get("arguments") or {}).get("action") or ""),
            }
            for step in step_plan
        ]
        plan_diagnostics: list[str] = []
        if unknown_include_tools:
            plan_diagnostics.append(f"include_tools not in this workflow plan: {', '.join(unknown_include_tools)}")
        if unknown_exclude_tools:
            plan_diagnostics.append(f"exclude_tools not in this workflow plan: {', '.join(unknown_exclude_tools)}")
        if conflicting_tools:
            plan_diagnostics.append(
                f"tools listed in both include_tools and exclude_tools: {', '.join(conflicting_tools)}"
            )
        if unavailable_steps:
            plan_diagnostics.append(
                f"pruned unavailable workflow steps: {', '.join(unavailable_steps[:12])}"
            )
        if not step_plan:
            plan_diagnostics.append("No workflow steps remain after filtering.")
        workflow_meta["plan_diagnostics"] = plan_diagnostics

        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "planned_calls": step_plan,
                "summary": {
                    "action": action,
                    "profile": profile,
                    "step_count": len(step_plan),
                    "dry_run": True,
                    "plan_diagnostics": plan_diagnostics,
                },
                "workflow_meta": workflow_meta,
            }

        if not step_plan:
            return make_error(
                MCPError.INVALID_ARGS,
                "Workflow plan is empty after include/exclude filtering",
                hint="Adjust include_tools/exclude_tools, or use dry_run=true to preview plan changes.",
            )

        batch_result = self._handle_batch({"calls": step_plan, "continue_on_error": True})
        if isinstance(batch_result, dict):
            batch_result.setdefault("workflow_meta", workflow_meta)
            if isinstance(batch_result.get("summary"), dict):
                batch_result["summary"].setdefault("workflow_meta", workflow_meta)
        return batch_result

    def _build_tools_list_catalog(self, mode: str) -> list[dict]:
        cache_key = (mode,)
        cached = self._tools_list_cache.get(cache_key)
        if cached and cached[0] == cache_key:
            return cached[1]

        def _tool_description(tool_name: str, tool_mode: str) -> str:
            if tool_mode == "lean":
                desc = build_tool_description_lean(tool_name)
            else:
                desc = build_tool_description_ultra(tool_name)
            desc_text = str(desc or "").strip()
            if desc_text:
                return desc_text
            return f"Use wiki(topic='tools/{tool_name}') for usage."

        catalog: list[dict] = []
        for t in TOOLS:
            if t in HIDDEN_TOOLS_IN_LIST:
                continue
            if mode == "lean":
                schema = build_input_schema_lean(t)
            else:
                schema = build_input_schema_ultra(t)
            schema = dict(schema) if isinstance(schema, dict) else {}

            if getattr(self, "vertex_compat", False):
                schema = sanitize_schema_for_vertex(schema)

            schema.setdefault("type", "object")

            if not getattr(self, "vertex_compat", False):
                schema.setdefault("properties", {})
                schema.setdefault("required", [])

            catalog.append(
                {
                    "name": t,
                    "description": _tool_description(t, mode),
                    "inputSchema": schema,
                    "category": classify_tool_category(t),
                }
            )

        self._tools_list_cache[cache_key] = (cache_key, catalog)
        return catalog
