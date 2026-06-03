#!/usr/bin/env python3
"""Predictor helpers extracted from the main server."""

import importlib.util
import os
from collections import Counter

from .config import _bounded_int
from .errors import MCPError, make_error
from .schemas import TOOL_ACTIONS


class ServerPredictorMixin:
    def _predict_next_tool_from_activity(
        self, activity_log: list[dict], limit: int = 5
    ) -> list[dict]:
        """2nd-order Markov predictor with recency weighting and phase/exploration priors."""
        if not activity_log:
            return []

        seq = [
            f"{str(e.get('tool') or '').strip()}.{str(e.get('action') or '').strip()}"
            for e in activity_log
            if e.get("tool") and e.get("action")
        ]
        seq = [s for s in seq if s and s != "."]
        if not seq:
            return []

        global_counts = Counter(seq)
        first_order: dict[str, Counter] = {}
        second_order: dict[tuple[str, str], Counter] = {}
        n = len(seq)
        for i in range(n - 1):
            src = seq[i]
            dst = seq[i + 1]
            # Recency decay: last 5 transitions get 2x, next 5 get 1.5x, older 1x.
            dist_from_tail = (n - 2) - i
            w = 2.0 if dist_from_tail < 5 else (1.5 if dist_from_tail < 10 else 1.0)
            first_order.setdefault(src, Counter())[dst] += w
            if i >= 1:
                key2 = (seq[i - 1], src)
                second_order.setdefault(key2, Counter())[dst] += w

        current = seq[-1]
        prev = seq[-2] if len(seq) > 1 else ""
        local_first = first_order.get(current, Counter())
        local_second = second_order.get((prev, current), Counter()) if prev else Counter()
        total_global = max(1.0, float(sum(global_counts.values())))
        total_first = max(1.0, float(sum(local_first.values())))
        total_second = max(1.0, float(sum(local_second.values())))

        candidates = set(global_counts.keys()) | set(local_first.keys()) | set(local_second.keys())
        scored: list[dict] = []
        seen_tools = {s.split(".", 1)[0] for s in seq if "." in s}
        phase = str(getattr(self.current_session, "phase", "") or "").strip().lower()
        for cand in candidates:
            p_second = float(local_second.get(cand, 0.0)) / total_second
            p_first = float(local_first.get(cand, 0.0)) / total_first
            p_global = global_counts.get(cand, 0) / total_global
            has_second = sum(local_second.values()) > 0
            # 2nd-order primary; fallback to 1st-order if cold start.
            base_score = (0.65 * p_second + 0.20 * p_first + 0.15 * p_global) if has_second else (0.75 * p_first + 0.25 * p_global)
            tool, action = cand.split(".", 1) if "." in cand else (cand, "")
            exploration_bonus = 0.15 if tool and tool not in seen_tools else 0.0
            phase_bonus = 0.0
            if phase == "triage" and tool in {"firmware_view", "workflow"}:
                phase_bonus = 0.10
            elif phase == "deep_analysis" and tool in {"code", "types", "taint"}:
                phase_bonus = 0.10
            score = base_score + exploration_bonus + phase_bonus
            scored.append(
                {
                    "tool": tool,
                    "action": action,
                    "score": round(score, 4),
                    "evidence": {
                        "transition_hits_first_order": float(local_first.get(cand, 0.0)),
                        "transition_hits_second_order": float(local_second.get(cand, 0.0)),
                        "global_hits": int(global_counts.get(cand, 0)),
                        "current": current,
                        "prev": prev,
                        "has_second_order": bool(has_second),
                        "exploration_bonus": exploration_bonus,
                        "phase_bonus": phase_bonus,
                        "phase": phase or None,
                    },
                }
            )

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[: max(1, limit)]

    def _apply_proposal(self, proposal: dict, engine) -> dict:
        """Apply accepted proposal items to IDA (renames, annotations, etc.)."""
        ptype = proposal.get("proposal_type", "")
        items = proposal.get("accepted_items", [])
        applied = {"renamed": 0, "annotated": 0, "errors": []}
        for item in items:
            addr = item.get("addr", "")
            try:
                if ptype == "rename_batch":
                    name = item.get("suggested_name", "")
                    if addr and name:
                        self._execute_tool("modify", {"action": "rename", "addr": addr, "name": name})
                        applied["renamed"] += 1
                elif ptype == "annotation_batch":
                    comment = item.get("comment", "")
                    if addr and comment:
                        self._execute_tool("modify", {"action": "comment", "addr": addr, "comment": comment})
                        applied["annotated"] += 1
                elif ptype == "cross_session":
                    name = item.get("suggested_name", "")
                    if addr and name:
                        self._execute_tool("modify", {"action": "rename", "addr": addr, "name": name})
                        applied["renamed"] += 1
            except Exception as e:
                applied["errors"].append({"addr": addr, "error": str(e)})
        # Push state update after applying
        self._send_notification({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": "ida://state"},
        })
        return applied

    def _handle_predictor(self, args: dict) -> dict:
        action = str(args.get("action") or "suggest_next_tool").strip()
        sid = args.get("session_id")
        if not sid and self.current_session:
            sid = self.current_session.session_id
        if not sid:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create/switch session first or pass session_id.",
            )
        if not self.session_mgr.session_exists(str(sid)):
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")

        limit = _bounded_int(args.get("limit", 5), 5, min_value=1, max_value=20)
        recent_n = _bounded_int(args.get("recent_n", 30), 30, min_value=5, max_value=200)
        context = str(args.get("context") or "").strip()

        activity = self.session_mgr.get_activity_log(str(sid), limit=recent_n)
        if isinstance(activity, dict) and activity.get("error"):
            return activity
        log = list((activity or {}).get("log") or [])

        if action == "suggest_next_tool":
            seq_suggestions = self._predict_next_tool_from_activity(log, limit=limit)

            # Augment with UsageIntelligence predictions (trained on real audit data)
            if getattr(self, "_usage_intel", None) and log:
                try:
                    last = log[-1] if log else {}
                    last_tool = last.get("tool", "")
                    last_action = last.get("action", "")
                    if last_tool:
                        ui_preds = self._usage_intel.predict_next(last_tool, last_action, top_k=limit * 3)
                        # Merge: UI predictions get a "usage_intelligence" source tag
                        from .schemas import TOOLS
                        existing_keys = {(r.get("tool"), r.get("action")) for r in seq_suggestions}
                        for p in ui_preds:
                            # Filter out legacy/unregistered tools
                            if p["tool"] not in TOOLS:
                                continue
                            key = (p["tool"], p["action"])
                            if key not in existing_keys:
                                seq_suggestions.append({
                                    "tool": p["tool"],
                                    "action": p["action"],
                                    "score": p["score"],
                                    "probability": p["probability"],
                                    "effectiveness": p["effectiveness"],
                                    "source": "usage_intelligence",
                                    "blended_confidence": round(p["score"], 4),
                                })
                            else:
                                # Boost existing suggestion with UI score
                                for r in seq_suggestions:
                                    if r.get("tool") == p["tool"] and r.get("action") == p["action"]:
                                        r["ui_score"] = p["score"]
                                        r["ui_effectiveness"] = p["effectiveness"]
                                        r["blended_confidence"] = round(
                                            (r.get("blended_confidence", r.get("score", 0)) + p["score"]) / 2, 4
                                        )
                    # Also check for drift signals
                    sid_str = str(sid)
                    drift = self._usage_intel.drift.check(sid_str)
                    if drift:
                        seq_suggestions = [{"drift_warning": d["message"],
                                            "signal": d["type"],
                                            "severity": d["severity"]}
                                           for d in drift[:2]] + seq_suggestions
                except Exception:
                    pass
            strategy = self.session_mgr.suggest_strategy(str(sid), context=context)
            strategy_rows = []
            strategy_confidence = 0.5
            bootstrap_prior = 0.5
            if isinstance(strategy, dict) and not strategy.get("error"):
                bootstrap_prior = float(strategy.get("bootstrap_prior", 0.5))
                for s in (strategy.get("suggestions") or [])[:limit]:
                    score = float(s.get("score", s.get("q_value", 0.0)))
                    blended = float(s.get("blended_score", score))
                    strategy_confidence = max(strategy_confidence, blended)
                    strategy_rows.append(
                        {
                            "skill_id": s.get("skill_id"),
                            "score": score,
                            "blended_score": blended,
                            "blend_weights": s.get("blend_weights", {}),
                            "bootstrap_prior": s.get("bootstrap_prior", bootstrap_prior),
                            "source": s.get("source", "local"),
                            "tags": s.get("tags", []),
                        }
                    )
            for row in seq_suggestions:
                base = float(row.get("score", 0.0))
                row["blended_confidence"] = round((0.7 * base) + (0.3 * bootstrap_prior), 4)

            # Augment with schemaboot-driven next targets (unanalyzed interesting functions)
            next_targets = []
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            if idb_path:
                try:
                    from .intelligence_context import get_assembler
                    asm = get_assembler()
                    next_targets = asm.suggest_next_targets(idb_path, limit=3)
                except Exception:
                    pass

            return {
                "ok": True,
                "session_id": sid,
                "model": "markov_plus_qvalue",
                "suggestions": seq_suggestions,
                "strategy_suggestions": strategy_rows,
                "next_targets": next_targets,  # schemaboot-ranked unanalyzed functions
                "strategy_confidence": round(strategy_confidence, 4),
                "bootstrap_prior": round(bootstrap_prior, 4),
                "activity_window": len(log),
                "context": context,
            }

        if action == "recommend_bundle":
            tool_res = self._handle_predictor(
                {
                    "action": "suggest_next_tool",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(tool_res, dict) or tool_res.get("error"):
                return tool_res
            focus_res = self._handle_predictor(
                {
                    "action": "suggest_focus",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(focus_res, dict) or focus_res.get("error"):
                return focus_res
            addr_res = self._handle_predictor(
                {
                    "action": "suggest_next_address",
                    "session_id": sid,
                    "limit": limit,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(addr_res, dict) or addr_res.get("error"):
                return addr_res
            stall_res = self._handle_predictor(
                {
                    "action": "risk_of_stall",
                    "session_id": sid,
                    "recent_n": recent_n,
                    "context": context,
                }
            )
            if not isinstance(stall_res, dict) or stall_res.get("error"):
                return stall_res

            return {
                "ok": True,
                "session_id": sid,
                "action": "recommend_bundle",
                "bundle": {
                    "tool_suggestions": tool_res.get("suggestions", []),
                    "strategy_suggestions": tool_res.get("strategy_suggestions", []),
                    "focus_pivots": focus_res.get("focus_pivots", []),
                    "address_suggestions": addr_res.get("suggestions", []),
                    "stall_risk": {
                        "risk_score": stall_res.get("risk_score"),
                        "dead_end_detected": stall_res.get("dead_end_detected"),
                        "entropy": stall_res.get("entropy"),
                    },
                },
                "summary": {
                    "tool_count": len(tool_res.get("suggestions", []) or []),
                    "focus_count": len(focus_res.get("focus_pivots", []) or []),
                    "address_count": len(addr_res.get("suggestions", []) or []),
                    "stall_risk": stall_res.get("risk_score"),
                },
            }

        if action == "detect_stuck":
            dead_end = self.session_mgr._detect_dead_end(log)
            return {
                "ok": True,
                "session_id": sid,
                "stuck": bool(dead_end),
                "signal": dead_end or {},
                "activity_window": len(log),
            }

        if action == "suggest_focus":
            dead_end = self.session_mgr._detect_dead_end(log)
            phase = self.session_mgr.get_phase(str(sid))
            phase_tools = []
            if isinstance(phase, dict) and not phase.get("error"):
                phase_tools = list(phase.get("suggested_tools") or [])

            pivots = []
            if dead_end and isinstance(dead_end, dict):
                dtype = str(dead_end.get("type") or "")
                if dtype == "repeated_decompile":
                    pivots = ["code:callers", "code:callees", "graph:dependency_graph"]
                elif dtype == "repeated_search":
                    pivots = ["search:structured", "schemaboot:query", "string_ops:indicators"]
                elif dtype == "tool_loop":
                    pivots = ["graph:cfg", "classify:function", "threat_hunt:quick"]

            if not pivots:
                pivots = [f"{t}:*" for t in phase_tools[:5]] if phase_tools else ["data:functions", "code:decompile", "search:name"]

            # Embedding-guided pivots from analyst context: map intent text to likely function targets.
            context_text = str(context or "").strip()
            embedding_focus = []
            if context_text:
                try:
                    idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
                    if idb_path:
                        from .intelligence_context import get_assembler
                        asm = get_assembler()
                        idx = asm._get_index(idb_path)
                        if getattr(idx, "size", 0) > 0:
                            q_vec = asm._embedder.embed(context_text[:500])
                            hits = idx.search(q_vec, top_k=max(6, min(9, max(1, limit) * 3)), threshold=0.0)
                            if hits:
                                vals = sorted(float(h.get("similarity") or 0.0) for h in hits)
                                q50 = vals[len(vals) // 2]
                                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [h for h in hits if float(h.get("similarity") or 0.0) >= gate]
                            for h in hits:
                                ea = str(h.get("ea") or "").strip()
                                if not ea:
                                    continue
                                embedding_focus.append(
                                    {
                                        "pivot": f"code:smart_decompile:{ea}",
                                        "similarity": round(float(h.get("similarity") or 0.0), 4),
                                        "name": h.get("name") or ea,
                                    }
                                )
                except Exception:
                    embedding_focus = []

            return {
                "ok": True,
                "session_id": sid,
                "focus_pivots": pivots[:limit],
                "embedding_focus": embedding_focus,
                "phase": phase.get("phase") if isinstance(phase, dict) else None,
                "dead_end": dead_end or {},
            }

        if action == "suggest_next_address":
            # Primary: blackboard next_target (priority queue with time decay + xref boost)
            bb_targets = []
            try:
                sid_str = str(sid)
                bb_path = os.path.join(self.cache_dir, f"{sid_str}.blackboard.db")
                if os.path.exists(bb_path):
                    import importlib.util as _ilu
                    _bb_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        "..", "ida_mcp", "tools", "blackboard.py"
                    )
                    _spec = _ilu.spec_from_file_location("_pred_bb", os.path.abspath(_bb_path))
                    _bmod = _ilu.module_from_spec(_spec)
                    _bmod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                           "idawrite": lambda f: f, "IDAError": Exception})
                    _spec.loader.exec_module(_bmod)
                    store = _bmod.BlackboardStore(db_path=bb_path)
                    raw_targets = store.next_target(limit=limit)
                    for t in raw_targets:
                        bb_targets.append({
                            "addr": t["addr"],
                            "reason": f"{t['category']}: {t['title'][:60]}",
                            "priority_score": t["priority_score"],
                            "source": "blackboard",
                            "tool": "code",
                            "action": "smart_decompile",
                        })
            except Exception:
                pass

            # Secondary: schemaboot + embedding index
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            schema_targets = []
            if idb_path:
                try:
                    from .intelligence_context import get_assembler
                    asm = get_assembler()
                    schema_targets = asm.suggest_next_targets(idb_path, limit=limit)
                except Exception:
                    pass

            # Merge: blackboard first, then schemaboot for any not already covered
            bb_addrs = {t["addr"] for t in bb_targets}
            merged = list(bb_targets)
            for t in schema_targets:
                if t.get("addr") not in bb_addrs:
                    t["source"] = "schemaboot"
                    merged.append(t)

            # Embedding-guided expansion from context when address set is sparse.
            context_text = str(context or "").strip()
            if context_text and len(merged) < limit:
                try:
                    idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
                    if idb_path:
                        from .intelligence_context import get_assembler
                        asm = get_assembler()
                        idx = asm._get_index(idb_path)
                        if getattr(idx, "size", 0) > 0:
                            q_vec = asm._embedder.embed(context_text[:500])
                            hits = idx.search(q_vec, top_k=max(limit * 3, 6), threshold=0.0)
                            if hits:
                                vals = sorted(float(h.get("similarity") or 0.0) for h in hits)
                                q50 = vals[len(vals) // 2]
                                q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                                gate = q50 + max(0.0, q75 - q50)
                                hits = [h for h in hits if float(h.get("similarity") or 0.0) >= gate]
                            known = {str(t.get("addr") or "") for t in merged}
                            for h in hits:
                                ea = str(h.get("ea") or "").strip()
                                if not ea or ea in known:
                                    continue
                                merged.append(
                                    {
                                        "addr": ea,
                                        "reason": f"context semantic match ({context_text[:48]})",
                                        "tool": "code",
                                        "action": "smart_decompile",
                                        "source": "embedding_context",
                                        "similarity": round(float(h.get("similarity") or 0.0), 4),
                                    }
                                )
                                known.add(ea)
                                if len(merged) >= limit:
                                    break
                except Exception:
                    pass

            # Fallback: recent addresses from activity log
            if not merged:
                addrs = []
                for e in log:
                    if not isinstance(e, dict):
                        continue
                    for k in ("addr", "address", "ea"):
                        v = e.get(k)
                        if v and str(v).startswith("0x"):
                            a = str(v).lower()
                            if a not in addrs:
                                addrs.append(a)
                if addrs:
                    merged = [{"addr": addrs[-1], "reason": "recent focus — check callers",
                               "tool": "code", "action": "callers", "source": "activity_log"}]

            return {
                "ok": True,
                "session_id": sid,
                "suggestions": merged[:limit],
                "sources_used": list({t.get("source", "unknown") for t in merged}),
                "note": (
                    "Ranked by blackboard priority (confidence x time_decay x xref_boost). "
                    "Use blackboard(action='next_target') for the full priority queue."
                ) if bb_targets else (
                    "No blackboard entries yet. Run schemaboot(action='ingest') for smarter suggestions."
                ),
            }

        if action == "risk_of_stall":
            dead_end = self.session_mgr._detect_dead_end(log)
            # Sequence entropy: low variety in recent tools -> high stall risk
            recent_tools = [f"{e.get('tool','')}.{e.get('action','')}" for e in log[-20:] if isinstance(e, dict)]
            unique_tools = len(set(recent_tools))
            total_recent = max(1, len(recent_tools))
            entropy = unique_tools / total_recent
            stall_score = 0.0
            if dead_end:
                stall_score += 0.5
            stall_score += max(0.0, 0.5 - entropy)
            return {
                "ok": True,
                "session_id": sid,
                "risk_score": round(min(1.0, stall_score), 3),
                "entropy": round(entropy, 3),
                "dead_end_detected": bool(dead_end),
                "recent_tool_variety": unique_tools,
                "recent_tool_total": total_recent,
            }

        if action == "explain_decision":
            # Explain why a tool/action was suggested, based on real activity state
            target_tool = str(args.get("target_tool") or "").strip()
            target_action = str(args.get("target_action") or "").strip()

            # Derive actual feature contributions from the session's activity log
            recent_tools = [
                f"{e.get('tool','')}.{e.get('action','')}"
                for e in log[-20:] if isinstance(e, dict)
            ]
            from collections import Counter
            tool_freq = Counter(recent_tools)
            ta_key = f"{target_tool}.{target_action}"

            explanations = []
            weights = {
                "markov_transition_probability": 0.0,
                "usage_pattern": 0.0,
                "strategy_weight": 0.0,
                "blackboard_coverage_gap": 0.0,
            }
            # 1. How often has this tool:action appeared in recent history?
            freq = tool_freq.get(ta_key, 0)
            total = max(1, len(recent_tools))
            if freq > 0:
                weights["usage_pattern"] = min(1.0, float(freq) / float(total))
                explanations.append({
                    "feature": "recent_frequency",
                    "count": freq,
                    "ratio": round(freq / total, 3),
                    "reason": f"Called {freq}x in last {total} tool calls",
                })
            # 2. Is this a natural next step from the last tool?
            if recent_tools:
                last = recent_tools[-1]
                NATURAL_NEXT = {
                    "code.decompile": ["crypto_id.identify", "code.callers", "code.callees",
                                        "annotation.mark_dangerous", "graph.call_chain"],
                    "search.api": ["code.decompile", "graph.call_chain"],
                    "search.find": ["code.decompile", "data.functions"],
                    "code.callers": ["code.decompile", "graph.call_chain"],
                }
                if ta_key in NATURAL_NEXT.get(last, []):
                    weights["markov_transition_probability"] = 0.8
                    explanations.append({
                        "feature": "natural_next_step",
                        "after": last,
                        "reason": f"Typical follow-up after {last}",
                    })
            # 3. Is this suggested by an active dangerous pattern?
            idb_path = getattr(self.current_session, "idb_path", None) if self.current_session else None
            if idb_path:
                try:
                    from .intelligence_context import get_assembler
                    asm = get_assembler()
                    targets = asm.suggest_next_targets(idb_path, limit=5)
                    if targets and target_tool == "code" and target_action == "decompile":
                        top = targets[0]
                        weights["blackboard_coverage_gap"] = 0.7
                        explanations.append({
                            "feature": "schemaboot_interest",
                            "top_target": top.get("ea"),
                            "reason": f"Unanalyzed function with {top.get('reason', 'high interest score')}",
                        })
                except Exception:
                    pass
            try:
                strategy = self.session_mgr.suggest_strategy(str(sid), context=f"{target_tool}:{target_action}")
                if isinstance(strategy, dict) and not strategy.get("error"):
                    suggs = strategy.get("suggestions") or []
                    if suggs:
                        weights["strategy_weight"] = max(
                            float(s.get("blended_score", s.get("score", 0.0)) or 0.0)
                            for s in suggs[:5]
                            if isinstance(s, dict)
                        )
            except Exception:
                pass

            if not explanations:
                explanations.append({
                    "feature": "no_strong_signal",
                    "reason": f"No specific signal in activity log for {target_tool}.{target_action}",
                })

            return {
                "ok": True,
                "session_id": sid,
                "target_tool": target_tool,
                "target_action": target_action,
                "activity_window": len(log),
                "explanations": explanations,
                "signal_weights": {k: round(float(v), 4) for k, v in weights.items()},
            }

        if action == "feedback":
            target_tool = str(args.get("tool") or args.get("target_tool") or "").strip().lower()
            target_action = str(args.get("target_action") or "").strip().lower()
            outcome = str(args.get("outcome") or "").strip().lower()
            if not target_tool or not target_action:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "feedback requires tool and target_action",
                    hint="Example: predictor(action='feedback', tool='search', target_action='find', outcome='helpful')",
                )
            if outcome not in {"helpful", "not_helpful"}:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "outcome must be 'helpful' or 'not_helpful'",
                )
            delta = 0.05 if outcome == "helpful" else -0.05
            meta = self.session_mgr.macro_get(str(sid), "__predictor_feedback") or {}
            if not isinstance(meta, dict):
                meta = {}
            key = f"{target_tool}.{target_action}"
            row = meta.get(key) if isinstance(meta.get(key), dict) else {"weight": 0.5, "count": 0}
            row["weight"] = max(0.0, min(1.0, float(row.get("weight", 0.5)) + delta))
            row["count"] = int(row.get("count", 0)) + 1
            row["last_outcome"] = outcome
            meta[key] = row
            self.session_mgr.macro_set(str(sid), "__predictor_feedback", meta)
            return {
                "ok": True,
                "session_id": sid,
                "tool": target_tool,
                "target_action": target_action,
                "outcome": outcome,
                "updated_weight": round(float(row["weight"]), 4),
                "feedback_count": int(row["count"]),
            }

        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported predictor action: '{action}'",
            hint=f"Valid predictor actions: {', '.join(TOOL_ACTIONS.get('predictor', []))}",
        )

