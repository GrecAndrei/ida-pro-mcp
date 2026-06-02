#!/usr/bin/env python3
"""Session skills, bootstrap, activity, and phase helpers."""

import json
import math
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .errors import MCPError, make_error
from .config import log_rpc
from .session_skills_bootstrap import SessionBootstrapMixin

# ====================================================================
# ANALYSIS PHASES
# ====================================================================

_ANALYSIS_PHASES = {
    "triage": {
        "order": 0,
        "threshold": {"functions_listed": 1, "strings_listed": 1, "imports_listed": 1},
        "suggested_tools": ["binary_info.headers", "idb.summary", "data.imports", "data.strings"],
        "description": "Initial triage: identify binary type, imports, and suspicious strings.",
    },
    "import_analysis": {
        "order": 1,
        "threshold": {"imports_categorized": 20, "api_patterns_detected": 1},
        "suggested_tools": ["imports_deep.thunks", "classify.categorize", "string_ops.find_urls"],
        "description": "Categorize imports and detect API usage patterns.",
    },
    "deep_analysis": {
        "order": 2,
        "threshold": {"functions_decompiled": 10, "function_attrs_indexed": 1},
        "suggested_tools": ["code.decompile", "ctree.get", "crypto_id.detect", "schemaboot.ingest"],
        "description": "Deep decompilation and semantic analysis.",
    },
    "behavior_mapping": {
        "order": 3,
        "threshold": {"functions_analyzed": 50, "xrefs_traced": 30},
        "suggested_tools": ["graph.call_chain", "bridge_search.search", "code.callers"],
        "description": "Map control flow and cross-reference chains.",
    },
    "vulnerability": {
        "order": 4,
        "threshold": {"functions_analyzed": 100, "dangerous_apis_identified": 5},
        "suggested_tools": ["gadgets.find", "stack_analysis.analyze_frame", "cfg_analysis.complexity"],
        "description": "Vulnerability and exploit analysis.",
    },
    "reporting": {
        "order": 5,
        "threshold": {"bookmarks_created": 5},
        "suggested_tools": ["blackboard.export", "bulk.export_annotations", "session.notebook"],
        "description": "Compile findings and produce report.",
    },
}


class SessionSkillsMixin(SessionBootstrapMixin):
    def _get_skills_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_skills.json")

    def _load_skills(self, sid: str) -> dict:
        path = self._get_skills_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"skills": {}, "q_table": {}, "activity_log": [], "hypotheses": []}

    def _save_skills(self, sid: str, data: dict):
        path = self._get_skills_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save skills for {sid}: {e}")

    def _bootstrap_plan_matrix(self) -> Dict[str, List[str]]:
        return {
            "phase1_bootstrap_core": [
                "bootstrap_init",
                "bootstrap_run_tournament",
                "bootstrap_compute_blend",
                "bootstrap_status",
            ],
            "phase2_scoring_integration": [
                "suggest_strategy_blended",
                "predictor_suggest_next_tool_blended",
            ],
            "phase3_outcome_dispute": [
                "bootstrap_ingest_outcome",
                "bootstrap_open_dispute",
                "bootstrap_list_disputes",
                "bootstrap_resolve_dispute",
            ],
            "phase4_observability_drift": [
                "bootstrap_summary",
                "bootstrap_summary_detailed",
                "bootstrap_calibration_report",
                "bootstrap_snapshot",
                "bootstrap_list_snapshots",
                "bootstrap_drift_report",
                "bootstrap_update_baseline",
                "bootstrap_evaluate_alerts",
            ],
            "phase5_mitigation_loop": [
                "bootstrap_mitigation_plan",
                "bootstrap_apply_mitigation",
                "bootstrap_mitigation_history",
                "bootstrap_mitigation_effectiveness",
            ],
            "phase6_adaptation_safeguards": [
                "bootstrap_policy_reweight",
                "bootstrap_policy_reweight_history",
                "bootstrap_autopilot",
                "bootstrap_set_autopilot_policy",
                "bootstrap_get_autopilot_policy",
                "bootstrap_rollback_last_reweight",
            ],
            "phase7_ops_hygiene": [
                "bootstrap_export_metrics",
                "bootstrap_prune_data",
                "bootstrap_simulate_batch",
            ],
        }

    def bootstrap_plan_status(self, sid: str) -> dict:
        """Return machine-readable implementation plan coverage and runtime readiness."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            matrix = self._bootstrap_plan_matrix()

            implemented_actions = set()
            # Session manager methods present at runtime.
            for phase_items in matrix.values():
                for item in phase_items:
                    if item in ("suggest_strategy_blended", "predictor_suggest_next_tool_blended"):
                        implemented_actions.add(item)
                    elif hasattr(self, item):
                        implemented_actions.add(item)

            phase_rows = []
            total_items = 0
            total_done = 0
            for phase, items in matrix.items():
                done = [i for i in items if i in implemented_actions]
                total_items += len(items)
                total_done += len(done)
                phase_rows.append(
                    {
                        "phase": phase,
                        "items": len(items),
                        "done": len(done),
                        "coverage": round((len(done) / max(1, len(items))) * 100.0, 2),
                        "missing": [i for i in items if i not in done],
                    }
                )

            runtime = {
                "bootstrap_initialized": bool(bootstrap),
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)) if bootstrap else 0,
                "total_rounds": int(bootstrap.get("total_rounds", 0)) if bootstrap else 0,
                "snapshot_count": len(bootstrap.get("metric_snapshots") or []) if bootstrap else 0,
                "dispute_count": len(bootstrap.get("disputes") or []) if bootstrap else 0,
                "mitigation_history_count": len(bootstrap.get("mitigation_history") or []) if bootstrap else 0,
                "reweight_history_count": len(bootstrap.get("policy_reweight_history") or []) if bootstrap else 0,
            }

            return {
                "ok": True,
                "overall": {
                    "items": total_items,
                    "done": total_done,
                    "coverage": round((total_done / max(1, total_items)) * 100.0, 2),
                },
                "phases": phase_rows,
                "runtime": runtime,
            }

    def bootstrap_readiness_gate(
        self,
        sid: str,
        min_tournament_rounds: int = 1000,
        min_snapshots: int = 10,
        min_outcomes: int = 200,
        max_ece: float = 0.2,
        max_open_disputes: int = 25,
    ) -> dict:
        """Programmatic completion gate for the full bootstrap implementation plan."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_plan_status(sid)
            if plan.get("error"):
                return plan
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary
            calib = self.bootstrap_calibration_report(sid, min_bin_n=1)
            if calib.get("error"):
                return calib
            eff = self.bootstrap_mitigation_effectiveness(sid, window=50)
            if eff.get("error"):
                return eff

            runtime = plan.get("runtime") or {}
            gates = {
                "phase_coverage_100": float((plan.get("overall") or {}).get("coverage", 0.0)) >= 100.0,
                "bootstrap_initialized": bool(runtime.get("bootstrap_initialized")),
                "tournament_rounds": int(runtime.get("total_rounds", 0)) >= max(1, int(min_tournament_rounds)),
                "snapshot_depth": int(runtime.get("snapshot_count", 0)) >= max(1, int(min_snapshots)),
                "outcome_depth": int((summary.get("outcomes") or {}).get("count", 0)) >= max(1, int(min_outcomes)),
                "ece_within_bound": float(calib.get("ece", 1.0)) <= float(max_ece),
                "open_disputes_bound": int((summary.get("disputes") or {}).get("open", 0)) <= max(0, int(max_open_disputes)),
                "mitigation_effectiveness_present": bool(eff.get("enough_data")),
            }

            passed = [k for k, v in gates.items() if bool(v)]
            failed = [k for k, v in gates.items() if not bool(v)]
            readiness = len(failed) == 0
            stage = "production_ready" if readiness else "needs_more_runtime_data"

            return {
                "ok": True,
                "readiness": readiness,
                "stage": stage,
                "passed": passed,
                "failed": failed,
                "gates": gates,
                "plan_overall": plan.get("overall"),
                "runtime": runtime,
                "summary": {
                    "ece": calib.get("ece"),
                    "open_disputes": (summary.get("disputes") or {}).get("open"),
                    "outcomes": (summary.get("outcomes") or {}).get("count"),
                    "mitigation_effectiveness": eff.get("effectiveness_score") if eff.get("enough_data") else None,
                },
                "thresholds": {
                    "min_tournament_rounds": int(min_tournament_rounds),
                    "min_snapshots": int(min_snapshots),
                    "min_outcomes": int(min_outcomes),
                    "max_ece": float(max_ece),
                    "max_open_disputes": int(max_open_disputes),
                },
            }

    def bootstrap_record_readiness(self, sid: str, tag: str = "") -> dict:
        """Record a readiness-gate snapshot into rolling history."""
        with self._lock:
            gate = self.bootstrap_readiness_gate(sid)
            if gate.get("error"):
                return gate
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            hist = bootstrap.setdefault("readiness_history", [])
            row = {
                "timestamp": datetime.now().isoformat(),
                "tag": str(tag or "").strip() or None,
                "readiness": bool(gate.get("readiness")),
                "stage": gate.get("stage"),
                "passed": list(gate.get("passed") or []),
                "failed": list(gate.get("failed") or []),
                "coverage": float((gate.get("plan_overall") or {}).get("coverage", 0.0)),
                "ece": (gate.get("summary") or {}).get("ece"),
                "outcomes": (gate.get("summary") or {}).get("outcomes"),
                "open_disputes": (gate.get("summary") or {}).get("open_disputes"),
            }
            hist.append(row)
            bootstrap["readiness_history"] = hist[-5000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "entry": row, "history_count": len(bootstrap["readiness_history"])}

    def bootstrap_readiness_history(self, sid: str, limit: int = 100, offset: int = 0) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("readiness_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 10000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_readiness_trend(self, sid: str, window: int = 50) -> dict:
        """Readiness pass-rate, slope, and regression signal over history window."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("readiness_history") or [])))
            if len(rows) < 2:
                return {
                    "ok": True,
                    "enough_data": False,
                    "count": len(rows),
                    "message": "Need at least 2 readiness records",
                }

            w = max(2, min(int(window), len(rows)))
            recent = rows[-w:]
            vals = [1.0 if bool(r.get("readiness")) else 0.0 for r in recent]
            coverage = [float(r.get("coverage", 0.0)) for r in recent]
            pass_rate = sum(vals) / max(1, len(vals))

            # Simple slope from first/last halves.
            mid = len(vals) // 2
            first_avg = sum(vals[:mid]) / max(1, len(vals[:mid]))
            last_avg = sum(vals[mid:]) / max(1, len(vals[mid:]))
            slope = last_avg - first_avg
            cov_slope = (coverage[-1] - coverage[0]) if coverage else 0.0

            regressing = slope < -0.15 or cov_slope < -5.0
            improving = slope > 0.15 or cov_slope > 5.0
            status = "stable"
            if regressing:
                status = "regressing"
            elif improving:
                status = "improving"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "pass_rate": round(pass_rate, 6),
                "readiness_slope": round(slope, 6),
                "coverage_slope": round(cov_slope, 6),
                "status": status,
                "regressing": regressing,
            }

    def bootstrap_readiness_regression_guard(
        self,
        sid: str,
        window: int = 50,
        auto_snapshot: bool = True,
    ) -> dict:
        """Guardrail action when readiness trend regresses."""
        with self._lock:
            trend = self.bootstrap_readiness_trend(sid, window=window)
            if trend.get("error"):
                return trend
            if not trend.get("enough_data"):
                return {"ok": True, "triggered": False, "reason": "insufficient_data", "trend": trend}

            triggered = bool(trend.get("regressing"))
            actions = []
            if triggered:
                actions.append(
                    {
                        "action": "bootstrap_update_baseline",
                        "params": {"window": max(30, int(window)), "percentile": 97.0},
                    }
                )
                actions.append(
                    {
                        "action": "bootstrap_mitigation_plan",
                        "params": {"window": max(20, int(window // 2))},
                    }
                )
                if auto_snapshot:
                    actions.append(
                        {
                            "action": "bootstrap_snapshot",
                            "params": {"name": "readiness_regression_guard"},
                        }
                    )

            return {
                "ok": True,
                "triggered": triggered,
                "trend": trend,
                "actions": actions,
            }

    def bootstrap_finalize_report(
        self,
        sid: str,
        trend_window: int = 50,
        effectiveness_window: int = 50,
    ) -> dict:
        """Produce a one-shot final status report for implementation plan closure."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_plan_status(sid)
            if plan.get("error"):
                return plan
            gate = self.bootstrap_readiness_gate(sid)
            if gate.get("error"):
                return gate
            trend = self.bootstrap_readiness_trend(sid, window=trend_window)
            if trend.get("error"):
                return trend
            eff = self.bootstrap_mitigation_effectiveness(sid, window=effectiveness_window)
            if eff.get("error"):
                return eff
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary

            release_ready = bool(gate.get("readiness")) and bool(plan.get("overall", {}).get("coverage", 0.0) >= 100.0)
            risk_flags = []
            if trend.get("enough_data") and trend.get("regressing"):
                risk_flags.append("readiness_regressing")
            if eff.get("enough_data") and str(eff.get("tier")) == "poor":
                risk_flags.append("mitigation_effectiveness_poor")
            if float((summary.get("calibration") or {}).get("ece", 0.0) or 0.0) > 0.2:
                risk_flags.append("ece_above_recommended")

            stage = "ready" if release_ready and not risk_flags else "needs_attention"
            return {
                "ok": True,
                "stage": stage,
                "release_ready": release_ready,
                "risk_flags": risk_flags,
                "plan": plan,
                "readiness_gate": gate,
                "readiness_trend": trend,
                "mitigation_effectiveness": eff,
                "bootstrap_summary": summary,
                "generated_at": datetime.now().isoformat(),
            }

    def _bootstrap_prior_confidence(self, bootstrap: Optional[dict]) -> float:
        """Estimate confidence prior from tournament policy quality (0..1)."""
        if not isinstance(bootstrap, dict):
            return 0.5
        policies = bootstrap.get("policies") or {}
        if not policies:
            return 0.5
        rows = []
        for p in policies.values():
            samples = max(1, int(p.get("samples", 0)))
            avg_brier = float(p.get("brier_sum", 0.0)) / samples
            rating = float(p.get("rating", 1500.0))
            # Convert rating to confidence-like weight around 0.5 baseline.
            rating_conf = 1.0 / (1.0 + math.exp(-(rating - 1500.0) / 220.0))
            quality = max(0.0, min(1.0, 1.0 - avg_brier))
            rows.append((samples, quality, rating_conf))
        if not rows:
            return 0.5
        # Weight by sample support and rating confidence.
        num = 0.0
        den = 0.0
        for samples, quality, rating_conf in rows:
            w = max(1.0, math.sqrt(float(samples))) * (0.5 + 0.5 * rating_conf)
            num += w * quality
            den += w
        if den <= 0.0:
            return 0.5
        return max(0.0, min(1.0, num / den))

    def crystallize_skill(
        self, sid: str, name: str, description: str, steps: list,
        tags: Optional[list] = None, memrl_reward: Optional[float] = None,
    ) -> dict:
        """Crystallize a workflow into a reusable L3 skill, stored in global registry."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            base_skill_id = f"skill_{name.lower().replace(' ', '_')}"
            skill_id = base_skill_id
            suffix = 2
            while skill_id in data["skills"]:
                skill_id = f"{base_skill_id}_{suffix}"
                suffix += 1
            skill = {
                "name": name,
                "description": description,
                "steps": steps,
                "tags": tags or [],
                "created_at": datetime.now().isoformat(),
                "success_count": 0,
                "failure_count": 0,
                "last_used": None,
                "q_value": 0.5,
            }
            data["skills"][skill_id] = skill
            data["q_table"][skill_id] = 0.5
            self._save_skills(sid, data)
            # Also save to global registry for cross-session access
            self._crystallize_to_global_registry(sid, skill_id, skill)
            session.update_access()
            self._save_metadata(session)
            return {"ok": True, "skill_id": skill_id, "skill": skill, "global": True}

    def rate_skill(self, sid: str, skill_id: str, reward: float) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skill = data["skills"].get(skill_id)
            if not skill:
                return make_error(MCPError.NOT_FOUND, f"Skill {skill_id} not found")
            alpha = 0.15
            current_q = data["q_table"].get(skill_id, 0.5)
            new_q = max(0.0, min(1.0, current_q + alpha * (reward - current_q)))
            data["q_table"][skill_id] = round(new_q, 4)
            skill["q_value"] = round(new_q, 4)
            skill["last_used"] = datetime.now().isoformat()
            if reward > 0:
                skill["success_count"] += 1
            else:
                skill["failure_count"] += 1
            self._save_skills(sid, data)
            # Update global registry
            self._crystallize_to_global_registry(sid, skill_id, skill)
            # L3 -> L2 promotion if Q-value exceeds 0.8
            result = {"ok": True, "skill_id": skill_id, "q_value": skill["q_value"], "reward": reward}
            if new_q >= 0.8:
                result["promoted_to_L2"] = True
            return result

    def list_skills(self, sid: str, min_q: float = 0.0, global_skills: bool = True) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            local = {
                k: v for k, v in data["skills"].items() if v.get("q_value", 0.0) >= min_q
            }
            # Sort by Q-value
            local = dict(sorted(local.items(), key=lambda x: x[1].get("q_value", 0), reverse=True))
            result = {"ok": True, "local_skills": local, "local_count": len(local)}
            if global_skills:
                local_tags = set()
                for sk in local.values():
                    for t in sk.get("tags", []) or []:
                        t = str(t).strip()
                        if t:
                            local_tags.add(t)
                global_skills = self._find_global_skills(tags=sorted(local_tags), limit=20)
                result["global_skills"] = global_skills
                result["global_count"] = len(global_skills)
            return result

    def suggest_strategy(self, sid: str, context: str = "") -> dict:
        """Suggest highest-Q skills from both local and global registry."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)

            # Local skills
            ranked = []
            ctx_lower = (context or "").lower()
            ctx_has_text = bool((context or "").strip())
            bootstrap = data.get("bootstrap")
            bootstrap_prior = self._bootstrap_prior_confidence(bootstrap)
            embedder = None
            ctx_vec = None
            if ctx_has_text:
                try:
                    from ida_pro_mcp.host.intelligence_core import BgeCodeEmbedder
                    embedder = BgeCodeEmbedder()
                    ctx_vec = embedder.embed((context or "")[:1200])
                except Exception:
                    embedder = None
                    ctx_vec = None
            for skill_id, skill in data["skills"].items():
                base_score = float(skill.get("q_value", 0.5))
                desc = (skill.get("description", "") + " " + " ".join(skill.get("tags", []))).lower()
                context_relevance = 0.0
                if ctx_has_text:
                    if embedder is not None and ctx_vec is not None and desc.strip():
                        try:
                            dvec = embedder.embed(desc[:1200])
                            context_relevance = float(BgeCodeEmbedder.cosine(ctx_vec, dvec))
                        except Exception:
                            context_relevance = 0.0
                    elif ctx_lower and any(word in desc for word in ctx_lower.split()):
                        # Deterministic fallback when embeddings unavailable.
                        context_relevance = 0.5
                    skill["context_match"] = bool(context_relevance > 0.0)
                score = ((base_score + context_relevance) / 2.0) if ctx_has_text else base_score
                samples = int(skill.get("success_count", 0)) + int(skill.get("failure_count", 0))
                blend = self.bootstrap_compute_blend(sid, session_samples=samples)
                weights = (blend or {}).get("weights") or {"bootstrap": 0.5, "session": 0.5}
                blended_score = (
                    float(weights.get("session", 0.5)) * float(score)
                    + float(weights.get("bootstrap", 0.5)) * float(bootstrap_prior)
                )
                ranked.append(
                    {
                        "skill_id": skill_id,
                        "score": round(score, 4),
                        "blended_score": round(blended_score, 4),
                        "blend_weights": weights,
                        "bootstrap_prior": round(bootstrap_prior, 4),
                        "source": "local",
                        **skill,
                    }
                )

            # Global skills
            global_skills = self._find_global_skills(context=context, limit=10)
            for gs in global_skills:
                if gs["skill_id"] not in data["skills"]:
                    base_score = float(gs.get("q_value", 0.5))
                    desc = (str(gs.get("description", "")) + " " + " ".join(gs.get("tags", []))).lower()
                    context_relevance = 0.0
                    if ctx_has_text:
                        if embedder is not None and ctx_vec is not None and desc.strip():
                            try:
                                dvec = embedder.embed(desc[:1200])
                                context_relevance = float(BgeCodeEmbedder.cosine(ctx_vec, dvec))
                            except Exception:
                                context_relevance = 0.0
                        elif ctx_lower and any(word in desc for word in ctx_lower.split()):
                            context_relevance = 0.5
                    score = ((base_score + context_relevance) / 2.0) if ctx_has_text else base_score
                    weights = (self.bootstrap_compute_blend(sid, session_samples=0) or {}).get("weights") or {
                        "bootstrap": 0.5,
                        "session": 0.5,
                    }
                    blended_score = (
                        float(weights.get("session", 0.5)) * float(score)
                        + float(weights.get("bootstrap", 0.5)) * float(bootstrap_prior)
                    )
                    ranked.append(
                        {
                            "skill_id": gs["skill_id"],
                            "score": round(score, 4),
                            "blended_score": round(blended_score, 4),
                            "blend_weights": weights,
                            "bootstrap_prior": round(bootstrap_prior, 4),
                            "source": "global",
                            **gs,
                        }
                    )

            ranked.sort(key=lambda x: -float(x.get("blended_score", x.get("score", 0.0))))
            return {
                "ok": True,
                "suggestions": ranked[:10],
                "context": context,
                "bootstrap_prior": round(bootstrap_prior, 4),
                "bootstrap_initialized": bool(bootstrap),
            }

    # ====================================================================
    # ACTIVITY LOG + DEAD-END DETECTION
    # ====================================================================

    def log_activity(self, sid: str, tool: str, action: str, result: str = "") -> dict:
        """Log activity and check for dead-end patterns."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            entry = {
                "tool": tool, "action": action, "result": result,
                "timestamp": datetime.now().isoformat(),
            }
            data.setdefault("activity_log", []).append(entry)
            # Keep last 500 entries (was 100 — way too small)
            data["activity_log"] = data["activity_log"][-500:]
            self._save_skills(sid, data)
            session.update_access()
            self._save_metadata(session)
            out = {"ok": True}
            # Dead-end detection
            dead_end = self._detect_dead_end(data["activity_log"])
            if dead_end:
                out["dead_end_warning"] = dead_end
            return out

    def check_state_contract(self, sid: str, window: int = 8) -> dict:
        """Check if analyst has persisted findings to blackboard within recent window."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return {"ok": False, "error": "session_not_found"}
            data = self._load_skills(sid)
            log = data.get("activity_log", [])
            recent = log[-window:]
            bb_writes = sum(
                1
                for e in recent
                if isinstance(e, dict)
                and e.get("tool") == "blackboard"
                and str(e.get("action") or "").startswith("write")
            )
            return {
                "ok": True,
                "session_id": sid,
                "contract_met": bb_writes > 0,
                "blackboard_writes_in_window": bb_writes,
                "window_size": len(recent),
                "recommended_action": {
                    "tool": "blackboard",
                    "arguments": {
                        "action": "write",
                        "name": "finding_summary",
                        "notes": "<concise finding from recent analysis>",
                        "category": "analysis",
                        "priority": 3,
                    },
                },
            }

    def _detect_dead_end(self, activity_log: List[dict]) -> Optional[dict]:
        """Detect stalled analysis patterns."""
        if len(activity_log) < 10:
            return None
        recent = activity_log[-20:]
        # Pattern 1: Same function decompiled >4 times in a row
        decompile_targets = [e.get("result") for e in recent if e.get("action") == "decompile" and e.get("result")]
        if len(decompile_targets) >= 5 and len(set(decompile_targets[-5:])) == 1:
            return {
                "type": "repeated_decompile",
                "function": decompile_targets[-1],
                "count": decompile_targets.count(decompile_targets[-1]),
                "suggestion": "Try looking at callers, callees, or xrefs of this function instead of redecompiling.",
            }
        # Pattern 2: Same search query >3 times
        searches = [e.get("result") for e in recent if e.get("action") in ("find", "search") and e.get("result")]
        if searches:
            last_search = searches[-1]
            if searches.count(last_search) >= 4:
                return {
                    "type": "repeated_search",
                    "query": last_search,
                    "suggestion": "Try broadening the search or using structured search with different constraints.",
                }
        # Pattern 3: Looping between two tools
        tool_seq = [(e["tool"], e["action"]) for e in recent[-10:]]
        if len(tool_seq) >= 6:
            pairs = [(tool_seq[i], tool_seq[i + 1]) for i in range(len(tool_seq) - 1)]
            for pair in set(pairs):
                if pairs.count(pair) >= 3:
                    return {
                        "type": "tool_loop",
                        "pattern": f"{pair[0][0]}.{pair[0][1]} <-> {pair[1][0]}.{pair[1][1]}",
                        "suggestion": "You may be stuck in a loop. Try pivoting to a different analysis approach.",
                    }
        return None

    def get_activity_log(self, sid: str, limit: int = 20) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            log = data.get("activity_log", [])
            return {"ok": True, "log": log[-limit:], "total": len(log)}

    # ====================================================================
    # METRICS DASHBOARD
    # ====================================================================

    def dashboard(self, sid: str) -> dict:
        """Analysis progress dashboard for the LLM."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            activity_log = data.get("activity_log", [])
            hypotheses = data.get("hypotheses", [])
            skills = data.get("skills", {})

            # Count unique actions
            unique_actions = set()
            tool_action_counts: Dict[str, int] = {}
            for e in activity_log:
                key = f"{e.get('tool')}.{e.get('action')}"
                unique_actions.add(key)
                tool_action_counts[key] = tool_action_counts.get(key, 0) + 1

            # Calculate completion indicators
            functions_decompiled = tool_action_counts.get("code.decompile", 0) + tool_action_counts.get("code.semantic_decompile", 0)
            searches_performed = sum(v for k, v in tool_action_counts.items() if k.startswith("search.") or k.startswith("data."))
            xrefs_traced = sum(v for k, v in tool_action_counts.items() if "xref" in k)

            return {
                "ok": True,
                "phase": session.phase,
                "activity": {
                    "total_actions": len(activity_log),
                    "unique_tools_used": len(unique_actions),
                    "functions_decompiled": functions_decompiled,
                    "searches_performed": searches_performed,
                    "xrefs_traced": xrefs_traced,
                },
                "hypotheses": {
                    "total": len(hypotheses),
                    "confirmed": sum(1 for h in hypotheses if h.get("status") == "confirmed"),
                    "refuted": sum(1 for h in hypotheses if h.get("status") == "refuted"),
                    "pending": sum(1 for h in hypotheses if h.get("status") == "pending"),
                },
                "skills": {"crystallized": len(skills), "avg_q_value": round(sum(s.get("q_value", 0) for s in skills.values()) / max(1, len(skills)), 3)},
                "bootstrap": {
                    "initialized": bool(data.get("bootstrap")),
                    "tournament_runs": int((data.get("bootstrap") or {}).get("tournament_runs", 0)),
                    "total_rounds": int((data.get("bootstrap") or {}).get("total_rounds", 0)),
                    "prior_confidence": round(self._bootstrap_prior_confidence(data.get("bootstrap")), 4),
                },
                "suggested_next": _ANALYSIS_PHASES.get(session.phase, {}).get("suggested_tools", []),
            }

    # ====================================================================
    # PHASE TRANSITION
    # ====================================================================

    def get_phase(self, sid: str) -> dict:
        session = self.sessions.get(sid)
        if not session:
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
        phase_info = _ANALYSIS_PHASES.get(session.phase, {})
        return {"ok": True, "phase": session.phase, "description": phase_info.get("description", ""),
                "suggested_tools": phase_info.get("suggested_tools", [])}

    def advance_phase(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            phases = sorted(_ANALYSIS_PHASES.keys(), key=lambda p: _ANALYSIS_PHASES[p]["order"])
            try:
                idx = phases.index(session.phase)
                if idx < len(phases) - 1:
                    session.phase = phases[idx + 1]
            except ValueError:
                session.phase = "triage"
            session.update_access()
            self._save_metadata(session)
            phase_info = _ANALYSIS_PHASES.get(session.phase, {})
            return {"ok": True, "phase": session.phase, "description": phase_info.get("description", ""),
                    "suggested_tools": phase_info.get("suggested_tools", [])}

    # ====================================================================
    # FEDERATED SESSION LINKING
    # ====================================================================

    def link_session(self, sid: str, other_sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            other = self.sessions.get(other_sid)
            if not session or not other:
                return make_error(MCPError.SESSION_NOT_FOUND, f"One or both sessions not found")
            if other_sid not in session.linked_sessions:
                session.linked_sessions.append(other_sid)
            if sid not in other.linked_sessions:
                other.linked_sessions.append(sid)
            session.update_access()
            self._save_metadata(session)
            self._save_metadata(other)
            return {"ok": True, "linked": [sid, other_sid]}

    def cross_reference_sessions(self, sid: str) -> dict:
        """Find shared functions/strings across linked sessions."""
        session = self.sessions.get(sid)
        if not session:
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
        linked = session.linked_sessions
        if not linked:
            return {"ok": True, "shared": [], "note": "No linked sessions. Use link_session to federate."}
        # Collect function names from all linked sessions' skills data
        shared_funcs: Dict[str, List[str]] = {}
        for lsid in [sid] + linked:
            data = self._load_skills(lsid)
            for entry in data.get("activity_log", []):
                func = entry.get("result", "")
                if func:
                    shared_funcs.setdefault(func, []).append(lsid)
        # Only keep functions appearing in multiple sessions
        cross = {k: v for k, v in shared_funcs.items() if len(set(v)) > 1}
        return {"ok": True, "shared_functions": list(cross.keys()), "details": cross}

