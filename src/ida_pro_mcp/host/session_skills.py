#!/usr/bin/env python3
"""Session skills, bootstrap, activity, and phase helpers."""

import json
import math
import os
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .errors import MCPError, make_error
from .config import log_rpc

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
        "suggested_tools": ["xref_analysis.call_chain", "bridgerag.search", "code.callers"],
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


class SessionSkillsMixin:
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

    def _default_bootstrap_policies(self) -> List[dict]:
        """Synthetic analyst policies used for cold-start tournament calibration."""
        return [
            {"id": "p01_balanced", "name": "Balanced Analyst", "weights": [0.35, 0.30, 0.20, 0.15], "bias": 0.00, "noise": 0.03},
            {"id": "p02_static_heavy", "name": "Static-Heavy", "weights": [0.55, 0.20, 0.15, 0.10], "bias": -0.03, "noise": 0.04},
            {"id": "p03_dynamic_heavy", "name": "Dynamic-Heavy", "weights": [0.18, 0.52, 0.20, 0.10], "bias": 0.02, "noise": 0.05},
            {"id": "p04_semantic_focus", "name": "Semantic Focus", "weights": [0.20, 0.20, 0.45, 0.15], "bias": 0.00, "noise": 0.04},
            {"id": "p05_novelty_hunter", "name": "Novelty Hunter", "weights": [0.15, 0.20, 0.20, 0.45], "bias": 0.04, "noise": 0.05},
            {"id": "p06_conservative", "name": "Conservative", "weights": [0.35, 0.25, 0.25, 0.15], "bias": -0.10, "noise": 0.02},
            {"id": "p07_aggressive", "name": "Aggressive", "weights": [0.25, 0.30, 0.25, 0.20], "bias": 0.12, "noise": 0.05},
            {"id": "p08_low_noise", "name": "Low Noise", "weights": [0.30, 0.30, 0.25, 0.15], "bias": 0.00, "noise": 0.01},
            {"id": "p09_high_noise", "name": "High Noise", "weights": [0.30, 0.30, 0.20, 0.20], "bias": 0.00, "noise": 0.10},
            {"id": "p10_risk_sensitive", "name": "Risk Sensitive", "weights": [0.25, 0.25, 0.30, 0.20], "bias": -0.02, "noise": 0.03},
            {"id": "p11_bridge_sensitive", "name": "Bridge Sensitive", "weights": [0.22, 0.22, 0.18, 0.38], "bias": 0.03, "noise": 0.04},
            {"id": "p12_entropy_guard", "name": "Entropy Guard", "weights": [0.40, 0.22, 0.20, 0.18], "bias": -0.01, "noise": 0.03},
        ]

    def bootstrap_init(
        self,
        sid: str,
        overwrite: bool = False,
        decay_lambda: float = 0.03,
        min_bootstrap_weight: float = 0.1,
    ) -> dict:
        """Initialize bootstrap synthetic-analyst lab for cold-start calibration."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            if data.get("bootstrap") and not overwrite:
                b = data["bootstrap"]
                return {
                    "ok": True,
                    "initialized": False,
                    "policies": len((b.get("policies") or {})),
                    "message": "Bootstrap lab already exists. Use overwrite=true to reset.",
                }
            policies = {}
            now = datetime.now().isoformat()
            for p in self._default_bootstrap_policies():
                policies[p["id"]] = {
                    "name": p["name"],
                    "weights": p["weights"],
                    "bias": p["bias"],
                    "noise": p["noise"],
                    "rating": 1500.0,
                    "samples": 0,
                    "brier_sum": 0.0,
                    "calibration_bins": {str(i): {"n": 0, "sum_pred": 0.0, "sum_obs": 0.0} for i in range(10)},
                }
            data["bootstrap"] = {
                "version": 1,
                "created_at": now,
                "updated_at": now,
                "decay_lambda": float(decay_lambda),
                "min_bootstrap_weight": float(min_bootstrap_weight),
                "tournament_runs": 0,
                "total_rounds": 0,
                "policies": policies,
                "history": [],
            }
            self._save_skills(sid, data)
            return {"ok": True, "initialized": True, "policies": len(policies)}

    def _policy_predict(self, policy: dict, features: List[float], rng: random.Random) -> float:
        weights = policy.get("weights") or [0.25, 0.25, 0.25, 0.25]
        score = sum(w * x for w, x in zip(weights, features))
        score += float(policy.get("bias", 0.0))
        noise = float(policy.get("noise", 0.0))
        if noise > 0.0:
            score += rng.gauss(0.0, noise)
        return min(0.999, max(0.001, score))

    def bootstrap_run_tournament(self, sid: str, rounds: int = 200, seed: int = 1337) -> dict:
        """Run synthetic policy tournament and update calibration/rating statistics."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                init_res = self.bootstrap_init(sid)
                if init_res.get("error"):
                    return init_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap")

            rounds = max(1, min(int(rounds), 50000))
            rng = random.Random(int(seed))
            policies = bootstrap.get("policies") or {}
            if not policies:
                return make_error(MCPError.INVALID_ARGS, "No bootstrap policies found")

            per_policy_loss: Dict[str, float] = {pid: 0.0 for pid in policies}
            per_policy_wins: Dict[str, int] = {pid: 0 for pid in policies}

            for _ in range(rounds):
                # Synthetic evidence cube: [static, dynamic, semantic, novelty]
                static = rng.betavariate(2.2, 2.4)
                dynamic = rng.betavariate(2.0, 2.0)
                semantic = rng.betavariate(2.4, 2.1)
                novelty = rng.betavariate(1.6, 2.8)
                features = [static, dynamic, semantic, novelty]

                # Latent probability (no direct ground truth in real world; synthetic proxy here)
                latent = (
                    0.34 * static
                    + 0.31 * dynamic
                    + 0.22 * semantic
                    + 0.13 * novelty
                    + rng.gauss(0.0, 0.05)
                )
                latent = min(0.999, max(0.001, latent))
                observed = 1 if rng.random() < latent else 0

                losses = {}
                for pid, p in policies.items():
                    pred = self._policy_predict(p, features, rng)
                    brier = (pred - observed) ** 2
                    losses[pid] = brier
                    per_policy_loss[pid] += brier

                    p["samples"] = int(p.get("samples", 0)) + 1
                    p["brier_sum"] = float(p.get("brier_sum", 0.0)) + brier
                    bin_idx = min(9, max(0, int(pred * 10)))
                    bucket = p["calibration_bins"][str(bin_idx)]
                    bucket["n"] += 1
                    bucket["sum_pred"] += pred
                    bucket["sum_obs"] += observed

                # Tournament winner (lowest loss this round)
                winner = min(losses.items(), key=lambda x: x[1])[0]
                per_policy_wins[winner] += 1

                # Elo-style update against round field average.
                avg_loss = sum(losses.values()) / max(1, len(losses))
                for pid, p in policies.items():
                    rating = float(p.get("rating", 1500.0))
                    actual = 1.0 if losses[pid] <= avg_loss else 0.0
                    expected = 1.0 / (1.0 + 10.0 ** ((1500.0 - rating) / 400.0))
                    p["rating"] = rating + 12.0 * (actual - expected)

            bootstrap["tournament_runs"] = int(bootstrap.get("tournament_runs", 0)) + 1
            bootstrap["total_rounds"] = int(bootstrap.get("total_rounds", 0)) + rounds
            bootstrap["updated_at"] = datetime.now().isoformat()

            avg_losses = {
                pid: (per_policy_loss[pid] / rounds) for pid in policies
            }
            sorted_policies = sorted(
                policies.items(),
                key=lambda kv: (avg_losses[kv[0]], -float(kv[1].get("rating", 1500.0))),
            )
            top = []
            for pid, p in sorted_policies[:5]:
                top.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "avg_brier": round(avg_losses[pid], 6),
                        "wins": per_policy_wins[pid],
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                    }
                )

            bootstrap.setdefault("history", []).append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "rounds": rounds,
                    "seed": int(seed),
                    "top": top,
                }
            )
            bootstrap["history"] = bootstrap["history"][-50:]
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {
                "ok": True,
                "rounds": rounds,
                "seed": int(seed),
                "policies": len(policies),
                "top_policies": top,
            }

    def bootstrap_compute_blend(self, sid: str, session_samples: int) -> dict:
        """Compute bootstrap/session blend weights with exponential bootstrap decay."""
        with self._lock:
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            decay_lambda = float(bootstrap.get("decay_lambda", 0.03))
            min_bootstrap_weight = float(bootstrap.get("min_bootstrap_weight", 0.1))
            n = max(0, int(session_samples))
            w_bootstrap = max(min_bootstrap_weight, math.exp(-decay_lambda * n))
            w_session = max(0.0, 1.0 - w_bootstrap)
            return {
                "ok": True,
                "session_samples": n,
                "decay_lambda": decay_lambda,
                "min_bootstrap_weight": min_bootstrap_weight,
                "weights": {
                    "bootstrap": round(w_bootstrap, 6),
                    "session": round(w_session, 6),
                },
            }

    def bootstrap_status(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                return {"ok": True, "initialized": False, "message": "Bootstrap lab not initialized"}
            policies = bootstrap.get("policies") or {}
            leaderboard = []
            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                leaderboard.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                        "samples": int(p.get("samples", 0)),
                        "avg_brier": round(avg_brier, 6),
                    }
                )
            leaderboard.sort(key=lambda x: (x["avg_brier"], -x["rating"]))
            return {
                "ok": True,
                "initialized": True,
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)),
                "total_rounds": int(bootstrap.get("total_rounds", 0)),
                "policy_count": len(policies),
                "leaderboard": leaderboard[:10],
            }

    def bootstrap_summary(self, sid: str) -> dict:
        """Compact one-shot bootstrap health snapshot (quality + disputes + outcomes)."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                return {
                    "ok": True,
                    "initialized": False,
                    "message": "Bootstrap lab not initialized",
                }

            policies = bootstrap.get("policies") or {}
            disputes = bootstrap.get("disputes") or []
            outcomes = bootstrap.get("outcomes") or []

            policy_rows = []
            ece_num = 0.0
            ece_den = 0
            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                rating = float(p.get("rating", 1500.0))
                policy_rows.append((pid, p.get("name"), samples, avg_brier, rating))
                bins = p.get("calibration_bins") or {}
                for b in bins.values():
                    n = int((b or {}).get("n", 0))
                    if n <= 0:
                        continue
                    pred_mean = float(b.get("sum_pred", 0.0)) / n
                    obs_mean = float(b.get("sum_obs", 0.0)) / n
                    ece_num += n * abs(pred_mean - obs_mean)
                    ece_den += n

            policy_rows.sort(key=lambda r: (r[3], -r[4]))
            top = [
                {
                    "policy_id": pid,
                    "name": name,
                    "samples": samples,
                    "avg_brier": round(avg_brier, 6),
                    "rating": round(rating, 2),
                }
                for pid, name, samples, avg_brier, rating in policy_rows[:5]
            ]

            open_disputes = sum(1 for d in disputes if d.get("status") == "open")
            resolved_disputes = sum(1 for d in disputes if d.get("status") == "resolved")
            dispute_brier = [
                float(d.get("brier"))
                for d in disputes
                if d.get("status") == "resolved" and d.get("brier") is not None
            ]
            outcome_brier = [float(o.get("brier", 0.0)) for o in outcomes if o.get("brier") is not None]

            return {
                "ok": True,
                "initialized": True,
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)),
                "total_rounds": int(bootstrap.get("total_rounds", 0)),
                "prior_confidence": round(self._bootstrap_prior_confidence(bootstrap), 4),
                "calibration": {
                    "ece": round((ece_num / ece_den) if ece_den > 0 else 0.0, 6),
                    "sampled_bins": ece_den,
                },
                "policies": {
                    "count": len(policies),
                    "top": top,
                },
                "disputes": {
                    "open": open_disputes,
                    "resolved": resolved_disputes,
                    "avg_brier_resolved": round(sum(dispute_brier) / len(dispute_brier), 6) if dispute_brier else None,
                },
                "outcomes": {
                    "count": len(outcomes),
                    "avg_brier": round(sum(outcome_brier) / len(outcome_brier), 6) if outcome_brier else None,
                },
            }

    def bootstrap_summary_detailed(self, sid: str, top_policies: int = 10) -> dict:
        """Detailed bootstrap diagnostics including per-policy calibration bins."""
        with self._lock:
            base = self.bootstrap_summary(sid)
            if base.get("error") or not base.get("initialized"):
                return base

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            rows = []

            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                bins = p.get("calibration_bins") or {}
                ece_num = 0.0
                ece_den = 0
                bin_rows = []
                for i in range(10):
                    b = bins.get(str(i), {})
                    n = int(b.get("n", 0))
                    if n <= 0:
                        continue
                    pred_mean = float(b.get("sum_pred", 0.0)) / n
                    obs_mean = float(b.get("sum_obs", 0.0)) / n
                    gap = abs(pred_mean - obs_mean)
                    ece_num += n * gap
                    ece_den += n
                    bin_rows.append(
                        {
                            "bin": i,
                            "n": n,
                            "pred_mean": round(pred_mean, 6),
                            "obs_mean": round(obs_mean, 6),
                            "gap": round(gap, 6),
                        }
                    )
                ece = (ece_num / ece_den) if ece_den > 0 else 0.0
                rows.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "samples": int(p.get("samples", 0)),
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                        "avg_brier": round(avg_brier, 6),
                        "ece": round(ece, 6),
                        "bins": bin_rows,
                    }
                )

            rows.sort(key=lambda r: (r["avg_brier"], r["ece"], -r["rating"]))
            return {
                "ok": True,
                "initialized": True,
                "summary": base,
                "policy_diagnostics": rows[: max(1, min(int(top_policies), 50))],
                "total_policies": len(rows),
            }

    def bootstrap_snapshot(self, sid: str, name: str = "") -> dict:
        """Persist a compact bootstrap metrics snapshot for drift tracking."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            if not bootstrap:
                return {"ok": False, "error": "bootstrap_not_initialized"}
            snaps = bootstrap.setdefault("metric_snapshots", [])
            snap_id = f"bsnap_{uuid.uuid4().hex[:8]}"
            row = {
                "snapshot_id": snap_id,
                "name": str(name or "").strip() or None,
                "timestamp": datetime.now().isoformat(),
                "prior_confidence": summary.get("prior_confidence"),
                "ece": ((summary.get("calibration") or {}).get("ece")),
                "outcomes": ((summary.get("outcomes") or {}).get("count", 0)),
                "open_disputes": ((summary.get("disputes") or {}).get("open", 0)),
                "resolved_disputes": ((summary.get("disputes") or {}).get("resolved", 0)),
                "tournament_runs": summary.get("tournament_runs", 0),
                "total_rounds": summary.get("total_rounds", 0),
            }
            snaps.append(row)
            bootstrap["metric_snapshots"] = snaps[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "snapshot": row}

    def bootstrap_list_snapshots(
        self,
        sid: str,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            snaps = list((((data.get("bootstrap") or {}).get("metric_snapshots") or [])))
            total = len(snaps)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 1000))
            rows = snaps[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(rows),
                "offset": offset,
                "limit": limit,
                "snapshots": rows,
            }

    def bootstrap_drift_report(self, sid: str, window: int = 20) -> dict:
        """Compute metric drift from bootstrap snapshots."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            snaps = list((((data.get("bootstrap") or {}).get("metric_snapshots") or [])))
            if len(snaps) < 2:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Need at least 2 snapshots",
                    "count": len(snaps),
                }
            w = max(2, min(int(window), len(snaps)))
            recent = snaps[-w:]
            first = recent[0]
            last = recent[-1]

            def _delta(key: str) -> Optional[float]:
                a = first.get(key)
                b = last.get(key)
                if a is None or b is None:
                    return None
                return float(b) - float(a)

            ece_delta = _delta("ece")
            conf_delta = _delta("prior_confidence")
            outcomes_delta = _delta("outcomes")
            risk = "stable"
            if ece_delta is not None and ece_delta > 0.03:
                risk = "degrading"
            elif ece_delta is not None and ece_delta < -0.03:
                risk = "improving"
            if conf_delta is not None and conf_delta < -0.08:
                risk = "degrading"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "risk": risk,
                "first_snapshot_id": first.get("snapshot_id"),
                "last_snapshot_id": last.get("snapshot_id"),
                "drift": {
                    "ece_delta": round(ece_delta, 6) if ece_delta is not None else None,
                    "prior_confidence_delta": round(conf_delta, 6) if conf_delta is not None else None,
                    "outcomes_delta": int(outcomes_delta) if outcomes_delta is not None else None,
                },
            }

    def bootstrap_update_baseline(
        self,
        sid: str,
        window: int = 50,
        percentile: float = 95.0,
    ) -> dict:
        """Update rolling baseline thresholds from snapshot history."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = list((bootstrap.get("metric_snapshots") or []))
            if len(snaps) < 5:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Need at least 5 snapshots",
                    "count": len(snaps),
                }

            w = max(5, min(int(window), len(snaps)))
            pctl = max(50.0, min(float(percentile), 99.9))
            recent = snaps[-w:]

            ece_vals = sorted([float(s.get("ece", 0.0)) for s in recent if s.get("ece") is not None])
            prior_vals = sorted([float(s.get("prior_confidence", 0.5)) for s in recent if s.get("prior_confidence") is not None])

            def _p(vals: list[float], q: float, fallback: float) -> float:
                if not vals:
                    return fallback
                idx = int((q / 100.0) * (len(vals) - 1))
                idx = max(0, min(idx, len(vals) - 1))
                return vals[idx]

            baseline = {
                "window": w,
                "percentile": pctl,
                "ece_p95": round(_p(ece_vals, pctl, 0.0), 6),
                "ece_p50": round(_p(ece_vals, 50.0, 0.0), 6),
                "prior_p05": round(_p(prior_vals, 5.0, 0.5), 6),
                "prior_p50": round(_p(prior_vals, 50.0, 0.5), 6),
                "updated_at": datetime.now().isoformat(),
            }
            bootstrap["baseline"] = baseline
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "enough_data": True, "baseline": baseline}

    def bootstrap_evaluate_alerts(
        self,
        sid: str,
        window: int = 20,
    ) -> dict:
        """Evaluate drift alerts against rolling baseline thresholds."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = list((bootstrap.get("metric_snapshots") or []))
            baseline = bootstrap.get("baseline") or {}
            if not baseline:
                baseline_res = self.bootstrap_update_baseline(sid, window=max(30, window))
                if baseline_res.get("error"):
                    return baseline_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap") or {}
                baseline = bootstrap.get("baseline") or {}

            if len(snaps) < 2:
                return {"ok": True, "enough_data": False, "alerts": [], "severity": "none"}

            w = max(2, min(int(window), len(snaps)))
            recent = snaps[-w:]
            ece_vals = [float(s.get("ece", 0.0)) for s in recent if s.get("ece") is not None]
            prior_vals = [float(s.get("prior_confidence", 0.5)) for s in recent if s.get("prior_confidence") is not None]
            latest = recent[-1]

            ece_now = float(latest.get("ece", 0.0) or 0.0)
            prior_now = float(latest.get("prior_confidence", 0.5) or 0.5)
            ece_p95 = float(baseline.get("ece_p95", 1.0))
            prior_p05 = float(baseline.get("prior_p05", 0.0))

            alerts = []
            if ece_now > ece_p95:
                alerts.append({
                    "type": "ece_regression",
                    "value": round(ece_now, 6),
                    "threshold": round(ece_p95, 6),
                    "excess": round(ece_now - ece_p95, 6),
                })
            if prior_now < prior_p05:
                alerts.append({
                    "type": "confidence_drop",
                    "value": round(prior_now, 6),
                    "threshold": round(prior_p05, 6),
                    "deficit": round(prior_p05 - prior_now, 6),
                })

            severity = "none"
            if alerts:
                max_signal = max([
                    abs(float(a.get("excess", 0.0) or a.get("deficit", 0.0)))
                    for a in alerts
                ] or [0.0])
                if max_signal > 0.08:
                    severity = "high"
                elif max_signal > 0.03:
                    severity = "medium"
                else:
                    severity = "low"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "alerts": alerts,
                "severity": severity,
                "latest": {
                    "ece": round(ece_now, 6),
                    "prior_confidence": round(prior_now, 6),
                    "timestamp": latest.get("timestamp"),
                },
                "baseline": baseline,
                "stats": {
                    "ece_mean_window": round(sum(ece_vals) / max(1, len(ece_vals)), 6),
                    "prior_mean_window": round(sum(prior_vals) / max(1, len(prior_vals)), 6),
                },
            }

    def bootstrap_mitigation_plan(self, sid: str, window: int = 20) -> dict:
        """Generate bounded mitigation actions from current alert state."""
        with self._lock:
            eval_res = self.bootstrap_evaluate_alerts(sid, window=window)
            if eval_res.get("error"):
                return eval_res
            if not eval_res.get("enough_data"):
                return {
                    "ok": True,
                    "enough_data": False,
                    "severity": "none",
                    "actions": [],
                    "reason": "insufficient_baseline_data",
                }

            severity = str(eval_res.get("severity") or "none")
            alerts = list(eval_res.get("alerts") or [])
            actions = []

            has_ece = any(a.get("type") == "ece_regression" for a in alerts)
            has_conf = any(a.get("type") == "confidence_drop" for a in alerts)

            if severity in ("medium", "high") and has_ece:
                actions.append(
                    {
                        "priority": 1,
                        "action": "bootstrap_run_tournament",
                        "params": {"rounds": 1500 if severity == "high" else 800},
                        "reason": "Re-calibrate synthetic policies against drift",
                    }
                )
            if severity in ("medium", "high") and has_conf:
                actions.append(
                    {
                        "priority": 2,
                        "action": "bootstrap_simulate_batch",
                        "params": {"n": 1200 if severity == "high" else 600, "positive_rate": 0.55},
                        "reason": "Stabilize confidence with bounded synthetic outcomes",
                    }
                )
            if severity == "high":
                actions.append(
                    {
                        "priority": 3,
                        "action": "bootstrap_snapshot",
                        "params": {"name": "pre_mitigation_high_alert"},
                        "reason": "Capture state before mitigation steps",
                    }
                )
                actions.append(
                    {
                        "priority": 4,
                        "action": "bootstrap_update_baseline",
                        "params": {"window": max(30, int(window)), "percentile": 97.0},
                        "reason": "Tighten baseline after high-severity drift",
                    }
                )
            if not actions:
                actions.append(
                    {
                        "priority": 1,
                        "action": "bootstrap_snapshot",
                        "params": {"name": "steady_state"},
                        "reason": "No mitigation needed; keep timeline continuity",
                    }
                )

            actions.sort(key=lambda a: int(a.get("priority", 99)))
            return {
                "ok": True,
                "enough_data": True,
                "severity": severity,
                "alerts": alerts,
                "actions": actions,
            }

    def bootstrap_apply_mitigation(
        self,
        sid: str,
        window: int = 20,
        max_actions: int = 4,
        dry_run: bool = False,
    ) -> dict:
        """Execute bounded mitigation plan and return step-by-step results."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_mitigation_plan(sid, window=window)
            if plan.get("error"):
                return plan
            actions = list(plan.get("actions") or [])[: max(1, min(int(max_actions), 10))]
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "severity": plan.get("severity"),
                    "actions": actions,
                    "executed": [],
                }

            executed = []
            for item in actions:
                name = str(item.get("action") or "")
                params = dict(item.get("params") or {})
                if name == "bootstrap_run_tournament":
                    out = self.bootstrap_run_tournament(
                        sid,
                        rounds=int(params.get("rounds", 800)),
                        seed=int(params.get("seed", int(time.time()) % 100000)),
                    )
                elif name == "bootstrap_simulate_batch":
                    out = self.bootstrap_simulate_batch(
                        sid,
                        n=int(params.get("n", 600)),
                        seed=int(params.get("seed", int(time.time()) % 100000)),
                        positive_rate=float(params.get("positive_rate", 0.55)),
                    )
                elif name == "bootstrap_snapshot":
                    out = self.bootstrap_snapshot(sid, name=str(params.get("name") or "mitigation"))
                elif name == "bootstrap_update_baseline":
                    out = self.bootstrap_update_baseline(
                        sid,
                        window=int(params.get("window", max(30, window))),
                        percentile=float(params.get("percentile", 95.0)),
                    )
                else:
                    out = make_error(MCPError.ACTION_NOT_FOUND, f"Unknown mitigation action {name}")

                executed.append(
                    {
                        "action": name,
                        "ok": bool(isinstance(out, dict) and out.get("ok")),
                        "result": out,
                    }
                )

            final_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            hist = bootstrap.setdefault("mitigation_history", [])
            hist.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "window": int(window),
                    "plan_severity": plan.get("severity"),
                    "actions_requested": len(actions),
                    "executed_ok": sum(1 for e in executed if e.get("ok")),
                    "executed_total": len(executed),
                    "pre_alerts": len(plan.get("alerts") or []),
                    "post_alerts": len((final_eval or {}).get("alerts") or []),
                    "post_severity": (final_eval or {}).get("severity"),
                }
            )
            bootstrap["mitigation_history"] = hist[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {
                "ok": True,
                "dry_run": False,
                "plan_severity": plan.get("severity"),
                "actions_requested": len(actions),
                "executed": executed,
                "post_eval": final_eval,
            }

    def bootstrap_mitigation_history(
        self,
        sid: str,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Return mitigation execution audit history."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("mitigation_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 5000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_mitigation_effectiveness(self, sid: str, window: int = 50) -> dict:
        """Score mitigation effectiveness from audit trail deltas."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("mitigation_history") or [])))
            if not rows:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "No mitigation history",
                    "count": 0,
                }
            w = max(1, min(int(window), len(rows)))
            recent = rows[-w:]

            severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
            improvements = 0
            worsened = 0
            same = 0
            alert_delta_sum = 0
            ok_ratio_sum = 0.0
            for r in recent:
                pre_s = severity_rank.get(str(r.get("plan_severity") or "none"), 0)
                post_s = severity_rank.get(str(r.get("post_severity") or "none"), 0)
                if post_s < pre_s:
                    improvements += 1
                elif post_s > pre_s:
                    worsened += 1
                else:
                    same += 1
                pre_a = int(r.get("pre_alerts", 0))
                post_a = int(r.get("post_alerts", 0))
                alert_delta_sum += (pre_a - post_a)
                et = max(1, int(r.get("executed_total", 0)))
                eo = int(r.get("executed_ok", 0))
                ok_ratio_sum += (eo / et)

            n = len(recent)
            avg_alert_reduction = alert_delta_sum / max(1, n)
            avg_exec_ok = ok_ratio_sum / max(1, n)
            effectiveness = (0.5 * (improvements / n)) + (0.3 * max(0.0, min(1.0, avg_alert_reduction / 3.0))) + (0.2 * avg_exec_ok)
            tier = "poor"
            if effectiveness >= 0.75:
                tier = "strong"
            elif effectiveness >= 0.5:
                tier = "moderate"

            return {
                "ok": True,
                "enough_data": True,
                "window": n,
                "counts": {
                    "improved": improvements,
                    "same": same,
                    "worsened": worsened,
                },
                "avg_alert_reduction": round(avg_alert_reduction, 6),
                "avg_exec_success_ratio": round(avg_exec_ok, 6),
                "effectiveness_score": round(effectiveness, 6),
                "tier": tier,
            }

    def bootstrap_policy_reweight(
        self,
        sid: str,
        window: int = 50,
        max_shift: float = 0.08,
        dry_run: bool = False,
    ) -> dict:
        """Closed-loop policy adaptation from mitigation effectiveness outcomes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            if not policies:
                return make_error(MCPError.INVALID_ARGS, "Bootstrap policies not initialized")

            eff = self.bootstrap_mitigation_effectiveness(sid, window=window)
            if eff.get("error"):
                return eff
            if not eff.get("enough_data"):
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Not enough mitigation history for policy adaptation",
                }

            score = float(eff.get("effectiveness_score", 0.0))
            tier = str(eff.get("tier") or "poor")
            shift_cap = max(0.005, min(float(max_shift), 0.25))

            # Adaptive target vector over [static, dynamic, semantic, novelty]
            if tier == "strong":
                target = [0.28, 0.30, 0.24, 0.18]
            elif tier == "moderate":
                target = [0.31, 0.28, 0.23, 0.18]
            else:
                target = [0.35, 0.24, 0.23, 0.18]

            # Blend factor scales with confidence in effectiveness signal.
            blend = max(0.05, min(0.5, 0.1 + (0.4 * score)))
            updates = []

            prior_weights = {}
            for pid, p in policies.items():
                old = list(p.get("weights") or [0.25, 0.25, 0.25, 0.25])
                if len(old) != 4:
                    old = [0.25, 0.25, 0.25, 0.25]
                prior_weights[pid] = [round(float(x), 6) for x in old]
                raw = [((1.0 - blend) * old[i]) + (blend * target[i]) for i in range(4)]

                # Per-dimension shift guardrail.
                bounded = []
                for i in range(4):
                    delta = raw[i] - old[i]
                    delta = max(-shift_cap, min(shift_cap, delta))
                    bounded.append(max(0.01, old[i] + delta))

                s = sum(bounded)
                if s <= 0:
                    new_w = [0.25, 0.25, 0.25, 0.25]
                else:
                    new_w = [x / s for x in bounded]

                updates.append(
                    {
                        "policy_id": pid,
                        "old_weights": [round(x, 6) for x in old],
                        "new_weights": [round(x, 6) for x in new_w],
                        "max_component_shift": round(max(abs(new_w[i] - old[i]) for i in range(4)), 6),
                    }
                )

                if not dry_run:
                    p["weights"] = new_w

            if not dry_run:
                bootstrap["policies"] = policies
                hist = bootstrap.setdefault("policy_reweight_history", [])
                hist.append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "window": int(window),
                        "effectiveness_score": round(score, 6),
                        "tier": tier,
                        "blend": round(blend, 6),
                        "max_shift": round(shift_cap, 6),
                        "prior_weights": prior_weights,
                        "updates": updates,
                    }
                )
                bootstrap["policy_reweight_history"] = hist[-2000:]
                bootstrap["updated_at"] = datetime.now().isoformat()
                data["bootstrap"] = bootstrap
                self._save_skills(sid, data)

            return {
                "ok": True,
                "dry_run": bool(dry_run),
                "effectiveness_score": round(score, 6),
                "tier": tier,
                "blend": round(blend, 6),
                "max_shift": round(shift_cap, 6),
                "updates": updates,
            }

    def bootstrap_set_autopilot_policy(
        self,
        sid: str,
        cooldown_seconds: int = 300,
        daily_budget: int = 100,
        max_live_actions: int = 4,
        rollback_on_regression: bool = True,
    ) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.setdefault("autopilot_policy", {})
            policy.update(
                {
                    "cooldown_seconds": max(0, min(int(cooldown_seconds), 86400)),
                    "daily_budget": max(1, min(int(daily_budget), 100000)),
                    "max_live_actions": max(1, min(int(max_live_actions), 10)),
                    "rollback_on_regression": bool(rollback_on_regression),
                    "updated_at": datetime.now().isoformat(),
                }
            )
            bootstrap["autopilot_policy"] = policy
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "policy": policy}

    def bootstrap_get_autopilot_policy(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.get("autopilot_policy") or {
                "cooldown_seconds": 300,
                "daily_budget": 100,
                "max_live_actions": 4,
                "rollback_on_regression": True,
            }
            return {"ok": True, "policy": policy}

    def bootstrap_rollback_last_reweight(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            hist = bootstrap.get("policy_reweight_history") or []
            if not hist:
                return {"ok": True, "rolled_back": False, "message": "No reweight history"}
            last = hist[-1]
            prior = dict(last.get("prior_weights") or {})
            if not prior:
                return {"ok": True, "rolled_back": False, "message": "No prior weights in last reweight record"}

            restored = 0
            for pid, w in prior.items():
                if pid in policies and isinstance(w, list) and len(w) == 4:
                    s = sum(float(x) for x in w)
                    if s > 0:
                        policies[pid]["weights"] = [float(x) / s for x in w]
                        restored += 1
            if restored <= 0:
                return {"ok": True, "rolled_back": False, "message": "No matching policies to restore"}

            bootstrap["policies"] = policies
            rb = bootstrap.setdefault("rollback_history", [])
            rb.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "restored_policies": restored,
                    "source_reweight_at": last.get("timestamp"),
                }
            )
            bootstrap["rollback_history"] = rb[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "rolled_back": True, "restored_policies": restored}

    def bootstrap_policy_reweight_history(self, sid: str, limit: int = 100, offset: int = 0) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("policy_reweight_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 5000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_autopilot(
        self,
        sid: str,
        window: int = 30,
        dry_run: bool = False,
    ) -> dict:
        """Plan/apply mitigation then policy reweight in one bounded control loop."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.get("autopilot_policy") or {
                "cooldown_seconds": 300,
                "daily_budget": 100,
                "max_live_actions": 4,
                "rollback_on_regression": True,
            }

            now = datetime.now()
            runs = bootstrap.get("autopilot_runs") or []
            day_key = now.strftime("%Y-%m-%d")
            day_runs = [r for r in runs if str(r.get("day")) == day_key]
            if len(day_runs) >= int(policy.get("daily_budget", 100)) and not dry_run:
                return {
                    "ok": True,
                    "dry_run": False,
                    "blocked": True,
                    "reason": "daily_budget_exceeded",
                    "daily_budget": int(policy.get("daily_budget", 100)),
                }

            last_run = runs[-1] if runs else None
            if last_run and not dry_run:
                try:
                    ts = datetime.fromisoformat(str(last_run.get("timestamp")))
                    delta = (now - ts).total_seconds()
                    if delta < int(policy.get("cooldown_seconds", 300)):
                        return {
                            "ok": True,
                            "dry_run": False,
                            "blocked": True,
                            "reason": "cooldown_active",
                            "cooldown_seconds": int(policy.get("cooldown_seconds", 300)),
                            "remaining_seconds": max(0, int(policy.get("cooldown_seconds", 300) - delta)),
                        }
                except Exception:
                    pass

            pre_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            plan = self.bootstrap_mitigation_plan(sid, window=window)
            if plan.get("error"):
                return plan
            apply_res = self.bootstrap_apply_mitigation(
                sid,
                window=window,
                max_actions=int(policy.get("max_live_actions", 4)),
                dry_run=dry_run,
            )
            if apply_res.get("error"):
                return apply_res
            reweight = self.bootstrap_policy_reweight(
                sid,
                window=max(20, int(window)),
                max_shift=0.08,
                dry_run=dry_run,
            )
            if reweight.get("error"):
                return reweight

            post_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            rollback = None
            if not dry_run and bool(policy.get("rollback_on_regression", True)):
                pre_sev = str((pre_eval or {}).get("severity") or "none")
                post_sev = str((post_eval or {}).get("severity") or "none")
                rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
                if rank.get(post_sev, 0) > rank.get(pre_sev, 0):
                    rollback = self.bootstrap_rollback_last_reweight(sid)

            if not dry_run:
                data2 = self._load_skills(sid)
                bootstrap2 = data2.get("bootstrap") or {}
                log = bootstrap2.setdefault("autopilot_runs", [])
                log.append(
                    {
                        "timestamp": now.isoformat(),
                        "day": day_key,
                        "window": int(window),
                        "pre_severity": (pre_eval or {}).get("severity"),
                        "post_severity": (post_eval or {}).get("severity"),
                        "rollback": rollback,
                    }
                )
                bootstrap2["autopilot_runs"] = log[-5000:]
                bootstrap2["updated_at"] = datetime.now().isoformat()
                data2["bootstrap"] = bootstrap2
                self._save_skills(sid, data2)

            return {
                "ok": True,
                "dry_run": bool(dry_run),
                "plan_severity": plan.get("severity"),
                "mitigation": apply_res,
                "policy_reweight": reweight,
                "policy": policy,
                "pre_eval": pre_eval,
                "post_eval": post_eval,
                "rollback": rollback,
            }

    def bootstrap_simulate_batch(
        self,
        sid: str,
        n: int = 500,
        seed: int = 2026,
        positive_rate: float = 0.5,
    ) -> dict:
        """Fast synthetic outcome ingestion for stress tests and calibration warm-up."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            count = max(1, min(int(n), 200000))
            p = max(0.01, min(0.99, float(positive_rate)))
            rng = random.Random(int(seed))
            brier_sum = 0.0
            positive = 0
            data = self._load_skills(sid)
            for _ in range(count):
                pred = min(0.999, max(0.001, rng.betavariate(2.0, 2.0)))
                obs = 1 if rng.random() < p else 0
                if obs:
                    positive += 1
                out = self._bootstrap_apply_outcome_in_memory(
                    sid,
                    data,
                    predicted=pred,
                    observed=obs,
                    skill_id=None,
                    delay_seconds=0,
                )
                if out.get("error"):
                    return out
                brier_sum += float(out.get("brier", 0.0))
            self._save_skills(sid, data)
            return {
                "ok": True,
                "n": count,
                "seed": int(seed),
                "positive_rate_target": p,
                "positive_rate_observed": round(positive / max(1, count), 6),
                "avg_brier": round(brier_sum / max(1, count), 6),
            }

    def bootstrap_prune_data(
        self,
        sid: str,
        max_outcomes: int = 1000,
        max_disputes: int = 500,
        max_snapshots: int = 2000,
    ) -> dict:
        """Prune bootstrap history buffers to bounded sizes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            before = {
                "outcomes": len(bootstrap.get("outcomes") or []),
                "disputes": len(bootstrap.get("disputes") or []),
                "metric_snapshots": len(bootstrap.get("metric_snapshots") or []),
            }
            max_outcomes = max(1, min(int(max_outcomes), 200000))
            max_disputes = max(1, min(int(max_disputes), 50000))
            max_snapshots = max(1, min(int(max_snapshots), 100000))
            bootstrap["outcomes"] = (bootstrap.get("outcomes") or [])[-max_outcomes:]
            bootstrap["disputes"] = (bootstrap.get("disputes") or [])[-max_disputes:]
            bootstrap["metric_snapshots"] = (bootstrap.get("metric_snapshots") or [])[-max_snapshots:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            after = {
                "outcomes": len(bootstrap.get("outcomes") or []),
                "disputes": len(bootstrap.get("disputes") or []),
                "metric_snapshots": len(bootstrap.get("metric_snapshots") or []),
            }
            return {"ok": True, "before": before, "after": after}

    def bootstrap_export_metrics(
        self,
        sid: str,
        status: str = "all",
        since: str = "",
        until: str = "",
        limit: int = 5000,
    ) -> dict:
        """Export condensed time-series metrics for external plotting/analysis."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = bootstrap.get("metric_snapshots") or []
            disputes = bootstrap.get("disputes") or []
            outcomes = bootstrap.get("outcomes") or []

            status = str(status or "all").strip().lower()
            t_since = None
            t_until = None
            if since:
                try:
                    t_since = datetime.fromisoformat(str(since))
                except Exception:
                    t_since = None
            if until:
                try:
                    t_until = datetime.fromisoformat(str(until))
                except Exception:
                    t_until = None

            def _in_window(ts: Optional[str]) -> bool:
                if not ts:
                    return False
                try:
                    t = datetime.fromisoformat(str(ts))
                except Exception:
                    return False
                if t_since and t < t_since:
                    return False
                if t_until and t > t_until:
                    return False
                return True

            snapshot_series = [
                {
                    "t": s.get("timestamp"),
                    "prior": s.get("prior_confidence"),
                    "ece": s.get("ece"),
                    "outcomes": s.get("outcomes"),
                    "open_disputes": s.get("open_disputes"),
                }
                for s in snaps
                if (not since and not until) or _in_window(s.get("timestamp"))
            ]
            dispute_series = [
                {
                    "t_open": d.get("opened_at"),
                    "t_resolved": d.get("resolved_at"),
                    "status": d.get("status"),
                    "brier": d.get("brier"),
                }
                for d in disputes
                if (
                    status in ("all", "")
                    or str(d.get("status") or "").lower() == status
                )
                and (
                    (not since and not until)
                    or _in_window(d.get("resolved_at") or d.get("opened_at"))
                )
            ]
            outcome_series = [
                {
                    "t": o.get("timestamp"),
                    "pred": o.get("predicted"),
                    "obs": o.get("observed"),
                    "brier": o.get("brier"),
                }
                for o in outcomes
                if (not since and not until) or _in_window(o.get("timestamp"))
            ]
            limit = max(1, min(int(limit), 200000))
            snapshot_series = snapshot_series[-limit:]
            dispute_series = dispute_series[-limit:]
            outcome_series = outcome_series[-limit:]
            return {
                "ok": True,
                "series": {
                    "snapshots": snapshot_series,
                    "disputes": dispute_series,
                    "outcomes": outcome_series,
                },
                "filters": {
                    "status": status,
                    "since": since or None,
                    "until": until or None,
                    "limit": limit,
                },
                "counts": {
                    "snapshots": len(snapshot_series),
                    "disputes": len(dispute_series),
                    "outcomes": len(outcome_series),
                },
            }

    def bootstrap_calibration_report(self, sid: str, min_bin_n: int = 20) -> dict:
        """Global calibration report with reliability bins aggregated across policies."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            agg = {i: {"n": 0, "sum_pred": 0.0, "sum_obs": 0.0} for i in range(10)}
            for p in policies.values():
                bins = p.get("calibration_bins") or {}
                for i in range(10):
                    b = bins.get(str(i), {})
                    agg[i]["n"] += int(b.get("n", 0))
                    agg[i]["sum_pred"] += float(b.get("sum_pred", 0.0))
                    agg[i]["sum_obs"] += float(b.get("sum_obs", 0.0))

            min_bin_n = max(1, min(int(min_bin_n), 1000000))
            ece_num = 0.0
            ece_den = 0
            bins_out = []
            for i in range(10):
                n = agg[i]["n"]
                if n < min_bin_n:
                    continue
                pred_mean = agg[i]["sum_pred"] / n
                obs_mean = agg[i]["sum_obs"] / n
                gap = abs(pred_mean - obs_mean)
                ece_num += n * gap
                ece_den += n
                bins_out.append(
                    {
                        "bin": i,
                        "n": n,
                        "pred_mean": round(pred_mean, 6),
                        "obs_mean": round(obs_mean, 6),
                        "gap": round(gap, 6),
                    }
                )
            bins_out.sort(key=lambda x: x["bin"])
            ece = (ece_num / ece_den) if ece_den > 0 else 0.0
            return {
                "ok": True,
                "min_bin_n": min_bin_n,
                "used_bins": len(bins_out),
                "ece": round(ece, 6),
                "bins": bins_out,
            }

    def bootstrap_ingest_outcome(
        self,
        sid: str,
        predicted: float,
        observed: int,
        skill_id: Optional[str] = None,
        delay_seconds: int = 0,
    ) -> dict:
        """Ingest delayed outcome and update both session and bootstrap calibration."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            res = self._bootstrap_apply_outcome_in_memory(
                sid,
                data,
                predicted=predicted,
                observed=observed,
                skill_id=skill_id,
                delay_seconds=delay_seconds,
            )
            if res.get("error"):
                return res
            self._save_skills(sid, data)
            return res

    def _bootstrap_apply_outcome_in_memory(
        self,
        sid: str,
        data: dict,
        predicted: float,
        observed: int,
        skill_id: Optional[str] = None,
        delay_seconds: int = 0,
    ) -> dict:
        bootstrap = data.get("bootstrap")
        if not bootstrap:
            init_res = self.bootstrap_init(sid)
            if init_res.get("error"):
                return init_res
            refreshed = self._load_skills(sid)
            data.clear()
            data.update(refreshed)
            bootstrap = data.get("bootstrap")

        pred = max(0.001, min(0.999, float(predicted)))
        obs = 1 if int(observed) else 0
        brier = (pred - obs) ** 2

        policies = bootstrap.get("policies") or {}
        bidx = min(9, max(0, int(pred * 10)))
        for p in policies.values():
            p["samples"] = int(p.get("samples", 0)) + 1
            p["brier_sum"] = float(p.get("brier_sum", 0.0)) + brier
            bucket = p["calibration_bins"][str(bidx)]
            bucket["n"] += 1
            bucket["sum_pred"] += pred
            bucket["sum_obs"] += obs

        session_update = None
        if skill_id:
            skills = data.get("skills", {})
            if skill_id in skills:
                q_old = float(skills[skill_id].get("q_value", 0.5))
                reward = max(0.0, min(1.0, 1.0 - brier))
                alpha = 0.15
                q_new = max(0.0, min(1.0, q_old + alpha * (reward - q_old)))
                skills[skill_id]["q_value"] = round(q_new, 4)
                skills[skill_id]["last_used"] = datetime.now().isoformat()
                if obs:
                    skills[skill_id]["success_count"] = int(skills[skill_id].get("success_count", 0)) + 1
                else:
                    skills[skill_id]["failure_count"] = int(skills[skill_id].get("failure_count", 0)) + 1
                data.setdefault("q_table", {})[skill_id] = round(q_new, 4)
                session_update = {
                    "skill_id": skill_id,
                    "old_q": round(q_old, 4),
                    "new_q": round(q_new, 4),
                    "reward": round(reward, 4),
                }

        bootstrap["updated_at"] = datetime.now().isoformat()
        bootstrap.setdefault("outcomes", []).append(
            {
                "timestamp": datetime.now().isoformat(),
                "predicted": pred,
                "observed": obs,
                "brier": round(brier, 6),
                "skill_id": skill_id,
                "delay_seconds": max(0, int(delay_seconds)),
            }
        )
        bootstrap["outcomes"] = bootstrap["outcomes"][-1000:]
        data["bootstrap"] = bootstrap
        return {
            "ok": True,
            "predicted": pred,
            "observed": obs,
            "brier": round(brier, 6),
            "session_update": session_update,
        }

    def bootstrap_open_dispute(
        self,
        sid: str,
        claim_id: str,
        predicted: float,
        reason: str,
        skill_id: Optional[str] = None,
    ) -> dict:
        """Open a dispute for a claim with delayed/contested outcome."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                init_res = self.bootstrap_init(sid)
                if init_res.get("error"):
                    return init_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap")
            disputes = bootstrap.setdefault("disputes", [])
            did = f"disp_{uuid.uuid4().hex[:8]}"
            row = {
                "dispute_id": did,
                "claim_id": str(claim_id),
                "skill_id": skill_id,
                "predicted": max(0.001, min(0.999, float(predicted))),
                "reason": str(reason or "").strip(),
                "status": "open",
                "opened_at": datetime.now().isoformat(),
                "resolved_at": None,
                "observed": None,
                "delay_seconds": None,
                "brier": None,
            }
            disputes.append(row)
            bootstrap["disputes"] = disputes[-500:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "dispute": row}

    def bootstrap_list_disputes(self, sid: str, status: Optional[str] = None) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            disputes = list(((data.get("bootstrap") or {}).get("disputes") or []))
            if status:
                status = str(status).strip().lower()
                disputes = [d for d in disputes if str(d.get("status", "")).lower() == status]
            return {
                "ok": True,
                "count": len(disputes),
                "open": sum(1 for d in disputes if d.get("status") == "open"),
                "resolved": sum(1 for d in disputes if d.get("status") == "resolved"),
                "disputes": disputes,
            }

    def bootstrap_resolve_dispute(
        self,
        sid: str,
        dispute_id: str,
        observed: int,
        delay_seconds: int = 0,
    ) -> dict:
        """Resolve a dispute and feed the outcome into calibration pipeline."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            disputes = bootstrap.get("disputes") or []
            target = None
            for d in disputes:
                if str(d.get("dispute_id")) == str(dispute_id):
                    target = d
                    break
            if not target:
                return make_error(MCPError.NOT_FOUND, f"Dispute {dispute_id} not found")
            if target.get("status") == "resolved":
                return {"ok": True, "dispute": target, "message": "Dispute already resolved"}

            ingest = self._bootstrap_apply_outcome_in_memory(
                sid,
                data,
                predicted=float(target.get("predicted", 0.5)),
                observed=int(observed),
                skill_id=target.get("skill_id"),
                delay_seconds=int(delay_seconds),
            )
            if ingest.get("error"):
                return ingest

            bootstrap2 = data.get("bootstrap") or {}
            disputes2 = bootstrap2.get("disputes") or []
            for d in disputes2:
                if str(d.get("dispute_id")) == str(dispute_id):
                    d["status"] = "resolved"
                    d["resolved_at"] = datetime.now().isoformat()
                    d["observed"] = 1 if int(observed) else 0
                    d["delay_seconds"] = max(0, int(delay_seconds))
                    d["brier"] = ingest.get("brier")
                    target = d
                    break
            bootstrap2["disputes"] = disputes2
            bootstrap2["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap2
            self._save_skills(sid, data)
            return {"ok": True, "dispute": target, "ingest": ingest}

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
                    from ida_pro_mcp.host.intelligence import BgeCodeEmbedder
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


