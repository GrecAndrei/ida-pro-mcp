#!/usr/bin/env python3
"""Bootstrap lifecycle helpers for session skills."""

import math
import random
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from .errors import MCPError, is_error_result, make_error
from .session_skills_bootstrap_monitoring import SessionBootstrapMonitoringMixin


class SessionBootstrapMixin(SessionBootstrapMonitoringMixin):
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
                if is_error_result(init_res):
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
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
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

    def bootstrap_mitigation_plan(self, sid: str, window: int = 20) -> dict:
        """Generate bounded mitigation actions from current alert state."""
        with self._lock:
            eval_res = self.bootstrap_evaluate_alerts(sid, window=window)
            if is_error_result(eval_res):
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
            if is_error_result(plan):
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
            if is_error_result(final_eval):
                return final_eval
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
            if is_error_result(eff):
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
            if is_error_result(pre_eval):
                return pre_eval
            plan = self.bootstrap_mitigation_plan(sid, window=window)
            if is_error_result(plan):
                return plan
            apply_res = self.bootstrap_apply_mitigation(
                sid,
                window=window,
                max_actions=int(policy.get("max_live_actions", 4)),
                dry_run=dry_run,
            )
            if is_error_result(apply_res):
                return apply_res
            reweight = self.bootstrap_policy_reweight(
                sid,
                window=max(20, int(window)),
                max_shift=0.08,
                dry_run=dry_run,
            )
            if is_error_result(reweight):
                return reweight

            post_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            if is_error_result(post_eval):
                return post_eval
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
                if is_error_result(out):
                    self._save_skills(sid, data)
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
            if is_error_result(res):
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
            if is_error_result(init_res):
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
                if is_error_result(init_res):
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
            if is_error_result(ingest):
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
