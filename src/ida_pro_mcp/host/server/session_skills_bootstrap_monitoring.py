#!/usr/bin/env python3
"""Bootstrap monitoring/reporting mixin for session skills."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from ..errors import MCPError, is_error_result, make_error


class SessionBootstrapMonitoringMixin:
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
            if is_error_result(base) or not base.get("initialized"):
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
            if is_error_result(summary):
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
                if is_error_result(baseline_res):
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
