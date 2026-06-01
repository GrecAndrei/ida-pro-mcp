"""
ContextAssembler policy / focus feedback mixin.

Extracted from intelligence_context.py to keep state orchestration focused
on enrichment and retrieval flow.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from .intelligence_helpers import compact_policy_blob, derive_focus_candidates, prune_policy_store


class ContextAssemblerPolicyMixin:
    def _policy_store_path(self, idb_path: str) -> str:
        if idb_path:
            return idb_path + ".focus_policy.json"
        return os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "focus_policy.json")

    def _compact_policy_blob(self, sess_blob: Dict[str, Any]) -> Dict[str, Any]:
        return compact_policy_blob(sess_blob)

    def _prune_policy_store(self, data: Dict[str, Any], max_sessions: int = 24) -> Dict[str, Any]:
        return prune_policy_store(data, max_sessions=max_sessions)

    def _bind_session_store(self, session_id: str, idb_path: str) -> None:
        if not session_id or not idb_path:
            return
        with self._store_binding_lock:
            self._session_store_binding[session_id] = self._policy_store_path(idb_path)

    def _load_session_policy(self, session_id: str, idb_path: str) -> None:
        if not session_id:
            return
        self._bind_session_store(session_id, idb_path)
        try:
            path = self._policy_store_path(idb_path)
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and int(data.get("schema_version") or 1) < 2:
                data = self._prune_policy_store(data)
            sess = data.get("sessions", {}).get(session_id)
            if not isinstance(sess, dict):
                return
            with self._retrieval_metrics_lock:
                if session_id not in self._retrieval_metrics or not self._retrieval_metrics[session_id]:
                    self._retrieval_metrics[session_id] = dict(sess.get("retrieval_metrics") or {})
            with self._focus_feedback_lock:
                if session_id not in self._focus_feedback or not self._focus_feedback[session_id]:
                    self._focus_feedback[session_id] = dict(sess.get("focus_feedback") or {})
            with self._semantic_threshold_lock:
                if session_id not in self._session_semantic_threshold:
                    thr = float(sess.get("semantic_threshold") or 0.5)
                    self._session_semantic_threshold[session_id] = max(0.35, min(0.75, thr))
            self._invalidate_session_caches(session_id)
        except Exception:
            return

    def _save_session_policy(self, session_id: str) -> None:
        if not session_id:
            return
        try:
            with self._store_binding_lock:
                path = self._session_store_binding.get(session_id)
            if not path:
                return
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data: Dict[str, Any] = {"sessions": {}}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if not isinstance(data, dict):
                        data = {"sessions": {}}
                except Exception:
                    data = {"sessions": {}}
            sessions = data.setdefault("sessions", {})
            with self._retrieval_metrics_lock:
                rm = dict(self._retrieval_metrics.get(session_id, {}))
            with self._focus_feedback_lock:
                ff = dict(self._focus_feedback.get(session_id, {}))
            with self._semantic_threshold_lock:
                thr = float(self._session_semantic_threshold.get(session_id, 0.5))
            sessions[session_id] = {
                "retrieval_metrics": rm,
                "focus_feedback": ff,
                "semantic_threshold": thr,
                "saved_at": time.time(),
            }
            data = self._prune_policy_store(data)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, sort_keys=True)
            self._invalidate_session_caches(session_id)
        except Exception:
            return

    def _schedule_policy_save(self, session_id: str, force: bool = False) -> None:
        """Debounce policy saves to reduce disk churn in bursty sessions."""
        if not session_id:
            return
        now = time.time()
        with self._policy_save_lock:
            due = now if force else (now + self._policy_save_debounce_sec)
            prev = self._policy_save_due_at.get(session_id)
            if prev is None or due < prev:
                self._policy_save_due_at[session_id] = due
            if session_id in self._policy_save_inflight:
                return
            self._policy_save_inflight.add(session_id)

        def _worker(sid: str) -> None:
            try:
                while True:
                    with self._policy_save_lock:
                        due_at = self._policy_save_due_at.get(sid)
                    if due_at is None:
                        break
                    wait = due_at - time.time()
                    if wait > 0:
                        time.sleep(min(wait, 0.1))
                        continue
                    self._save_session_policy(sid)
                    with self._policy_save_lock:
                        latest = self._policy_save_due_at.get(sid)
                        if latest is None or latest <= due_at:
                            self._policy_save_due_at.pop(sid, None)
                            break
            finally:
                with self._policy_save_lock:
                    self._policy_save_inflight.discard(sid)

        threading.Thread(target=_worker, args=(session_id,), daemon=True).start()

    def flush_policy_saves(self, session_id: str = "") -> None:
        """Force-flush pending debounced policy saves (best-effort)."""
        targets: List[str]
        with self._policy_save_lock:
            if session_id:
                targets = [session_id]
            else:
                targets = list(self._policy_save_due_at.keys())
            for sid in targets:
                self._policy_save_due_at[sid] = time.time()
        for sid in targets:
            self._schedule_policy_save(sid, force=True)

    def _record_focus_suggestion(self, session_id: str, focus: Dict[str, Any]) -> None:
        if not session_id or not focus:
            return
        try:
            with self._focus_feedback_lock:
                m = self._focus_feedback[session_id]
                m["suggested"] = int(m.get("suggested", 0)) + 1
            self._invalidate_session_caches(session_id)
            with self._pending_focus_lock:
                self._pending_focus[session_id] = {
                    "tool": focus.get("tool"),
                    "action": focus.get("action"),
                    "ts": time.time(),
                }
            self._schedule_policy_save(session_id)
        except Exception:
            return

    def _consume_focus_follow(self, session_id: str, tool: str, action: str) -> bool:
        if not session_id:
            return False
        try:
            with self._pending_focus_lock:
                pending = self._pending_focus.pop(session_id, None)
            if not pending:
                return False
            followed = (pending.get("tool") == tool and pending.get("action") == action)
            if followed:
                with self._focus_feedback_lock:
                    m = self._focus_feedback[session_id]
                    m["followed"] = int(m.get("followed", 0)) + 1
                self._invalidate_session_caches(session_id)
            return followed
        except Exception:
            return False

    def _record_focus_outcome(self, session_id: str, tool: str, action: str, success: bool) -> None:
        if not session_id:
            return
        try:
            ta = f"{tool}:{action}"
            with self._focus_feedback_lock:
                m = self._focus_feedback[session_id]
                if success:
                    m["successful"] = int(m.get("successful", 0)) + 1
                    m[f"action.{ta}.ok"] = int(m.get(f"action.{ta}.ok", 0)) + 1
                else:
                    m["failed"] = int(m.get("failed", 0)) + 1
                    m[f"action.{ta}.fail"] = int(m.get(f"action.{ta}.fail", 0)) + 1
            self._invalidate_session_caches(session_id)
            self._schedule_policy_save(session_id)
        except Exception:
            return

    def _focus_action_bias(self, session_id: str, tool: str, action: str) -> float:
        if not session_id:
            return 1.0
        try:
            ta = f"{tool}:{action}"
            with self._focus_feedback_lock:
                m = dict(self._focus_feedback.get(session_id, {}))
            ok = int(m.get(f"action.{ta}.ok", 0))
            fail = int(m.get(f"action.{ta}.fail", 0))
            total = ok + fail
            if total < 3:
                return 1.0
            rate = ok / max(1, total)
            return round(0.8 + rate * 0.45, 3)
        except Exception:
            return 1.0

    def _session_source_policy(self, session_id: str) -> Dict[str, Dict[str, Any]]:
        """Adaptive source policy tuned from per-session retrieval outcomes."""
        base = {
            "address_linked": {"weight": 1.4, "min_confidence": 0.0, "max_take": 8},
            "relation_linked": {"weight": 1.2, "min_confidence": 0.25, "max_take": 6},
            "api_linked": {"weight": 1.0, "min_confidence": 0.35, "max_take": 5},
            "semantic_linked": {"weight": 0.9, "min_confidence": 0.45, "max_take": 4},
        }
        if not session_id:
            return base
        try:
            with self._retrieval_metrics_lock:
                metrics = dict(self._retrieval_metrics.get(session_id, {}))
            fp = (
                int(metrics.get("address_linked.total", 0)),
                int(metrics.get("relation_linked.total", 0)),
                int(metrics.get("api_linked.total", 0)),
                int(metrics.get("semantic_linked.total", 0)),
            )
            with self._policy_cache_lock:
                cached = self._source_policy_cache.get(session_id)
                if cached and cached[0] == fp:
                    return dict(cached[1])
            for src, cfg in base.items():
                total = int(metrics.get(f"{src}.total", 0))
                kept = int(metrics.get(f"{src}.kept", 0))
                if total < 6:
                    continue
                hit_rate = kept / max(1, total)
                if hit_rate < 0.25:
                    cfg["weight"] = round(max(0.5, float(cfg["weight"]) - 0.2), 3)
                    cfg["min_confidence"] = round(min(0.9, float(cfg["min_confidence"]) + 0.08), 3)
                    cfg["max_take"] = max(2, int(cfg["max_take"]) - 1)
                elif hit_rate > 0.7:
                    cfg["weight"] = round(min(1.8, float(cfg["weight"]) + 0.15), 3)
                    cfg["min_confidence"] = round(max(0.0, float(cfg["min_confidence"]) - 0.05), 3)
                    cfg["max_take"] = min(8, int(cfg["max_take"]) + 1)
            with self._policy_cache_lock:
                self._source_policy_cache[session_id] = (fp, dict(base))
            return base
        except Exception:
            return base

    def _derive_analysis_focus(
        self,
        pack: Dict[str, Any],
        addr: str,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Derive a single best next focus action for the current step using:
        - adaptive source policy
        - observed retrieval richness
        - structural risk signals
        """
        if not addr:
            return None
        try:
            cands = self._derive_focus_candidates(pack, addr, session_id)
            if cands:
                return cands[0]
            return None
        except Exception:
            return None

    def _derive_focus_candidates(
        self,
        pack: Dict[str, Any],
        addr: str,
        session_id: str,
    ) -> List[Dict[str, Any]]:
        try:
            policy = self._session_source_policy(session_id)
            stats = self._session_retrieval_stats(session_id)
            return derive_focus_candidates(
                pack=pack,
                addr=addr,
                policy=policy,
                stats=stats,
                bias_fn=lambda t, a: self._focus_action_bias(session_id, t, a),
            )
        except Exception:
            return []
