#!/usr/bin/env python3
"""Active Blackboard Kernel: obligations, receipts, attention debt, policy."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional


HIGH_IMPACT_ACTIONS = {
    "rename",
    "set_name",
    "comment",
    "patch_asm",
    "apply_type",
    "set_type",
    "set_prototype",
    "write",
    "export",
}

READ_HEAVY_TOOLS = {"code", "data", "search", "graph", "ctree", "query"}


class AttentionKernel:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "attention_kernel.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    ts REAL NOT NULL,
                    tool TEXT,
                    action TEXT,
                    args_json TEXT,
                    result_json TEXT,
                    digest TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS obligations (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    ts REAL NOT NULL,
                    status TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT,
                    required_receipt TEXT,
                    source_obs_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    ts REAL NOT NULL,
                    tool TEXT,
                    action TEXT,
                    obligation_id TEXT,
                    evidence_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attention_debt (
                    session_id TEXT PRIMARY KEY,
                    debt REAL NOT NULL DEFAULT 0,
                    updated_ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmark_policies (
                    feature_id TEXT PRIMARY KEY,
                    helpfulness_score REAL NOT NULL DEFAULT 0,
                    ignore_rate REAL NOT NULL DEFAULT 0,
                    failure_when_ignored REAL NOT NULL DEFAULT 0,
                    best_enforcement_level INTEGER NOT NULL DEFAULT 0,
                    tool_contexts_json TEXT,
                    updated_ts REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _sid(self, session_id: Optional[str]) -> str:
        return str(session_id or "default")

    def _get_debt(self, sid: str) -> float:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT debt FROM attention_debt WHERE session_id = ?", (sid,)
            ).fetchone()
            return float(row[0]) if row else 0.0

    def _set_debt(self, sid: str, value: float):
        now = time.time()
        value = max(0.0, min(5.0, float(value)))
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO attention_debt(session_id, debt, updated_ts)
                VALUES (?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET debt=excluded.debt, updated_ts=excluded.updated_ts
                """,
                (sid, value, now),
            )
            conn.commit()

    def debt_level(self, session_id: Optional[str]) -> int:
        d = self._get_debt(self._sid(session_id))
        return int(round(d))

    def unresolved_obligations(self, session_id: Optional[str]) -> List[Dict[str, Any]]:
        sid = self._sid(session_id)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, kind, payload_json, required_receipt, ts FROM obligations WHERE session_id=? AND status='open' ORDER BY ts DESC LIMIT 50",
                (sid,),
            ).fetchall()
        out = []
        for rid, kind, payload_json, req, ts in rows:
            try:
                payload = json.loads(payload_json or "{}")
            except Exception:
                payload = {}
            out.append({"id": rid, "kind": kind, "payload": payload, "required_receipt": req, "ts": ts})
        return out

    def add_obligation(self, session_id: Optional[str], kind: str, payload: Dict[str, Any], required_receipt: str, source_obs_id: str = ""):
        sid = self._sid(session_id)
        oid = f"obl_{uuid.uuid4().hex[:8]}"
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO obligations(id, session_id, ts, status, kind, payload_json, required_receipt, source_obs_id) VALUES(?, ?, ?, 'open', ?, ?, ?, ?)",
                (oid, sid, now, kind, json.dumps(payload, ensure_ascii=False), required_receipt, source_obs_id),
            )
            conn.commit()
        self._set_debt(sid, self._get_debt(sid) + 0.7)
        return oid

    def observe_context(self, session_id: Optional[str], tool: str, action: str, context: Dict[str, Any]):
        sid = self._sid(session_id)
        cognitive = context.get("cognitive", {}) if isinstance(context, dict) else {}
        voids = list(cognitive.get("voids", []) or [])
        shadows = list(cognitive.get("shadow_warnings", []) or [])
        gaps = list(cognitive.get("narrative_gaps", []) or [])

        if voids:
            self.add_obligation(sid, "coverage_gap", {"voids": voids[:3], "tool": tool, "action": action}, "inspect_unseen_surface")
        if shadows:
            self.add_obligation(sid, "shadow_warning", {"warnings": shadows[:2], "tool": tool, "action": action}, "disprove_or_branch")
        if gaps:
            self.add_obligation(sid, "narrative_gap", {"gaps": gaps[:2], "tool": tool, "action": action}, "connect_story_nodes")

    def observe_result(self, session_id: Optional[str], tool: str, action: str, args: Dict[str, Any], result: Any):
        sid = self._sid(session_id)
        obs_id = f"obs_{uuid.uuid4().hex[:10]}"
        now = time.time()
        try:
            args_json = json.dumps(args or {}, ensure_ascii=False, default=str)
        except Exception:
            args_json = "{}"
        try:
            result_json = json.dumps(result or {}, ensure_ascii=False, default=str)
        except Exception:
            result_json = "{}"
        digest = str(abs(hash(f"{tool}|{action}|{args_json[:512]}|{result_json[:512]}")))
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO observations(id, session_id, ts, tool, action, args_json, result_json, digest) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (obs_id, sid, now, tool, action, args_json, result_json, digest),
            )
            conn.commit()

        self._resolve_receipts(sid, tool, action, args, result)

    def _resolve_receipts(self, sid: str, tool: str, action: str, args: Dict[str, Any], result: Any):
        open_obs = self.unresolved_obligations(sid)
        if not open_obs:
            return

        addr = str((args or {}).get("addr", ""))
        text = ""
        try:
            text = json.dumps(result, ensure_ascii=False, default=str).lower()
        except Exception:
            text = str(result).lower()

        resolved = []
        for obl in open_obs:
            kind = obl.get("kind", "")
            good = False
            if kind == "coverage_gap":
                good = tool in {"data", "search", "imports_deep", "query"}
            elif kind == "shadow_warning":
                good = tool in {"code", "search", "graph", "ctree"}
            elif kind == "narrative_gap":
                good = tool in {"graph", "code", "ctree", "search"}
            if addr and addr.lower() in text:
                good = True
            if good:
                resolved.append(obl)

        if not resolved:
            return

        now = time.time()
        with self._conn() as conn:
            for obl in resolved:
                rid = f"rcp_{uuid.uuid4().hex[:10]}"
                conn.execute(
                    "INSERT INTO receipts(id, session_id, ts, tool, action, obligation_id, evidence_json) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (rid, sid, now, tool, action, obl["id"], json.dumps({"addr": addr, "tool": tool, "action": action})),
                )
                conn.execute("UPDATE obligations SET status='resolved' WHERE id=?", (obl["id"],))
            conn.commit()

        self._set_debt(sid, self._get_debt(sid) - 0.9 * len(resolved))

    def preflight(self, session_id: Optional[str], tool: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = self._sid(session_id)
        debt = self._get_debt(sid)
        unresolved = self.unresolved_obligations(sid)
        if not unresolved:
            return {"decision": "allow", "debt": debt}

        if action in HIGH_IMPACT_ACTIONS and debt >= 2.0:
            return {
                "decision": "block_high_impact",
                "debt": debt,
                "blocked_by": [u["id"] for u in unresolved[:3]],
                "required_receipts": [u.get("required_receipt", "") for u in unresolved[:3]],
            }

        if tool in READ_HEAVY_TOOLS and debt >= 1.0:
            return {
                "decision": "shape",
                "debt": debt,
                "focus_obligations": unresolved[:3],
            }

        return {"decision": "allow", "debt": debt}

    def shape_result(self, decision: Dict[str, Any], result: Any) -> Any:
        if decision.get("decision") != "shape":
            return result
        if not isinstance(result, dict):
            return result
        focus = decision.get("focus_obligations", [])
        result = dict(result)
        result["attention_focus"] = {
            "mode": "obligation_weighted",
            "debt": decision.get("debt", 0.0),
            "obligations": focus,
        }
        return result

    def upsert_policy(
        self,
        feature_id: str,
        helpfulness_score: float,
        ignore_rate: float,
        failure_when_ignored: float,
        best_enforcement_level: int,
        tool_contexts: List[str],
    ):
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO benchmark_policies(feature_id, helpfulness_score, ignore_rate, failure_when_ignored, best_enforcement_level, tool_contexts_json, updated_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feature_id) DO UPDATE SET
                    helpfulness_score=excluded.helpfulness_score,
                    ignore_rate=excluded.ignore_rate,
                    failure_when_ignored=excluded.failure_when_ignored,
                    best_enforcement_level=excluded.best_enforcement_level,
                    tool_contexts_json=excluded.tool_contexts_json,
                    updated_ts=excluded.updated_ts
                """,
                (
                    feature_id,
                    float(helpfulness_score),
                    float(ignore_rate),
                    float(failure_when_ignored),
                    int(best_enforcement_level),
                    json.dumps(tool_contexts or []),
                    time.time(),
                ),
            )
            conn.commit()

    def status(self, session_id: Optional[str]) -> Dict[str, Any]:
        sid = self._sid(session_id)
        unresolved = self.unresolved_obligations(sid)
        with self._conn() as conn:
            rcp = conn.execute(
                "SELECT COUNT(*) FROM receipts WHERE session_id=?", (sid,)
            ).fetchone()[0]
        return {
            "ok": True,
            "session_id": sid,
            "debt": self._get_debt(sid),
            "obligations_open": len(unresolved),
            "obligations": unresolved[:10],
            "receipts_total": int(rcp),
        }
