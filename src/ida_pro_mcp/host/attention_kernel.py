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
    "rename", "set_name", "comment", "patch_asm",
    "apply_type", "set_type", "set_prototype", "write", "export",
    "auto_comment", "mark_dangerous", "annotate_constants",
}

READ_HEAVY_TOOLS = {"code", "data", "search", "graph", "ctree", "query"}


def _impact_score(tool: str, action: str, args: Dict[str, Any]) -> float:
    """Deep intent extraction: compute semantic impact from full payload."""
    score = 0.0
    act = str(action or "").strip().lower()
    if act in HIGH_IMPACT_ACTIONS:
        score += 2.0
    if act in {"rename", "set_name", "patch_asm"}:
        score += 1.5
    if act in {"comment", "auto_comment"}:
        score += 1.0
    if tool in {"modify", "bulk", "annotation"}:
        score += 1.0
    if tool == "funcs" and act in {"rename", "set_name", "set_type"}:
        score += 1.0
    if tool == "types" and act in {"set_prototype", "apply_type"}:
        score += 0.5
    if _coerce_bool(args.get("_guardrail_ack"), False):
        score -= 2.5
    return max(0.0, score)


def _coerce_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).lower() in {"1", "true", "yes", "on"}


def _extract_bridges(obj: Any) -> set[str]:
    """Recursively extract all string tokens that look like addresses or latent symbols."""
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            s = str(k).lower()
            if s.startswith("0x") or s.startswith("b_") or s.startswith("s_"):
                out.add(s)
            out |= _extract_bridges(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _extract_bridges(v)
    else:
        s = str(obj).lower()
        if s.startswith("0x") or s.startswith("b_") or s.startswith("s_"):
            out.add(s)
    return out


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
                    expires_at REAL NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT,
                    required_receipt TEXT,
                    source_obs_id TEXT,
                    bridges_json TEXT DEFAULT '[]'
                )
                """
            )
            # Migrate existing tables that may lack new columns
            cols = {row[1] for row in conn.execute("PRAGMA table_info(obligations)").fetchall()}
            if "expires_at" not in cols:
                conn.execute("ALTER TABLE obligations ADD COLUMN expires_at REAL NOT NULL DEFAULT 0")
            if "bridges_json" not in cols:
                conn.execute("ALTER TABLE obligations ADD COLUMN bridges_json TEXT DEFAULT '[]'")
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS overrides (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    ts REAL NOT NULL,
                    obligation_id TEXT,
                    tool TEXT,
                    action TEXT,
                    reason TEXT
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

    def _current_focus_bridges(self, sid: str) -> set[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT args_json FROM observations WHERE session_id=? ORDER BY ts DESC LIMIT 1", (sid,)
            ).fetchone()
        if not row:
            return set()
        try:
            args = json.loads(row[0] or "{}")
            return _extract_bridges(args)
        except Exception:
            return set()

    def unresolved_obligations(self, session_id: Optional[str]) -> List[Dict[str, Any]]:
        sid = self._sid(session_id)
        now = time.time()
        focus = self._current_focus_bridges(sid)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, kind, payload_json, required_receipt, ts, bridges_json FROM obligations WHERE session_id=? AND status='open' AND (expires_at=0 OR expires_at>?) ORDER BY ts DESC LIMIT 50",
                (sid, now),
            ).fetchall()
        out = []
        for rid, kind, payload_json, req, ts, bridges_json in rows:
            try:
                payload = json.loads(payload_json or "{}")
            except Exception:
                payload = {}
            try:
                obl_bridges = set(json.loads(bridges_json or "[]"))
            except Exception:
                obl_bridges = set()
            relevance = 0.5
            if focus and obl_bridges:
                overlap = focus & obl_bridges
                relevance = 0.5 + 0.5 * (len(overlap) / max(len(obl_bridges), 1))
            out.append({"id": rid, "kind": kind, "payload": payload, "required_receipt": req, "ts": ts, "relevance": round(relevance, 2), "bridges": list(obl_bridges)})
        out.sort(key=lambda x: x["relevance"], reverse=True)
        return out

    def add_obligation(self, session_id: Optional[str], kind: str, payload: Dict[str, Any], required_receipt: str, source_obs_id: str = "", bridges: Optional[List[str]] = None):
        sid = self._sid(session_id)
        oid = f"obl_{uuid.uuid4().hex[:8]}"
        now = time.time()
        expires = now + 600
        bridges = bridges or []
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO obligations(id, session_id, ts, expires_at, status, kind, payload_json, required_receipt, source_obs_id, bridges_json) VALUES(?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)",
                (oid, sid, now, expires, kind, json.dumps(payload, ensure_ascii=False), required_receipt, source_obs_id, json.dumps(bridges)),
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
        bridges = _extract_bridges(context)

        if voids:
            self.add_obligation(sid, "coverage_gap", {"voids": voids[:3], "tool": tool, "action": action}, "inspect_unseen_surface", bridges=list(bridges))
        if shadows:
            self.add_obligation(sid, "shadow_warning", {"warnings": shadows[:2], "tool": tool, "action": action}, "disprove_or_branch", bridges=list(bridges))
        if gaps:
            self.add_obligation(sid, "narrative_gap", {"gaps": gaps[:2], "tool": tool, "action": action}, "connect_story_nodes", bridges=list(bridges))

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

        result_bridges = _extract_bridges(result)
        args_bridges = _extract_bridges(args)
        all_bridges = result_bridges | args_bridges
        addr = str((args or {}).get("addr", "")).lower()
        if addr:
            all_bridges.add(addr)

        resolved = []
        for obl in open_obs:
            kind = obl.get("kind", "")
            good = False
            obl_bridges = set(obl.get("bridges", []))
            if obl_bridges and all_bridges:
                overlap = obl_bridges & all_bridges
                if len(overlap) >= max(1, len(obl_bridges) // 2):
                    good = True
            if not good:
                if kind == "coverage_gap":
                    good = tool in {"data", "search", "imports_deep", "query"}
                elif kind == "shadow_warning":
                    good = tool in {"code", "search", "graph", "ctree"}
                elif kind == "narrative_gap":
                    good = tool in {"graph", "code", "ctree", "search"}
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
                    (rid, sid, now, tool, action, obl["id"], json.dumps({"addr": addr, "tool": tool, "action": action, "bridges_matched": list(all_bridges & set(obl.get("bridges", [])))})),
                )
                conn.execute("UPDATE obligations SET status='resolved' WHERE id=?", (obl["id"],))
            conn.commit()

        self._set_debt(sid, self._get_debt(sid) - 0.9 * len(resolved))

    def _policy_boost(self, sid: str, unresolved: List[Dict[str, Any]]) -> float:
        boost = 0.0
        with self._conn() as conn:
            for row in conn.execute(
                "SELECT feature_id, failure_when_ignored, best_enforcement_level FROM benchmark_policies"
            ).fetchall():
                feat, fail_rate, level = row
                boost += float(fail_rate) * 0.5 * float(level)
        return boost

    def preflight(self, session_id: Optional[str], tool: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = self._sid(session_id)
        debt = self._get_debt(sid)
        unresolved = self.unresolved_obligations(sid)
        if not unresolved:
            return {"decision": "allow", "debt": debt}

        impact = _impact_score(tool, action, args)
        policy_boost = self._policy_boost(sid, unresolved)
        effective_debt = debt + policy_boost

        if impact >= 2.0 and effective_debt >= 2.0:
            return {
                "decision": "block_high_impact",
                "debt": debt,
                "effective_debt": round(effective_debt, 2),
                "blocked_by": [u["id"] for u in unresolved[:3]],
                "required_receipts": [u.get("required_receipt", "") for u in unresolved[:3]],
            }

        if tool in READ_HEAVY_TOOLS and effective_debt >= 1.0:
            return {
                "decision": "shape",
                "debt": debt,
                "effective_debt": round(effective_debt, 2),
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

        # Reorder xrefs/callees by obligation relevance
        for key in ("xrefs", "callers", "callees", "refs"):
            if key in result and isinstance(result[key], list):
                obl_addrs = set()
                for f in focus:
                    obl_addrs |= set(f.get("bridges", []))
                def _score(item):
                    item_text = json.dumps(item, default=str).lower()
                    return sum(1 for a in obl_addrs if a in item_text)
                result[key] = sorted(result[key], key=_score, reverse=True)

        # Crop huge text fields to surface relevant regions
        for key in ("code", "disasm", "decompile"):
            if key in result and isinstance(result[key], str):
                text = result[key]
                if len(text) > 2000:
                    obl_addrs = set()
                    for f in focus:
                        obl_addrs |= set(f.get("bridges", []))
                    best_pos = 0
                    best_score = 0
                    for i in range(0, len(text) - 500, 250):
                        window = text[i:i+800].lower()
                        score = sum(1 for a in obl_addrs if a in window)
                        if score > best_score:
                            best_score = score
                            best_pos = i
                    if best_score > 0:
                        result[key] = text[best_pos:best_pos+1200] + "\n... [cropped to obligation-relevant region] ..."

        result["attention_focus"] = {
            "mode": "obligation_weighted",
            "debt": decision.get("debt", 0.0),
            "effective_debt": decision.get("effective_debt", 0.0),
            "obligations": focus,
        }
        return result

    def record_override(self, session_id: Optional[str], obligation_id: str, tool: str, action: str, reason: str = ""):
        sid = self._sid(session_id)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO overrides(session_id, ts, obligation_id, tool, action, reason) VALUES(?, ?, ?, ?, ?, ?)",
                (sid, time.time(), obligation_id, tool, action, reason),
            )
            conn.commit()
        # Reduce sensitivity for this kind of obligation
        self._set_debt(sid, self._get_debt(sid) - 0.3)

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
            ov = conn.execute(
                "SELECT COUNT(*) FROM overrides WHERE session_id=?", (sid,)
            ).fetchone()[0]
        return {
            "ok": True,
            "session_id": sid,
            "debt": self._get_debt(sid),
            "obligations_open": len(unresolved),
            "obligations": unresolved[:10],
            "receipts_total": int(rcp),
            "overrides_total": int(ov),
        }
