#!/usr/bin/env python3
"""Active Blackboard Kernel v2: Smart obligations, fuzzy bridges, episodic learning, per-kind Q, dependency graph, semantic cropping."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


HIGH_IMPACT_ACTIONS = {
    "rename", "set_name", "comment", "patch_asm",
    "apply_type", "set_type", "set_prototype", "write", "export",
    "auto_comment", "mark_dangerous", "annotate_constants",
}

READ_HEAVY_TOOLS = {"code", "data", "search", "graph", "ctree", "query"}

STRUCTURAL_MNEMONICS = {
    'call', 'jmp', 'jz', 'jnz', 'je', 'jne', 'ret', 'retn',
    'push', 'pop', 'lea', 'mov', 'bl', 'blr', 'b', 'bx', 'cbz', 'cbnz'
}

SUGGESTED_ALTERNATIVE_TOOLS = {
    "coverage_gap": ["data", "search", "query", "imports_deep"],
    "shadow_warning": ["code", "search", "graph", "ctree"],
    "narrative_gap": ["graph", "code", "ctree", "search"],
}


def _hex_prefix(s: str) -> bool:
    return s.startswith("0x") or s.startswith("-0x")


def _symbol_prefix(s: str) -> bool:
    return s.startswith("s_") or s.startswith("b_")


def _try_parse_hex(s: str) -> Optional[int]:
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None


def _impact_score(tool: str, action: str, args: Dict[str, Any]) -> float:
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
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            s = str(k).lower()
            if _hex_prefix(s) or _symbol_prefix(s):
                out.add(s)
            out |= _extract_bridges(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _extract_bridges(v)
    else:
        s = str(obj).lower()
        if _hex_prefix(s) or _symbol_prefix(s):
            out.add(s)
    return out


def _hash_sequence(seq: List[str]) -> str:
    raw = "|".join(seq)
    return hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


# ============================================================================
# Task 1: BridgeSimilarityEngine
# ============================================================================

class BridgeSimilarityEngine:
    def __init__(self, autogenic_db_path: str):
        self._autogenic_db_path = autogenic_db_path

    def _autogenic_conn(self):
        return sqlite3.connect(self._autogenic_db_path)

    def address_proximity(self, addr1: str, addr2: str) -> float:
        a1 = str(addr1).lower()
        a2 = str(addr2).lower()
        if a1 == a2:
            return 1.0
        if _hex_prefix(a1) and _hex_prefix(a2):
            v1 = _try_parse_hex(a1)
            v2 = _try_parse_hex(a2)
            if v1 is None or v2 is None:
                return 0.0
            diff = abs(v1 - v2)
            if diff == 0:
                return 1.0
            if diff <= 0x100:
                return 0.8
            if diff <= 0x10000:
                return 0.5
        return 0.0

    def symbol_cooccurrence(self, sym1: str, sym2: str) -> float:
        a = str(sym1).lower()
        b = str(sym2).lower()
        if not (_symbol_prefix(a) and _symbol_prefix(b)):
            return 0.0
        if a == b:
            return 1.0
        try:
            with self._autogenic_conn() as conn:
                row = conn.execute(
                    "SELECT seen_count FROM pairs WHERE (a=? AND b=?) OR (a=? AND b=?) LIMIT 1",
                    (a, b, b, a),
                ).fetchone()
                if row and row[0]:
                    count = int(row[0])
                    # Get max count for percentile normalization
                    max_row = conn.execute(
                        "SELECT MAX(seen_count) FROM pairs"
                    ).fetchone()
                    max_count = int(max_row[0]) if max_row and max_row[0] else 1
                    # Normalize using log scale relative to max
                    import math
                    score = math.log1p(count) / math.log1p(max(max_count, 1))
                    return min(1.0, max(0.0, score))
        except Exception:
            pass
        return 0.0

    def _pair_similarity(self, a: str, b: str) -> float:
        prox = self.address_proximity(a, b)
        if prox > 0:
            return prox
        cooc = self.symbol_cooccurrence(a, b)
        return cooc

    def bridge_similarity(self, bridge_set_a: Set[str], bridge_set_b: Set[str]) -> float:
        if not bridge_set_a or not bridge_set_b:
            return 0.0
        if bridge_set_a == bridge_set_b:
            return 1.0

        list_a = list(bridge_set_a)
        list_b = list(bridge_set_b)
        pairs = []
        for i, ia in enumerate(list_a):
            for j, jb in enumerate(list_b):
                sim = self._pair_similarity(ia, jb)
                if sim > 0:
                    pairs.append((1.0 - sim, i, j))
        if not pairs:
            return 0.0
        pairs.sort(key=lambda x: x[0])
        used_a: Set[int] = set()
        used_b: Set[int] = set()
        total_cost = 0.0
        match_count = 0
        for cost, i, j in pairs:
            if i in used_a or j in used_b:
                continue
            used_a.add(i)
            used_b.add(j)
            total_cost += cost
            match_count += 1
        max_len = max(len(bridge_set_a), len(bridge_set_b))
        if max_len == 0:
            return 0.0
        avg_cost = total_cost / max_len
        return max(0.0, min(1.0, 1.0 - avg_cost))


# ============================================================================
# Task 2: EpisodicLearner
# ============================================================================

class EpisodicLearner:
    SEQUENCE_LEN = 5

    def __init__(self, conn_fn: Callable[[], sqlite3.Connection]):
        self._conn_fn = conn_fn

    def _init_tables(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                ts REAL NOT NULL,
                sequence_hash TEXT NOT NULL,
                toll_json TEXT NOT NULL DEFAULT '[]',
                outcome TEXT NOT NULL,
                reward REAL NOT NULL
            )
            """
        )
        ep_cols = {row[1] for row in conn.execute("PRAGMA table_info(episodes)").fetchall()}
        if "toll_json" not in ep_cols:
            conn.execute("ALTER TABLE episodes ADD COLUMN toll_json TEXT NOT NULL DEFAULT '[]'")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_episodes_session_hash ON episodes(session_id, sequence_hash)"
        )
        conn.commit()

    def record_sequence(self, session_id: str, tool_sequence: List[str], outcome: str, reward: float):
        seq_hash = _hash_sequence(tool_sequence[-self.SEQUENCE_LEN:])
        with self._conn_fn() as conn:
            self._init_tables(conn)
            conn.execute(
                "INSERT INTO episodes(session_id, ts, sequence_hash, toll_json, outcome, reward) VALUES(?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), seq_hash, json.dumps(tool_sequence[-self.SEQUENCE_LEN:]), outcome, reward),
            )
            conn.commit()

    def predict_next_outcome(self, session_id: str, current_sequence: List[str]) -> Dict[str, Any]:
        if len(current_sequence) < 3:
            return {"outcome": "unknown", "confidence": 0.0}
        suffix = current_sequence[-3:]
        with self._conn_fn() as conn:
            self._init_tables(conn)
            rows = conn.execute(
                "SELECT toll_json, outcome FROM episodes WHERE session_id=? ORDER BY ts DESC LIMIT 200",
                (session_id,),
            ).fetchall()
        if not rows:
            return {"outcome": "unknown", "confidence": 0.0}
        matches = []
        for toll_json, outcome in rows:
            try:
                seq = json.loads(toll_json)
            except Exception:
                continue
            if len(seq) < 3:
                continue
            # Check if any 3-element subsequence of the stored sequence matches our suffix
            for i in range(len(seq) - 2):
                if seq[i:i+3] == suffix:
                    matches.append(outcome)
                    break
        if not matches:
            return {"outcome": "unknown", "confidence": 0.0}
        from collections import Counter
        tally = Counter(matches)
        top_outcome, top_count = tally.most_common(1)[0]
        confidence = top_count / len(matches)
        return {"outcome": top_outcome, "confidence": round(confidence, 3)}

    def detect_stuck_pattern(self, session_id: str) -> bool:
        with self._conn_fn() as conn:
            self._init_tables(conn)
            rows = conn.execute(
                "SELECT tool FROM observations WHERE session_id=? ORDER BY ts DESC LIMIT 5",
                (session_id,),
            ).fetchall()
        if len(rows) < 3:
            return False
        tools = [r[0] for r in rows if r[0]]
        if len(tools) < 3:
            return False
        for i in range(len(tools) - 2):
            if tools[i] == tools[i+1] == tools[i+2]:
                return True
        with self._conn_fn() as conn:
            rows = conn.execute(
                "SELECT 1 FROM episodes WHERE session_id=? AND outcome='failure' AND reward < 0 ORDER BY ts DESC LIMIT 3",
                (session_id,),
            ).fetchall()
            if len(rows) >= 3:
                return True
        return False

    def get_alternative_tools(self, session_id: str) -> List[str]:
        with self._conn_fn() as conn:
            self._init_tables(conn)
            rows2 = conn.execute(
                "SELECT tool FROM observations WHERE session_id=? ORDER BY ts DESC LIMIT 10",
                (session_id,),
            ).fetchall()
            seen_tools = {r[0] for r in rows2 if r[0]}
            rows = conn.execute(
                "SELECT outcome, toll_json FROM episodes WHERE session_id=? AND reward > 0 ORDER BY ts DESC LIMIT 20",
                (session_id,),
            ).fetchall()
            for _, toll_json in rows:
                try:
                    seq = json.loads(toll_json)
                    for tool_name in seq:
                        if tool_name not in seen_tools and tool_name in READ_HEAVY_TOOLS:
                            seen_tools.add(tool_name)
                except (json.JSONDecodeError, TypeError):
                    pass
            alternatives = [t for t in READ_HEAVY_TOOLS if t not in seen_tools]
            return alternatives[:3]


# ============================================================================
# Task 3: ObligationKindQLearner
# ============================================================================

class ObligationKindQLearner:
    ALPHA = 0.2
    Q_MIN = 0.1
    Q_MAX = 2.0

    def __init__(self, conn_fn: Callable[[], sqlite3.Connection]):
        self._conn_fn = conn_fn

    def _ensure_tables(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS obligation_kind_q (
                kind TEXT NOT NULL,
                session_id TEXT NOT NULL,
                q_value REAL NOT NULL DEFAULT 1.0,
                overrides_count INTEGER NOT NULL DEFAULT 0,
                success_count INTEGER NOT NULL DEFAULT 0,
                total_count INTEGER NOT NULL DEFAULT 0,
                updated_ts REAL NOT NULL,
                PRIMARY KEY (kind, session_id)
            )
            """
        )

    def update(self, sid: str, kind: str, resolved: bool, overridden: bool, conn: Optional[sqlite3.Connection] = None):
        if conn is not None:
            self._do_update(conn, sid, kind, resolved, overridden)
        else:
            with self._conn_fn() as new_conn:
                self._do_update(new_conn, sid, kind, resolved, overridden)
                new_conn.commit()

    def _do_update(self, conn: sqlite3.Connection, sid: str, kind: str, resolved: bool, overridden: bool):
        self._ensure_tables(conn)
        row = conn.execute(
            "SELECT q_value, overrides_count, success_count, total_count FROM obligation_kind_q WHERE kind=? AND session_id=?",
            (kind, sid),
        ).fetchone()
        if row:
            q, ov_count, suc_count, tot_count = float(row[0]), int(row[1]), int(row[2]), int(row[3])
        else:
            q, ov_count, suc_count, tot_count = 1.0, 0, 0, 0

        if resolved and not overridden:
            reward = 1.5
        elif overridden:
            reward = 0.1
            ov_count += 1
        else:
            reward = 0.5

        tot_count += 1
        if resolved:
            suc_count += 1

        q = q + self.ALPHA * (reward - q)
        q = max(self.Q_MIN, min(self.Q_MAX, q))

        conn.execute(
            """
            INSERT INTO obligation_kind_q(kind, session_id, q_value, overrides_count, success_count, total_count, updated_ts)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, session_id) DO UPDATE SET
                q_value=excluded.q_value,
                overrides_count=excluded.overrides_count,
                success_count=excluded.success_count,
                total_count=excluded.total_count,
                updated_ts=excluded.updated_ts
            """,
            (kind, sid, q, ov_count, suc_count, tot_count, time.time()),
        )

    def get_enforcement_multiplier(self, sid: str, kind: str) -> float:
        with self._conn_fn() as conn:
            self._ensure_tables(conn)
            row = conn.execute(
                "SELECT q_value FROM obligation_kind_q WHERE kind=? AND session_id=?",
                (kind, sid),
            ).fetchone()
            if row:
                return float(row[0])
        return 1.0


# ============================================================================
# Task 4: ObligationDependencyGraph
# ============================================================================

class ObligationDependencyGraph:
    def __init__(self, conn_fn: Callable[[], sqlite3.Connection]):
        self._conn_fn = conn_fn

    def _ensure_tables(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS obligation_dependencies (
                a_kind TEXT NOT NULL,
                b_kind TEXT NOT NULL,
                resolution_lag REAL NOT NULL DEFAULT 0,
                co_resolution_rate REAL NOT NULL DEFAULT 0,
                samples INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (a_kind, b_kind)
            )
            """
        )

    def record_resolution_pair(self, a_kind: str, b_kind: str, lag_calls: int, conn: Optional[sqlite3.Connection] = None):
        if conn is not None:
            self._do_record(conn, a_kind, b_kind, lag_calls)
        else:
            with self._conn_fn() as new_conn:
                self._do_record(new_conn, a_kind, b_kind, lag_calls)
                new_conn.commit()

    def _do_record(self, conn: sqlite3.Connection, a_kind: str, b_kind: str, lag_calls: int):
        self._ensure_tables(conn)
        row = conn.execute(
            "SELECT resolution_lag, co_resolution_rate, samples FROM obligation_dependencies WHERE a_kind=? AND b_kind=?",
            (a_kind, b_kind),
        ).fetchone()
        if row:
            old_lag, old_rate, old_samples = float(row[0]), float(row[1]), int(row[2])
            new_samples = old_samples + 1
            new_lag = old_lag + (lag_calls - old_lag) / new_samples
            new_rate = old_rate + (1.0 - old_rate) / new_samples
        else:
            new_lag = float(lag_calls)
            new_rate = 1.0 / 1.0
            new_samples = 1
        conn.execute(
            """
            INSERT INTO obligation_dependencies(a_kind, b_kind, resolution_lag, co_resolution_rate, samples)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(a_kind, b_kind) DO UPDATE SET
                resolution_lag=excluded.resolution_lag,
                co_resolution_rate=excluded.co_resolution_rate,
                samples=excluded.samples
            """,
            (a_kind, b_kind, new_lag, new_rate, new_samples),
        )

    def get_predicted_resolution_time(self, kind: str, unresolved_kinds: List[str], conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        predictions = {}
        if conn is not None:
            self._ensure_tables(conn)
            for b_kind in unresolved_kinds:
                if b_kind == kind:
                    continue
                row = conn.execute(
                    "SELECT resolution_lag, co_resolution_rate FROM obligation_dependencies WHERE a_kind=? AND b_kind=? AND co_resolution_rate > 0.3",
                    (kind, b_kind),
                ).fetchone()
                if row:
                    predictions[b_kind] = {
                        "predicted_lag": float(row[0]),
                        "co_resolution_rate": float(row[1]),
                    }
            return predictions

        with self._conn_fn() as conn:
            self._ensure_tables(conn)
            for b_kind in unresolved_kinds:
                if b_kind == kind:
                    continue
                row = conn.execute(
                    "SELECT resolution_lag, co_resolution_rate FROM obligation_dependencies WHERE a_kind=? AND b_kind=? AND co_resolution_rate > 0.3",
                    (kind, b_kind),
                ).fetchone()
                if row:
                    predictions[b_kind] = {
                        "predicted_lag": float(row[0]),
                        "co_resolution_rate": float(row[1]),
                    }
        return predictions


# ============================================================================
# Task 5: SemanticCropper
# ============================================================================

class SemanticCropper:
    STRING_QUOTE_CHARS = {'"', "'", '`'}

    @staticmethod
    def _line_is_preserved(line: str) -> bool:
        stripped = line.strip().lower()
        # Preserve lines with string literals (quotes)
        for ch in SemanticCropper.STRING_QUOTE_CHARS:
            if ch in line and line.count(ch) >= 2:
                return True
        # Preserve lines with high structural density (many non-space chars per token)
        tokens = stripped.split()
        if len(tokens) >= 3:
            avg_len = sum(len(t) for t in tokens) / len(tokens)
            if avg_len > 6:
                return True
        # Preserve lines that look like they contain calls/jumps/returns
        # Detected generically by short verbs at line start followed by addresses
        if tokens and len(tokens[0]) <= 4:
            rest = ' '.join(tokens[1:])
            if any(c in rest for c in ('0x', 'sub_', 'loc_', 'off_')):
                return True
        # Preserve lines with API-like patterns (word with dot)
        for tok in tokens:
            if '.' in tok and len(tok) > 3:
                return True
        return False

    @staticmethod
    def _line_has_bridge(line: str, bridges: Set[str]) -> bool:
        line_lower = line.lower()
        for b in bridges:
            if b in line_lower:
                return True
        return False

    @staticmethod
    def crop_decompile(text: str, obligation_bridges: Set[str], preserve_lines: int = 5) -> str:
        if not text:
            return text
        lines = text.split('\n')
        if len(lines) <= 40:
            return text

        anchored: Set[int] = set()
        preserved_line_indices: Set[int] = set()

        for i, line in enumerate(lines):
            if SemanticCropper._line_has_bridge(line, obligation_bridges):
                anchored.add(i)

        for i, line in enumerate(lines):
            if SemanticCropper._line_is_preserved(line):
                preserved_line_indices.add(i)

        keep: Set[int] = set()
        for anchor_idx in anchored:
            start = max(0, anchor_idx - preserve_lines)
            end = min(len(lines), anchor_idx + preserve_lines + 1)
            for j in range(start, end):
                keep.add(j)
        keep |= preserved_line_indices

        if not keep:
            return text

        sorted_keep = sorted(keep)
        output_lines: List[str] = []
        prev = -2
        for idx in sorted_keep:
            gap = idx - prev - 1
            if gap > 0:
                if prev >= 0 and gap > 3:
                    output_lines.append(f"... [{gap} lines omitted] ...")
                else:
                    for g in range(prev + 1, idx):
                        if g < len(lines):
                            output_lines.append(lines[g])
            output_lines.append(lines[idx])
            prev = idx

        if prev < len(lines) - 1:
            remaining = len(lines) - 1 - prev
            if remaining > 3:
                output_lines.append(f"... [{remaining} lines omitted] ...")
            else:
                for g in range(prev + 1, len(lines)):
                    output_lines.append(lines[g])

        preserved_set = anchored | preserved_line_indices
        anchored_or_preserved = len([l for l in output_lines if l in {lines[i] for i in preserved_set}])
        total = len(output_lines)
        if total > 0 and anchored_or_preserved / total < 0.6:
            expanded_keep = set(keep)
            for anchor_idx in anchored:
                start = max(0, anchor_idx - preserve_lines - 3)
                end = min(len(lines), anchor_idx + preserve_lines + 4)
                for j in range(start, end):
                    expanded_keep.add(j)
            sorted_expanded = sorted(expanded_keep)
            output_lines = []
            prev = -2
            for idx in sorted_expanded:
                gap = idx - prev - 1
                if gap > 4:
                    output_lines.append(f"... [{gap} lines omitted] ...")
                else:
                    for g in range(prev + 1, idx):
                        if g < len(lines):
                            output_lines.append(lines[g])
                output_lines.append(lines[idx])
                prev = idx

        return '\n'.join(output_lines)

    @staticmethod
    def reorder_xrefs(xrefs: list, obligation_bridges: Set[str], similarity_engine: BridgeSimilarityEngine) -> list:
        if not xrefs:
            return xrefs
        scored = []
        for xref in xrefs:
            xref_text = json.dumps(xref, default=str).lower()
            xref_bridges = _extract_bridges(xref)
            sim = similarity_engine.bridge_similarity(xref_bridges, obligation_bridges)
            if sim == 0.0 and not xref_bridges:
                sim = 0.1
            scored.append((sim, xref))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [x[1] for x in scored]


# ============================================================================
# AttentionKernel v2 — Smart Blackboard Kernel
# ============================================================================

class AttentionKernel:
    def __init__(self, db_path: Optional[str] = None, autogenic_db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "attention_kernel.db"
        )
        self._autogenic_db_path = autogenic_db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "autogenic_semantics.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self.bridge_engine = BridgeSimilarityEngine(self._autogenic_db_path)
        self.episodic_learner = EpisodicLearner(self._conn)
        self.kind_q_learner = ObligationKindQLearner(self._conn)
        self.dep_graph = ObligationDependencyGraph(self._conn)
        self._init_db()
        self._observation_counts: Dict[str, int] = {}

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
                    evidence_json TEXT,
                    bridge_similarity REAL NOT NULL DEFAULT 0.0
                )
                """
            )
            rcp_cols = {row[1] for row in conn.execute("PRAGMA table_info(receipts)").fetchall()}
            if "bridge_similarity" not in rcp_cols:
                conn.execute("ALTER TABLE receipts ADD COLUMN bridge_similarity REAL NOT NULL DEFAULT 0.0")
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

        prev_debt = self._get_debt(sid)
        self._resolve_receipts(sid, tool, action, args, result)
        new_debt = self._get_debt(sid)

        # Episodic learning: every 5th observation, record sequence
        self._observation_counts[sid] = self._observation_counts.get(sid, 0) + 1
        if self._observation_counts[sid] % 5 == 0:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT tool, action FROM observations WHERE session_id=? ORDER BY ts DESC LIMIT 5",
                    (sid,),
                ).fetchall()
                sequence = [f"{r[0]}:{r[1] or ''}" for r in reversed(rows)]
                debt_delta = prev_debt - new_debt
                if debt_delta > 0.5:
                    outcome = "success"
                    reward = 0.5
                elif debt_delta < -0.5:
                    outcome = "failure"
                    reward = -0.5
                else:
                    outcome = "neutral"
                    reward = -0.1
                self.episodic_learner.record_sequence(sid, sequence, outcome, reward)

    def _resolve_receipts(self, sid: str, tool: str, action: str, args: Dict[str, Any], result: Any):
        open_obs = self.unresolved_obligations(sid)
        if not open_obs:
            return

        result_bridges = _extract_bridges(result)
        args_bridges = _extract_bridges(args)
        addr = str((args or {}).get("addr", "")).lower()
        if addr:
            args_bridges.add(addr)

        resolved = []
        for obl in open_obs:
            kind = obl.get("kind", "")
            good = False
            obl_bridges = set(obl.get("bridges", []))

            result_sim = self.bridge_engine.bridge_similarity(obl_bridges, result_bridges)
            args_sim = self.bridge_engine.bridge_similarity(obl_bridges, args_bridges)

            if result_sim >= 0.6:
                good = True
            elif args_sim >= 0.4:
                good = True

            if not good:
                if kind == "coverage_gap":
                    good = tool in {"data", "search", "imports_deep", "query"}
                elif kind == "shadow_warning":
                    good = tool in {"code", "search", "graph", "ctree"}
                elif kind == "narrative_gap":
                    good = tool in {"graph", "code", "ctree", "search"}
            if good:
                resolved.append((obl, max(result_sim, args_sim), obl_bridges))

        if not resolved:
            return

        resolved_kinds = list(set(obl.get("kind", "") for obl, _, _ in resolved))
        unresolved_kinds = [o.get("kind", "") for o in open_obs if o["id"] not in [r[0]["id"] for r in resolved]]

        # Pre-compute predictions outside the write transaction
        dep_predictions: Dict[str, Dict[str, Any]] = {}
        with self._conn() as conn:
            for rk in resolved_kinds:
                preds = self.dep_graph.get_predicted_resolution_time(rk, unresolved_kinds, conn=conn)
                if preds:
                    dep_predictions[rk] = preds

        now = time.time()
        resolved_ids = {r[0]["id"] for r in resolved}
        with self._conn() as conn:
            for obl, sim, obl_bridges in resolved:
                rid = f"rcp_{uuid.uuid4().hex[:10]}"
                conn.execute(
                    "UPDATE obligations SET status='resolved' WHERE id=?", (obl["id"],)
                )
                conn.execute(
                    "INSERT INTO receipts(id, session_id, ts, tool, action, obligation_id, evidence_json, bridge_similarity) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (rid, sid, now, tool, action, obl["id"],
                     json.dumps({"addr": addr, "tool": tool, "action": action, "bridges_matched": list(obl_bridges & result_bridges | obl_bridges & args_bridges)}),
                     sim),
                )
                self.kind_q_learner.update(sid, obl.get("kind", ""), resolved=True, overridden=False, conn=conn)

            # Record dependency pairs only when bridges overlap (relevant co-occurrence)
            resolved_obl_map = {obl.get("kind", ""): set(obl.get("bridges", [])) for obl, _, _ in resolved}
            for obl in open_obs:
                if obl["id"] in resolved_ids:
                    continue
                other_kind = obl.get("kind", "")
                other_bridges = set(obl.get("bridges", []))
                for rk, rk_bridges in resolved_obl_map.items():
                    if rk != other_kind and (rk_bridges & other_bridges):
                        self.dep_graph.record_resolution_pair(rk, other_kind, 1, conn=conn)

            # Auto-resolve predicted downstream obligations
            predicted_count = 0
            for rk, predictions in dep_predictions.items():
                for b_kind, pred_info in predictions.items():
                    if pred_info["predicted_lag"] <= 2:
                        for obl in open_obs:
                            if obl.get("kind") == b_kind and obl["id"] not in resolved_ids:
                                conn.execute(
                                    "UPDATE obligations SET status='predicted' WHERE id=?",
                                    (obl["id"],),
                                )
                                resolved_ids.add(obl["id"])
                                predicted_count += 1

            conn.commit()

        debt_reduction = 0.9 * len(resolved) + 0.5 * predicted_count
        self._set_debt(sid, self._get_debt(sid) - debt_reduction)

    def _policy_boost(self, sid: str, unresolved: List[Dict[str, Any]]) -> float:
        boost = 0.0
        with self._conn() as conn:
            for row in conn.execute(
                "SELECT feature_id, failure_when_ignored, best_enforcement_level FROM benchmark_policies"
            ).fetchall():
                feat, fail_rate, level = row
                boost += float(fail_rate) * 0.5 * float(level)
        return boost

    def _compute_kind_adjusted_debt(self, sid: str, unresolved: List[Dict[str, Any]], current_bridges: set[str]) -> float:
        total_contrib = 0.0

        for obl in unresolved:
            kind = obl.get("kind", "unknown")
            multiplier = self.kind_q_learner.get_enforcement_multiplier(sid, kind)

            # Check dependency graph: is this obligation predicted to resolve soon?
            dep_skip = False
            for u2 in unresolved:
                if u2["id"] == obl["id"]:
                    continue
                u2_kind = u2.get("kind", "")
                predictions = self.dep_graph.get_predicted_resolution_time(u2_kind, [kind])
                if kind in predictions and predictions[kind]["predicted_lag"] <= 2:
                    u2_bridges = set(u2.get("bridges", []))
                    if current_bridges and u2_bridges:
                        overlap = current_bridges & u2_bridges
                        if len(overlap) > 0:
                            dep_skip = True
                            break

            if dep_skip:
                continue

            contrib = 0.7 * multiplier
            total_contrib += contrib

        return total_contrib

    def preflight(self, session_id: Optional[str], tool: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = self._sid(session_id)
        debt = self._get_debt(sid)
        unresolved = self.unresolved_obligations(sid)
        current_bridges = _extract_bridges(args)

        result: Dict[str, Any] = {"decision": "allow", "debt": debt}

        stuck = self.episodic_learner.detect_stuck_pattern(sid)
        if stuck:
            result["stuck_warning"] = True
            result["alternative_tools"] = self.episodic_learner.get_alternative_tools(sid)
            debt += 1.5

        if unresolved:
            last_4 = []
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT tool, action FROM observations WHERE session_id=? ORDER BY ts DESC LIMIT 4",
                    (sid,),
                ).fetchall()
                last_4 = [f"{r[0]}:{r[1] or ''}" for r in reversed(rows)]
            prediction = self.episodic_learner.predict_next_outcome(sid, last_4)
            if prediction.get("outcome") == "failure" and prediction.get("confidence", 0) > 0.7:
                result["stuck_warning"] = True
                result["predicted_outcome"] = "failure"
                result["predicted_confidence"] = prediction["confidence"]
                result["alternative_tools"] = self.episodic_learner.get_alternative_tools(sid)
                debt += 1.0

        kind_adjusted = self._compute_kind_adjusted_debt(sid, unresolved, current_bridges)
        policy_boost = self._policy_boost(sid, unresolved)
        effective_debt = debt + kind_adjusted + policy_boost

        if not unresolved:
            return result

        impact = _impact_score(tool, action, args)

        if impact >= 2.0 and effective_debt >= 2.0:
            result["decision"] = "block_high_impact"
            result["effective_debt"] = round(effective_debt, 2)
            result["blocked_by"] = [u["id"] for u in unresolved[:3]]
            result["required_receipts"] = [u.get("required_receipt", "") for u in unresolved[:3]]
            if stuck:
                result["hint"] = "Analyst appears stuck. Try: " + ", ".join(result.get("alternative_tools", []))
            return result

        if tool in READ_HEAVY_TOOLS and (effective_debt >= 1.0 or stuck):
            result["decision"] = "shape"
            result["effective_debt"] = round(effective_debt, 2)
            result["focus_obligations"] = unresolved[:3]
            if stuck:
                result["stuck_warning"] = True
            return result

        result["effective_debt"] = round(effective_debt, 2)
        return result

    def shape_result(self, decision: Dict[str, Any], result: Any) -> Any:
        if decision.get("decision") != "shape":
            return result
        if not isinstance(result, dict):
            return result
        focus = decision.get("focus_obligations", [])
        result = dict(result)

        obl_bridges: Set[str] = set()
        for f in focus:
            obl_bridges |= set(f.get("bridges", []))

        # Reorder xrefs/callees by bridge similarity
        for key in ("xrefs", "callers", "callees", "refs"):
            if key in result and isinstance(result[key], list):
                result[key] = SemanticCropper.reorder_xrefs(
                    result[key], obl_bridges, self.bridge_engine
                )

        # Semantic crop text fields
        for key in ("code", "disasm", "decompile"):
            if key in result and isinstance(result[key], str):
                text = result[key]
                if len(text) > 2000:
                    result[key] = SemanticCropper.crop_decompile(text, obl_bridges)

        result["attention_focus"] = {
            "mode": "obligation_weighted",
            "debt": decision.get("debt", 0.0),
            "effective_debt": decision.get("effective_debt", 0.0),
            "obligations": focus,
        }
        if decision.get("stuck_warning"):
            result["attention_focus"]["stuck_warning"] = True
            result["attention_focus"]["alternative_tools"] = decision.get("alternative_tools", [])
        return result

    def record_override(self, session_id: Optional[str], obligation_id: str, tool: str, action: str, reason: str = ""):
        sid = self._sid(session_id)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO overrides(session_id, ts, obligation_id, tool, action, reason) VALUES(?, ?, ?, ?, ?, ?)",
                (sid, time.time(), obligation_id, tool, action, reason),
            )
            row = conn.execute(
                "SELECT kind FROM obligations WHERE id=?", (obligation_id,)
            ).fetchone()
            conn.commit()

        kind = row[0] if row else "unknown"
        self.kind_q_learner.update(sid, kind, resolved=False, overridden=True)

        current_debt = self._get_debt(sid)
        multiplier = self.kind_q_learner.get_enforcement_multiplier(sid, kind)
        reduction = 0.3 * multiplier
        self._set_debt(sid, current_debt - reduction)

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
