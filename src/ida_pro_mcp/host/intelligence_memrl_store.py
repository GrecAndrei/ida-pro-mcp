"""MemRL preference store and reward constants."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


REWARD_ACCEPT = 1.0
REWARD_PARTIAL = 0.5
REWARD_NEUTRAL = 0.0
REWARD_REJECT = -0.5
REWARD_DANGEROUS = -1.0

Q_FLOOR = -1.0
Q_CEILING = 1.0
DEFAULT_ALPHA = 0.15


class PreferenceMemoryBank:
    """
    SQLite-backed intent/expression utility memory.

    This is the canonical runtime backend for MemRL-style ranking and
    suggestion tracking. The legacy `ida_mcp.tools.memrl` module remains as a
    compatibility surface for tests and direct imports.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "memrl.db")
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_triplets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_key TEXT NOT NULL,
                    experience_key TEXT NOT NULL,
                    intent_z BLOB,
                    experience_meta TEXT,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    visit_count INTEGER NOT NULL DEFAULT 0,
                    last_updated REAL NOT NULL,
                    UNIQUE(intent_key, experience_key)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intent ON memrl_triplets(intent_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_experience ON memrl_triplets(experience_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_q_value ON memrl_triplets(q_value)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_suggestions (
                    suggestion_id TEXT PRIMARY KEY,
                    intent_key TEXT NOT NULL,
                    experience_key TEXT NOT NULL,
                    source_tool TEXT DEFAULT '',
                    source_action TEXT DEFAULT '',
                    context_addr TEXT DEFAULT '',
                    experience_meta TEXT,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    initial_q REAL NOT NULL DEFAULT 0.5,
                    reward REAL,
                    feedback_type TEXT,
                    feedback_timestamp REAL,
                    created_at REAL NOT NULL,
                    last_updated REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_intent ON memrl_suggestions(intent_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_created ON memrl_suggestions(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sug_feedback ON memrl_suggestions(feedback_type)")
            conn.commit()

    def record(
        self,
        intent_key: str,
        experience_key: str,
        intent_z: Optional[bytes] = None,
        experience_meta: Optional[dict] = None,
        initial_q: float = 0.5,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO memrl_triplets
                (intent_key, experience_key, intent_z, experience_meta, q_value, visit_count, last_updated)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(intent_key, experience_key) DO UPDATE SET
                    visit_count = visit_count + 1,
                    last_updated = excluded.last_updated
                """,
                (
                    intent_key,
                    experience_key,
                    intent_z,
                    json.dumps(experience_meta) if experience_meta else None,
                    initial_q,
                    time.time(),
                ),
            )
            conn.commit()

    def update_q(
        self,
        intent_key: str,
        experience_key: str,
        reward: float,
        alpha: float = DEFAULT_ALPHA,
    ) -> float:
        reward = max(Q_FLOOR, min(Q_CEILING, reward))
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            )
            row = cur.fetchone()
            if row is None:
                new_q = reward
                self.record(intent_key, experience_key, initial_q=new_q)
                return new_q
            old_q = float(row[0])
            new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * (reward - old_q)))
            cur.execute(
                """
                UPDATE memrl_triplets
                SET q_value = ?, last_updated = ?, visit_count = visit_count + 1
                WHERE intent_key = ? AND experience_key = ?
                """,
                (new_q, time.time(), intent_key, experience_key),
            )
            conn.commit()
            return new_q

    def batch_update_q(
        self,
        intent_key: str,
        experience_keys: List[str],
        rewards: List[float],
        alpha: float = DEFAULT_ALPHA,
    ) -> Dict[str, float]:
        return {
            ek: self.update_q(intent_key, ek, reward=r, alpha=alpha)
            for ek, r in zip(experience_keys, rewards)
        }

    def two_phase_retrieve(
        self,
        intent_key: str,
        candidate_pool: List[Dict[str, Any]],
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
    ) -> List[Dict[str, Any]]:
        if not candidate_pool:
            return []
        with self._conn() as conn:
            cur = conn.cursor()
            sims = [float(c.get(similarity_key, 0.0) or 0.0) for c in candidate_pool]
            n = len(sims)
            sim_mean = sum(sims) / n if n else 0.0
            sim_std = math.sqrt(sum((s - sim_mean) ** 2 for s in sims) / n) if n > 1 else 1.0
            if sim_std < 1e-9:
                sim_std = 1.0
            q_vals: List[float] = []
            for c in candidate_pool:
                exp_key = c.get("ea", c.get("name", str(id(c))))
                cur.execute(
                    "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                    (intent_key, exp_key),
                )
                row = cur.fetchone()
                q_vals.append(float(row[0]) if row else 0.5)
            q_mean = sum(q_vals) / n if n else 0.0
            q_std = math.sqrt(sum((q - q_mean) ** 2 for q in q_vals) / n) if n > 1 else 1.0
            if q_std < 1e-9:
                q_std = 1.0
        scored: List[Tuple[Dict[str, Any], float, float]] = []
        for c, sim, q in zip(candidate_pool, sims, q_vals):
            norm_sim = (sim - sim_mean) / sim_std
            norm_q = (q - q_mean) / q_std
            final_score = (1.0 - lambda_explore) * norm_sim + lambda_explore * norm_q
            scored.append((c, final_score, q))
        scored.sort(key=lambda x: x[1], reverse=True)
        out: List[Dict[str, Any]] = []
        for c, final_score, q in scored[:top_k]:
            merged = dict(c)
            merged["memrl_score"] = round(final_score, 4)
            merged["q_value"] = round(q, 4)
            out.append(merged)
        return out

    def get_q(self, intent_key: str, experience_key: str) -> float:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            ).fetchone()
            return float(row[0]) if row else 0.5

    def ingest_suggestion(
        self,
        intent_key: str,
        experience_key: str,
        source_tool: str = "",
        source_action: str = "",
        context_addr: str = "",
        experience_meta: Optional[dict] = None,
        initial_q: float = 0.5,
    ) -> str:
        suggestion_id = uuid.uuid4().hex[:12]
        now = time.time()
        self.record(
            intent_key=intent_key,
            experience_key=experience_key,
            experience_meta=experience_meta,
            initial_q=initial_q,
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO memrl_suggestions
                (suggestion_id, intent_key, experience_key, source_tool, source_action,
                 context_addr, experience_meta, q_value, initial_q, created_at, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    suggestion_id,
                    intent_key,
                    experience_key,
                    source_tool,
                    source_action,
                    context_addr,
                    json.dumps(experience_meta) if experience_meta else None,
                    initial_q,
                    initial_q,
                    now,
                    now,
                ),
            )
            conn.commit()
        return suggestion_id

    def auto_reward_for_addr(
        self,
        addr: str,
        reward: float = 0.7,
        alpha: float = DEFAULT_ALPHA,
        max_age_seconds: float = 1800.0,
    ) -> int:
        cutoff = time.time() - max_age_seconds
        updated = 0
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT suggestion_id, intent_key, experience_key, q_value
                FROM memrl_suggestions
                WHERE context_addr = ?
                  AND (feedback_type IS NULL OR feedback_type = 'neutral')
                  AND created_at >= ?
                ORDER BY created_at DESC
                LIMIT 5
                """,
                (addr, cutoff),
            )
            rows = cur.fetchall()
            now = time.time()
            for suggestion_id, intent_key, experience_key, old_q in rows:
                old_q = float(old_q or 0.5)
                new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * (reward - old_q)))
                cur.execute(
                    """
                    UPDATE memrl_suggestions
                    SET q_value = ?, reward = ?, feedback_type = 'auto_accept',
                        feedback_timestamp = ?, last_updated = ?
                    WHERE suggestion_id = ?
                    """,
                    (new_q, reward, now, now, suggestion_id),
                )
                self.update_q(intent_key, experience_key, reward, alpha)
                updated += 1
            conn.commit()
        return updated

    @staticmethod
    def _classify_reward(reward: float) -> str:
        if reward >= 0.8:
            return "accept"
        if reward >= 0.3:
            return "partial"
        if reward >= -0.2:
            return "neutral"
        if reward >= -0.8:
            return "reject"
        return "dangerous"

    def process_feedback(
        self,
        suggestion_id: str,
        reward: float,
        alpha: float = DEFAULT_ALPHA,
    ) -> Dict[str, Any]:
        reward = max(Q_FLOOR, min(Q_CEILING, reward))
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT intent_key, experience_key, q_value FROM memrl_suggestions WHERE suggestion_id = ?",
                (suggestion_id,),
            )
            row = cur.fetchone()
            if row is None:
                return {"ok": False, "error": f"Suggestion not found: {suggestion_id}"}
            intent_key, experience_key, old_q = str(row[0]), str(row[1]), float(row[2])
            td_error = reward - old_q
            new_q = max(Q_FLOOR, min(Q_CEILING, old_q + alpha * td_error))
            now = time.time()
            cur.execute(
                """
                UPDATE memrl_suggestions
                SET q_value = ?, reward = ?, feedback_type = ?,
                    feedback_timestamp = ?, last_updated = ?
                WHERE suggestion_id = ?
                """,
                (new_q, reward, self._classify_reward(reward), now, now, suggestion_id),
            )
            conn.commit()
        self.update_q(intent_key, experience_key, reward, alpha)
        return {
            "ok": True,
            "suggestion_id": suggestion_id,
            "old_q": round(old_q, 4),
            "new_q": round(new_q, 4),
            "reward": reward,
            "td_error": round(td_error, 4),
            "alpha": alpha,
            "feedback_type": self._classify_reward(reward),
        }

    def suggest_best(
        self,
        query_embedding: Optional[List[float]],
        candidate_pool: List[Dict[str, Any]],
        intent_key: str = "",
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
        epsilon: float = 0.0,
    ) -> List[Dict[str, Any]]:
        if not candidate_pool:
            return []
        if epsilon > 0:
            bucket = int(hashlib.md5((str(time.time()) + intent_key).encode()).hexdigest(), 16) % 1000
            if bucket < int(epsilon * 1000):
                selected = candidate_pool[: min(top_k, len(candidate_pool))]
                for s in selected:
                    s["memrl_score"] = 0.0
                    s["q_value"] = self.get_q(intent_key, s.get("ea", s.get("name", str(id(s)))))
                return selected
        return self.two_phase_retrieve(
            intent_key=intent_key,
            candidate_pool=candidate_pool,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
        )

    def get_suggestion(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT suggestion_id, intent_key, experience_key,
                       source_tool, source_action, context_addr,
                       experience_meta, q_value, initial_q,
                       reward, feedback_type, feedback_timestamp,
                       created_at, last_updated
                FROM memrl_suggestions WHERE suggestion_id = ?
                """,
                (suggestion_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "suggestion_id": row[0],
                "intent_key": row[1],
                "experience_key": row[2],
                "source_tool": row[3],
                "source_action": row[4],
                "context_addr": row[5],
                "experience_meta": json.loads(row[6]) if row[6] else None,
                "q_value": round(float(row[7]), 4),
                "initial_q": round(float(row[8]), 4),
                "reward": row[9],
                "feedback_type": row[10],
                "feedback_timestamp": row[11],
                "created_at": row[12],
                "last_updated": row[13],
            }

    def list_suggestions(self, intent_key: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        with self._conn() as conn:
            cur = conn.cursor()
            if intent_key:
                cur.execute(
                    """
                    SELECT suggestion_id, intent_key, experience_key,
                           source_tool, source_action, context_addr,
                           q_value, feedback_type, created_at
                    FROM memrl_suggestions WHERE intent_key = ?
                    ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (intent_key, limit, offset),
                )
                rows = cur.fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM memrl_suggestions WHERE intent_key = ?",
                    (intent_key,),
                ).fetchone()[0] or 0
            else:
                cur.execute(
                    """
                    SELECT suggestion_id, intent_key, experience_key,
                           source_tool, source_action, context_addr,
                           q_value, feedback_type, created_at
                    FROM memrl_suggestions ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
                rows = cur.fetchall()
                total = conn.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
            suggestions = [
                {
                    "suggestion_id": r[0],
                    "intent_key": r[1],
                    "experience_key": r[2],
                    "source_tool": r[3],
                    "source_action": r[4],
                    "context_addr": r[5],
                    "q_value": round(float(r[6]), 4),
                    "feedback_type": r[7],
                    "created_at": r[8],
                }
                for r in rows
            ]
            return {"ok": True, "suggestions": suggestions, "total": int(total), "count": len(suggestions)}

    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            cur = conn.cursor()
            total, avg_q, max_q, min_q = cur.execute(
                "SELECT COUNT(*), AVG(q_value), MAX(q_value), MIN(q_value) FROM memrl_triplets"
            ).fetchone()
            total_visits = cur.execute("SELECT SUM(visit_count) FROM memrl_triplets").fetchone()[0] or 0
            unique_intents = cur.execute("SELECT COUNT(DISTINCT intent_key) FROM memrl_triplets").fetchone()[0] or 0
            total_suggestions = cur.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
            feedback_count = cur.execute(
                "SELECT COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL"
            ).fetchone()[0] or 0
            feedback_dist = {
                r[0]: r[1]
                for r in cur.execute(
                    "SELECT feedback_type, COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL GROUP BY feedback_type"
                ).fetchall()
            }
            top_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                }
                for r in cur.execute(
                    "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value DESC LIMIT 5"
                ).fetchall()
            ]
            bottom_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                }
                for r in cur.execute(
                    "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value ASC LIMIT 5"
                ).fetchall()
            ]
            recent_qs = [r[0] for r in cur.execute(
                "SELECT q_value FROM memrl_triplets ORDER BY last_updated DESC LIMIT 100"
            ).fetchall()]
            recent_n = len(recent_qs)
            recent_avg = sum(recent_qs) / recent_n if recent_n else 0.0
            recent_std = math.sqrt(sum((q - recent_avg) ** 2 for q in recent_qs) / recent_n) if recent_n > 1 else 0.0
            histogram = {"[-1.0, -0.5)": 0, "[-0.5, 0.0)": 0, "[0.0, 0.5)": 0, "[0.5, 1.0]": 0}
            for (qv,) in cur.execute("SELECT q_value FROM memrl_triplets").fetchall():
                if qv < -0.5:
                    histogram["[-1.0, -0.5)"] += 1
                elif qv < 0.0:
                    histogram["[-0.5, 0.0)"] += 1
                elif qv < 0.5:
                    histogram["[0.0, 0.5)"] += 1
                else:
                    histogram["[0.5, 1.0]"] += 1
            return {
                "ok": True,
                "total_triplets": int(total or 0),
                "unique_intents": int(unique_intents),
                "avg_q_value": round(float(avg_q), 4) if avg_q is not None else 0.0,
                "max_q_value": round(float(max_q), 4) if max_q is not None else 0.0,
                "min_q_value": round(float(min_q), 4) if min_q is not None else 0.0,
                "total_visits": int(total_visits),
                "total_suggestions": int(total_suggestions),
                "feedback_count": int(feedback_count),
                "feedback_rate": round(feedback_count / total_suggestions, 4) if total_suggestions else 0.0,
                "feedback_distribution": feedback_dist,
                "recent_q_avg": round(recent_avg, 4),
                "recent_q_std": round(recent_std, 4),
                "q_value_histogram": histogram,
                "top_q_memories": top_q,
                "bottom_q_memories": bottom_q,
            }

    def top_memories(self, intent_key: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            cur = conn.cursor()
            if intent_key:
                rows = cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets WHERE intent_key = ? ORDER BY q_value DESC LIMIT ?
                    """,
                    (intent_key, limit),
                ).fetchall()
            else:
                rows = cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets ORDER BY q_value DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(float(r[2]), 4),
                    "visit_count": r[3],
                    "meta": json.loads(r[4]) if r[4] else None,
                }
                for r in rows
            ]

    def clear(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM memrl_triplets")
            conn.execute("DELETE FROM memrl_suggestions")
            conn.commit()

    def prune_low_q(self, threshold: float = -0.5) -> int:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM memrl_triplets WHERE q_value < ?", (threshold,))
            pruned = cur.rowcount
            conn.commit()
            return int(pruned)

