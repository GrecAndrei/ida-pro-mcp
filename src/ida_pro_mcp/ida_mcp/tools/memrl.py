"""
MemRL: Non-Parametric Reinforcement Learning on Episodic Memory.

Deterministic Q-value learning system for ranking retrieved functions
by historical utility rather than pure similarity.  Adapts the MemRL
framework (arXiv:2601.03192) for reverse-engineering retrieval.

No LLM dependencies.  Standalone SQLite-backed Q-table.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
from typing import Dict, List, Optional, Tuple

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

# Safety fallbacks if _common import partially failed
if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore
if "idawrite" not in globals():
    idawrite = lambda f: f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore


class MemRLBank:
    """
    Episodic memory bank storing Intent-Experience-Utility triplets.

    Each entry maps a function address (or feature hash) to:
      - intent_z : embedding or feature signature of the query context
      - experience_e : the retrieved candidate (function address)
      - q_value    : learned scalar utility
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "memrl.db")
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self):
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
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_intent ON memrl_triplets(intent_key)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_experience ON memrl_triplets(experience_key)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_q_value ON memrl_triplets(q_value)
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def record(
        self,
        intent_key: str,
        experience_key: str,
        intent_z: Optional[bytes] = None,
        experience_meta: Optional[dict] = None,
        initial_q: float = 0.5,
    ) -> None:
        """Store or update a triplet in the memory bank."""
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
        alpha: float = 0.15,
    ) -> float:
        """
        Apply Monte-Carlo TD update: Q_new = Q_old + alpha * (reward - Q_old).
        Returns the new Q-value.
        """
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            )
            row = cur.fetchone()
            if row is None:
                # Auto-insert with reward as initial Q
                new_q = reward
                self.record(intent_key, experience_key, initial_q=new_q)
                return new_q

            old_q = row[0]
            new_q = old_q + alpha * (reward - old_q)
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
        alpha: float = 0.15,
    ) -> Dict[str, float]:
        """Update Q-values for multiple experiences from the same intent."""
        results: Dict[str, float] = {}
        for ek, r in zip(experience_keys, rewards):
            results[ek] = self.update_q(intent_key, ek, r, alpha)
        return results

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def two_phase_retrieve(
        self,
        intent_key: str,
        candidate_pool: List[Dict],
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
    ) -> List[Dict]:
        """
        Two-phase retrieval:
          Phase A: candidates already recalled (provided in candidate_pool)
          Phase B: re-rank by (1-λ)*normalized_similarity + λ*normalized_Q
        """
        if not candidate_pool:
            return []

        with self._conn() as conn:
            cur = conn.cursor()
            scored: List[Tuple[Dict, float, float]] = []

            sims = [c.get(similarity_key, 0.0) for c in candidate_pool]
            sim_mean = sum(sims) / len(sims) if sims else 0.0
            sim_std = math.sqrt(sum((s - sim_mean) ** 2 for s in sims) / len(sims)) if sims else 1.0
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
                q = row[0] if row else 0.5
                q_vals.append(q)

            q_mean = sum(q_vals) / len(q_vals) if q_vals else 0.0
            q_std = math.sqrt(sum((q - q_mean) ** 2 for q in q_vals) / len(q_vals)) if q_vals else 1.0
            if q_std < 1e-9:
                q_std = 1.0

            for c, sim, q in zip(candidate_pool, sims, q_vals):
                norm_sim = (sim - sim_mean) / sim_std
                norm_q = (q - q_mean) / q_std
                final_score = (1.0 - lambda_explore) * norm_sim + lambda_explore * norm_q
                scored.append((c, final_score, q))

        scored.sort(key=lambda x: x[1], reverse=True)
        results: List[Dict] = []
        for c, final_score, q in scored[:top_k]:
            merged = dict(c)
            merged["memrl_score"] = round(final_score, 4)
            merged["q_value"] = round(q, 4)
            results.append(merged)
        return results

    def get_q(self, intent_key: str, experience_key: str) -> float:
        """Get current Q-value for a triplet."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, experience_key),
            )
            row = cur.fetchone()
            return row[0] if row else 0.5

    def stats(self) -> Dict:
        """Return aggregate statistics about the memory bank."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), AVG(q_value), MAX(q_value), MIN(q_value) FROM memrl_triplets")
            total, avg_q, max_q, min_q = cur.fetchone()
            cur.execute("SELECT SUM(visit_count) FROM memrl_triplets")
            total_visits = cur.fetchone()[0] or 0
            return {
                "ok": True,
                "total_triplets": total or 0,
                "avg_q_value": round(avg_q, 4) if avg_q else 0.0,
                "max_q_value": round(max_q, 4) if max_q else 0.0,
                "min_q_value": round(min_q, 4) if min_q else 0.0,
                "total_visits": total_visits,
            }

    def top_memories(self, intent_key: Optional[str] = None, limit: int = 20) -> List[Dict]:
        """Return highest-Q memories, optionally filtered by intent."""
        with self._conn() as conn:
            cur = conn.cursor()
            if intent_key:
                cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets WHERE intent_key = ? ORDER BY q_value DESC LIMIT ?
                    """,
                    (intent_key, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                    FROM memrl_triplets ORDER BY q_value DESC LIMIT ?
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
            return [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(r[2], 4),
                    "visit_count": r[3],
                    "meta": json.loads(r[4]) if r[4] else None,
                }
                for r in rows
            ]


# ---------------------------------------------------------------------------
# MCP Tool Interface
# ---------------------------------------------------------------------------

from typing import Annotated, Literal


@tool
@idawrite
def memrl(
    action: Annotated[Literal["record", "update", "rank", "stats", "top", "get_q"], "MemRL action"] = "record",
    intent_key: Annotated[str, "Identifier for the query/analyst intent"] = "",
    experience_key: Annotated[str, "Identifier for the retrieved candidate"] = "",
    reward: Annotated[Optional[float], "Environmental feedback (+1 success, -0.5 ignored, -1 undo)"] = None,
    alpha: Annotated[float, "Learning rate for TD updates"] = 0.15,
    candidate_pool: Annotated[Optional[List[Dict]], "Candidates from Phase A for Phase B re-ranking"] = None,
    top_k: Annotated[int, "Number of results to return"] = 10,
    lambda_explore: Annotated[float, "Weight for Q-value vs similarity (0=pure similarity, 1=pure Q)"] = 0.3,
    similarity_key: Annotated[str, "Dict key to read similarity score from candidate_pool items"] = "score",
    db_path: Annotated[Optional[str], "Override path to MemRL SQLite DB"] = None,
) -> Dict:
    """
    MemRL: Non-parametric Q-value learning for retrieval ranking.

    Parameters
    ----------
    action : str
        "record"     - store a new intent-experience triplet
        "update"     - apply TD update to a specific triplet's Q-value
        "rank"       - two-phase retrieval: re-rank candidates by Q+similarity
        "stats"      - return aggregate statistics
        "top"        - return highest-Q memories
        "get_q"      - return Q-value for a single triplet
    intent_key : str
        Identifier for the query/analyst intent (e.g., function address or query hash).
    experience_key : str
        Identifier for the retrieved candidate (e.g., function address).
    reward : float
        Environmental feedback (+1 for success, -0.5 for ignored, -1 for undo).
    alpha : float
        Learning rate for TD updates (default 0.15).
    candidate_pool : list[dict]
        Candidates from Phase A (similarity recall) for Phase B re-ranking.
    top_k : int
        Number of results to return.
    lambda_explore : float
        Weight for Q-value vs similarity in ranking (0 = pure similarity, 1 = pure Q).
    similarity_key : str
        Dict key to read similarity score from candidate_pool items.
    db_path : str
        Override path to MemRL SQLite DB.
    """
    bank = MemRLBank(db_path=db_path)

    if action == "record":
        if not intent_key or not experience_key:
            return {"ok": False, "error": "intent_key and experience_key required"}
        bank.record(intent_key, experience_key)
        return {"ok": True, "action": "record"}

    elif action == "update":
        if reward is None:
            return {"ok": False, "error": "reward required for update"}
        new_q = bank.update_q(intent_key, experience_key, reward, alpha)
        return {"ok": True, "new_q": round(new_q, 4), "alpha": alpha}

    elif action == "rank":
        if candidate_pool is None:
            return {"ok": False, "error": "candidate_pool required for rank"}
        ranked = bank.two_phase_retrieve(
            intent_key=intent_key,
            candidate_pool=candidate_pool,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
        )
        return {"ok": True, "ranked": ranked, "count": len(ranked)}

    elif action == "stats":
        return bank.stats()

    elif action == "top":
        return {"ok": True, "memories": bank.top_memories(intent_key=intent_key or None, limit=top_k)}

    elif action == "get_q":
        q = bank.get_q(intent_key, experience_key)
        return {"ok": True, "q_value": round(q, 4)}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
