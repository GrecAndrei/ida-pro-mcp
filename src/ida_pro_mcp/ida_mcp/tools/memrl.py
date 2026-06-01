"""
MemRL: Non-Parametric Reinforcement Learning on Episodic Memory.

Deterministic Q-value learning system for ranking retrieved functions
by historical utility rather than pure similarity.  Adapts the MemRL
framework (arXiv:2601.03192) for reverse-engineering retrieval.

No LLM dependencies.  Standalone SQLite-backed Q-table.

Phase 2b enhancements:
  - Suggestion tracking with feedback loops (memrl_suggestions table)
  - TD(0) updates: Q_new = Q_old + alpha * (reward - Q_old)
  - Ingest / suggest / feedback actions for analyst workflow integration
  - Enhanced stats with convergence metrics and top/bottom Q analysis
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
import uuid
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


# ---------------------------------------------------------------------------
# Reward constants
# ---------------------------------------------------------------------------
REWARD_ACCEPT = 1.0      # Analyst accepts suggestion (no manual override)
REWARD_PARTIAL = 0.5     # Suggestion partially correct (analyst minor edit)
REWARD_NEUTRAL = 0.0     # No feedback (suggestion ignored)
REWARD_REJECT = -0.5     # Suggestion incorrect (analyst rejects or reverts)
REWARD_DANGEROUS = -1.0  # Suggestion dangerous (governance blocked it)

Q_FLOOR = -1.0
Q_CEILING = 1.0
DEFAULT_ALPHA = 0.15


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
                "CREATE INDEX IF NOT EXISTS idx_intent ON memrl_triplets(intent_key)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_experience ON memrl_triplets(experience_key)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_q_value ON memrl_triplets(q_value)"
            )

            # Suggestion tracking table for analyst feedback loops
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sug_intent ON memrl_suggestions(intent_key)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sug_created ON memrl_suggestions(created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sug_feedback ON memrl_suggestions(feedback_type)"
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
        alpha: float = DEFAULT_ALPHA,
    ) -> float:
        """
        Apply Monte-Carlo TD update: Q_new = Q_old + alpha * (reward - Q_old).
        Returns the new Q-value.
        """
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

            old_q = row[0]
            new_q = old_q + alpha * (reward - old_q)
            new_q = max(Q_FLOOR, min(Q_CEILING, new_q))
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
          Phase B: re-rank by (1-lambda)*normalized_similarity + lambda*normalized_Q
        """
        if not candidate_pool:
            return []

        with self._conn() as conn:
            cur = conn.cursor()
            scored: List[Tuple[Dict, float, float]] = []

            sims = [c.get(similarity_key, 0.0) for c in candidate_pool]
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
                q = row[0] if row else 0.5
                q_vals.append(q)

            q_mean = sum(q_vals) / n if n else 0.0
            q_std = math.sqrt(sum((q - q_mean) ** 2 for q in q_vals) / n) if n > 1 else 1.0
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

    # ==================================================================
    # Phase 2b: Suggestion Tracking with Feedback Loops
    # ==================================================================

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
        """
        Record a new suggestion from an analyst tool (rename, comment, type).

        Stores the suggestion in memrl_suggestions and the triplet in
        memrl_triplets.  Returns a suggestion_id that can be used for
        later feedback via process_feedback().

        Parameters
        ----------
        intent_key : str
            Semantic key for the query context (e.g. function address).
        experience_key : str
            The actual suggestion payload (e.g. proposed name, comment text).
        source_tool : str
            Tool that created the suggestion (e.g. 'modify', 'annotation').
        source_action : str
            Action that created the suggestion (e.g. 'rename', 'comment').
        context_addr : str
            Address context for the suggestion.
        experience_meta : dict
            Arbitrary metadata stored alongside the suggestion.
        initial_q : float
            Starting Q-value for this suggestion.
        """
        suggestion_id = uuid.uuid4().hex[:12]
        now = time.time()

        # Ensure underlying triplet exists
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
        """
        Auto-infer a reward signal when the LLM visits an address that was
        previously emitted as a MemRL suggestion.

        Called by the server's _record_activity after each successful tool
        call to close the feedback loop without requiring explicit LLM
        cooperation.  If the LLM navigated to an address we suggested, that's
        an implicit accept — reward ≈ 0.7 (not 1.0 because we can't confirm
        the suggestion was the cause rather than coincidence).

        Returns the number of suggestions updated.
        """
        cutoff = time.time() - max_age_seconds
        updated = 0
        try:
            with self._conn() as conn:
                cur = conn.cursor()
                # Look for recent pending suggestions whose context_addr matches
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
                    old_q = old_q or 0.5
                    new_q = old_q + alpha * (reward - old_q)
                    new_q = max(Q_FLOOR, min(Q_CEILING, new_q))
                    cur.execute(
                        """
                        UPDATE memrl_suggestions
                        SET q_value = ?, reward = ?, feedback_type = 'auto_accept',
                            feedback_timestamp = ?, last_updated = ?
                        WHERE suggestion_id = ?
                        """,
                        (new_q, reward, now, now, suggestion_id),
                    )
                    # Propagate to underlying triplet
                    self.update_q(intent_key, experience_key, reward, alpha)
                    updated += 1
                conn.commit()
        except Exception:
            pass
        return updated

    def _classify_reward(self, reward: float) -> str:
        """Classify reward value into a human-readable feedback type."""
        if reward >= 0.8:
            return "accept"
        elif reward >= 0.3:
            return "partial"
        elif reward >= -0.2:
            return "neutral"
        elif reward >= -0.8:
            return "reject"
        else:
            return "dangerous"

    def process_feedback(
        self,
        suggestion_id: str,
        reward: float,
        alpha: float = DEFAULT_ALPHA,
    ) -> Dict:
        """
        Apply TD(0) update for a specific tracked suggestion.

        Reward signals:
          +1.0  accept     Analyst accepts suggestion (no manual override)
          +0.5  partial    Suggestion partially correct (analyst minor edit)
           0.0  neutral    No feedback (suggestion ignored)
          -0.5  reject     Suggestion incorrect (analyst rejects or reverts)
          -1.0  dangerous  Suggestion dangerous (governance blocked it)

        TD(0) update (MemRL Eq. 4):
            Q_new = Q_old + alpha * (reward - Q_old)

        Convergence: error decays exponentially: E[Q_t] -> beta as t->inf
        """
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

            intent_key, experience_key, old_q = row[0], row[1], row[2]

            # TD(0) update: Q_new = Q_old + alpha * (reward - Q_old)
            td_error = reward - old_q
            new_q = old_q + alpha * td_error
            new_q = max(Q_FLOOR, min(Q_CEILING, new_q))

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

        # Also propagate to the underlying triplet
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
        candidate_pool: List[Dict],
        intent_key: str = "",
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
        epsilon: float = 0.0,
    ) -> List[Dict]:
        """
        Re-rank candidates by Q-value (Phase B of two-phase retrieval).

        If epsilon > 0, performs epsilon-greedy exploration: with probability
        epsilon, returns a random subset instead of the value-ranked results.

        This is the primary method for integrating MemRL into analyst workflows:
        tool outputs can be passed as candidate_pool and MemRL will re-rank
        them based on learned Q-values from past feedback.
        """
        if not candidate_pool:
            return []

        # epsilon-greedy exploration
        if epsilon > 0 and (hash(str(time.time()) + str(id(candidate_pool))) % 1000) < epsilon * 1000:
            k = min(top_k, len(candidate_pool))
            selected = candidate_pool[:k]
            for s in selected:
                s["memrl_score"] = 0.0
                s["q_value"] = self.get_q(
                    intent_key, s.get("ea", s.get("name", str(id(s))))
                )
            return selected

        return self.two_phase_retrieve(
            intent_key=intent_key,
            candidate_pool=candidate_pool,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
        )

    def get_suggestion(self, suggestion_id: str) -> Optional[Dict]:
        """Get full details of a specific suggestion."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT suggestion_id, intent_key, experience_key,
                       source_tool, source_action, context_addr,
                       experience_meta, q_value, initial_q,
                       reward, feedback_type, feedback_timestamp,
                       created_at, last_updated
                FROM memrl_suggestions WHERE suggestion_id = ?
                """,
                (suggestion_id,),
            )
            row = cur.fetchone()
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
                "q_value": round(row[7], 4),
                "initial_q": round(row[8], 4),
                "reward": row[9],
                "feedback_type": row[10],
                "feedback_timestamp": row[11],
                "created_at": row[12],
                "last_updated": row[13],
            }

    def list_suggestions(
        self,
        intent_key: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> Dict:
        """List recent suggestions, optionally filtered by intent_key."""
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
                cur.execute(
                    "SELECT COUNT(*) FROM memrl_suggestions WHERE intent_key = ?",
                    (intent_key,),
                )
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
                cur.execute("SELECT COUNT(*) FROM memrl_suggestions")
            total = cur.fetchone()[0] or 0
            rows = cur.fetchall() if intent_key else []
            if not rows and not intent_key:
                # Re-fetch after the count query above consumed the result
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

            suggestions = [
                {
                    "suggestion_id": r[0],
                    "intent_key": r[1],
                    "experience_key": r[2],
                    "source_tool": r[3],
                    "source_action": r[4],
                    "context_addr": r[5],
                    "q_value": round(r[6], 4),
                    "feedback_type": r[7],
                    "created_at": r[8],
                }
                for r in rows
            ]
            return {
                "ok": True,
                "suggestions": suggestions,
                "total": total,
                "count": len(suggestions),
            }

    # ------------------------------------------------------------------
    # Enhanced Statistics
    # ------------------------------------------------------------------

    def stats(self) -> Dict:
        """Return aggregate statistics including convergence metrics."""
        with self._conn() as conn:
            cur = conn.cursor()

            # Triplet aggregate stats
            cur.execute(
                "SELECT COUNT(*), AVG(q_value), MAX(q_value), MIN(q_value) FROM memrl_triplets"
            )
            total, avg_q, max_q, min_q = cur.fetchone()

            cur.execute("SELECT SUM(visit_count) FROM memrl_triplets")
            total_visits = cur.fetchone()[0] or 0

            cur.execute("SELECT COUNT(DISTINCT intent_key) FROM memrl_triplets")
            unique_intents = cur.fetchone()[0] or 0

            # Suggestion stats
            cur.execute("SELECT COUNT(*) FROM memrl_suggestions")
            total_suggestions = cur.fetchone()[0] or 0

            cur.execute(
                "SELECT COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL"
            )
            feedback_count = cur.fetchone()[0] or 0

            # Feedback type distribution
            cur.execute(
                "SELECT feedback_type, COUNT(*) FROM memrl_suggestions "
                "WHERE feedback_type IS NOT NULL GROUP BY feedback_type"
            )
            feedback_dist = {r[0]: r[1] for r in cur.fetchall()}

            # Top 5 highest Q
            cur.execute(
                "SELECT intent_key, experience_key, q_value, visit_count "
                "FROM memrl_triplets ORDER BY q_value DESC LIMIT 5"
            )
            top_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(r[2], 4),
                    "visit_count": r[3],
                }
                for r in cur.fetchall()
            ]

            # Bottom 5 lowest Q
            cur.execute(
                "SELECT intent_key, experience_key, q_value, visit_count "
                "FROM memrl_triplets ORDER BY q_value ASC LIMIT 5"
            )
            bottom_q = [
                {
                    "intent_key": r[0],
                    "experience_key": r[1],
                    "q_value": round(r[2], 4),
                    "visit_count": r[3],
                }
                for r in cur.fetchall()
            ]

            # Convergence metrics: mean + std of last 100 updated triplets
            cur.execute(
                "SELECT q_value FROM memrl_triplets ORDER BY last_updated DESC LIMIT 100"
            )
            recent_qs = [r[0] for r in cur.fetchall()]
            recent_n = len(recent_qs)
            recent_avg = sum(recent_qs) / recent_n if recent_n else 0.0
            recent_std = (
                math.sqrt(
                    sum((q - recent_avg) ** 2 for q in recent_qs) / recent_n
                )
                if recent_n > 1
                else 0.0
            )

            # Q-value histogram bins
            histogram = {"[-1.0, -0.5)": 0, "[-0.5, 0.0)": 0, "[0.0, 0.5)": 0, "[0.5, 1.0]": 0}
            cur.execute("SELECT q_value FROM memrl_triplets")
            for (qv,) in cur.fetchall():
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
                "total_triplets": total or 0,
                "unique_intents": unique_intents,
                "avg_q_value": round(avg_q, 4) if avg_q else 0.0,
                "max_q_value": round(max_q, 4) if max_q else 0.0,
                "min_q_value": round(min_q, 4) if min_q else 0.0,
                "total_visits": total_visits,
                "total_suggestions": total_suggestions,
                "feedback_count": feedback_count,
                "feedback_rate": (
                    round(feedback_count / total_suggestions, 4)
                    if total_suggestions > 0
                    else 0.0
                ),
                "feedback_distribution": feedback_dist,
                "recent_q_avg": round(recent_avg, 4),
                "recent_q_std": round(recent_std, 4),
                "q_value_histogram": histogram,
                "top_q_memories": top_q,
                "bottom_q_memories": bottom_q,
            }

    def top_memories(
        self, intent_key: Optional[str] = None, limit: int = 20
    ) -> List[Dict]:
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

    def clear(self) -> None:
        """Clear all memories and suggestions (reset)."""
        with self._conn() as conn:
            conn.execute("DELETE FROM memrl_triplets")
            conn.execute("DELETE FROM memrl_suggestions")
            conn.commit()

    def prune_low_q(self, threshold: float = -0.5) -> int:
        """Remove triplets below Q threshold to control memory growth."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM memrl_triplets WHERE q_value < ?", (threshold,)
            )
            pruned = cur.rowcount
            conn.commit()
            return pruned


# ======================================================================
# Helper: emit reward signal from any tool
# ======================================================================

def emit_memrl_suggestion(
    source_tool: str,
    source_action: str,
    addr: str,
    value: str,
    db_path: Optional[str] = None,
) -> str:
    """
    Emit a suggestion to MemRL from a tool action.

    Called by modify.py, annotation.py, etc. after successful actions.
    Returns the suggestion_id for later feedback.

    Parameters
    ----------
    source_tool : str
        Tool name (e.g. 'modify', 'annotation').
    source_action : str
        Action name (e.g. 'rename', 'comment', 'validate').
    addr : str
        Address the suggestion applies to.
    value : str
        The suggested value (name, comment text, etc.).
    db_path : str, optional
        Override MemRL database path.
    """
    try:
        from ida_pro_mcp.host.intelligence_core import PreferenceMemoryBank
        bank = PreferenceMemoryBank(db_path=db_path)
    except Exception:
        bank = MemRLBank(db_path=db_path)
    intent_key = f"{source_tool}:{source_action}:{addr}"
    experience_key = f"{source_tool}:{source_action}:{addr}:{value[:64]}"
    return bank.ingest_suggestion(
        intent_key=intent_key,
        experience_key=experience_key,
        source_tool=source_tool,
        source_action=source_action,
        context_addr=addr,
        experience_meta={"value": value},
        initial_q=0.5,
    )


# ======================================================================
# MCP Tool Interface
# ======================================================================

from typing import Annotated, Literal


@tool
@idawrite
def memrl(
    action: Annotated[
        Literal[
            "record",
            "update",
            "rank",
            "stats",
            "top",
            "get_q",
            "suggest",
            "feedback",
            "ingest",
            "list_suggestions",
            "get_suggestion",
        ],
        "MemRL action",
    ] = "record",
    intent_key: Annotated[
        str, "Identifier for the query/analyst intent"
    ] = "",
    experience_key: Annotated[
        str, "Identifier for the retrieved candidate"
    ] = "",
    reward: Annotated[
        Optional[float],
        "Environmental feedback (+1 success, -0.5 ignored, -1 undo)",
    ] = None,
    alpha: Annotated[float, "Learning rate for TD updates"] = DEFAULT_ALPHA,
    candidate_pool: Annotated[
        Optional[List[Dict]],
        "Candidates from Phase A for Phase B re-ranking",
    ] = None,
    top_k: Annotated[int, "Number of results to return"] = 10,
    lambda_explore: Annotated[
        float,
        "Weight for Q-value vs similarity (0=pure similarity, 1=pure Q)",
    ] = 0.3,
    similarity_key: Annotated[
        str, "Dict key to read similarity score from candidate_pool items"
    ] = "score",
    suggestion_id: Annotated[
        Optional[str], "Suggestion ID for feedback actions"
    ] = None,
    source_tool: Annotated[
        Optional[str],
        "Tool that created the suggestion (e.g. modify, annotation)",
    ] = None,
    source_action: Annotated[
        Optional[str],
        "Action that created the suggestion (e.g. rename, comment)",
    ] = None,
    context_addr: Annotated[
        Optional[str], "Address context for the suggestion"
    ] = None,
    initial_q: Annotated[
        Optional[float], "Initial Q-value for new memories"
    ] = None,
    experience_meta: Annotated[
        Optional[Dict], "Metadata for the experience"
    ] = None,
    epsilon: Annotated[
        float, "Epsilon-greedy exploration probability"
    ] = 0.0,
    query_embedding: Annotated[
        Optional[List[float]], "Query embedding for semantic search"
    ] = None,
    feedback_type: Annotated[
        Optional[str], "Feedback type: accept, reject, partial, undo, skip"
    ] = None,
    limit: Annotated[int, "Max items to return"] = 50,
    offset: Annotated[int, "Pagination offset"] = 0,
    db_path: Annotated[
        Optional[str], "Override path to MemRL SQLite DB"
    ] = None,
) -> Dict:
    """
    MemRL: Non-parametric Q-value learning for retrieval ranking.

    Stores (intent, experience, Q-value) triplets in SQLite and learns
    from analyst feedback via TD(0) updates.

    Actions
    -------
    record      Store a new intent-experience triplet.
    update      Apply TD update to a specific triplet's Q-value.
    rank        Two-phase retrieval: re-rank candidates by Q+similarity.
    stats       Return aggregate statistics with convergence metrics.
    top         Return highest-Q memories.
    get_q       Return Q-value for a single triplet.
    suggest     Re-rank candidates by Q-value (alias for rank with epsilon).
    feedback    Apply TD(0) update via suggestion_id tracking.
    ingest      Manual ingest of intent+experience with initial Q.
    list_suggestions  List tracked suggestions.
    get_suggestion    Get details of a specific suggestion.

    Reward signals for feedback:
      +1.0  accept     Analyst accepts suggestion (no manual override)
      +0.5  partial    Suggestion partially correct (analyst minor edit)
       0.0  neutral    No feedback (suggestion ignored)
      -0.5  reject     Suggestion incorrect (analyst rejects or reverts)
      -1.0  dangerous  Suggestion dangerous (governance blocked it)

    TD(0) update:
        Q_new = Q_old + alpha * (reward - Q_old)
    """
    try:
        from ida_pro_mcp.host.intelligence_core import PreferenceMemoryBank
        bank = PreferenceMemoryBank(db_path=db_path)
    except Exception:
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

    elif action == "suggest":
        if candidate_pool is None:
            return {"ok": False, "error": "candidate_pool required for suggest"}
        ranked = bank.suggest_best(
            query_embedding=query_embedding,
            candidate_pool=candidate_pool,
            intent_key=intent_key,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
            epsilon=epsilon,
        )
        return {"ok": True, "ranked": ranked, "count": len(ranked)}

    elif action == "feedback":
        if not suggestion_id:
            return {"ok": False, "error": "suggestion_id required for feedback"}
        if reward is None:
            return {"ok": False, "error": "reward required for feedback"}
        result = bank.process_feedback(suggestion_id, reward, alpha)
        return result

    elif action == "ingest":
        if not intent_key or not experience_key:
            return {
                "ok": False,
                "error": "intent_key and experience_key required for ingest",
            }
        q_init = initial_q if initial_q is not None else 0.5
        sid = bank.ingest_suggestion(
            intent_key=intent_key,
            experience_key=experience_key,
            source_tool=source_tool or "",
            source_action=source_action or "",
            context_addr=context_addr or "",
            experience_meta=experience_meta,
            initial_q=q_init,
        )
        return {"ok": True, "suggestion_id": sid, "initial_q": q_init}

    elif action == "stats":
        return bank.stats()

    elif action == "top":
        return {
            "ok": True,
            "memories": bank.top_memories(
                intent_key=intent_key or None, limit=top_k
            ),
        }

    elif action == "get_q":
        q = bank.get_q(intent_key, experience_key)
        return {"ok": True, "q_value": round(q, 4)}

    elif action == "list_suggestions":
        return bank.list_suggestions(
            intent_key=intent_key, limit=limit, offset=offset
        )

    elif action == "get_suggestion":
        if not suggestion_id:
            return {"ok": False, "error": "suggestion_id required"}
        sug = bank.get_suggestion(suggestion_id)
        if sug is None:
            return {
                "ok": False,
                "error": f"Suggestion not found: {suggestion_id}",
            }
        return {"ok": True, "suggestion": sug}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
