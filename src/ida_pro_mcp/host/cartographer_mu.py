#!/usr/bin/env python3
"""
Cartographer-μ: VOERA-Inspired Embedded Semantic Engine for MCP Context Relevance.

A 32KB-parameter, pure-Python semantic engine that replaces passive blackboard
injection with utility-driven, relevance-ranked context selection.

Components:
  - S4REncoder: Selective State Space encoder with RE-specific structural priors
  - TurboQuantLite: 4-bit PolarQuant for fast similarity
  - BridgeRAGLite: Cross-reference bridge extraction + scoring
  - MemRLUtility: Non-parametric Q-learning on blackboard entry utility
  - SchemaBootRE: Deterministic attribute induction for pre-filtering
  - ContextComposer: Pipeline orchestrator

Dependencies: numpy only. Zero external ML libraries.
Deterministic: fixed seeds, no stochastic inference.
"""

import os
import json
import time
import base64
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .adaptive_heuristics import (
    AdaptiveWeightLearner,
    FuzzyBridgeExtractor,
    LearnedPhaseClassifier,
    OutcomeTracker,
)
from .cognitive_layer import (
    NarrativeThread,
    PatternSynthesizer,
    TaskInference,
    ErrorAttribution,
    AnalystActionModel,
    CognitiveOrchestrator,
)
from .autogenic_semantics import AutogenicSemanticField

# =============================================================================
# Configuration
# =============================================================================

CARTOGRAPHER_DIM = int(os.environ.get("IDA_MCP_CARTOGRAPHER_DIM", "128"))
CARTOGRAPHER_TOPK = int(os.environ.get("IDA_MCP_CARTOGRAPHER_TOPK", "3"))
CARTOGRAPHER_ALPHA = float(os.environ.get("IDA_MCP_CARTOGRAPHER_ALPHA", "0.15"))
CARTOGRAPHER_DECAY_ADDR = float(os.environ.get("IDA_MCP_CARTOGRAPHER_DECAY_ADDR", "0.95"))
CARTOGRAPHER_DECAY_API = float(os.environ.get("IDA_MCP_CARTOGRAPHER_DECAY_API", "0.80"))
CARTOGRAPHER_DECAY_STR = float(os.environ.get("IDA_MCP_CARTOGRAPHER_DECAY_STR", "0.50"))
CARTOGRAPHER_DECAY_CF = float(os.environ.get("IDA_MCP_CARTOGRAPHER_DECAY_CF", "0.85"))
CARTOGRAPHER_DECAY_GEN = float(os.environ.get("IDA_MCP_CARTOGRAPHER_DECAY_GEN", "0.30"))

# =============================================================================
# S4REncoder: Selective State Space Encoder
# =============================================================================

class S4REncoder:
    """
    Selective State Space encoder for binary analysis context.
    128 hidden dims with RE-specific structured decay priors.
    """

    def __init__(self, state_dim: int = CARTOGRAPHER_DIM):
        self.dim = state_dim
        self.A = self._build_decay_matrix(state_dim)
        rng = np.random.RandomState(1337)
        self.B = rng.randn(state_dim, 64).astype(np.float32) * 0.01
        self.C = rng.randn(64, state_dim).astype(np.float32) * 0.01
        self.D = rng.randn(64).astype(np.float32) * 0.001

    def _build_decay_matrix(self, dim: int) -> np.ndarray:
        """Build structured decay matrix with RE-specific priors."""
        A = np.zeros((dim, dim), dtype=np.float32)
        decay_rates = {
            (0, 16): CARTOGRAPHER_DECAY_ADDR,
            (16, 32): CARTOGRAPHER_DECAY_API,
            (32, 48): CARTOGRAPHER_DECAY_STR,
            (48, 64): CARTOGRAPHER_DECAY_CF,
            (64, dim): CARTOGRAPHER_DECAY_GEN,
        }
        for (start, end), rate in decay_rates.items():
            for i in range(start, min(end, dim)):
                A[i, i] = rate
        return A

    def _tokenize_payload(self, payload: Any, tool_name: str) -> List[str]:
        """Convert payload to structure-first feature tokens without predefined patterns."""
        tokens: List[str] = [f"tool:{tool_name}"]

        def walk(obj: Any, path: str = ""):
            if isinstance(obj, dict):
                tokens.append(f"n:{path}:dict:{len(obj)}")
                for k in sorted(obj.keys(), key=lambda x: str(x)):
                    kp = f"{path}.{k}" if path else str(k)
                    tokens.append(f"k:{kp}")
                    walk(obj[k], kp)
                return
            if isinstance(obj, list):
                tokens.append(f"n:{path}:list:{len(obj)}")
                for i, v in enumerate(obj[:32]):
                    walk(v, f"{path}[{i}]")
                return
            if isinstance(obj, (int, float, bool)):
                tokens.append(f"v:{path}:num:{str(obj)[:24]}")
                return
            sval = str(obj)
            tokens.append(f"v:{path}:str:{len(sval)}")
            b = sval.encode("utf-8", errors="ignore")
            for n in (3, 4):
                if len(b) < n:
                    continue
                for i in range(min(len(b) - n + 1, 32)):
                    tokens.append(f"g{n}:{b[i:i+n].hex()}")

        walk(payload)
        return tokens[:256]

    def _embed_token(self, token: str) -> np.ndarray:
        """Deterministic token embedding via hash-based projection."""
        h = hash(token) & 0xFFFFFFFF
        rng = np.random.RandomState(h)
        emb = rng.randn(64).astype(np.float32)
        emb = emb / (np.linalg.norm(emb) + 1e-9)
        return emb

    def encode(self, payload: Any, tool_name: str = "") -> np.ndarray:
        """
        Encode a tool response payload into a 128-dim state vector.
        """
        tokens = self._tokenize_payload(payload, tool_name)
        h_t = np.zeros(self.dim, dtype=np.float32)
        for token in tokens:
            x_t = self._embed_token(token)
            # State update: h_t = A @ h_t + B @ x_t
            h_t = self.A @ h_t + self.B @ x_t
        # Output projection: y = C @ h_t + D (skip)
        # We return the hidden state itself as the embedding
        return h_t / (np.linalg.norm(h_t) + 1e-9)


# =============================================================================
# TurboQuantLite: 4-bit PolarQuant
# =============================================================================

class TurboQuantLite:
    """
    4-bit PolarQuant for fast similarity computation.
    Uses Hadamard rotation + Lloyd-Max quantization.
    """

    def __init__(self, dim: int = CARTOGRAPHER_DIM):
        self.dim = dim
        self.chunk_size = 128 if dim >= 128 else dim
        self.num_chunks = dim // self.chunk_size
        # Hadamard matrix
        self.H = self._hadamard(self.chunk_size).astype(np.float32)
        self.H = self.H / np.sqrt(self.chunk_size)
        # Random diagonal sign matrix (fixed seed)
        rng = np.random.RandomState(4242)
        self.D = rng.choice([-1.0, 1.0], size=(self.num_chunks, self.chunk_size)).astype(np.float32)
        # Lloyd-Max boundaries for 4-bit (16 levels)
        self.bins = np.array(
            [-2.0, -1.5, -1.0, -0.75, -0.5, -0.25, -0.1, 0.0,
             0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0],
            dtype=np.float32,
        )
        # Centroids
        self.centroids = np.array(
            [-2.3, -1.75, -1.25, -0.875, -0.625, -0.375, -0.175, -0.05,
             0.05, 0.175, 0.375, 0.625, 0.875, 1.25, 1.75, 2.3],
            dtype=np.float32,
        )

    def _hadamard(self, n: int) -> np.ndarray:
        """Build Walsh-Hadamard matrix of size n (power of 2)."""
        if n == 1:
            return np.array([[1.0]], dtype=np.float32)
        h = self._hadamard(n // 2)
        return np.block([[h, h], [h, -h]]).astype(np.float32)

    def encode(self, vector: np.ndarray) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Compress float32 vector to quantized indices + QJL signs.
        Returns: (q_indices, q_signs, norm)
        """
        norm = float(np.linalg.norm(vector))
        if norm < 1e-9:
            zeros = np.zeros(self.dim, dtype=np.uint8)
            return zeros, zeros.astype(np.int8), 0.0
        normalized = vector.astype(np.float32) / norm
        # PolarQuant rotation
        if self.num_chunks > 0:
            reshaped = normalized[:self.num_chunks * self.chunk_size].reshape(
                self.num_chunks, self.chunk_size
            )
            rotated = np.einsum('ij,ij,kj->ik', reshaped, self.D, self.H).flatten()
        else:
            rotated = normalized
        # Pad if needed
        if len(rotated) < self.dim:
            rotated = np.pad(rotated, (0, self.dim - len(rotated)), mode='constant')
        # 4-bit quantization
        q_indices = np.digitize(rotated, self.bins).astype(np.uint8)
        q_indices = np.clip(q_indices, 0, 15)
        dequantized = self.centroids[q_indices]
        # QJL 1-bit residual
        residual = rotated - dequantized
        q_signs = np.where(residual >= 0, 1, -1).astype(np.int8)
        return q_indices, q_signs, norm

    def similarity(
        self,
        q_idx1: np.ndarray,
        q_signs1: np.ndarray,
        norm1: float,
        q_idx2: np.ndarray,
        q_signs2: np.ndarray,
        norm2: float,
    ) -> float:
        """
        Compute approximate inner product similarity.
        Uses bin-matching + QJL correction.
        """
        if norm1 < 1e-9 or norm2 < 1e-9:
            return 0.0
        # Bin match score (Jaccard-like)
        bin_match = np.mean(q_idx1 == q_idx2)
        # QJL correction
        sign_match = np.where(q_signs1 == q_signs2, 1, -1)
        correction = np.mean(sign_match) * 0.02
        return float(np.clip((bin_match + correction) * norm1 * norm2, 0.0, 1.0))


# =============================================================================
# BridgeRAGLite: Cross-Reference Bridge Scoring
# =============================================================================

class BridgeRAGLite:
    """
    Extract cross-reference bridge entities (addr, API, func_name)
    and score relevance via bridge overlap.
    
    Uses fuzzy matching for obfuscated APIs and adaptive weights
    learned from historical outcomes.
    """

    def __init__(self, quantizer: TurboQuantLite):
        self.quantizer = quantizer
        self.fuzzy = FuzzyBridgeExtractor(threshold=0.65)
        self.weight_learner = AdaptiveWeightLearner()

    def extract_bridges(self, payload: Any, tool_name: str = "") -> List[str]:
        """Extract latent bridge entities from structure, not predefined signatures."""
        tokens: List[str] = []

        def walk(obj: Any, path: str = ""):
            if isinstance(obj, dict):
                tokens.append(f"n:{path}:d:{len(obj)}")
                for k in sorted(obj.keys(), key=lambda x: str(x)):
                    kp = f"{path}.{k}" if path else str(k)
                    tokens.append(f"k:{kp}")
                    walk(obj[k], kp)
                return
            if isinstance(obj, list):
                tokens.append(f"n:{path}:l:{len(obj)}")
                for i, v in enumerate(obj[:24]):
                    walk(v, f"{path}[{i}]")
                return
            sval = str(obj)
            tokens.append(f"v:{path}:{len(sval)}")
            b = sval.encode("utf-8", errors="ignore")
            for n in (3, 5):
                if len(b) < n:
                    continue
                for i in range(min(len(b) - n + 1, 20)):
                    tokens.append(f"g{n}:{b[i:i+n].hex()}")

        walk({"tool": tool_name, "payload": payload})
        # lightweight recurrence filter
        counts: Dict[str, int] = {}
        for t in tokens:
            counts[t] = counts.get(t, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (kv[1], len(kv[0])), reverse=True)
        return [f"b_{abs(hash(t)) & 0xffffffff:08x}" for t, _ in ranked[:20]]

    def score_relevance(
        self,
        query_bridges: List[str],
        query_vector: np.ndarray,
        query_quantized: Tuple[np.ndarray, np.ndarray, float],
        entry: Dict[str, Any],
        call_age: int = 0,
        tool: str = "",
        action: str = "",
        phase: str = "triage",
    ) -> Tuple[float, Dict[str, float]]:
        """
        Score relevance of a blackboard entry to current query.
        Uses ADAPTIVE weights learned from historical outcomes.
        Returns (score, signal_breakdown).
        """
        # Parse entry bridges
        entry_bridges = entry.get("bridges", [])
        if isinstance(entry_bridges, str):
            try:
                entry_bridges = json.loads(entry_bridges)
            except Exception:
                entry_bridges = []
        if not isinstance(entry_bridges, list):
            entry_bridges = []

        q_set = set(query_bridges)
        e_set = set(entry_bridges)

        # EXACT ADDRESS MATCH: still hardcoded as the strongest signal
        query_addrs = {b for b in q_set if b.startswith("0x")}
        entry_addrs = {b for b in e_set if b.startswith("0x")}
        shared_addrs = query_addrs & entry_addrs
        if shared_addrs:
            shared_non_addrs = (q_set - query_addrs) & (e_set - entry_addrs)
            exact_bonus = 1.0 if shared_non_addrs else 0.85
            temporal = np.exp(-call_age / 20.0)
            score = exact_bonus * (0.7 + 0.3 * temporal)
            return score, {"exact_addr": exact_bonus, "temporal": temporal}

        # Bridge overlap score (Jaccard) — with fuzzy match support
        if q_set and e_set:
            # Count exact matches
            exact_matches = len(q_set & e_set)
            # Count fuzzy matches (marked with ~)
            fuzzy_matches = 0
            for qb in q_set:
                if qb.startswith("~"):
                    base = qb[1:]
                    for eb in e_set:
                        if base.lower() in eb.lower() or eb.lower() in base.lower():
                            fuzzy_matches += 0.5
            bridge_score = (exact_matches + fuzzy_matches) / max(len(q_set), len(e_set))
        else:
            bridge_score = 0.0

        # Semantic similarity
        semantic_score = 0.0
        if bridge_score < 0.01:
            entry_quantized = entry.get("quantized")
            entry_q_signs = entry.get("q_signs")
            entry_norm = entry.get("norm", 0.0)
            if (
                entry_quantized is not None
                and entry_q_signs is not None
                and entry_norm > 0
            ):
                try:
                    if isinstance(entry_quantized, str):
                        entry_quantized = np.frombuffer(
                            bytes.fromhex(entry_quantized), dtype=np.uint8
                        )
                    if isinstance(entry_q_signs, str):
                        entry_q_signs = np.frombuffer(
                            bytes.fromhex(entry_q_signs), dtype=np.int8
                        )
                    semantic_score = self.quantizer.similarity(
                        query_quantized[0],
                        query_quantized[1],
                        query_quantized[2],
                        entry_quantized,
                        entry_q_signs,
                        entry_norm,
                    )
                except Exception:
                    pass

        # Adaptive temporal decay: per-category learned rate
        category = str(entry.get("category", "finding"))
        decay_rates = {
            "finding": 10.0, "vuln": 12.0, "behavior": 8.0,
            "crypto": 14.0, "network": 14.0, "general": 6.0,
        }
        decay = decay_rates.get(category, 8.0)
        if bridge_score < 0.01:
            decay = decay / 2.5  # Orphans decay faster
        temporal_decay = np.exp(-call_age / decay)

        # ADAPTIVE weights: learned from outcomes
        w = self.weight_learner.get_weights(tool, action, phase)
        score = (
            w["bridge"] * bridge_score
            + w["semantic"] * semantic_score
            + w["temporal"] * temporal_decay
        )
        breakdown = {
            "bridge": bridge_score,
            "semantic": semantic_score,
            "temporal": temporal_decay,
            "weights": w,
        }
        return score, breakdown


# =============================================================================
# MemRLUtility: Non-Parametric Q-Learning
# =============================================================================

class MemRLUtility:
    """
    Learn which blackboard entries are actually useful by observing LLM behavior.

    BRIDGE-KEYED Q-LEARNING:
    - Q-values are stored per bridge (address, API name) not per entry_id.
    - When an entry about 0x140001000 is useful, ALL future entries about
      0x140001000 inherit that Q-value.
    - This makes learning transfer across sessions and binaries.
    """

    def __init__(
        self,
        alpha: float = CARTOGRAPHER_ALPHA,
        db_path: Optional[str] = None,
    ):
        self.alpha = alpha
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "cartographer_mu_q.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()
        self._bridge_q: Dict[str, float] = {}   # bridge -> Q
        self._entry_q: Dict[str, float] = {}    # entry_id -> Q (legacy)
        self._load_cache()
        self.outcome_tracker = OutcomeTracker()
        self._injected_history: Dict[str, Dict[str, Any]] = {}  # entry_id -> {ts, bridges, phase}

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            # Legacy entry-level table (kept for migration)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_q (
                    entry_id TEXT PRIMARY KEY,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    access_count INTEGER NOT NULL DEFAULT 0,
                    last_updated REAL NOT NULL
                )
                """
            )
            # NEW: bridge-keyed Q table — survives across sessions
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memrl_bridge_q (
                    bridge TEXT PRIMARY KEY,
                    q_value REAL NOT NULL DEFAULT 0.5,
                    access_count INTEGER NOT NULL DEFAULT 0,
                    last_updated REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _load_cache(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            # Load bridge Q-values
            cur.execute("SELECT bridge, q_value FROM memrl_bridge_q")
            self._bridge_q = {row[0]: row[1] for row in cur.fetchall()}
            # Load legacy entry Q-values (for backward compat)
            cur.execute("SELECT entry_id, q_value FROM memrl_q")
            self._entry_q = {row[0]: row[1] for row in cur.fetchall()}

    def _normalize_bridge(self, bridge: str) -> str:
        """Normalize bridge for consistent keying."""
        # Strip fuzzy-match prefix
        if bridge.startswith("~"):
            bridge = bridge[1:]
        # Lowercase addresses and APIs for consistent matching
        if bridge.startswith("0x"):
            return bridge.lower()
        return bridge

    def _save_bridge_q(self, bridge: str, q_value: float):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO memrl_bridge_q (bridge, q_value, access_count, last_updated)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(bridge) DO UPDATE SET
                    q_value = excluded.q_value,
                    access_count = access_count + 1,
                    last_updated = excluded.last_updated
                """,
                (bridge, q_value, time.time()),
            )
            conn.commit()

    def _save_entry_q(self, entry_id: str, q_value: float):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO memrl_q (entry_id, q_value, access_count, last_updated)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(entry_id) DO UPDATE SET
                    q_value = excluded.q_value,
                    access_count = access_count + 1,
                    last_updated = excluded.last_updated
                """,
                (entry_id, q_value, time.time()),
            )
            conn.commit()

    def get_q(self, entry_or_bridges) -> float:
        """
        Get Q-value. If given a list of bridges, compute from bridge Q-values.
        If given an entry_id string, fallback to legacy entry Q.
        """
        with self._lock:
            if isinstance(entry_or_bridges, str):
                # Legacy: entry_id
                return self._entry_q.get(entry_or_bridges, 0.5)
            if isinstance(entry_or_bridges, (list, tuple)):
                # Bridge-keyed: average Q across bridges
                if not entry_or_bridges:
                    return 0.5
                q_vals = []
                for b in entry_or_bridges:
                    norm = self._normalize_bridge(str(b))
                    q_vals.append(self._bridge_q.get(norm, 0.5))
                if not q_vals:
                    return 0.5
                # Use max instead of mean to avoid dilution from weak bridges
                return float(max(q_vals))
            return 0.5

    def update_q(self, entry_id: str, reward: float, bridges: Optional[List[str]] = None):
        """
        TD update. Updates Q for both the entry AND each bridge,
        so future entries about the same address/API inherit the learning.
        """
        with self._lock:
            # Update legacy entry Q
            old_q = self._entry_q.get(entry_id, 0.5)
            new_q = old_q + self.alpha * (reward - old_q)
            new_q = max(0.0, min(1.0, new_q))
            self._entry_q[entry_id] = new_q
            self._save_entry_q(entry_id, new_q)

            # Update bridge Q-values (the magic: survives across sessions)
            if bridges:
                for b in bridges:
                    norm = self._normalize_bridge(str(b))
                    old_bq = self._bridge_q.get(norm, 0.5)
                    new_bq = old_bq + self.alpha * (reward - old_bq)
                    new_bq = max(0.0, min(1.0, new_bq))
                    self._bridge_q[norm] = new_bq
                    self._save_bridge_q(norm, new_bq)

    def observe_usage(
        self,
        entry_id: str,
        was_injected: bool,
        next_bridges: List[str],
        entry_bridges: List[str],
        next_tool: str = "",
        next_action: str = "",
        next_payload: Any = None,
        phase_after: str = "triage",
    ):
        """
        Infer utility from LLM behavior and update Q-value.
        Uses OutcomeTracker for richer, multi-signal rewards.
        """
        # Base reward from bridge overlap (legacy signal)
        base_reward = 0.0
        if was_injected:
            if set(next_bridges) & set(entry_bridges):
                base_reward = 1.0
            else:
                base_reward = -0.3
        else:
            if set(next_bridges) & set(entry_bridges):
                base_reward = 0.5

        # Rich reward from outcome tracking
        rich_reward = base_reward
        if was_injected and entry_id in self._injected_history:
            rich_reward = self.outcome_tracker.record_follow_up(
                entry_id=entry_id,
                next_tool=next_tool,
                next_action=next_action,
                next_payload=next_payload,
                next_bridges=next_bridges,
                phase_after=phase_after,
            )
            reward = 0.6 * rich_reward + 0.4 * base_reward
        else:
            reward = base_reward

        # Update with bridge propagation
        self.update_q(entry_id, reward, bridges=entry_bridges)

    def record_injection(
        self,
        entry_id: str,
        session_id: Optional[str] = None,
        phase_before: str = "triage",
        bridges: List[str] = None,
    ):
        """Record that an entry was injected so we can track outcomes."""
        self._injected_history[entry_id] = {
            "ts": time.time(),
            "session_id": session_id,
            "phase": phase_before,
            "bridges": bridges or [],
        }
        self.outcome_tracker.record_injection(
            entry_id=entry_id,
            session_id=session_id,
            phase_before=phase_before,
            injected_bridges=bridges or [],
        )
        # Prune old history
        cutoff = time.time() - 3600
        to_remove = [eid for eid, info in self._injected_history.items() if info["ts"] < cutoff]
        for eid in to_remove:
            del self._injected_history[eid]

    def rank_entries(self, entries: List[Dict[str, Any]]) -> List[Tuple[float, str]]:
        """Re-rank entries by Q-value (bridge-keyed)."""
        scored = []
        for entry in entries:
            eid = entry.get("id", "") if isinstance(entry, dict) else str(entry)
            bridges = entry.get("bridges", []) if isinstance(entry, dict) else []
            q = self.get_q(bridges) if bridges else self.get_q(eid)
            scored.append((q, eid))
        scored.sort(reverse=True, key=lambda x: x[0])
        return scored

    def get_bridge_stats(self, bridge: str) -> Dict[str, Any]:
        """Get Q and access count for a specific bridge."""
        norm = self._normalize_bridge(bridge)
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT q_value, access_count, last_updated FROM memrl_bridge_q WHERE bridge = ?",
                (norm,),
            )
            row = cur.fetchone()
            if row:
                return {
                    "bridge": norm,
                    "q_value": round(row[0], 3),
                    "access_count": row[1],
                    "last_updated": row[2],
                }
            return {"bridge": norm, "q_value": 0.5, "access_count": 0}

    def prune_low_q(self, threshold: float = 0.2) -> int:
        """Remove entries and bridges with Q below threshold."""
        with self._lock:
            to_remove = [eid for eid, q in self._entry_q.items() if q < threshold]
            for eid in to_remove:
                del self._entry_q[eid]
            bridges_remove = [b for b, q in self._bridge_q.items() if q < threshold]
            for b in bridges_remove:
                del self._bridge_q[b]
            with sqlite3.connect(self.db_path) as conn:
                for eid in to_remove:
                    conn.execute("DELETE FROM memrl_q WHERE entry_id = ?", (eid,))
                for b in bridges_remove:
                    conn.execute("DELETE FROM memrl_bridge_q WHERE bridge = ?", (b,))
                conn.commit()
            return len(to_remove) + len(bridges_remove)


# =============================================================================
# SchemaBootRE: Deterministic Attribute Induction
# =============================================================================

class SchemaBootRE:
    """
    Extract RE-specific attributes from tool payloads
    for structured pre-filtering.

    Uses learned phase classifier instead of hardcoded keyword rules.
    """

    def __init__(self):
        self.phase_classifier = LearnedPhaseClassifier()

    def induce_schema(self, payload: Any, tool_name: str = "") -> Dict[str, Any]:
        """Extract structure-driven schema from a tool response."""
        text = json.dumps(payload, ensure_ascii=False, default=str)
        action = ""
        confidence = 0.5
        if isinstance(payload, dict):
            action = str(payload.get("action", ""))
            confidence = float(payload.get("confidence", 0.5))

        # Zero-prior structural features
        nesting = 0
        list_nodes = 0
        dict_nodes = 0
        scalar_nodes = 0

        def walk(obj: Any, depth: int = 0):
            nonlocal nesting, list_nodes, dict_nodes, scalar_nodes
            nesting = max(nesting, depth)
            if isinstance(obj, dict):
                dict_nodes += 1
                for v in obj.values():
                    walk(v, depth + 1)
            elif isinstance(obj, list):
                list_nodes += 1
                for v in obj[:64]:
                    walk(v, depth + 1)
            else:
                scalar_nodes += 1

        walk(payload)
        text_len = len(text)
        digit_ratio = (sum(ch.isdigit() for ch in text) / max(text_len, 1))

        schema = {
            "tool": tool_name,
            "action": action,
            "has_addr": digit_ratio > 0.15,
            "has_api": dict_nodes > 0 and scalar_nodes > 4,
            "has_crypto": text_len > 256 and nesting >= 3,
            "has_network": list_nodes > 0 and scalar_nodes > 6,
            "confidence": confidence,
            "phase_hint": "triage",
        }

        # Phase inference: learned classifier with keyword fallback for cold start
        predicted = self.phase_classifier.predict(schema, tool_name, action)
        # If classifier has no training data (returns default triage) but we have
        # strong keyword signals, use keyword rules as fallback
        has_learned = any(p in self.phase_classifier._weights for p in self.phase_classifier.PHASES)
        if not has_learned and predicted == "triage":
            if schema["has_crypto"] or schema["has_network"]:
                predicted = "threat_analysis"
            elif schema["has_api"]:
                predicted = "behavioral_analysis"
        schema["phase_hint"] = predicted

        return schema

    def pre_filter(
        self,
        entries: List[Dict[str, Any]],
        query_schema: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Filter blackboard entries by schema compatibility.
        """
        filtered = []
        for entry in entries:
            entry_schema = entry.get("schema", {})
            if isinstance(entry_schema, str):
                try:
                    entry_schema = json.loads(entry_schema)
                except Exception:
                    entry_schema = {}
            if not isinstance(entry_schema, dict):
                entry_schema = {}

            # Phase match
            if entry_schema.get("phase_hint") == query_schema.get("phase_hint"):
                filtered.append(entry)
                continue

            # Address bridge compatibility
            if query_schema.get("has_addr") and entry_schema.get("has_addr"):
                filtered.append(entry)
                continue

            # High confidence entries always pass
            if entry_schema.get("confidence", 0) > 0.8 or entry.get("confidence", 0) > 0.8:
                filtered.append(entry)
                continue

            # API compatibility
            if query_schema.get("has_api") and entry_schema.get("has_api"):
                filtered.append(entry)
                continue

        return filtered


# =============================================================================
# ContextComposer: Pipeline Orchestrator
# =============================================================================

class ContextComposer:
    """
    Orchestrate the full relevance pipeline and format output for LLM consumption.

    Now integrates CognitiveOrchestrator for structural/narrative intelligence
    that goes beyond mathematical scoring.
    """

    def __init__(
        self,
        encoder: S4REncoder,
        quantizer: TurboQuantLite,
        bridgerag: BridgeRAGLite,
        memrl: MemRLUtility,
        schemaboot: SchemaBootRE,
        topk: int = CARTOGRAPHER_TOPK,
    ):
        self.encoder = encoder
        self.quantizer = quantizer
        self.bridgerag = bridgerag
        self.memrl = memrl
        self.schemaboot = schemaboot
        self.topk = topk
        self._call_counter = 0
        self.cognitive = CognitiveOrchestrator()
        self.autogenic = AutogenicSemanticField()

    def compose(
        self,
        current_tool: str,
        current_action: str,
        payload: Any,
        blackboard_entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run the full pipeline and return compact working memory.
        """
        self._call_counter += 1

        # 1. SCHEMABOOT: Extract attributes
        query_schema = self.schemaboot.induce_schema(payload, current_tool)
        query_bridges = self.autogenic.induce(payload, current_tool, current_action)

        # 2. ENCODE: Compress to state vector
        query_vector = self.encoder.encode(payload, current_tool)
        query_quantized = self.quantizer.encode(query_vector)

        # 3. PRE-FILTER: Structured filtering
        candidates = self.schemaboot.pre_filter(blackboard_entries, query_schema)
        for entry in candidates:
            entry_bridges = entry.get("bridges", [])
            if isinstance(entry_bridges, str):
                try:
                    entry_bridges = json.loads(entry_bridges)
                except Exception:
                    entry_bridges = []
            if not entry_bridges:
                # zero-prior latent symbol induction for older entries
                synthesized = {
                    "id": entry.get("id", ""),
                    "title": entry.get("title", ""),
                    "content": entry.get("content", ""),
                    "addr": entry.get("addr", ""),
                    "category": entry.get("category", ""),
                }
                entry["bridges"] = self.autogenic.induce(synthesized, "blackboard", "entry")

        # 4. BRIDGERAG: Score relevance with ADAPTIVE weights
        scored = []
        for entry in candidates:
            entry_call_idx = entry.get("call_idx", 0)
            call_age = max(0, self._call_counter - entry_call_idx)
            score, breakdown = self.bridgerag.score_relevance(
                query_bridges,
                query_vector,
                query_quantized,
                entry,
                call_age=call_age,
                tool=current_tool,
                action=current_action,
                phase=query_schema.get("phase_hint", "triage"),
            )
            scored.append((score, breakdown, entry))

        # 5. MEMRL: Combine relevance + Q-value for final ranking
        # Uses ADAPTIVE weights learned from historical outcomes
        # BRIDGE-KEYED: Q-values come from entry bridges, not entry_id
        phase = query_schema.get("phase_hint", "triage")
        w = self.bridgerag.weight_learner.get_weights(current_tool, current_action, phase)
        ranked = []
        for score, breakdown, entry in scored:
            eid = entry.get("id", "")
            entry_bridges = entry.get("bridges", [])
            if isinstance(entry_bridges, str):
                try:
                    entry_bridges = json.loads(entry_bridges)
                except Exception:
                    entry_bridges = []
            # Bridge-keyed Q: inherits from ALL previous sessions
            q = self.memrl.get_q(entry_bridges) if entry_bridges else self.memrl.get_q(eid)
            # Adaptive combination: learned weights + Q-value
            utility = (
                w["bridge"] * breakdown.get("bridge", 0)
                + w["semantic"] * breakdown.get("semantic", 0)
                + w["temporal"] * breakdown.get("temporal", 0)
                + w["q"] * q
            )
            ranked.append((utility, score, q, entry, breakdown))
        ranked.sort(reverse=True, key=lambda x: x[0])

        # 6. SELECT: Take top-k
        top_entries = []
        for utility, score, q, entry, breakdown in ranked[:self.topk]:
            entry_copy = dict(entry)
            entry_copy["relevance_score"] = round(score, 2)
            entry_copy["q_value"] = round(q, 2)
            entry_copy["adaptive_weights"] = breakdown.get("weights", {})
            top_entries.append(entry_copy)
            # Record injection for outcome tracking
            self.memrl.record_injection(
                entry_id=entry.get("id", ""),
                phase_before=query_schema.get("phase_hint", "triage"),
                bridges=entry.get("bridges", []),
            )
            # Reinforce utility for induced symbols
            self.autogenic.update_symbol_utility(entry.get("bridges", []), q)

        # 7. COGNITIVE ENRICHMENT: Structural/narrative intelligence
        # This is where the magic happens — non-mathematical reasoning about
        # patterns, tasks, gaps, errors, voids, shadows, surprises, and hierarchy.
        cognitive_context = self.cognitive.enrich_context(
            current_tool=current_tool,
            current_action=current_action,
            payload=payload,
            working_memory=top_entries,
            blackboard_entries=blackboard_entries,
            query_bridges=query_bridges,
        )

        # Apply error attribution: if a bridge has caused hallucinations before,
        # downgrade entries that feature it and boost alternatives
        error_bridges = set()
        for entry in top_entries:
            bridges = entry.get("bridges", [])
            if isinstance(bridges, str):
                try:
                    bridges = json.loads(bridges)
                except Exception:
                    bridges = []
            for b in bridges:
                stats = self.memrl.get_bridge_stats(b)
                if stats["q_value"] < 0.2 and stats["access_count"] > 3:
                    # This bridge has been penalized repeatedly — likely misleading
                    error_bridges.add(b)

        if error_bridges:
            # Find alternatives that don't have error bridges
            alternatives = []
            for utility, score, q, entry, breakdown in ranked[self.topk:self.topk+3]:
                entry_bridges = entry.get("bridges", [])
                if isinstance(entry_bridges, str):
                    try:
                        entry_bridges = json.loads(entry_bridges)
                    except Exception:
                        entry_bridges = []
                if not error_bridges & set(entry_bridges):
                    alternatives.append(entry)
            if alternatives:
                cognitive_context["error_recovery"] = {
                    "message": f"Avoided {len(error_bridges)} error-prone bridges; suggested {len(alternatives)} alternatives",
                    "avoided": list(error_bridges),
                    "alternatives": [{"id": a.get("id"), "title": a.get("title")} for a in alternatives[:2]],
                }

        # 8. DENSITY OPTIMIZE: Compact to 1-line summaries
        compact_entries = []
        for e in top_entries:
            compact = {
                "id": e.get("id", ""),
                "title": str(e.get("title", ""))[:80],
                "addr": str(e.get("addr", ""))[:32],
                "category": str(e.get("category", "finding")),
                "relevance": e.get("relevance_score", 0.0),
                "utility": e.get("q_value", 0.5),
            }
            if compact["addr"] == "None":
                compact["addr"] = ""
            compact_entries.append(compact)

        avg_utility = (
            round(np.mean([e["utility"] for e in compact_entries]), 2)
            if compact_entries
            else 0.0
        )

        return {
            "working_memory": compact_entries,
            "memory_stats": {
                "total_considered": len(blackboard_entries),
                "pre_filtered": len(candidates),
                "injected": len(compact_entries),
                "avg_utility": avg_utility,
                "adaptive_weights": w,
            },
            "analysis_phase": query_schema.get("phase_hint", "triage"),
            "bridges_detected": query_bridges[:5],
            "cognitive": {
                "synthesized_patterns": cognitive_context.get("synthesized_patterns", []),
                "narrative_gaps": cognitive_context.get("narrative_gaps", []),
                "inferred_task": cognitive_context.get("inferred_task", {}),
                "error_recovery": cognitive_context.get("error_recovery", {}),
                "voids": cognitive_context.get("voids", []),
                "shadow_warnings": cognitive_context.get("shadow_warnings", []),
                "surprising_findings": cognitive_context.get("surprising_findings", []),
                "temporal_patterns": cognitive_context.get("temporal_patterns", []),
                "multi_resolution": cognitive_context.get("multi_resolution", {}),
            },
        }


# =============================================================================
# CartographerMu: Unified Interface
# =============================================================================

class CartographerMu:
    """
    Unified interface for the Cartographer-μ semantic engine.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.encoder = S4REncoder()
        self.quantizer = TurboQuantLite()
        self.bridgerag = BridgeRAGLite(self.quantizer)
        self.memrl = MemRLUtility(db_path=db_path)
        self.schemaboot = SchemaBootRE()
        self.composer = ContextComposer(
            self.encoder,
            self.quantizer,
            self.bridgerag,
            self.memrl,
            self.schemaboot,
        )

    def encode_payload(self, payload: Any, tool_name: str = "") -> np.ndarray:
        """Encode a tool payload to a state vector."""
        return self.encoder.encode(payload, tool_name)

    def quantize(self, vector: np.ndarray) -> Tuple[np.ndarray, np.ndarray, float]:
        """Quantize a state vector."""
        return self.quantizer.encode(vector)

    def extract_bridges(self, payload: Any, tool_name: str = "") -> List[str]:
        """Extract bridge entities from a payload."""
        return self.bridgerag.extract_bridges(payload, tool_name)

    def induce_schema(self, payload: Any, tool_name: str = "") -> Dict[str, Any]:
        """Induce structured schema from a payload."""
        return self.schemaboot.induce_schema(payload, tool_name)

    def inject_context(
        self,
        current_tool: str,
        current_action: str,
        payload: Any,
        blackboard_entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Main entrypoint: run full pipeline and return compact working memory.
        """
        return self.composer.compose(
            current_tool, current_action, payload, blackboard_entries
        )

    def observe_usage(
        self,
        entry_id: str,
        was_injected: bool,
        next_bridges: List[str],
        entry_bridges: List[str],
        next_tool: str = "",
        next_action: str = "",
        next_payload: Any = None,
        phase_after: str = "triage",
    ):
        """Observe LLM behavior and update Q-values."""
        self.memrl.observe_usage(
            entry_id, was_injected, next_bridges, entry_bridges,
            next_tool=next_tool, next_action=next_action,
            next_payload=next_payload, phase_after=phase_after,
        )

    def get_q(self, entry_id: str) -> float:
        """Get current Q-value for an entry."""
        return self.memrl.get_q(entry_id)

    def update_q(self, entry_id: str, reward: float):
        """Manually update Q-value for an entry."""
        self.memrl.update_q(entry_id, reward)

    def prune_low_q(self, threshold: float = 0.2) -> int:
        """Prune entries with low Q-values."""
        return self.memrl.prune_low_q(threshold)
