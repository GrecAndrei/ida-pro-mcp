"""
Context assembly layer for IDA Pro MCP.

Extracted from intelligence.py so the core embedding / classifier / memory
backends can live in a smaller dedicated module.
"""

from __future__ import annotations

import hashlib
import atexit
import json
import math
import os
import re
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .intelligence_core import (
    BgeCodeEmbedder,
    BehaviorClassifier,
    FunctionEmbeddingIndex,
    EMBED_DIM,
    INTEL_PROFILE,
    PreferenceMemoryBank,
    _extract_signature,
    emit_memrl_suggestion,
)
from .intelligence_helpers import compact_policy_blob, derive_focus_candidates, prune_policy_store
from .intelligence_context_state import ContextAssemblerStateMixin
class ContextAssembler(ContextAssemblerStateMixin):
    """
    Per-call context assembly.  Replaces cognitive_layer, cartographer_mu,
    and attention_kernel with a clean, honest pipeline:

      1. Blackboard: addr-matched past findings
      2. Embedding similarity: similar functions in this binary
      3. Zero-shot behavior classification: what does this function do?
      4. Rule-based next actions: what should the LLM do next?
      5. Stuck detection: has the LLM been spinning here?

    Produces a compact `context_pack` injected into every relevant response.
    """

    def __init__(self):
        self._embedder   = BgeCodeEmbedder()
        # Shared singleton classifier — anchors loaded once across all instances
        self._classifier = BehaviorClassifier.instance(self._embedder)
        # Per-binary embedding indexes keyed by idb_path
        self._indexes: Dict[str, FunctionEmbeddingIndex] = {}
        self._idx_lock   = threading.Lock()
        # Activity tracking for stuck detection (in-memory, per session)
        self._activity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._activity_lock = threading.Lock()
        self._related_addr_graph: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._related_addr_lock = threading.Lock()
        self._retrieval_metrics: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._retrieval_metrics_lock = threading.Lock()
        self._session_semantic_threshold: Dict[str, float] = {}
        self._semantic_threshold_lock = threading.Lock()
        self._focus_feedback: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._focus_feedback_lock = threading.Lock()
        self._pending_focus: Dict[str, Dict[str, Any]] = {}
        self._pending_focus_lock = threading.Lock()
        self._session_call_outcomes: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._session_call_outcomes_lock = threading.Lock()
        self._session_store_binding: Dict[str, str] = {}
        self._store_binding_lock = threading.Lock()
        # Cache blackboard entry embeddings by stable key to avoid repeated
        # re-embedding the same rows on every decompile call.
        self._bb_entry_vec_cache: Dict[str, Tuple[List[float], float]] = {}
        self._bb_entry_vec_cache_lock = threading.Lock()
        self._bb_entry_cache_ttl_sec = 900.0
        self._bb_entry_cache_max = 4000
        self._bb_cache_hits = 0
        self._bb_cache_misses = 0
        self._bb_cache_stats_lock = threading.Lock()
        self._last_housekeeping_ts = 0.0
        self._housekeeping_lock = threading.Lock()
        self._pending_focus_ttl_sec = 420.0
        self._related_graph_max_edges = 1200
        self._semantic_circuit_breaker_until: Dict[str, int] = {}
        self._circuit_breaker_lock = threading.Lock()
        self._session_stats_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._stats_cache_lock = threading.Lock()
        self._stats_cache_ttl_sec = 1.5
        self._source_policy_cache: Dict[str, Tuple[Tuple[int, int, int, int], Dict[str, Dict[str, Any]]]] = {}
        self._policy_cache_lock = threading.Lock()
        self._perf_buckets: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._perf_lock = threading.Lock()
        self._policy_save_due_at: Dict[str, float] = {}
        self._policy_save_inflight: set = set()
        self._policy_save_lock = threading.Lock()
        self._policy_save_debounce_sec = 0.35
        self._semantic_result_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._semantic_result_cache_lock = threading.Lock()
        self._semantic_result_cache_ttl_sec = 3.0
        self._semantic_budget_cache: Dict[str, Tuple[float, int]] = {}
        self._semantic_budget_lock = threading.Lock()


# Module-level singleton access
# ─────────────────────────────────────────────────────────────────────────────

_assembler: Optional[ContextAssembler] = None
_assembler_lock = threading.Lock()


def get_assembler() -> ContextAssembler:
    global _assembler
    with _assembler_lock:
        if _assembler is None:
            _assembler = ContextAssembler()
    return _assembler


def _shutdown_intelligence_singleton() -> None:
    global _assembler
    try:
        if _assembler is not None:
            _assembler.stop()
    except Exception:
        pass


atexit.register(_shutdown_intelligence_singleton)
