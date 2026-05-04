#!/usr/bin/env python3
"""
Adaptive Heuristics for Cartographer-μ.

Replaces hardcoded rules with online-learned parameters:
  - Adaptive scoring weights (bridge/semantic/temporal/Q)
  - Entry-type-specific temporal decay
  - Fuzzy bridge extraction for obfuscated APIs
  - Learned phase classifier
  - Rich reward signals with outcome tracking

All learning is local, deterministic, and privacy-preserving.
"""
from __future__ import annotations

import os
import json
import time
import sqlite3
import threading
import difflib
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


# =============================================================================
# Adaptive Weight Learner
# =============================================================================

class AdaptiveWeightLearner:
    """
    Online learning of scoring weights via correlation tracking.

    Instead of fixed 0.7*bridge + 0.2*semantic + 0.1*temporal,
    track which signals actually predict utility and weight them accordingly.
    """

    def __init__(self, db_path: Optional[str] = None, learning_rate: float = 0.05):
        self.lr = learning_rate
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "adaptive_weights.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._weights: Dict[str, Dict[str, float]] = {}
        self._stats: Dict[str, Dict[str, List[float]]] = {}
        self._init_db()
        self._load()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS weights (
                    context TEXT PRIMARY KEY,
                    bridge_w REAL DEFAULT 0.5,
                    semantic_w REAL DEFAULT 0.25,
                    temporal_w REAL DEFAULT 0.15,
                    q_w REAL DEFAULT 0.1,
                    samples INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    context TEXT NOT NULL,
                    bridge_score REAL,
                    semantic_score REAL,
                    temporal_score REAL,
                    q_value REAL,
                    utility REAL
                )
            """)
            conn.commit()

    def _load(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT context, bridge_w, semantic_w, temporal_w, q_w, samples FROM weights")
            for row in cur.fetchall():
                self._weights[row[0]] = {
                    "bridge": row[1], "semantic": row[2],
                    "temporal": row[3], "q": row[4],
                }

    def _save(self, context: str):
        w = self._weights.get(context, {"bridge": 0.5, "semantic": 0.25, "temporal": 0.15, "q": 0.1})
        samples = len(self._stats.get(context, {}).get("utility", []))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO weights (context, bridge_w, semantic_w, temporal_w, q_w, samples)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(context) DO UPDATE SET
                    bridge_w=excluded.bridge_w, semantic_w=excluded.semantic_w,
                    temporal_w=excluded.temporal_w, q_w=excluded.q_w,
                    samples=excluded.samples""",
                (context, w["bridge"], w["semantic"], w["temporal"], w["q"], samples),
            )
            conn.commit()

    def _context_key(self, tool: str, action: str, phase: str) -> str:
        # Coarse contexts: by tool category and phase
        tool_cat = "analysis" if tool in {"code", "data", "search", "decompile"} else \
                   "trace" if tool in {"trace", "debug", "static_trace"} else \
                   "structure" if tool in {"funcs", "segments", "types"} else "general"
        return f"{tool_cat}:{phase}"

    def get_weights(self, tool: str = "", action: str = "", phase: str = "triage") -> Dict[str, float]:
        """Get learned weights for a context. Falls back to defaults if no data."""
        ctx = self._context_key(tool, action, phase)
        with self._lock:
            if ctx in self._weights:
                w = self._weights[ctx].copy()
                # Normalize to sum to 1.0
                total = sum(w.values())
                if total > 0:
                    return {k: v / total for k, v in w.items()}
        # Default: bridge dominates, semantic secondary, temporal/Q minor
        return {"bridge": 0.65, "semantic": 0.20, "temporal": 0.10, "q": 0.05}

    def record_outcome(
        self,
        tool: str,
        action: str,
        phase: str,
        bridge_score: float,
        semantic_score: float,
        temporal_score: float,
        q_value: float,
        utility: float,
    ):
        """
        Record a scoring outcome. Utility is the observed usefulness
        (e.g., 1.0 if entry was used, 0.0 if ignored, -0.5 if harmful).
        """
        ctx = self._context_key(tool, action, phase)
        with self._lock:
            if ctx not in self._stats:
                self._stats[ctx] = {"bridge": [], "semantic": [], "temporal": [], "q": [], "utility": []}
            self._stats[ctx]["bridge"].append(bridge_score)
            self._stats[ctx]["semantic"].append(semantic_score)
            self._stats[ctx]["temporal"].append(temporal_score)
            self._stats[ctx]["q"].append(q_value)
            self._stats[ctx]["utility"].append(utility)

            # Online update: shift weights toward signals that correlate with utility
            # Simple heuristic: if a signal is high when utility is high, increase its weight
            stats = self._stats[ctx]
            if len(stats["utility"]) >= 5:
                self._update_weights(ctx)
                self._save(ctx)
                # Trim to prevent unbounded growth
                for k in stats:
                    stats[k] = stats[k][-50:]

            # Persist outcome
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT INTO outcomes (ts, context, bridge_score, semantic_score,
                    temporal_score, q_value, utility)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (time.time(), ctx, bridge_score, semantic_score, temporal_score, q_value, utility),
                )
                conn.commit()

    def _update_weights(self, ctx: str):
        """Update weights based on correlation with utility."""
        stats = self._stats[ctx]
        utilities = np.array(stats["utility"])
        if len(utilities) < 5:
            return

        w = self._weights.get(ctx, {"bridge": 0.5, "semantic": 0.25, "temporal": 0.15, "q": 0.1}).copy()

        for signal in ("bridge", "semantic", "temporal", "q"):
            scores = np.array(stats[signal])
            if np.std(scores) < 1e-6 or np.std(utilities) < 1e-6:
                continue
            # Pearson correlation
            corr = np.corrcoef(scores, utilities)[0, 1]
            if np.isnan(corr):
                continue
            # Shift weight toward signals with positive correlation
            if corr > 0.1:
                w[signal] += self.lr * corr
            elif corr < -0.1:
                w[signal] -= self.lr * abs(corr)
            w[signal] = max(0.01, min(0.95, w[signal]))

        self._weights[ctx] = w


# =============================================================================
# Fuzzy Bridge Extractor
# =============================================================================

class FuzzyBridgeExtractor:
    """
    Extract bridges with fuzzy matching for obfuscated/renamed APIs.

    Maintains a vocabulary of known API names. Uses edit distance
    and substring similarity to catch obfuscated variants like:
      VirtualAlloc → VirtAll, VrtAllc, VAlloc, etc.
    """

    # Known API vocabulary — expanded from BRIDGE_PATTERNS
    KNOWN_APIS = frozenset({
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "CreateThread",
        "RegSetValue", "RegQueryValue", "RegOpenKey", "RegCreateKey",
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
        "Socket", "Connect", "Recv", "Send", "Listen", "Accept",
        "InternetOpen", "InternetConnect", "HttpSendRequest",
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
        "BCryptEncrypt", "BCryptDecrypt",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "LoadLibrary", "GetProcAddress", "WinExec", "CreateProcess",
        "ShellExecute", "CoCreateInstance", "SetWindowsHookEx",
        "MapViewOfFile", "OpenProcess", "OpenThread",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "QueueUserAPC", "SetThreadContext", "ResumeThread",
        "HeapAlloc", "GlobalAlloc", "LocalAlloc", "malloc", "free",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "sprintf",
        "fopen", "fwrite", "fread", "fclose", "exit", "system",
        "socket", "bind", "connect", "send", "recv", "sendto", "recvfrom",
        "gethostbyname", "getaddrinfo", "SSL_new", "SSL_connect",
        "AES_encrypt", "RSA_public_encrypt", "SHA256_Init", "MD5_Init",
        "inflate", "deflate", "crc32",
    })

    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold

    def extract(self, text: str) -> List[Tuple[str, float]]:
        """Extract fuzzy API matches from text. Returns [(api_name, similarity), ...]."""
        found = []
        # Tokenize on non-alphanumeric
        tokens = [t for t in re.split(r"[^a-zA-Z0-9_]", text) if len(t) >= 4]
        for token in tokens:
            token_lower = token.lower()
            # Skip pure hex and addresses
            if re.fullmatch(r"0x[0-9a-fA-F]+", token):
                continue
            # Exact match first
            for api in self.KNOWN_APIS:
                if token_lower == api.lower():
                    found.append((api, 1.0))
                    break
            else:
                # Fuzzy match
                best_api = None
                best_score = 0.0
                for api in self.KNOWN_APIS:
                    score = self._similarity(token_lower, api.lower())
                    if score > best_score:
                        best_score = score
                        best_api = api
                if best_score >= self.threshold:
                    found.append((best_api, best_score))
        # Deduplicate, keep highest score per API
        seen = {}
        for api, score in found:
            if api not in seen or score > seen[api]:
                seen[api] = score
        return [(api, score) for api, score in seen.items()]

    def _similarity(self, a: str, b: str) -> float:
        """Substring-aware similarity with obfuscation tolerance."""
        max_len = max(len(a), len(b))
        min_len = min(len(a), len(b))
        # Quick rejection: too different in length (more lenient for short tokens)
        threshold = 0.55 if max_len < 10 else 0.45
        if abs(len(a) - len(b)) > max_len * threshold:
            return 0.0
        # Check if one is substring of the other
        if a in b or b in a:
            return 0.85
        # Longest Common Subsequence ratio (catches VrtAllc vs VirtualAlloc)
        lcs_len = self._lcs_length(a, b)
        lcs_score = lcs_len / max_len if max_len > 0 else 0.0
        # Check for common 3-char subsequences
        common_3grams = len(set(a[i:i+3] for i in range(len(a)-2)) &
                           set(b[i:i+3] for i in range(len(b)-2)))
        ngram_score = min(0.7, common_3grams / min(max_len - 2, 1) * 1.5) if common_3grams > 0 else 0.0
        # Edit distance ratio
        ratio = difflib.SequenceMatcher(None, a, b).ratio()
        return max(ratio, lcs_score * 0.9, ngram_score)

    def _lcs_length(self, a: str, b: str) -> int:
        """Longest common subsequence length."""
        m, n = len(a), len(b)
        if m == 0 or n == 0:
            return 0
        # Use rolling array for O(min(m,n)) space
        if m < n:
            a, b = b, a
            m, n = n, m
        prev = [0] * (n + 1)
        curr = [0] * (n + 1)
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i-1] == b[j-1]:
                    curr[j] = prev[j-1] + 1
                else:
                    curr[j] = max(prev[j], curr[j-1])
            prev, curr = curr, prev
            curr = [0] * (n + 1)
        return prev[n]


# =============================================================================
# Learned Phase Classifier
# =============================================================================

class LearnedPhaseClassifier:
    """
    Replace keyword-based phase inference with a simple perceptron.

    Features: tool name, action, has_addr, has_api, api_categories present,
    string count, confidence level.
    """

    PHASES = ["triage", "behavioral_analysis", "threat_analysis", "structure_recovery", "reporting"]

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "phase_classifier.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._weights: Dict[str, np.ndarray] = {}
        self._bias: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._init_db()
        self._load()
        # Fallback keyword rules for cold start
        # Use word boundaries to avoid matching JSON field names like "has_api"
        self._keyword_rules = {
            "threat_analysis": re.compile(
                r"\b(crypt|encrypt|decrypt|cipher|hash|md5|sha|aes|rsa|ssl|tls|network|socket|connect|http|c2|beacon)\b", re.I
            ),
            "behavioral_analysis": re.compile(
                r"\b(api|call|invoke|thread|process|memory|alloc|hook|inject)\b", re.I
            ),
            "structure_recovery": re.compile(
                r"\b(struct|type|enum|union|class|vtable|inherit)\b", re.I
            ),
            "reporting": re.compile(
                r"\b(report|summary|export|ioc|indicator|finding)\b", re.I
            ),
        }

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS phase_weights (
                    phase TEXT PRIMARY KEY,
                    weights BLOB NOT NULL,
                    bias REAL NOT NULL,
                    samples INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def _load(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT phase, weights, bias, samples FROM phase_weights")
            for row in cur.fetchall():
                self._weights[row[0]] = np.frombuffer(row[1], dtype=np.float32)
                self._bias[row[0]] = row[2]

    def _save(self, phase: str):
        if phase not in self._weights:
            return
        w = self._weights[phase].tobytes()
        samples = int(np.sum(np.abs(self._weights[phase]) > 0.001))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO phase_weights (phase, weights, bias, samples)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(phase) DO UPDATE SET
                    weights=excluded.weights, bias=excluded.bias, samples=excluded.samples""",
                (phase, w, self._bias[phase], samples),
            )
            conn.commit()

    def _features(self, schema: Dict[str, Any], tool: str = "", action: str = "", payload_text: str = "") -> np.ndarray:
        """Extract feature vector from schema."""
        f = np.zeros(12, dtype=np.float32)
        f[0] = 1.0 if schema.get("has_addr") else 0.0
        f[1] = 1.0 if schema.get("has_api") else 0.0
        f[2] = schema.get("confidence", 0.5)
        # Use payload text for keyword search if available, else schema text
        text = payload_text if payload_text else json.dumps(schema, default=str)
        # Avoid matching JSON field names by requiring word boundaries around keywords
        f[3] = 1.0 if self._keyword_rules["threat_analysis"].search(text) else 0.0
        f[4] = 1.0 if self._keyword_rules["behavioral_analysis"].search(text) else 0.0
        f[5] = 1.0 if self._keyword_rules["structure_recovery"].search(text) else 0.0
        f[6] = 1.0 if self._keyword_rules["reporting"].search(text) else 0.0
        f[7] = 1.0 if tool in {"code", "ctree", "decompile"} else 0.0
        f[8] = 1.0 if tool in {"data", "search", "schemaboot"} else 0.0
        f[9] = 1.0 if tool in {"trace", "debug", "static_trace"} else 0.0
        f[10] = 1.0 if tool in {"modify", "bulk", "annotation"} else 0.0
        f[11] = 1.0 if action in {"decompile", "disasm", "semantic_decompile"} else 0.0
        return f

    def predict(self, schema: Dict[str, Any], tool: str = "", action: str = "") -> str:
        """Predict phase. Falls back to keyword rules if no learned weights or low confidence."""
        f = self._features(schema, tool, action)
        scores = {}
        has_learned = False
        with self._lock:
            for phase in self.PHASES:
                if phase in self._weights:
                    has_learned = True
                    scores[phase] = float(np.dot(self._weights[phase], f)) + self._bias.get(phase, 0.0)
                else:
                    # Cold start: use keyword rule score as initial bias
                    scores[phase] = f[3] if phase == "threat_analysis" else \
                                    f[4] if phase == "behavioral_analysis" else \
                                    f[5] if phase == "structure_recovery" else \
                                    f[6] if phase == "reporting" else 0.1
        best = max(scores, key=scores.get)
        # If learned but confidence is low (margin < 0.3), apply keyword fallback
        if has_learned:
            sorted_scores = sorted(scores.values(), reverse=True)
            margin = sorted_scores[0] - sorted_scores[1] if len(sorted_scores) > 1 else 0
            if margin < 0.3 and best == "triage":
                if schema.get("has_crypto") or schema.get("has_network"):
                    best = "threat_analysis"
                elif schema.get("has_api"):
                    best = "behavioral_analysis"
        return best

    def update(self, schema: Dict[str, Any], tool: str, action: str, true_phase: str, lr: float = 0.1):
        """Online update with a labeled example."""
        f = self._features(schema, tool, action)
        with self._lock:
            pred = self.predict(schema, tool, action)
            if pred == true_phase:
                return  # Correct prediction, no update needed
            # Initialize weights if missing
            for phase in (pred, true_phase):
                if phase not in self._weights:
                    self._weights[phase] = np.zeros(12, dtype=np.float32)
                    self._bias[phase] = 0.0
            # Perceptron update: promote true phase, demote predicted
            self._weights[true_phase] += lr * f
            self._bias[true_phase] += lr * 1.0
            self._weights[pred] -= lr * f
            self._bias[pred] -= lr * 1.0
            # Clip weights
            for phase in (pred, true_phase):
                self._weights[phase] = np.clip(self._weights[phase], -5.0, 5.0)
                self._bias[phase] = np.clip(self._bias[phase], -5.0, 5.0)
            self._save(true_phase)
            self._save(pred)


# =============================================================================
# Outcome Tracker
# =============================================================================

class OutcomeTracker:
    """
    Track what happens after context injection to enable richer rewards.

    Records:
      - Phase before/after injection
      - Whether LLM asked follow-up about injected content
      - Whether same query was repeated (rework)
      - Time to next action
      - Whether analysis completed (rename/patch/annotation made)
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "outcomes.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._pending: Dict[str, Dict[str, Any]] = {}  # entry_id -> outcome dict

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    entry_id TEXT NOT NULL,
                    session_id TEXT,
                    phase_before TEXT,
                    phase_after TEXT,
                    follow_up_referenced INTEGER DEFAULT 0,
                    same_query_repeated INTEGER DEFAULT 0,
                    time_to_next_ms REAL,
                    analysis_advanced INTEGER DEFAULT 0,
                    bridges_in_next TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_outcome_entry ON outcomes(entry_id)")
            conn.commit()

    def record_injection(
        self,
        entry_id: str,
        session_id: Optional[str] = None,
        phase_before: str = "triage",
        injected_bridges: List[str] = None,
    ):
        """Call when an entry is injected."""
        self._pending[entry_id] = {
            "ts": time.time(),
            "session_id": session_id,
            "phase_before": phase_before,
            "injected_bridges": injected_bridges or [],
        }

    def record_follow_up(
        self,
        entry_id: str,
        next_tool: str,
        next_action: str,
        next_payload: Any,
        next_bridges: List[str],
        phase_after: str = "triage",
    ) -> float:
        """
        Call when next tool call happens. Returns computed reward.
        """
        if entry_id not in self._pending:
            return 0.0
        pending = self._pending.pop(entry_id)
        elapsed_ms = (time.time() - pending["ts"]) * 1000.0

        # Did follow-up reference injected bridges?
        injected = set(pending["injected_bridges"])
        next_set = set(next_bridges)
        follow_up_ref = len(injected & next_set) > 0

        # Did follow-up reference injected content specifically?
        # Check if next payload mentions entry-specific content
        content_referenced = False
        if isinstance(next_payload, dict):
            payload_text = json.dumps(next_payload, default=str).lower()
            for bridge in injected:
                if bridge.lower() in payload_text:
                    content_referenced = True
                    break

        # Phase progression?
        phase_advanced = self._phase_rank(phase_after) > self._phase_rank(pending["phase_before"])

        # Analysis advanced? (rename, patch, annotation after injection)
        analysis_advanced = next_tool in {"modify", "bulk", "annotation", "comment_mgr"}

        # Store outcome
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO outcomes (ts, entry_id, session_id, phase_before, phase_after,
                follow_up_referenced, same_query_repeated, time_to_next_ms, analysis_advanced, bridges_in_next)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pending["ts"], entry_id, pending["session_id"],
                    pending["phase_before"], phase_after,
                    int(follow_up_ref or content_referenced),
                    0,  # same_query_repeated requires tracking across multiple injections
                    elapsed_ms, int(analysis_advanced),
                    json.dumps(list(next_set)),
                ),
            )
            conn.commit()

        # Compute reward
        reward = 0.0
        if follow_up_ref or content_referenced:
            reward += 1.0  # Strong signal: LLM actually used the context
        if phase_advanced:
            reward += 0.5
        if analysis_advanced:
            reward += 0.3
        if elapsed_ms < 5000:
            reward += 0.1  # Quick follow-up suggests the context was immediately useful
        if not follow_up_ref and not content_referenced:
            reward -= 0.3  # Injected but ignored
        return reward

    def _phase_rank(self, phase: str) -> int:
        order = {"triage": 0, "behavioral_analysis": 1, "threat_analysis": 2, "structure_recovery": 3, "reporting": 4}
        return order.get(phase, 0)

    def get_entry_stats(self, entry_id: str) -> Dict[str, Any]:
        """Get aggregated outcomes for an entry."""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT COUNT(*), AVG(follow_up_referenced), AVG(analysis_advanced),
                AVG(time_to_next_ms) FROM outcomes WHERE entry_id = ?""",
                (entry_id,),
            )
            row = cur.fetchone()
            return {
                "injection_count": row[0] or 0,
                "follow_up_rate": round(row[1] or 0, 3),
                "analysis_advance_rate": round(row[2] or 0, 3),
                "avg_time_to_next_ms": round(row[3] or 0, 1),
            }


# Need re import for FuzzyBridgeExtractor
import re as _re_module
re = _re_module
