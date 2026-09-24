"""
Context assembly layer for IDA Pro MCP.

Extracted from the historical intelligence layer. The production path keeps
context assembly deterministic and uses only bounded typed-question advisories.
"""

from __future__ import annotations

import atexit
import contextlib
import copy
import hashlib
import json
import re
import threading
import time
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from . import helpers as _helpers
from .core import (
    BehaviorClassifier,
    BgeCodeEmbedder,
    FunctionEmbeddingIndex,
    _extract_signature,
)
from .embeddings import _file_mtime_ns
from .lexical import LexicalFunctionIndex, signature_index_path

_DECOMPILER_LITERAL_RE = re.compile(r'(?s)(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')
_DECOMPILER_COMMENT_RE = re.compile(r"(?s)/\*.*?\*/|//[^\r\n]*")
_CALL_EXPRESSION_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONDITION_OPERATOR_RE = re.compile(
    r"==|!=|<=|>=|&&|\|\||(?<![<])<(?![<])|(?<![-<>])>(?![>])|&|\||\^|!"
)
_NUMERIC_LITERAL_RE = re.compile(r"0[xX][0-9A-Fa-f]+|\b\d+(?:\.\d+)?\b")
_SAFE_FEATURE_LABEL_RE = re.compile(r"[A-Za-z0-9_.$:+/()-]{1,96}")
_CONTROL_CALLS = frozenset({"if", "for", "while", "switch", "sizeof", "alignof", "catch"})
_CONDITION_OPERATOR_LABELS = {
    "==": "equal",
    "!=": "not_equal",
    "<=": "less_equal",
    ">=": "greater_equal",
    "<": "less_than",
    ">": "greater_than",
    "&&": "and",
    "||": "or",
    "&": "bit_and",
    "|": "bit_or",
    "^": "bit_xor",
    "!": "not",
}


def _intel_profile_enabled() -> bool:
    """Look up the canonical symbol at call time so tests/runtime can toggle
    the profile flag by mutating the module attribute on intelligence_core."""
    from . import core as intelligence_core

    return bool(intelligence_core.INTEL_PROFILE)


def _compact_function_signature(
    body: Any,
    prototype: Any = "",
    function_name: Any = "",
) -> str:
    """Describe a decompiled function without forwarding its source text.

    The signature retains useful symbol/API names, call sites, and coarse
    control-flow shape. Literal values and comments are removed before any
    text-derived feature is collected; arguments, statements, and expressions
    stay local to IDA.
    """
    source = str(body or "")
    source = _DECOMPILER_LITERAL_RE.sub(" ", source)
    source = _DECOMPILER_COMMENT_RE.sub(" ", source)
    prototype_text = _DECOMPILER_LITERAL_RE.sub(" ", str(prototype or ""))
    prototype_text = _DECOMPILER_COMMENT_RE.sub(" ", prototype_text)
    if not source.strip() and not prototype_text.strip():
        return ""

    function_symbol = str(function_name or "").strip().casefold()
    call_names: list[str] = []
    seen_calls: set[str] = set()
    call_expressions = [
        name
        for name in _CALL_EXPRESSION_RE.findall(source)
        if name.lower() not in _CONTROL_CALLS and name.casefold() != function_symbol
    ]
    for name in call_expressions:
        if name in seen_calls:
            continue
        seen_calls.add(name)
        call_names.append(name[:96])
        if len(call_names) >= 48:
            break

    identifier_terms = _extract_signature(source, max_idents=256)
    prototype_terms = _extract_signature(prototype_text, max_idents=48)
    conditionals = len(re.findall(r"\b(?:if|switch|case)\b|\?", source))
    loops = len(re.findall(r"\b(?:for|while|do)\b", source))
    comparisons = len(re.findall(r"==|!=|<=|>=|(?<![<])<(?!<)|(?<![>])>(?!>)", source))
    member_accesses = len(re.findall(r"->|(?<!\.)\.(?!\.)", source))
    indexed_accesses = len(re.findall(r"\[[^]\r\n]{0,80}\]", source))
    shape = (
        f"calls={len(call_expressions)}, conditionals={conditionals}, loops={loops}, "
        f"comparisons={comparisons}, member_accesses={member_accesses}, "
        f"indexed_accesses={indexed_accesses}"
    )

    fields = [f"shape: {shape}"]
    if prototype_terms:
        fields.append(f"prototype terms: {prototype_terms}")
    if call_names:
        fields.append(f"call symbols: {' '.join(call_names)}")
    if identifier_terms:
        fields.append(f"identifier terms: {identifier_terms}")
    return "; ".join(fields)[:8_192]


def _safe_feature_labels(values: Any, *, limit: int = 24) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    labels: list[str] = []
    for value in values[: max(0, int(limit))]:
        if not isinstance(value, str):
            continue
        label = value.strip().split(" — ", 1)[0]
        if _SAFE_FEATURE_LABEL_RE.fullmatch(label) and label not in labels:
            labels.append(label)
    return labels


def _function_evidence_features(record: Mapping[str, Any]) -> dict[str, Any]:
    """Project deterministic decompiler output into compact safe evidence."""
    features: dict[str, Any] = {}
    for source_key, target_key in (
        ("api_calls", "api_calls"),
        ("crypto_hints", "crypto_hints"),
        ("behavior_tags", "ida_behavior_tags"),
    ):
        labels = _safe_feature_labels(record.get(source_key))
        if labels:
            features[target_key] = labels

    patterns: list[str] = []
    raw_patterns = record.get("dangerous_patterns")
    if not isinstance(raw_patterns, (list, tuple)):
        raw_patterns = []
    for item in raw_patterns[:24]:
        if isinstance(item, Mapping):
            label = item.get("pattern")
        elif isinstance(item, str):
            label = item.split(" — ", 1)[0]
        else:
            continue
        if isinstance(label, str):
            safe = _safe_feature_labels([label], limit=1)
            if safe and safe[0] not in patterns:
                patterns.append(safe[0])
    if patterns:
        features["risk_patterns"] = patterns

    for source_key, target_key in (("callers", "caller_symbols"), ("callees", "callee_symbols")):
        neighbors = record.get(source_key)
        if not isinstance(neighbors, list):
            continue
        compact_neighbors: list[dict[str, str]] = []
        for item in neighbors[:16]:
            if not isinstance(item, Mapping):
                continue
            address = item.get("addr") or item.get("address")
            name = item.get("name")
            compact: dict[str, str] = {}
            if isinstance(address, str) and re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{1,16}", address.strip()):
                compact["address"] = address.strip()[:18]
            safe_name = _safe_feature_labels([name], limit=1) if isinstance(name, str) else []
            if safe_name:
                compact["name"] = safe_name[0]
            if compact:
                compact_neighbors.append(compact)
        if compact_neighbors:
            features[target_key] = compact_neighbors

    complexity = record.get("complexity")
    if isinstance(complexity, Mapping):
        compact_complexity = {
            key: value
            for key in ("lines", "calls", "branches", "loops", "xor_ops", "switch_cases")
            if isinstance((value := complexity.get(key)), int)
            and not isinstance(value, bool)
            and 0 <= value <= 1_000_000
        }
        if compact_complexity:
            features["complexity"] = compact_complexity

    raw_structure = record.get("structure")
    if isinstance(raw_structure, Mapping):
        compact_structure: dict[str, Any] = {}
        cfg = raw_structure.get("cfg")
        if isinstance(cfg, Mapping):
            for source_key, target_key in (
                ("nodes", "blocks"),
                ("edges", "edges"),
                ("entry_blocks", "entry_blocks"),
                ("exit_blocks", "exit_blocks"),
                ("back_edges", "back_edges"),
                ("cyclomatic_complexity", "cyclomatic_complexity"),
            ):
                value = cfg.get(source_key)
                if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000:
                    compact_structure[target_key] = value
        call_targets = _safe_feature_labels(raw_structure.get("call_targets"))
        if call_targets:
            compact_structure["call_targets"] = call_targets
        points = raw_structure.get("control_points")
        if isinstance(points, list):
            control_flow: list[dict[str, Any]] = []
            for point in points[:8]:
                if not isinstance(point, Mapping):
                    continue
                kind_values = _safe_feature_labels([point.get("kind")], limit=1)
                if not kind_values:
                    continue
                condition = str(point.get("condition") or "")
                condition = _DECOMPILER_LITERAL_RE.sub(" ", condition)
                condition = _DECOMPILER_COMMENT_RE.sub(" ", condition)
                control = {"kind": kind_values[0]}
                variables = _extract_signature(condition, max_idents=12).split()
                if variables:
                    control["variables"] = variables
                operators = [
                    _CONDITION_OPERATOR_LABELS[token]
                    for token in _CONDITION_OPERATOR_RE.findall(condition)
                ]
                if operators:
                    control["operators"] = operators[:8]
                if _NUMERIC_LITERAL_RE.search(condition):
                    control["has_constant"] = True
                control_flow.append(control)
            if control_flow:
                compact_structure["control_flow"] = control_flow
            kinds = _safe_feature_labels(
                [item.get("kind") for item in control_flow],
                limit=8,
            )
            if kinds:
                compact_structure["control_kinds"] = kinds
        dataflow = raw_structure.get("dataflow")
        if isinstance(dataflow, Mapping):
            arguments = _safe_feature_labels(dataflow.get("argument_variables"), limit=16)
            if arguments:
                compact_structure["argument_names"] = arguments
        if compact_structure:
            features["structure"] = compact_structure
    return features


def _decompile_neighborhood_candidates(
    payload: Mapping[str, Any],
    pseudocode: str,
    focus_address: str,
    focus_name: str,
) -> list[dict[str, Any]]:
    """Extract compact local signatures for a focus function and its chain.

    Decompiler text remains host-local. Only symbol/API names, coarse
    structural counts, and the observed caller/callee relation are returned
    for a typed provider request.
    """
    records = payload.get("results")
    roots = records if isinstance(records, list) else [payload]
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(
        address: Any,
        name: Any,
        body: Any,
        relationship: str,
        prototype: Any = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        signature = _compact_function_signature(body, prototype, name)
        if not signature:
            return
        addr_text = str(address or "")[:64]
        name_text = str(name or "")[:256]
        identity = addr_text or f"{relationship}:{name_text}:{signature[:64]}"
        if identity in seen:
            return
        seen.add(identity)
        candidate = {
            "address": addr_text,
            "name": name_text,
            "relationship": relationship,
            "signature": signature,
        }
        if isinstance(metadata, Mapping):
            candidate.update(_function_evidence_features(metadata))
        candidates.append(candidate)

    for root_index, root in enumerate(roots):
        if not isinstance(root, Mapping):
            continue
        root_addr = root.get("addr") or (focus_address if root_index == 0 else "")
        root_name = root.get("name") or (focus_name if root_index == 0 else "")
        body = root.get("pseudocode") or root.get("code")
        if root_index == 0 and not body:
            body = pseudocode
        add(
            root_addr,
            root_name,
            body,
            "focus" if root_index == 0 else "batch_member",
            root.get("prototype"),
            root,
        )

        related_groups = [
            (relationship, root.get(field))
            for field, relationship in (
                ("callers_context", "caller"),
                ("callees_context", "callee"),
            )
        ]
        max_related = max(
            (len(items) for _relationship, items in related_groups if isinstance(items, list)),
            default=0,
        )
        for related_index in range(max_related):
            for relationship, related in related_groups:
                if not isinstance(related, list) or related_index >= len(related):
                    continue
                item = related[related_index]
                if not isinstance(item, Mapping):
                    continue
                add(
                    item.get("addr") or item.get("address"),
                    item.get("name"),
                    item.get("signature") or item.get("pseudocode_head"),
                    relationship,
                    metadata=item,
                )
    return candidates


def _recommended_ida_call(evidence_kind: Any, address: Any) -> dict[str, Any] | None:
    """Map a typed evidence choice to one provider-neutral public operation."""
    target = str(address or "").strip()[:64]
    if not target:
        return None
    operations: dict[str, tuple[str, dict[str, Any]]] = {
        "inspect_callers": ("ida_callers", {"address": target}),
        "inspect_callees": ("ida_callees", {"address": target}),
        "inspect_xrefs": ("ida_xrefs_to", {"address": target}),
        "inspect_control_flow": (
            "ida_decompile",
            {"address": target, "details": True},
        ),
        "inspect_strings": ("ida_list_strings", {"limit": 50}),
    }
    selected = operations.get(str(evidence_kind or ""))
    if selected is None:
        return None
    tool, arguments = selected
    return {"tool": tool, "arguments": arguments}


class ContextAssembler:
    """
    Per-call context assembly.  Replaces cognitive_layer, cartographer_mu,
    and attention_kernel with a clean, honest pipeline:

      1. Blackboard: addr-matched past findings
      2. Lexical signature retrieval: similar functions in this binary
      3. Provider advisory classification: what behavior is suggested?
      4. Rule-based next actions for the calling agent
      5. Stuck detection: has the agent been spinning here?

    Produces a compact `context_pack` injected into every relevant response.
    """

    def __init__(self):
        self._embedder = BgeCodeEmbedder()
        # Shared singleton classifier — anchors loaded once across all instances
        self._classifier = BehaviorClassifier.instance(self._embedder)
        # Per-binary signature indexes keyed by idb_path
        self._indexes: dict[str, FunctionEmbeddingIndex] = {}
        self._idx_lock = threading.Lock()
        # Bounded LRU for _indexes so long-running sessions cannot pin an
        # unbounded number of signature indexes (and their in-memory caches)
        # in RAM.
        self._max_indexes = 4
        self._idx_last_access: dict[str, float] = {}
        # Activity tracking for stuck detection (in-memory, per session)
        self._activity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._activity_lock = threading.Lock()
        # Last-seen wall-clock per session, used to prune stale per-session
        # state (activity, related graphs, retrieval metrics) so long-running
        # servers do not accumulate unbounded per-session memory.
        self._session_last_seen: dict[str, float] = {}
        self._session_last_seen_lock = threading.Lock()
        self._related_addr_graph: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._related_addr_lock = threading.Lock()
        self._retrieval_metrics: dict[str, dict[str, int]] = defaultdict(dict)
        self._retrieval_metrics_lock = threading.Lock()
        self._session_semantic_threshold: dict[str, float] = {}
        self._semantic_threshold_lock = threading.Lock()
        self._last_housekeeping_ts = 0.0
        self._housekeeping_lock = threading.Lock()
        self._related_graph_max_edges = 1200
        self._semantic_circuit_breaker_until: dict[str, int] = {}
        self._circuit_breaker_lock = threading.Lock()
        self._session_stats_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._stats_cache_lock = threading.Lock()
        self._stats_cache_ttl_sec = 1.5
        self._perf_buckets: dict[str, dict[str, float]] = defaultdict(dict)
        self._perf_lock = threading.Lock()
        self._semantic_budget_cache: dict[str, tuple[float, int]] = {}
        self._semantic_budget_lock = threading.Lock()
        # Decompile enrichment is on the request path and can touch many
        # functions in quick succession.  Keep its best-effort SQLite writes
        # bounded just like FunctionEmbeddingIndex.index_async; otherwise a
        # burst of uncached decompiles creates one daemon thread per function.
        self._persist_gate = threading.Semaphore(4)

    # ── helpers ─────────────────────────────────────────────────────────

    def _behavior_classifier(self) -> BehaviorClassifier:
        """Return the shared classifier, re-binding it if the embedder changed.

        Test doubles can inject a classifier without an `_embedder` attribute;
        those are left untouched so unit tests can isolate the enrichment path.
        """
        classifier = getattr(self, "_classifier", None)
        if classifier is None:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
            return classifier
        classifier_embedder = getattr(classifier, "_embedder", None)
        if classifier_embedder is not None and classifier_embedder is not self._embedder:
            classifier = BehaviorClassifier.instance(self._embedder)
            self._classifier = classifier
        return classifier

    def _get_index(self, idb_path: str) -> FunctionEmbeddingIndex:
        with self._idx_lock:
            now = time.time()
            self._idx_last_access[idb_path] = now
            if idb_path not in self._indexes:
                db = signature_index_path(idb_path)
                if getattr(self._embedder, "_provider_only", False):
                    self._indexes[idb_path] = LexicalFunctionIndex(db)
                else:
                    # Explicit compatibility/test facades may still provide a
                    # vector index; production provider mode never reaches it.
                    self._indexes[idb_path] = FunctionEmbeddingIndex(db, self._embedder)
            index = self._indexes[idb_path]
            if len(self._indexes) > self._max_indexes:
                # Evict least-recently-used indexes, keeping the current one.
                candidates = sorted(
                    (p for p in self._indexes if p != idb_path),
                    key=lambda p: self._idx_last_access.get(p, 0.0),
                )
                for evict in candidates[: (len(self._indexes) - self._max_indexes)]:
                    self._indexes.pop(evict, None)
                    self._idx_last_access.pop(evict, None)
        # Return the object captured while holding the lock. Another request
        # may evict this path immediately after unlock; indexing/searching
        # against the still-valid object is safe, while a second dictionary
        # lookup here could spuriously raise KeyError.
        return index

    def _schedule_embedding_persist(
        self,
        idx: FunctionEmbeddingIndex,
        ea: str,
        name: str,
        vec: list[float],
        pseudo_hash: str,
        signature_text: str,
        signature_hash: str,
        document_text: str | None = None,
    ) -> bool:
        """Persist a request-time vector without retaining source text.

        ``document_text`` remains an ignored compatibility argument for older
        injected vector facades. Provider mode never persists decompilation or
        other raw document content, even when a test/extension supplies a
        vector-compatible object.

        The vector is already in the in-memory cache, so dropping a saturated
        persistence attempt is safe: a later request can retry it. This is
        deliberately separate from ``index_async`` because re-embedding here
        would duplicate the expensive model call that just produced ``vec``.
        """
        del document_text
        gate = getattr(self, "_persist_gate", None)
        if gate is None:
            # Some focused tests construct this class with ``__new__``.
            gate = threading.Semaphore(4)
            self._persist_gate = gate
        if not gate.acquire(blocking=False):
            return False

        def _persist() -> None:
            try:
                with idx._conn() as conn:
                    # Never clobber a higher-quality stored embedding: this
                    # path has no structural metadata, so an upsert must not
                    # erase rows written by index_many.
                    row = conn.execute("SELECT index_quality FROM func_embeddings WHERE ea=?", (ea,)).fetchone()
                    if row and str(row[0] or "unknown") in ("full", "fast", "fast_fallback"):
                        return
                    conn.execute(
                        """
                        INSERT INTO func_embeddings
                           (ea, name, dim, vec_blob, pseudo_hash, indexed_at,
                            signature_text, signature_hash, document_text)
                        VALUES(?,?,?,?,?,?,?,?,NULL)
                        ON CONFLICT(ea) DO UPDATE SET
                            name=excluded.name, vec_blob=excluded.vec_blob,
                            pseudo_hash=excluded.pseudo_hash,
                            indexed_at=excluded.indexed_at,
                            signature_text=excluded.signature_text,
                            signature_hash=excluded.signature_hash,
                            document_text=excluded.document_text
                        """,
                        (
                            ea,
                            name,
                            len(vec),
                            idx._pack(vec),
                            pseudo_hash,
                            time.time(),
                            signature_text,
                            signature_hash,
                        ),
                    )
                    conn.commit()
                # This writer already updated the index's on-disk state; avoid
                # making the next similarity query perform a full O(N) reload
                # just because of our own commit. Do this after closing the
                # connection because SQLite may update the database/WAL during
                # close. A later external writer changes the mtime again and
                # remains observable through db_changed_since_load().
                with contextlib.suppress(OSError):
                    idx._db_mtime_ns = _file_mtime_ns(idx._db_path)
            except Exception:
                # Request-time enrichment must never fail the primary IDA
                # operation because an optional cache write was unavailable.
                pass
            finally:
                gate.release()

        try:
            threading.Thread(target=_persist, daemon=True).start()
        except Exception:
            gate.release()
            return False
        return True

    # ── blackboard retrieval ──────────────────────────────────────────────

    def _get_bb_entries(self, addr: str, bb_store) -> list[dict[str, Any]]:
        """Fetch blackboard entries relevant to this address."""
        if bb_store is None or not addr:
            return []
        try:
            entries = bb_store.list(addr=addr, limit=5, include_resolved=False)
            return entries or []
        except Exception:
            return []

    def _merge_related_findings(
        self,
        pack: dict[str, Any],
        entries: list[dict[str, Any]],
        source: str,
        session_id: str = "",
    ) -> None:
        """
        Merge findings into pack['related_findings'] with deterministic ranking.

        Ranking priority:
          1) evidence source: address_linked > relation_linked > api_linked > semantic_linked
          2) confidence
          3) updated_at recency
        """
        if not entries:
            return
        min_conf = 0.0
        max_take = 8
        weight = 1.0
        filtered_entries = [e for e in entries if float(e.get("confidence") or 0.0) >= min_conf]
        if max_take > 0:
            filtered_entries = sorted(
                filtered_entries,
                key=lambda e: (
                    float(e.get("priority") or 0.5),
                    float(e.get("confidence") or 0.0),
                    float(e.get("updated_at") or 0.0),
                ),
                reverse=True,
            )[:max_take]
        if not filtered_entries:
            return
        src_rank = {
            "address_linked": 4,
            "relation_linked": 3,
            "api_linked": 2,
            "semantic_linked": 1,
        }
        merged: dict[str, dict[str, Any]] = {}
        for existing in pack.get("related_findings", []):
            e = dict(existing)
            e.setdefault("retrieval_source", "address_linked")
            merged[str(e.get("id") or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest())] = e
        for entry in filtered_entries:
            e = dict(entry)
            e["retrieval_source"] = source
            e["retrieval_weight"] = round(weight, 3)
            key = str(e.get("id") or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest())
            prev = merged.get(key)
            if prev is None:
                merged[key] = e
                continue
            prev_rank = src_rank.get(str(prev.get("retrieval_source") or "semantic_linked"), 0)
            new_rank = src_rank.get(source, 0)
            if new_rank > prev_rank:
                merged[key] = e
                continue
            if new_rank == prev_rank and float(e.get("confidence") or 0.0) > float(prev.get("confidence") or 0.0):
                merged[key] = e

        ranked = sorted(
            merged.values(),
            key=lambda x: (
                src_rank.get(str(x.get("retrieval_source") or "semantic_linked"), 0),
                float(x.get("retrieval_weight") or 1.0),
                float(x.get("priority") or 0.5),
                float(x.get("confidence") or 0.0),
                float(x.get("updated_at") or 0.0),
            ),
            reverse=True,
        )
        pack["related_findings"] = ranked[:8]
        if session_id:
            try:
                with self._retrieval_metrics_lock:
                    metrics = self._retrieval_metrics[session_id]
                    key_total = f"{source}.total"
                    key_accepted = f"{source}.accepted"
                    key_kept = f"{source}.kept"
                    metrics[key_total] = int(metrics.get(key_total, 0)) + len(entries)
                    metrics[key_accepted] = int(metrics.get(key_accepted, 0)) + len(filtered_entries)
                    kept = sum(1 for e in filtered_entries if any((r.get("id") and r.get("id") == e.get("id")) for r in pack.get("related_findings", [])))
                    metrics[key_kept] = int(metrics.get(key_kept, 0)) + kept
                self._invalidate_session_caches(session_id)
            except Exception:
                pass

    def _invalidate_session_caches(self, session_id: str) -> None:
        if not session_id:
            return
        with self._stats_cache_lock:
            self._session_stats_cache.pop(session_id, None)

    def _perf_start(self) -> float:
        return time.perf_counter()

    def _perf_end(self, session_id: str, bucket: str, t0: float) -> None:
        if not _intel_profile_enabled() or not session_id:
            return
        dt_ms = (time.perf_counter() - t0) * 1000.0
        with self._perf_lock:
            b = self._perf_buckets[session_id]
            b[f"{bucket}.count"] = float(b.get(f"{bucket}.count", 0.0) + 1.0)
            b[f"{bucket}.sum_ms"] = float(b.get(f"{bucket}.sum_ms", 0.0) + dt_ms)
            b[f"{bucket}.max_ms"] = max(float(b.get(f"{bucket}.max_ms", 0.0)), dt_ms)

    def _session_retrieval_stats(self, session_id: str) -> dict[str, Any]:
        if not session_id:
            return {}
        try:
            now = time.time()
            with self._stats_cache_lock:
                cached = self._session_stats_cache.get(session_id)
                if cached and (now - cached[0] <= self._stats_cache_ttl_sec):
                    # Deep copy so callers cannot corrupt the cached snapshot
                    # by mutating a returned bucket dict.
                    return copy.deepcopy(cached[1])
            with self._retrieval_metrics_lock:
                metrics = dict(self._retrieval_metrics.get(session_id, {}))
            if not metrics:
                return {}
            out: dict[str, Any] = {}
            sources = ["address_linked", "relation_linked", "api_linked", "semantic_linked"]
            for src in sources:
                total = int(metrics.get(f"{src}.total", 0))
                accepted = int(metrics.get(f"{src}.accepted", 0))
                kept = int(metrics.get(f"{src}.kept", 0))
                if total <= 0:
                    continue
                out[src] = {
                    "total": total,
                    "accepted": accepted,
                    "kept": kept,
                    "accept_rate": round(accepted / max(1, total), 3),
                    "hit_rate": round(kept / max(1, total), 3),
                }
            out["semantic_threshold"] = self._get_semantic_threshold(session_id)
            with self._stats_cache_lock:
                self._session_stats_cache[session_id] = (now, copy.deepcopy(out))
            return out
        except Exception:
            return {}

    def _run_housekeeping(self, session_id: str) -> None:
        """Periodic cleanup for relation graph bounds."""
        now = time.time()
        if now - self._last_housekeeping_ts < 30.0:
            return
        if not self._housekeeping_lock.acquire(blocking=False):
            return
        try:
            self._last_housekeeping_ts = now
            # Bound relation graph size per session.
            if session_id:
                with self._related_addr_lock:
                    graph = self._related_addr_graph.get(session_id)
                    if graph:
                        total_edges = sum(len(v) for v in graph.values())
                        if total_edges > self._related_graph_max_edges:
                            # Drop smallest-degree nodes first.
                            nodes = sorted(graph.items(), key=lambda kv: len(kv[1]))
                            drop_budget = total_edges - self._related_graph_max_edges
                            for node, nbrs in nodes:
                                if drop_budget <= 0:
                                    break
                                drop_budget -= len(nbrs)
                                graph.pop(node, None)
                # Drop per-session state for sessions idle longer than
                # 10 minutes so long-running servers do not accumulate
                # unbounded per-session memory.  Snapshot under the lock:
                # record_call updates last_seen under the same lock, so the
                # iteration cannot race a concurrent insert.
                stale_cutoff = now - 600.0
                with self._session_last_seen_lock:
                    stale_sessions = [sid for sid, last in self._session_last_seen.items() if last < stale_cutoff]
                for sid in stale_sessions:
                    # Re-check under the lock (TOCTOU guard): the session may
                    # have resumed activity between the snapshot and teardown.
                    with self._session_last_seen_lock:
                        if self._session_last_seen.get(sid, 0.0) >= stale_cutoff:
                            continue
                        self._session_last_seen.pop(sid, None)
                    self._drop_session_state(sid)
        except Exception:
            pass
        finally:
            self._housekeeping_lock.release()

    def _drop_session_state(self, session_id: str) -> None:
        """Release all in-memory per-session state for ``session_id``.

        The last-seen ledger is handled by the caller (housekeeping and
        drop_session manage it under ``_session_last_seen_lock``) so a caller
        already holding that lock does not re-acquire it.
        """
        if not session_id:
            return
        with self._activity_lock:
            self._activity.pop(session_id, None)
        with self._related_addr_lock:
            self._related_addr_graph.pop(session_id, None)
        with self._retrieval_metrics_lock:
            self._retrieval_metrics.pop(session_id, None)
        with self._semantic_threshold_lock:
            self._session_semantic_threshold.pop(session_id, None)
        with self._circuit_breaker_lock:
            self._semantic_circuit_breaker_until.pop(session_id, None)
        with self._semantic_budget_lock:
            self._semantic_budget_cache.pop(session_id, None)
        with self._perf_lock:
            self._perf_buckets.pop(session_id, None)
        with self._stats_cache_lock:
            self._session_stats_cache.pop(session_id, None)

    def drop_session(self, session_id: str) -> None:
        """Teardown hook for a closed/abandoned session.

        Removes the session's in-memory intelligence state (activity log,
        related-address graph, retrieval metrics, adaptive semantic threshold,
        circuit breaker, caches) so it neither leaks past the session's death
        nor contaminates a reused session id.  Invoke from the session
        close/abandon handlers; housekeeping prunes long-idle sessions on the
        same path.
        """
        self._drop_session_state(session_id)
        with self._session_last_seen_lock:
            self._session_last_seen.pop(session_id, None)

    def _semantic_circuit_open(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._circuit_breaker_lock:
            return int(self._semantic_circuit_breaker_until.get(session_id, 0)) > int(time.time())

    @staticmethod
    def _quantile(vals: list[float], q: float, default: float = 0.0) -> float:
        """Deterministic quantile helper with sane fallback."""
        try:
            return _helpers.quantile(vals, q, default)
        except Exception:
            return float(default)

    def _semantic_quality_profile(self, session_id: str) -> dict[str, float]:
        """
        Build adaptive semantic-quality profile from session telemetry.
        Avoids fixed cutoffs by deriving baselines from observed distributions.
        """
        stats = self._session_retrieval_stats(session_id) if session_id else {}
        rates: list[float] = []
        totals: list[int] = []
        for src in ("address_linked", "relation_linked", "api_linked", "semantic_linked"):
            bucket = stats.get(src) if isinstance(stats, dict) else None
            if not isinstance(bucket, dict):
                continue
            if "hit_rate" in bucket:
                rates.append(float(bucket.get("hit_rate") or 0.0))
            if "total" in bucket:
                totals.append(int(bucket.get("total") or 0))
        q25 = self._quantile(rates, 0.25, default=0.35)
        q50 = self._quantile(rates, 0.50, default=0.5)
        q75 = self._quantile(rates, 0.75, default=0.65)
        total_sum = sum(max(0, int(x)) for x in totals)
        total_med = self._quantile([float(x) for x in totals if x > 0], 0.50, default=6.0)
        min_total = max(4, int(round(min(total_med, max(6.0, total_sum / 4.0)))))
        # Read perf data directly from _perf_buckets
        perf_avgs = []
        if _intel_profile_enabled() and session_id:
            with self._perf_lock:
                b = dict(self._perf_buckets.get(session_id, {}))
            for k in ("assemble", "decompile_enrich", "search_enrich"):
                cnt = float(b.get(f"{k}.count", 0.0))
                sm = float(b.get(f"{k}.sum_ms", 0.0))
                if cnt > 0:
                    perf_avgs.append(sm / cnt)
        perf_q25 = self._quantile(perf_avgs, 0.25, default=20.0)
        perf_q50 = self._quantile(perf_avgs, 0.50, default=45.0)
        perf_q75 = self._quantile(perf_avgs, 0.75, default=75.0)
        return {
            "hit_q25": q25,
            "hit_q50": q50,
            "hit_q75": q75,
            "perf_q25": perf_q25,
            "perf_q50": perf_q50,
            "perf_q75": perf_q75,
            "min_total": float(min_total),
        }

    def _adaptive_semantic_budget(self, session_id: str, default_max: int = 24) -> int:
        """Dynamically tune semantic candidate budget using quality/perf signals."""
        if not session_id:
            return default_max
        now = time.time()
        with self._semantic_budget_lock:
            cached = self._semantic_budget_cache.get(session_id)
            if cached and (now - cached[0] <= 2.0):
                return int(cached[1])
        budget = int(default_max)
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            hit = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            hit_iqr = max(0.05, profile["hit_q75"] - profile["hit_q25"])
            hit_center = profile["hit_q50"]
            hit_shift = (hit - hit_center) / hit_iqr
            budget += int(round(hit_shift * 4.0))

            # Read perf data directly from _perf_buckets
            avg_ms = 0.0
            if _intel_profile_enabled() and session_id:
                with self._perf_lock:
                    b = dict(self._perf_buckets.get(session_id, {}))
                cnt = float(b.get("decompile_enrich.count", 0.0))
                sm = float(b.get("decompile_enrich.sum_ms", 0.0))
                if cnt > 0:
                    avg_ms = sm / cnt
            if avg_ms > 0.0:
                perf_iqr = max(5.0, profile["perf_q75"] - profile["perf_q25"])
                perf_shift = (avg_ms - profile["perf_q50"]) / perf_iqr
                budget -= int(round(perf_shift * 3.0))
            if self._semantic_circuit_open(session_id):
                budget = int(round(budget * 0.5))
        except Exception:
            pass
        floor = max(6, int(round(default_max * 0.33)))
        ceil = max(floor + 2, int(round(default_max * 2.0)))
        budget = max(floor, min(ceil, budget))
        with self._semantic_budget_lock:
            self._semantic_budget_cache[session_id] = (now, budget)
        return budget

    def _update_semantic_circuit_breaker(self, session_id: str) -> None:
        """Open semantic circuit briefly when retrieval quality is persistently weak."""
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") or {}
            sem_total = int(sem.get("total") or 0)
            sem_hit = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            min_total = int(profile.get("min_total") or 6)
            expected_hit = max(profile["hit_q50"], self._get_semantic_threshold(session_id))
            quality_gap = expected_hit - sem_hit
            if sem_total >= min_total and quality_gap > max(0.05, profile["hit_q75"] - profile["hit_q25"]):
                with self._circuit_breaker_lock:
                    ttl = int(max(45, min(240, round(60 + (quality_gap * 180)))))
                    self._semantic_circuit_breaker_until[session_id] = int(time.time()) + ttl
        except Exception:
            return

    def _get_semantic_threshold(self, session_id: str) -> float:
        if not session_id:
            return 0.5
        with self._semantic_threshold_lock:
            return float(self._session_semantic_threshold.get(session_id, 0.5))

    def _tune_semantic_threshold(self, session_id: str) -> None:
        """
        Tune semantic threshold from observed semantic hit-rate.
        """
        if not session_id:
            return
        try:
            stats = self._session_retrieval_stats(session_id)
            sem = stats.get("semantic_linked") if isinstance(stats, dict) else None
            if not sem:
                return
            total = int(sem.get("total") or 0)
            hit_rate = float(sem.get("hit_rate") or 0.0)
            profile = self._semantic_quality_profile(session_id)
            min_total = int(profile.get("min_total") or 6)
            if total < min_total:
                return
            with self._semantic_threshold_lock:
                cur = float(self._session_semantic_threshold.get(session_id, 0.5))
                nxt = cur
                iqr = max(0.05, profile["hit_q75"] - profile["hit_q25"])
                z = (hit_rate - profile["hit_q50"]) / iqr
                step = max(0.01, min(0.06, abs(z) * 0.02))
                if z < -0.25:
                    nxt = min(0.9, cur + step)
                elif z > 0.25:
                    nxt = max(0.2, cur - step)
                if abs(nxt - cur) >= 0.005:
                    self._session_semantic_threshold[session_id] = round(nxt, 3)
                    self._invalidate_session_caches(session_id)
                    # Thresholds are adaptive in-memory session state (the
                    # old context_policy persistence hook was removed with
                    # the policy mixin); they re-tune from live retrieval
                    # telemetry on the next enrichment cycle.
        except Exception:
            return

    def _record_related_addresses(self, session_id: str, anchor_addr: str, related_addrs: list[str]) -> None:
        """Record caller/callee/xref relations observed in tool outputs."""
        if not session_id or not anchor_addr or not related_addrs:
            return
        try:
            with self._related_addr_lock:
                graph = self._related_addr_graph[session_id]
                for other in related_addrs:
                    if not other or other == anchor_addr:
                        continue
                    graph[anchor_addr].add(other)
                    graph[other].add(anchor_addr)
        except Exception:
            pass

    def _get_bb_by_related_addresses(
        self,
        session_id: str,
        addr: str,
        bb_store,
        top_k: int = 4,
    ) -> list[dict[str, Any]]:
        """
        Retrieve blackboard findings from addresses related through recent
        caller/callee/xref exploration in this session.
        """
        if bb_store is None or not session_id or not addr:
            return []
        try:
            with self._related_addr_lock:
                neighbors = list(self._related_addr_graph.get(session_id, {}).get(addr, set()))
            if not neighbors:
                return []
            out: list[dict[str, Any]] = []
            seen: set = set()
            for naddr in neighbors[:8]:
                for entry in bb_store.list(addr=naddr, limit=3):
                    eid = entry.get("id")
                    if not eid or eid in seen:
                        continue
                    seen.add(eid)
                    out.append(entry)
                    if len(out) >= top_k:
                        return out
            return out
        except Exception:
            return []

    # ── stuck detection ──────────────────────────────────────────────────

    def record_call(self, session_id: str, tool: str, action: str, addr: str) -> None:
        # Empty/whitespace session ids must not accumulate shared per-session
        # state; every other per-session writer already skips them.
        if not session_id or not session_id.strip():
            return
        with self._session_last_seen_lock:
            self._session_last_seen[session_id] = time.time()
        with self._activity_lock:
            log = self._activity[session_id]
            # Carry a monotonic per-session call sequence number so the
            # every-5-calls target-suggestion gate in assemble() survives the
            # 50-entry trim below (len() alone would pin at the cap).
            n = int(log[-1].get("_n") or 0) + 1 if log else 1
            log.append({"tool": tool, "action": action, "addr": addr, "ts": time.time(), "_n": n})
            # Keep last 50 calls
            if len(log) > 50:
                self._activity[session_id] = log[-50:]

    def check_stuck(
        self,
        session_id: str,
        addr: str,
        tool: str,
        action: str,
    ) -> dict[str, Any] | None:
        with self._activity_lock:
            log = list(self._activity.get(session_id, []))
        if len(log) < 4:
            return None

        # Same address analyzed 3+ times
        if addr:
            addr_hits = sum(1 for e in log[-20:] if e.get("addr") == addr)
            if addr_hits >= 3:
                return {
                    "type": "repeated_address",
                    "address": addr,
                    "count": addr_hits,
                    "message": f"This address has been analyzed {addr_hits} times. Consider exploring callers, callees, or cross-references.",
                    "pivot_suggestions": [
                        f"code(action='callers', addr='{addr}')",
                        f"code(action='callees', addr='{addr}')",
                        f"graph(action='call_chain', addr='{addr}')",
                        "data(action='imports') — review imports for context",
                    ],
                }

        # Same tool:action repeated 5+ times in last 15 calls
        recent = log[-15:]
        ta = f"{tool}:{action}"
        ta_count = sum(1 for e in recent if f"{e['tool']}:{e['action']}" == ta)
        if ta_count >= 5:
            pivots = {
                "code:decompile": ["code:callers", "code:callees", "search:semantic"],
                "search:find": ["search:structured", "data:imports", "code:decompile"],
                "code:disasm": ["code:decompile", "code:blocks", "ctree:get"],
            }
            return {
                "type": "repeated_tool",
                "tool_action": ta,
                "count": ta_count,
                "message": f"Called {ta} {ta_count} times recently. Try a different approach.",
                "pivot_suggestions": pivots.get(
                    ta,
                    [
                        "blackboard(action='list') — review what you've found so far",
                        "predictor(action='suggest_focus') — get focus suggestions",
                    ],
                ),
            }

        return None

    # ── main entry point ─────────────────────────────────────────────────

    def assemble(
        self,
        tool: str,
        action: str,
        payload: dict[str, Any],
        addr: str,
        session_id: str,
        idb_path: str,
        bb_store=None,
        mode: str = "full",
        detail: str = "normal",
    ) -> dict[str, Any]:
        """
        Build a context_pack for injection into the tool response.
        Non-blocking: slow operations (indexing a new function) are async.
        Returns empty dict if nothing meaningful to inject.
        """
        _full = mode == "full"
        t_all = self._perf_start()
        pack: dict[str, Any] = {}

        self._run_housekeeping(session_id)

        # Record for stuck detection
        self.record_call(session_id, tool, action, addr)

        # ── 1. Address-matched blackboard findings
        bb_addr = self._get_bb_entries(addr, bb_store)
        if bb_addr:
            # Guarded like every other enrichment step: a malformed blackboard
            # entry (non-numeric confidence/updated_at, un-serializable value)
            # must not abort the whole context pack for this call.
            with contextlib.suppress(Exception):
                self._merge_related_findings(pack, bb_addr, "address_linked", session_id=session_id)

        # ── 2. Decompile-specific enrichment
        is_decompile = tool == "ida_decompile" or (
            tool == "code"
            and action in (
                "decompile",
                "semantic_decompile",
                "decompile_chain",
                "smart_decompile",
            )
        )
        pseudocode = ""
        if is_decompile:
            pseudocode = payload.get("code") or payload.get("pseudocode") or payload.get("output") or ""
            # For decompile_chain, grab the main pseudocode
            if not pseudocode and isinstance(payload.get("results"), list):
                for r in payload["results"]:
                    pseudocode = r.get("pseudocode") or r.get("code") or ""
                    if pseudocode:
                        break

        if pseudocode and len(pseudocode.strip()) > 80:
            t_dec = self._perf_start()
            with contextlib.suppress(Exception):
                self._enrich_decompile(
                    pack,
                    payload,
                    pseudocode,
                    addr,
                    idb_path,
                    bb_store,
                    session_id,
                    mode=mode,
                    detail=detail,
                )
            self._perf_end(session_id, "decompile_enrich", t_dec)

        # ── 2b. Search/xref result enrichment ─────────────────────────────
        # When a search returns a list of addresses, enrich each with
        # structural data so the LLM doesn't need extra tool calls
        # to assess which hits are interesting.
        is_search = tool in ("search", "graph", "code") and action in (
            "find",
            "api",
            "callers",
            "callees",
            "xrefs_to",
            "xrefs_from",
            "data_ref",
            "code_ref",
            "name",
            "string",
            "bytes",
            "call_chain",
            "common_callers",
            "hub_functions",
        )
        if is_search and idb_path:
            t_search = self._perf_start()
            try:
                # Collect addresses from the result payload
                hit_addrs: list[str] = []
                for key in ("matches", "items", "results", "callers", "callees", "xrefs", "refs", "addresses", "functions"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, str) and item.startswith("0x"):
                                hit_addrs.append(item)
                            elif isinstance(item, dict):
                                for k in ("ea", "addr", "address", "from", "to"):
                                    v = item.get(k)
                                    if v and str(v).startswith("0x"):
                                        hit_addrs.append(str(v))
                                        break
                if hit_addrs:
                    if addr:
                        self._record_related_addresses(session_id, addr, hit_addrs)
                    enriched = self._enrich_address_list(hit_addrs, idb_path)
                    if _full and enriched:
                        pack["hit_details"] = enriched
            except Exception:
                pass
            self._perf_end(session_id, "search_enrich", t_search)

        # ── 2c. Suggest next unanalyzed targets (after any tool call) ─────
        # Use the deterministic signature index to recommend high-interest functions not yet seen.
        if idb_path:
            try:
                # Only inject next_targets occasionally — every 5 calls per
                # session.  Count from the monotonic sequence number recorded
                # by record_call, since len() of the activity log pins at the
                # 50-entry cap and would otherwise fire on every call.
                with self._activity_lock:
                    log = self._activity.get(session_id, [])
                    n_calls = int(log[-1].get("_n") or len(log)) if log else 0
                if n_calls % 5 == 0 and n_calls > 0:
                    targets = self.suggest_next_targets(idb_path, limit=3)
                    if _full and targets:
                        pack["suggested_targets"] = targets
            except Exception:
                pass

        # ── 3. Stuck detection
        stuck = self.check_stuck(session_id, addr, tool, action)
        if _full and stuck:
            pack["stuck"] = stuck

        self._perf_end(session_id, "assemble", t_all)

        return pack

    def _enrich_decompile(
        self,
        pack: dict[str, Any],
        payload: dict[str, Any],
        pseudocode: str,
        addr: str,
        idb_path: str,
        bb_store,
        session_id: str,
        mode: str = "full",
        detail: str = "normal",
    ) -> None:
        """
        Decompile-specific enrichment. Deterministic first, provider advisory second.

        Priority order:
          1. Neighborhood assessment via the typed-question provider (detail-scaled)
          2. Suggested next actions (full mode)
          3. Signature-index similarity when an explicit vector-compatible extension is supplied
          4. Cross-address blackboard retrieval (callgraph-linked, fast SQL)
          5. Semantic blackboard retrieval (slow, only if bb_store populated)
        """
        _full = mode == "full"
        advisor_detail = str(detail or "normal").strip().lower()
        if advisor_detail not in {"triage", "normal", "deep"}:
            advisor_detail = "normal"
        result_rows = payload.get("results")
        first_result = (
            result_rows[0]
            if isinstance(result_rows, list)
            and result_rows
            and isinstance(result_rows[0], Mapping)
            else {}
        )
        func_name = payload.get("name") or first_result.get("name") or f"sub_{addr}"

        # ── Advisory behavior decision through the explicit provider ──
        # Only a compact signature/metadata view crosses the provider boundary;
        # raw decompilation remains local and is never persisted by this path.
        behavior_hits: list[dict[str, Any]] = []
        if pseudocode.strip():
            try:
                candidates = _decompile_neighborhood_candidates(
                    payload,
                    pseudocode,
                    str(addr),
                    str(func_name),
                )
                signature = candidates[0]["signature"] if candidates else ""
                classifier = getattr(self, "_classifier", None)
                if signature and classifier is not None and not isinstance(classifier, BehaviorClassifier):
                    # Focused callers may inject a deterministic classifier
                    # double; production always uses the provider-backed
                    # BehaviorClassifier below.
                    advisory = classifier.classify(signature, threshold=0.0, top_k=4, block=False)
                    if isinstance(advisory, list):
                        behavior_hits = advisory
                elif candidates:
                    from .advisory import assess_function_neighborhood

                    focus_record = (
                        result_rows[0]
                        if isinstance(result_rows, list) and result_rows and isinstance(result_rows[0], Mapping)
                        else payload
                    )
                    advisory = assess_function_neighborhood(
                        {
                            "focus_address": str(addr),
                            "focus_name": str(func_name)[:256],
                            "focus_signature": signature,
                            "architecture": focus_record.get("architecture") or focus_record.get("processor"),
                            "bitness": focus_record.get("bitness"),
                            "endian": focus_record.get("endian"),
                            "file_format": focus_record.get("file_format"),
                            "caller_count": focus_record.get("caller_count"),
                            "callee_count": focus_record.get("callee_count"),
                            "candidate_source": "decompile_chain" if len(candidates) > 1 else "decompile",
                        },
                        candidates,
                        session_id=session_id,
                        operation="context_neighborhood",
                        detail=advisor_detail,
                    )
                else:
                    advisory = None
                if isinstance(advisory, dict) and advisory.get("error"):
                    pack["intelligence_provider"] = {
                        "code": advisory.get("code"),
                        "message": advisory.get("message"),
                    }
                elif isinstance(advisory, dict) and isinstance(advisory.get("functions"), list):
                    behavior_hits = advisory["functions"]
                    focus_hit = next(
                        (
                            hit
                            for hit in behavior_hits
                            if hit.get("relationship") == "focus"
                            or str(hit.get("address") or "") == str(addr)
                        ),
                        None,
                    )
                    pack["investigation_advisory"] = {
                        "priorities": advisory.get("priorities", []),
                        "recommended_next": advisory.get("recommended_next"),
                        "recommended_evidence": advisory.get("recommended_evidence"),
                        "recommended_tool_call": _recommended_ida_call(
                            advisory.get("recommended_evidence"), addr
                        ),
                        "advisory_order": [
                            {
                                key: item.get(key)
                                for key in ("candidate_id", "address", "name", "relationship")
                            }
                            for item in advisory.get("advisory_order", [])
                            if isinstance(item, Mapping)
                        ],
                        "evidence_sufficiency": advisory.get("evidence_sufficiency"),
                        "priority_disagreement": advisory.get("priority_disagreement"),
                        "evidence": advisory.get("evidence", {}),
                        "disagreement": advisory.get("disagreement", False),
                        "applied": False,
                    }
                    if focus_hit is not None:
                        pack["behavior_tags"] = [focus_hit.get("behavior")]
                elif isinstance(advisory, list):
                    behavior_hits = advisory
            except Exception:
                behavior_hits = []
        if behavior_hits:
            pack["behavior_classifications"] = behavior_hits
            pack.setdefault(
                "behavior_tags",
                [hit.get("behavior") for hit in behavior_hits if hit.get("behavior")],
            )

        # ── Step 4: Next-action suggestion (full mode only).
        # The earlier API-pattern/structural rule evaluation was removed; only
        # the deterministic "suggest callers" action remains.
        if _full:
            actions: list[dict[str, Any]] = []
            if addr:
                actions.append(
                    {
                        "tool": "code",
                        "action": "callers",
                        "addr": addr,
                        "reason": "See what calls this function",
                    }
                )
            if actions:
                pack["suggested_next_actions"] = actions[:6]

        # ── Step 5: Optional explicit vector extension (background-safe) ─
        query_vec: list[float] | None = None
        if idb_path:
            try:
                # Any optional vector-compatible test/provider facade receives
                # only the compact identifier signature. Typed-question Jev
                # and custom providers never implement this path.
                sig = _extract_signature(pseudocode, max_idents=64) or ""
                query_vec = self._embedder.embed_vector(sig)
                if query_vec is None:
                    raise RuntimeError("embedding unavailable")
                idx = self._get_index(idb_path)
                idx.cache_store(addr, query_vec)
                ph = idx._phash(pseudocode)
                sig_hash = hashlib.sha256((sig or pseudocode).encode("utf-8", errors="replace")).hexdigest()[:16]
                self._schedule_embedding_persist(idx, addr, func_name, query_vec, ph, sig, sig_hash)

                # Similarity search over the in-memory cache. Only surfaced in
                # full mode, so skip the cosine scan entirely in compact mode —
                # the embed + async persist above is the valuable indexing
                # side-effect.  Delegates to FunctionEmbeddingIndex.similar_vec
                # so the numpy-accelerated batch cosine is used here too.
                if _full:
                    similar = idx.similar_vec(query_vec, top_k=3, threshold=0.6, exclude_ea=addr)
                    if similar:
                        pack["similar_functions"] = [{"ea": row["ea"], "name": row["name"], "similarity": row["similarity"]} for row in similar]
            except Exception:
                pass

        # ── Step 6: Cross-address blackboard retrieval (callgraph-linked) ─
        if bb_store is not None and addr and session_id:
            try:
                rel_bb = self._get_bb_by_related_addresses(session_id, addr, bb_store, top_k=4)
                if rel_bb:
                    self._merge_related_findings(pack, rel_bb, "relation_linked", session_id=session_id)
            except Exception:
                pass

        # ── Step 7: Semantic blackboard retrieval ─────────────────────────
        # Runs only when an explicit vector extension supplied a query vector;
        # otherwise BlackboardStore.semantic_search retains its deterministic
        # lexical fallback. Provider advisories never write findings.
        if query_vec is not None and bb_store is not None and not self._semantic_circuit_open(session_id):
            try:
                sem_thr = self._get_semantic_threshold(session_id)
                sig = _extract_signature(pseudocode, max_idents=40)
                sem_bb = bb_store.semantic_search(
                    query=sig,
                    top_k=5,
                    threshold=sem_thr,
                )
                # Exclude the entry for this exact address to avoid self-reference
                sem_bb = [e for e in sem_bb if e.get("addr") != addr][:3]
                if sem_bb:
                    self._merge_related_findings(pack, sem_bb, "semantic_linked", session_id=session_id)
            except Exception:
                pass

        self._tune_semantic_threshold(session_id)
        self._update_semantic_circuit_breaker(session_id)
        stats = self._session_retrieval_stats(session_id)
        if _full and stats:
            pack["retrieval_stats"] = stats

    def _enrich_address_list(
        self,
        addresses: list[str],
        idb_path: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Enrich addresses with structural data from the signature index."""
        if not addresses or not idb_path:
            return []
        try:
            idx = self._get_index(idb_path)
            if idx is None or idx.size == 0:
                return []

            # The ea column stores hex strings like "0x401000", so
            # convert inputs to hex strings to match exactly.
            def _to_hex(a: str) -> str | None:
                try:
                    n = int(a, 0)
                    return hex(n)
                except (ValueError, TypeError):
                    return None

            eas = [_to_hex(a) for a in addresses[:limit]]
            eas = [a for a in eas if a is not None]
            if not eas:
                return []
            # Query signature index for structural metadata
            enriched = []
            with idx._conn() as conn:
                ph = ",".join("?" * len(eas))
                for row in conn.execute(f"SELECT ea, name, func_size, bb_count, has_loops, api_count, string_count, segment, cyclomatic FROM func_embeddings WHERE ea IN ({ph})", eas):
                    entry = {"ea": hex(int(row[0], 16)) if row[0] else "", "name": row[1] or ""}
                    if row[2]:
                        entry["size"] = row[2]
                    if row[3]:
                        entry["bb_count"] = row[3]
                    if row[4]:
                        entry["has_loops"] = True
                    if row[5]:
                        entry["api_count"] = row[5]
                    if row[6]:
                        entry["string_count"] = row[6]
                    if row[7]:
                        entry["segment"] = row[7]
                    if row[8]:
                        entry["cyclomatic"] = row[8]
                    enriched.append(entry)
            return enriched
        except Exception:
            return []

    def suggest_next_targets(
        self,
        idb_path: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend unanalyzed functions worth examining next.

        Uses the deterministic signature index to find high-value structural candidates.
        """
        if not idb_path:
            return []
        try:
            idx = self._get_index(idb_path)
            if idx is None or idx.size == 0:
                return []
            # Query signature index for interesting functions
            rows = idx.search_structured(
                {"min_size": 64, "min_bb": 3},
                query="high value reverse engineering target",
                top_k=limit * 4,
            )
            analyzed = idx.cache_keys()
            results = []
            seen = set()
            for r in rows:
                ea = r["ea"]
                if ea in analyzed or ea in seen:
                    continue
                seen.add(ea)
                results.append(
                    {
                        "ea": ea,
                        "name": r["name"],
                        "reason": f"size={r['func_size']}, bb={r['bb_count']}, apis={r['api_count']}",
                        "interest_score": 0.5,
                        "api_count": r["api_count"],
                        "bb_count": r["bb_count"],
                        "has_loops": r["has_loops"],
                    }
                )
            return results[:limit]
        except Exception:
            return []

    def stop(self) -> None:
        """Release provider-neutral in-memory context state."""
        self._embedder.stop()

    def ensure_embedding_server(self) -> bool:
        """Return provider readiness; no local server is started."""
        return self._embedder.check_availability()

    @property
    def status(self) -> dict[str, Any]:
        return {
            "provider": self._embedder.status(),
            "embedding_supported": False,
            "indexes": {idb: {"functions_indexed": idx.size} for idb, idx in self._indexes.items()},
        }


# Module-level singleton access
# ─────────────────────────────────────────────────────────────────────────────

_assembler: ContextAssembler | None = None
_assembler_lock = threading.Lock()


def get_assembler() -> ContextAssembler:
    global _assembler
    with _assembler_lock:
        if _assembler is None:
            _assembler = ContextAssembler()
    return _assembler


def _shutdown_intelligence_singleton() -> None:
    try:
        if _assembler is not None:
            _assembler.stop()
    except Exception:
        pass


atexit.register(_shutdown_intelligence_singleton)
