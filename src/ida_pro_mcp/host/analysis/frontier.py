"""
FrontierEngine — embedding-driven analysis frontier for firmware RE.

Core idea:
  1. Cluster all indexed function embeddings (k-means, pure numpy)
  2. When LLM labels a function, propagate that label to cluster neighbors
     with decayed confidence (cosine_sim * label_confidence * decay)
  3. Score every unvisited function: proximity to labeled functions in
     embedding space + xref count + entropy + call-graph adjacency
  4. Return a ranked frontier — the most promising unanalyzed functions
  5. Detect contradictions: same cluster, very different LLM labels

No IDA deps — runs on the host side against the embeddings DB.
"""

from __future__ import annotations

import math
import sqlite3
import time
from typing import Any

from ..intelligence.helpers import cosine_similarity as _cosine, unpack_floats as _unpack


def _vec_add(a: list[float], b: list[float]) -> list[float]:
    return [x + y for x, y in zip(a, b, strict=False)]


def _vec_scale(a: list[float], s: float) -> list[float]:
    return [x * s for x in a]


def _vec_norm(a: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in a))
    if n < 1e-9:
        return a
    return [x / n for x in a]


# ── k-means (pure python/numpy-free) ─────────────────────────────────────────

def _kmeans(
    vecs: list[list[float]],
    k: int,
    max_iter: int = 30,
    seed: int = 42,
) -> list[int]:
    """Assign each vector to one of k clusters. Returns cluster id per vector."""
    if not vecs or k <= 1:
        return [0] * len(vecs)
    k = min(k, len(vecs))
    dim = len(vecs[0])

    # Deterministic init: spread centroids by picking every n-th vector
    step = max(1, len(vecs) // k)
    centroids = [list(vecs[i * step]) for i in range(k)]

    assignments = [0] * len(vecs)
    for _ in range(max_iter):
        # Assign
        changed = False
        for i, v in enumerate(vecs):
            best_c, best_sim = 0, -1.0
            for c_idx, centroid in enumerate(centroids):
                sim = _cosine(v, centroid)
                if sim > best_sim:
                    best_sim, best_c = sim, c_idx
            if assignments[i] != best_c:
                assignments[i] = best_c
                changed = True

        if not changed:
            break

        # Update centroids
        sums = [[0.0] * dim for _ in range(k)]
        counts = [0] * k
        for i, v in enumerate(vecs):
            c = assignments[i]
            sums[c] = _vec_add(sums[c], v)
            counts[c] += 1
        for c in range(k):
            if counts[c] > 0:
                centroids[c] = _vec_norm(_vec_scale(sums[c], 1.0 / counts[c]))

    return assignments


# ── FrontierEngine ────────────────────────────────────────────────────────────

class FrontierEngine:
    """
    Maintains a cluster model over all indexed function embeddings and
    uses LLM-provided labels to score the analysis frontier.

    Usage (host side, no IDA):
        fe = FrontierEngine(embeddings_db, blackboard_db)
        fe.refresh()                          # rebuild clusters
        frontier = fe.frontier(limit=20)      # ranked unvisited functions
        fe.propagate_labels()                 # spread BB labels to neighbors
        contradictions = fe.detect_contradictions()
    """

    # Propagation: neighbors within this cosine distance get the label
    PROPAGATE_THRESHOLD = 0.82
    PROPAGATE_DECAY = 0.75        # confidence multiplier per hop
    PROPAGATE_MIN_CONF = 0.35     # don't propagate below this

    # Frontier scoring weights
    W_PROXIMITY = 0.45   # cosine similarity to nearest labeled function
    W_XREF      = 0.25   # normalized xref count
    W_ENTROPY   = 0.15   # byte entropy (0-8 scale)
    W_CLUSTER   = 0.15   # cluster has labeled members

    # Contradiction: same cluster, label cosine < this threshold
    CONTRADICTION_LABEL_SIM = 0.35

    def __init__(self, embeddings_db: str, blackboard_db: str):
        self._emb_db = embeddings_db
        self._bb_db  = blackboard_db
        # cluster state
        self._ea_list:    list[str]        = []
        self._vecs:       list[list[float]] = []
        self._names:      dict[str, str]   = {}
        self._clusters:   list[int]        = []   # cluster id per ea
        self._centroids:  list[list[float]] = []
        self._built_at:   float = 0.0
        self._k:          int   = 0

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _emb_conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._emb_db)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _bb_conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._bb_db)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _load_embeddings(self) -> tuple[list[str], list[list[float]], dict[str, str]]:
        eas, vecs, names = [], [], {}
        try:
            with self._emb_conn() as conn:
                for row in conn.execute(
                    "SELECT ea, name, vec_blob FROM func_embeddings"
                ):
                    ea, name, blob = row
                    if blob:
                        eas.append(ea)
                        vecs.append(_unpack(blob))
                        names[ea] = name or ea
        except Exception:
            pass
        return eas, vecs, names

    def _load_bb_labels(self) -> dict[str, dict]:
        """Load blackboard entries that have addresses — these are LLM labels."""
        labels: dict[str, dict] = {}
        try:
            with self._bb_conn() as conn:
                for row in conn.execute("""
                    SELECT addr, category, title, confidence, tags, source_type
                    FROM blackboard
                    WHERE resolved=0 AND contradicted=0
                      AND addr != '' AND addr IS NOT NULL
                """):
                    addr, cat, title, conf, tags, src = row
                    if addr not in labels or (conf or 0) > labels[addr].get("confidence", 0):
                        labels[addr] = {
                            "category": cat,
                            "title": title,
                            "confidence": float(conf or 0.5),
                            "tags": tags or "",
                            "source_type": src or "manual",
                        }
        except Exception:
            pass
        return labels

    # ── cluster build ─────────────────────────────────────────────────────────

    def refresh(self, k: int | None = None) -> int:
        """Rebuild cluster model. Returns number of functions indexed."""
        eas, vecs, names = self._load_embeddings()
        if not eas:
            return 0
        n = len(eas)
        # Auto-select k: sqrt(n/2), clamped 5..100
        if k is None:
            k = max(5, min(100, int(math.sqrt(n / 2))))
        self._ea_list   = eas
        self._vecs      = vecs
        self._names     = names
        self._k         = k
        self._clusters  = _kmeans(vecs, k)
        # Compute centroids
        dim = len(vecs[0])
        sums   = [[0.0] * dim for _ in range(k)]
        counts = [0] * k
        for i, c in enumerate(self._clusters):
            sums[c] = _vec_add(sums[c], vecs[i])
            counts[c] += 1
        self._centroids = [
            _vec_norm(_vec_scale(sums[c], 1.0 / counts[c])) if counts[c] else [0.0] * dim
            for c in range(k)
        ]
        self._built_at = time.time()
        return n

    def _ea_to_idx(self) -> dict[str, int]:
        return {ea: i for i, ea in enumerate(self._ea_list)}

    # ── label propagation ─────────────────────────────────────────────────────

    def propagate_labels(self) -> list[dict]:
        """
        For every blackboard entry with an address that has an embedding,
        find all cluster neighbors within PROPAGATE_THRESHOLD cosine distance
        and write propagated entries to the blackboard.

        Returns list of newly propagated entries.
        """
        if not self._ea_list:
            self.refresh()
        if not self._ea_list:
            return []

        labels = self._load_bb_labels()
        ea_idx = self._ea_to_idx()
        propagated = []

        # Existing propagated entries (avoid duplicates)
        existing_propagated: set = set()
        try:
            with self._bb_conn() as conn:
                for row in conn.execute(
                    "SELECT addr FROM blackboard WHERE source_type='propagated'"
                ):
                    existing_propagated.add(row[0])
        except Exception:
            pass

        for src_addr, label in labels.items():
            src_idx = ea_idx.get(src_addr)
            if src_idx is None:
                continue
            src_vec = self._vecs[src_idx]
            src_conf = label["confidence"]
            if src_conf < self.PROPAGATE_MIN_CONF:
                continue

            for tgt_idx, tgt_ea in enumerate(self._ea_list):
                if tgt_ea == src_addr:
                    continue
                if tgt_ea in labels:
                    continue  # already labeled by LLM
                if tgt_ea in existing_propagated:
                    continue

                sim = _cosine(src_vec, self._vecs[tgt_idx])
                if sim < self.PROPAGATE_THRESHOLD:
                    continue

                prop_conf = src_conf * self.PROPAGATE_DECAY * sim
                if prop_conf < self.PROPAGATE_MIN_CONF:
                    continue

                propagated.append({
                    "addr": tgt_ea,
                    "name": self._names.get(tgt_ea, tgt_ea),
                    "source_addr": src_addr,
                    "source_title": label["title"],
                    "category": label["category"],
                    "confidence": round(prop_conf, 3),
                    "similarity": round(sim, 3),
                    "cluster": self._clusters[tgt_idx],
                })

        # Write to blackboard
        if propagated:
            try:
                import uuid as _uuid
                now = time.time()
                with self._bb_conn() as conn:
                    for p in propagated:
                        conn.execute("""
                            INSERT OR IGNORE INTO blackboard
                            (id, category, title, content, addr, confidence,
                             created_at, updated_at, source_type, source, xref_count)
                            VALUES (?,?,?,?,?,?,?,?,'propagated','frontier_engine',0)
                        """, (
                            str(_uuid.uuid4()),
                            p["category"],
                            f"[propagated] {p['source_title'][:60]}",
                            f"Propagated from {p['source_addr']} (sim={p['similarity']:.3f})",
                            p["addr"],
                            p["confidence"],
                            now, now,
                        ))
                    conn.commit()
            except Exception:
                pass

        return propagated

    # ── frontier scoring ──────────────────────────────────────────────────────

    def frontier(
        self,
        limit: int = 20,
        xref_counts: dict[str, int] | None = None,
        entropy_map: dict[str, float] | None = None,
        query: str | None = None,
    ) -> list[dict]:
        """
        Return ranked list of unvisited functions most worth analyzing next.

        xref_counts: {ea_hex: count} — from IDA (optional, improves scoring)
        entropy_map: {ea_hex: entropy} — from entropy scan (optional)
        query: semantic query (optional, e.g. "AES encrypt" or "http post")
        """
        if not self._ea_list:
            self.refresh()
        if not self._ea_list:
            return []

        # Setup intelligence helpers
        embedder = None
        classifier = None
        query_vec = None
        try:
            from ..intelligence.core import BehaviorClassifier, BgeCodeEmbedder
            embedder = BgeCodeEmbedder()
            classifier = BehaviorClassifier.instance(embedder)
            if query and query.strip():
                query_vec = embedder.embed_vector(query)
                if query_vec is None:
                    raise RuntimeError("embedding unavailable")
        except Exception:
            pass

        labels = self._load_bb_labels()
        labeled_eas = set(labels.keys())

        # Which clusters have labeled members?
        cluster_labeled: dict[int, list[str]] = {}
        ea_idx = self._ea_to_idx()
        for ea in labeled_eas:
            idx = ea_idx.get(ea)
            if idx is not None:
                c = self._clusters[idx]
                cluster_labeled.setdefault(c, []).append(ea)

        # Max xref for normalization
        max_xref = max(xref_counts.values()) if xref_counts else 1
        max_xref = max(max_xref, 1)

        scored = []
        for i, ea in enumerate(self._ea_list):
            if ea in labeled_eas:
                continue  # already analyzed

            cluster_id = self._clusters[i]
            vec = self._vecs[i]

            # Proximity: cosine to nearest labeled function
            proximity = 0.0
            nearest_label = None
            for lbl_ea in labeled_eas:
                lbl_idx = ea_idx.get(lbl_ea)
                if lbl_idx is None:
                    continue
                sim = _cosine(vec, self._vecs[lbl_idx])
                if sim > proximity:
                    proximity = sim
                    nearest_label = lbl_ea

            # Cluster score: fraction of cluster that is labeled
            cluster_members = sum(1 for c in self._clusters if c == cluster_id)
            cluster_labeled_count = len(cluster_labeled.get(cluster_id, []))
            cluster_score = cluster_labeled_count / max(cluster_members, 1)

            # Xref score (normalized)
            xref_raw = (xref_counts or {}).get(ea, 0)
            xref_score = xref_raw / max_xref

            # Entropy score (0-8 → 0-1, high entropy = interesting)
            ent_raw = (entropy_map or {}).get(ea, 0.0)
            ent_score = min(1.0, ent_raw / 8.0)

            total = (
                self.W_PROXIMITY * proximity
                + self.W_XREF     * xref_score
                + self.W_ENTROPY  * ent_score
                + self.W_CLUSTER  * cluster_score
            )

            # Zero-shot behavior classification boost
            detected_behaviors = []
            behavior_boost = 0.0
            if classifier is not None:
                try:
                    matches = classifier.classify_vec(vec, threshold=0.35, top_k=3, block=False)
                    detected_behaviors = [m["behavior"] for m in matches]
                    if detected_behaviors:
                        behavior_boost = 0.15
                except Exception:
                    pass

            total = min(1.0, total + behavior_boost)

            query_similarity = 0.0
            if query_vec is not None:
                query_similarity = _cosine(vec, query_vec)
                # Blend: 60% query match, 40% structural/proximity match
                total = 0.6 * max(0.0, query_similarity) + 0.4 * total

            scored.append({
                "addr": ea,
                "name": self._names.get(ea, ea),
                "score": round(total, 4),
                "cluster": cluster_id,
                "proximity": round(proximity, 3),
                "nearest_labeled": nearest_label,
                "nearest_label_title": labels.get(nearest_label, {}).get("title", "") if nearest_label else "",
                "xref_count": xref_raw,
                "entropy": round(ent_raw, 2),
                "cluster_coverage": round(cluster_score, 3),
                "detected_behaviors": detected_behaviors,
                "query_similarity": round(query_similarity, 4) if query_vec is not None else None,
            })

        scored.sort(key=lambda x: -x["score"])
        return scored[:limit]

    # ── coverage map ──────────────────────────────────────────────────────────

    def coverage(self) -> dict[str, Any]:
        """
        Return coverage statistics: analyzed/visited/unvisited counts,
        per-cluster breakdown, and overall coverage percentage.
        """
        if not self._ea_list:
            self.refresh()

        labels = self._load_bb_labels()
        labeled_eas = set(labels.keys())
        total = len(self._ea_list)
        analyzed = sum(1 for ea in self._ea_list if ea in labeled_eas)
        unvisited = total - analyzed

        # Per-cluster breakdown
        cluster_stats: dict[int, dict] = {}
        for i, ea in enumerate(self._ea_list):
            c = self._clusters[i]
            if c not in cluster_stats:
                cluster_stats[c] = {"total": 0, "analyzed": 0, "sample_names": []}
            cluster_stats[c]["total"] += 1
            if ea in labeled_eas:
                cluster_stats[c]["analyzed"] += 1
            elif len(cluster_stats[c]["sample_names"]) < 3:
                cluster_stats[c]["sample_names"].append(self._names.get(ea, ea))

        clusters_summary = []
        for c_id, stats in sorted(cluster_stats.items()):
            pct = stats["analyzed"] / max(stats["total"], 1) * 100
            clusters_summary.append({
                "cluster": c_id,
                "total": stats["total"],
                "analyzed": stats["analyzed"],
                "coverage_pct": round(pct, 1),
                "sample_unvisited": stats["sample_names"],
            })
        # Sort by least covered first (most work remaining)
        clusters_summary.sort(key=lambda x: x["coverage_pct"])

        return {
            "total_indexed": total,
            "analyzed": analyzed,
            "unvisited": unvisited,
            "coverage_pct": round(analyzed / max(total, 1) * 100, 1),
            "clusters": len(cluster_stats),
            "cluster_breakdown": clusters_summary[:20],
            "built_at": self._built_at,
            "note": (
                f"{analyzed}/{total} functions have blackboard entries. "
                f"{unvisited} unvisited. "
                f"Use blackboard(action='frontier') to get ranked next targets."
            ),
        }

    # ── contradiction detection ───────────────────────────────────────────────

    def detect_contradictions(self) -> list[dict]:
        """
        Find pairs of blackboard entries in the same cluster whose labels
        are semantically inconsistent (very different categories/titles).

        Returns list of contradiction candidates for LLM review.
        """
        if not self._ea_list:
            self.refresh()

        labels = self._load_bb_labels()
        ea_idx = self._ea_to_idx()

        # Group labeled functions by cluster
        cluster_labels: dict[int, list[tuple[str, dict]]] = {}
        for ea, lbl in labels.items():
            idx = ea_idx.get(ea)
            if idx is None:
                continue
            c = self._clusters[idx]
            cluster_labels.setdefault(c, []).append((ea, lbl))

        contradictions = []
        for c_id, members in cluster_labels.items():
            if len(members) < 2:
                continue
            # Check all pairs in cluster
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    ea_a, lbl_a = members[i]
                    ea_b, lbl_b = members[j]
                    idx_a = ea_idx[ea_a]
                    idx_b = ea_idx[ea_b]
                    # Embedding similarity (should be high since same cluster)
                    emb_sim = _cosine(self._vecs[idx_a], self._vecs[idx_b])
                    # Category mismatch
                    cat_match = lbl_a["category"] == lbl_b["category"]
                    # High embedding similarity but different categories = contradiction candidate
                    if emb_sim >= 0.75 and not cat_match:
                        contradictions.append({
                            "cluster": c_id,
                            "addr_a": ea_a,
                            "title_a": lbl_a["title"],
                            "category_a": lbl_a["category"],
                            "addr_b": ea_b,
                            "title_b": lbl_b["title"],
                            "category_b": lbl_b["category"],
                            "embedding_similarity": round(emb_sim, 3),
                            "note": (
                                f"Functions at {ea_a} and {ea_b} are in the same embedding cluster "
                                f"(sim={emb_sim:.3f}) but labeled as '{lbl_a['category']}' vs "
                                f"'{lbl_b['category']}'. One label may be wrong."
                            ),
                        })

        contradictions.sort(key=lambda x: -x["embedding_similarity"])
        return contradictions[:20]
