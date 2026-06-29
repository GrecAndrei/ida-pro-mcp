"""Multi-Hop Bridge-Conditioned Retrieval.

Deterministic multi-hop retrieval that finds structurally related
functions through shared bridge entities (APIs, strings, xrefs).  Uses
SchemaBoot's SQLite index as the bridge source.  No LLM required for
the algorithm itself (an optional embedder improves scoring).

The scoring model is
  s(q, b, c) = conditional utility of candidate c given query q and bridge b.

This module is the canonical host-layer implementation.  The thin MCP
tool wrapper lives in ``ida_mcp.tools.bridge_search`` so the
``bridge_search(...)`` action continues to be exposed to LLM clients.
"""

from __future__ import annotations

import math
import os
import sqlite3
from typing import Any

try:
    from .core import BgeCodeEmbedder
except Exception:  # pragma: no cover - test/import flexibility
    try:
        from core import BgeCodeEmbedder  # type: ignore[import-not-found]
    except Exception:
        BgeCodeEmbedder = None  # type: ignore


# ---------------------------------------------------------------------------
# SchemaBoot DB helpers
# ---------------------------------------------------------------------------

def _resolve_schemaboot_db_path(candidate: str | None = None) -> str:
    """Resolve the SchemaBoot DB path.

    Tries the explicit candidate first, then walks a list of common
    variations (.i64.schemaboot.db vs .schemaboot.db vs sibling files
    in the same directory) and returns the first one whose tables
    actually exist.
    """
    base = candidate or "unknown.schemaboot.db"
    candidates = [base]
    if base.endswith(".i64.schemaboot.db"):
        candidates.append(base.replace(".i64.schemaboot.db", ".schemaboot.db"))
    parent = os.path.dirname(base) or "."
    bname = os.path.basename(base)
    if ".i64." in bname:
        suffix = bname.split(".i64.", 1)[-1]
        try:
            for name in os.listdir(parent):
                if name.endswith(suffix):
                    candidates.append(os.path.join(parent, name))
        except Exception:
            pass
    for path in candidates:
        if not path or not os.path.exists(path):
            continue
        try:
            with sqlite3.connect(path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='function_attrs'"
                )
                ok = cur.fetchone() is not None
            if ok:
                return path
        except Exception:
            continue
    return base


# ---------------------------------------------------------------------------
# Multi-hop bridge-conditioned retrieval
# ---------------------------------------------------------------------------

class MultiHopBridgeIndex:
    """Multi-hop search using SchemaBoot as the bridge entity source.

    The retrieval pipeline is:
        seed  --(extract_bridges)-->  bridge entities
        bridges  --(search_via_bridges)-->  candidate functions
        candidates  --(optional hop 3)-->  expanded candidate set

    Ranking uses an IDF-weighted tripartite scorer
    s(q, b, c) with percentile-rank (PIT) fusion between the judge
    score and a raw bridge-overlap signal.
    """

    def __init__(self, db_path: str | None = None, embedder: Any | None = None):
        self.db_path = _resolve_schemaboot_db_path(db_path)
        self._embedder = embedder

    def _get_embedder(self):
        if self._embedder is not None:
            return self._embedder
        if BgeCodeEmbedder is None:
            return None
        try:
            self._embedder = BgeCodeEmbedder()
        except Exception:
            self._embedder = None
        return self._embedder

    def _conn(self):
        return sqlite3.connect(self.db_path)

    # ------------------------------------------------------------------
    # Hop-1: Bridge extraction
    # ------------------------------------------------------------------

    def extract_bridges(
        self,
        func_ea: int | None = None,
        func_name: str | None = None,
        bridge_types: tuple[str, ...] = ("apis", "strings"),
        max_bridges: int = 10,
    ) -> dict[str, list[str]]:
        """Extract bridge entities from a seed function.

        Returns ``{"apis": [...], "strings": [...]}`` sorted by frequency.
        """
        bridges: dict[str, list[str]] = {}

        if func_ea is not None:
            where = "fa.func_ea = ?"
            param = (func_ea,)
        elif func_name is not None:
            where = "attrs.name = ?"
            param = (func_name,)
        else:
            return bridges

        try:
            with self._conn() as conn:
                cur = conn.cursor()

                if "apis" in bridge_types:
                    cur.execute(
                        f"""
                        SELECT api_name FROM function_apis fa
                        JOIN function_attrs attrs ON fa.func_ea = attrs.ea
                        WHERE {where}
                        ORDER BY fa.func_ea
                        """,
                        param,
                    )
                    bridges["apis"] = [r[0] for r in cur.fetchall()]

                if "strings" in bridge_types:
                    cur.execute(
                        f"""
                        SELECT string_text FROM function_strings fs
                        JOIN function_attrs attrs ON fs.func_ea = attrs.ea
                        WHERE {where}
                        ORDER BY fs.func_ea
                        """,
                        param,
                    )
                    bridges["strings"] = [r[0] for r in cur.fetchall()]
        except sqlite3.OperationalError:
            # SchemaBoot DB missing or tables don't exist
            return bridges

        # Deduplicate and limit
        for k in bridges:
            seen: set[str] = set()
            uniq: list[str] = []
            for v in bridges[k]:
                if v not in seen:
                    seen.add(v)
                    uniq.append(v)
                    if len(uniq) >= max_bridges:
                        break
            bridges[k] = uniq

        return bridges

    # ------------------------------------------------------------------
    # Hop-2: Candidate retrieval via bridges
    # ------------------------------------------------------------------

    def _compute_bridge_idf(
        self, bridge_apis: list[str], bridge_strings: list[str]
    ) -> dict[str, float]:
        """IDF weights for bridge entities.

        Rare bridges (appearing in few functions) are more discriminative:
        IDF(b) = log(N / DF(b) + 1).

        A bridge that appears in every function tells us nothing; one
        that appears in only 3 functions is highly informative.
        """
        idf: dict[str, float] = {}
        try:
            with self._conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM function_attrs")
                row = cur.fetchone()
                N = row[0] if row else 1

                for api in bridge_apis:
                    cur.execute(
                        "SELECT COUNT(DISTINCT func_ea) FROM function_apis WHERE api_name = ?",
                        (api,),
                    )
                    r = cur.fetchone()
                    df = r[0] if r else 1
                    idf[api] = math.log(N / max(df, 1) + 1)

                for s in bridge_strings:
                    cur.execute(
                        "SELECT COUNT(DISTINCT func_ea) FROM function_strings WHERE string_text = ?",
                        (s,),
                    )
                    r = cur.fetchone()
                    df = r[0] if r else 1
                    idf[s] = math.log(N / max(df, 1) + 1)
        except Exception:
            # Fall back to uniform weight
            for k in bridge_apis + bridge_strings:
                idf[k] = 1.0
        return idf

    def _tripartite_score(
        self,
        seed_attrs: dict,
        bridge_attrs: dict,
        candidate_attrs: dict,
        idf_weights: dict[str, float] | None = None,
    ) -> float:
        """Tripartite scorer s(q, b, c).

        Conditional utility of candidate c given query q and bridge b.

        Implements IDF-weighted bridge overlap so rare APIs/strings count
        more than ubiquitous ones (e.g. malloc, free).

        Returns score in [0, 1].
        """
        # Embedding-first scoring over structured bridge/context summaries.
        seed_apis = " ".join(seed_attrs.get("apis", []) or [])
        seed_strings = " ".join(seed_attrs.get("strings", []) or [])
        bridge_apis = " ".join(bridge_attrs.get("apis", []) or [])
        bridge_strings = " ".join(bridge_attrs.get("strings", []) or [])
        cand_apis = " ".join(candidate_attrs.get("apis", []) or [])
        cand_strings = " ".join(candidate_attrs.get("strings", []) or [])

        seed_text = (
            f"name={seed_attrs.get('name','')} segment={seed_attrs.get('segment','')} "
            f"size={seed_attrs.get('size',0)} cc={seed_attrs.get('cyclomatic_complexity',0)} "
            f"apis={seed_apis} strings={seed_strings} bridges={bridge_apis} {bridge_strings}"
        )
        cand_text = (
            f"name={candidate_attrs.get('name','')} segment={candidate_attrs.get('segment','')} "
            f"size={candidate_attrs.get('size',0)} cc={candidate_attrs.get('cyclomatic_complexity',0)} "
            f"apis={cand_apis} strings={cand_strings}"
        )

        embedder = self._get_embedder()
        if embedder is not None and BgeCodeEmbedder is not None:
            try:
                sv = embedder.embed(seed_text[:1200])
                cv = embedder.embed(cand_text[:1200])
                sim = float(BgeCodeEmbedder.cosine(sv, cv))
                return max(0.0, min(1.0, sim))
            except Exception:
                pass

        # Deterministic fallback: Jaccard on bridge/entity tokens (no weighted heuristics).
        s_tokens = set((seed_apis + " " + seed_strings + " " + bridge_apis + " " + bridge_strings).split())
        c_tokens = set((cand_apis + " " + cand_strings).split())
        if not s_tokens or not c_tokens:
            return 0.0
        inter = len(s_tokens.intersection(c_tokens))
        union = len(s_tokens.union(c_tokens))
        return float(inter) / float(max(1, union))

    def _pit_fusion(
        self,
        judge_scores: list[float],
        bridge_scores: list[float],
        alpha: float = 0.1,
    ) -> list[float]:
        """Percentile-rank (PIT) fusion of tripartite judge scores and bridge similarity.

        F(i) = (1 - alpha) * PIT_judge(i) + alpha * PIT_bridge(i)
        """
        def _pit(scores: list[float]) -> list[float]:
            if not scores:
                return []
            sorted_idx = sorted(range(len(scores)), key=lambda i: scores[i])
            ranks = [0.0] * len(scores)
            if len(scores) == 1:
                ranks[sorted_idx[0]] = 1.0
                return ranks
            for rank, idx in enumerate(sorted_idx):
                ranks[idx] = rank / float(len(scores) - 1)
            return ranks

        pit_judge = _pit(judge_scores)
        pit_bridge = _pit(bridge_scores)

        fused = []
        for i in range(len(judge_scores)):
            f = (1 - alpha) * pit_judge[i] + alpha * pit_bridge[i]
            fused.append(f)
        return fused

    def search_via_bridges(
        self,
        bridges: dict[str, list[str]],
        top_k: int = 20,
        exclude_ea: int | None = None,
        seed_ea: int | None = None,
    ) -> list[dict]:
        """Find functions that share bridge entities with the seed.

        Uses tripartite judging + PIT fusion for ranking.
        """
        if not bridges or not any(bridges.values()):
            return []

        # Precompute IDF weights for all bridge entities once
        idf_weights = self._compute_bridge_idf(
            bridge_apis=bridges.get("apis", []),
            bridge_strings=bridges.get("strings", []),
        )

        with self._conn() as conn:
            cur = conn.cursor()

            # Get seed attributes for tripartite judging
            seed_attrs = {}
            if seed_ea is not None:
                cur.execute(
                    "SELECT name, segment, size, entropy, cyclomatic_complexity, api_count, string_count FROM function_attrs WHERE ea = ?",
                    (seed_ea,)
                )
                row = cur.fetchone()
                if row:
                    seed_attrs = {
                        "name": row[0], "segment": row[1], "size": row[2],
                        "entropy": row[3], "cyclomatic_complexity": row[4],
                        "api_count": row[5], "string_count": row[6],
                        "apis": bridges.get("apis", []),
                        "strings": bridges.get("strings", []),
                    }

            # Collect all candidate EAs that match any bridge
            candidate_eas: set[int] = set()
            bridge_scores: dict[int, float] = {}

            api_bridges = bridges.get("apis", [])
            string_bridges = bridges.get("strings", [])

            if api_bridges:
                placeholders = ",".join("?" * len(api_bridges))
                cur.execute(
                    f"SELECT func_ea FROM function_apis WHERE api_name IN ({placeholders})",
                    tuple(api_bridges),
                )
                for row in cur.fetchall():
                    ea = row[0]
                    if exclude_ea is not None and ea == exclude_ea:
                        continue
                    candidate_eas.add(ea)
                    bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 2.0

            if string_bridges:
                placeholders = ",".join("?" * len(string_bridges))
                cur.execute(
                    f"SELECT func_ea FROM function_strings WHERE string_text IN ({placeholders})",
                    tuple(string_bridges),
                )
                for row in cur.fetchall():
                    ea = row[0]
                    if exclude_ea is not None and ea == exclude_ea:
                        continue
                    candidate_eas.add(ea)
                    bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 1.0

            if not candidate_eas:
                return []

            # Fetch candidate details
            placeholders = ",".join("?" * len(candidate_eas))
            cur.execute(
                f"""
                SELECT ea, name, segment, size, entropy, bb_count, call_count,
                       cyclomatic_complexity, api_count, string_count, xref_count,
                       has_loops, is_thunk, is_library
                FROM function_attrs
                WHERE ea IN ({placeholders})
                """,
                tuple(candidate_eas),
            )

            candidates = []
            for row in cur.fetchall():
                ea = row[0]
                cand_attrs = {
                    "name": row[1], "segment": row[2], "size": row[3],
                    "entropy": row[4], "bb_count": row[5], "call_count": row[6],
                    "cyclomatic_complexity": row[7], "api_count": row[8],
                    "string_count": row[9], "xref_count": row[10],
                    "has_loops": bool(row[11]), "is_thunk": bool(row[12]),
                    "is_library": bool(row[13]),
                }

                # IDF-weighted tripartite scoring (core of the multi-hop bridge algorithm)
                judge_score = self._tripartite_score(
                    seed_attrs, seed_attrs, cand_attrs, idf_weights=idf_weights
                ) if seed_attrs else 0.5

                # Bridge overlap count for observability (not used for ranking).
                bscore = bridge_scores.get(ea, 0.0)

                candidates.append({
                    "ea": hex(ea),
                    "attrs": cand_attrs,
                    "judge_score": judge_score,
                    "bridge_score": bscore,
                })

        # PIT fusion
        judge_scores = [c["judge_score"] for c in candidates]
        bridge_scores_list = [c["bridge_score"] for c in candidates]
        fused_scores = self._pit_fusion(judge_scores, bridge_scores_list, alpha=0.1)

        for i, c in enumerate(candidates):
            c["fused_score"] = round(fused_scores[i], 4)
            # Merge attrs into result
            result = dict(c["attrs"])
            result["ea"] = c["ea"]
            result["tripartite_score"] = round(c["judge_score"], 4)
            result["bridge_score"] = round(c["bridge_score"], 2)
            result["fused_score"] = c["fused_score"]
            candidates[i] = result

        candidates.sort(key=lambda x: x["fused_score"], reverse=True)
        return candidates[:top_k]

__all__ = [
    "MultiHopBridgeIndex",
    "_resolve_schemaboot_db_path",
]
