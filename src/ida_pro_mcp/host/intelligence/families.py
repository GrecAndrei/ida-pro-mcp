"""Function families — cluster lookalike functions by embedding cosine.

The embedding index gives every function a vector. Functions that "look alike"
(reused logic, renamed wrappers, compiler-generated variants, copy-paste
families) cluster tightly in that space.  This module finds those clusters and
describes each one so an agent can examine one representative and skip the rest
with confidence.

Clustering is deterministic connected-components on a cosine threshold (a
greedy union-find over the pairwise similarity matrix, computed in numpy
chunks).  No scikit-learn dependency — numpy is already a runtime dep.

Each family carries:
  - a centroid summary (shared signature tokens, member count, representative)
  - a representative member (closest to the centroid, named preferred)
  - a per-member delta vs the representative (what each variant adds/omits)
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

import numpy as np

# Chunk size for the pairwise similarity scan: bounds peak memory without
# building the full NxN matrix at once.
_SIM_CHUNK = 512


def _ea_sort_key(ea: Any) -> int:
    """Best-effort integer sort key for an EA string.

    The embedding index keys functions by their EA as a string. Most are
    ``0x``-prefixed hex, but the index format is not part of this module's
    contract: a bare hex string, a decimal string, or a symbolic name must
    never abort the whole clustering run. Parse leniently — Python-literal
    syntax first, then bare hex, then decimal — and fall back to a stable
    hash so a malformed value still sorts deterministically.
    """
    s = str(ea).strip()
    if not s:
        return 0
    for base in (0, 16, 10):
        try:
            return int(s, base)
        except ValueError:
            continue
    return hash(s) & 0x7FFFFFFF


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(text or "")))


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def compute_function_families(
    idx,
    *,
    min_size: int = 2,
    min_similarity: float = 0.85,
    address_ranges: list[tuple[int, int]] | None = None,
    name_filter: str = "",
    max_functions: int = 4000,
    limit: int = 25,
) -> dict:
    """Cluster the indexed functions and describe each family.

    Args:
        idx: a FunctionEmbeddingIndex with a populated ``_cache``.
        min_size: minimum family size to report (default 2).
        min_similarity: cosine threshold for "lookalike" (default 0.85).
        address_ranges: optional [(start, end)] scope.
        name_filter: optional substring filter on function names.
        max_functions: cap on how many functions are clustered at once
            (unbounded runs exceed memory; scope the binary for big ones).
        limit: maximum number of families to return.

    Returns a dict with ``families`` and summary counts, ready to embed in a
    tool response.
    """
    snapshot = idx._similarity_candidates(None, address_ranges)
    if not snapshot:
        return {"families": [], "clustered": 0, "singletons": 0, "families_found": 0}

    rows: list[tuple[str, str, np.ndarray]] = []  # (ea, name, normalized vec)
    for ea, vec in snapshot:
        if not isinstance(vec, (list, tuple)) or not vec:
            continue
        try:
            arr = np.asarray([float(x) for x in vec], dtype=np.float64)
        except (TypeError, ValueError):
            continue
        if arr.size == 0:
            continue
        name = idx._row_meta_for_eas([ea]).get(ea, {}).get("name", ea)
        if name_filter and name_filter.lower() not in str(name).lower():
            continue
        norm = np.linalg.norm(arr) or 1.0
        rows.append((ea, str(name), arr / norm))
        if len(rows) >= max_functions:
            break

    if len(rows) < max(2, min_size):
        return {"families": [], "clustered": len(rows), "singletons": len(rows),
                "families_found": 0}

    eas = [r[0] for r in rows]
    names = [r[1] for r in rows]
    mat = np.stack([r[2] for r in rows])

    uf = _UnionFind(len(rows))
    n = len(rows)
    for start in range(0, n, _SIM_CHUNK):
        block = mat[start:start + _SIM_CHUNK]
        sims = block @ mat.T
        for i_local, i in enumerate(range(start, min(start + _SIM_CHUNK, n))):
            # Only connect to strictly-later indices so each pair is checked once.
            for j in range(i + 1, n):
                if sims[i_local, j] >= min_similarity:
                    uf.union(i, j)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)

    meta = idx._row_meta_for_eas(eas)
    docs = getattr(idx, "_row_docs_for_eas", None)
    doc_text = docs(eas) if callable(docs) else {}

    families = []
    for group in groups.values():
        if len(group) < min_size:
            continue
        members = sorted(group, key=lambda i: _ea_sort_key(eas[i]))
        sub = mat[members]
        centroid = sub.mean(axis=0)
        cn = np.linalg.norm(centroid) or 1.0
        centroid = centroid / cn
        sims_c = (sub @ centroid).tolist()

        # Representative: prefer a named function, then closest to centroid.
        candidates = sorted(
            range(len(members)),
            key=lambda k: (
                1 if names[members[k]].startswith(("sub_", "j_", "loc_")) else 0,
                -sims_c[k],
                _ea_sort_key(eas[members[k]]),
            ),
        )
        rep_idx = candidates[0]
        rep_ea = eas[members[rep_idx]]
        rep_name = names[members[rep_idx]]
        rep_tokens = _tokenize(doc_text.get(rep_ea, meta.get(rep_ea, {}).get("signature_text", "")))

        member_rows = []
        deltas = []
        for k in range(len(members)):
            ea = eas[members[k]]
            name = names[members[k]]
            entry = {"ea": ea, "name": name, "similarity": round(sims_c[k], 4),
                     "representative": ea == rep_ea}
            member_rows.append(entry)
            if ea != rep_ea:
                text = doc_text.get(ea, meta.get(ea, {}).get("signature_text", ""))
                tokens = _tokenize(text)
                added = sorted(tokens - rep_tokens)[:8]
                missing = sorted(rep_tokens - tokens)[:8]
                delta = [f"+{t}" for t in added] + [f"-{t}" for t in missing]
                deltas.append({**entry, "delta": delta})

        # Shared signature tokens = the family fingerprint.
        token_counts: dict[str, int] = defaultdict(int)
        for ea, _name, _vec in rows:
            if ea in {member_rows[k]["ea"] for k in range(len(member_rows))}:
                text = doc_text.get(ea, meta.get(ea, {}).get("signature_text", ""))
                for tok in _tokenize(text):
                    token_counts[tok] += 1
        shared = sorted(
            (t for t, c in token_counts.items() if c >= len(member_rows)),
            key=lambda t: -token_counts[t],
        )[:12]

        families.append(
            {
                "id": hex(_ea_sort_key(rep_ea)),
                "size": len(member_rows),
                "representative": {"ea": rep_ea, "name": rep_name},
                "centroid_similarity": round(float(max(sims_c)), 4),
                "members": member_rows,
                "deltas": deltas,
                "summary": (
                    f"{len(member_rows)} functions share "
                    f"{', '.join(shared[:8]) or 'a similar body'}"
                    f"; representative {rep_name} ({rep_ea})."
                ),
            }
        )

    families.sort(key=lambda f: (-f["size"], f["id"]))
    families = families[:limit]
    return {
        "families": families,
        "clustered": len(rows),
        "singletons": sum(len(g) for g in groups.values() if len(g) < min_size),
        "families_found": len(families),
        "scope": {
            "functions_considered": len(rows),
            "min_similarity": min_similarity,
            "min_size": min_size,
        },
    }
