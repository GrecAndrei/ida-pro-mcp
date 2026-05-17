"""Shared embedding-first semantic helpers for tool-side fuzzy matching."""

from __future__ import annotations

import re
from typing import Mapping, Optional, Sequence

try:
    from ida_pro_mcp.host.intelligence import BgeCodeEmbedder
except Exception:
    try:
        from host.intelligence import BgeCodeEmbedder  # type: ignore
    except Exception:
        BgeCodeEmbedder = None  # type: ignore


_EMBEDDER = None
_EMB_CACHE: dict[str, list[float]] = {}
_EMB_CACHE_MAX = 1024


def _get_embedder():
    global _EMBEDDER
    if _EMBEDDER is not None:
        return _EMBEDDER
    if BgeCodeEmbedder is None:
        return None
    try:
        _EMBEDDER = BgeCodeEmbedder()
    except Exception:
        _EMBEDDER = None
    return _EMBEDDER


def _embed_text(text: str) -> Optional[list[float]]:
    txt = (text or "").strip().lower()
    if not txt:
        return None
    key = txt[:500]
    cached = _EMB_CACHE.get(key)
    if cached is not None:
        return cached
    embedder = _get_embedder()
    if embedder is None:
        return None
    try:
        vec = embedder.embed(key)
    except Exception:
        return None
    if len(_EMB_CACHE) >= _EMB_CACHE_MAX:
        try:
            _EMB_CACHE.pop(next(iter(_EMB_CACHE)))
        except Exception:
            _EMB_CACHE.clear()
    _EMB_CACHE[key] = vec
    return vec


def semantic_tokens(text: str) -> list[str]:
    """Extract lowercase alphanumeric tokens (length >= 2) for semantic matching."""
    if not text:
        return []
    return [tok for tok in re.findall(r"[A-Za-z0-9_]+", text.lower()) if len(tok) >= 2]


def semantic_score(
    query: str,
    candidate: str,
    *,
    substring_bonus: float = 60.0,
    fuzzy_bonus: float = 20.0,
    include_fuzzy: bool = True,
) -> float:
    """Compute semantic similarity score (higher is better, 0..120 scale)."""
    if not query or not candidate:
        return 0.0
    q = query.strip().lower()
    c = candidate.strip().lower()
    if not q or not c:
        return 0.0

    # Embedding-first similarity.
    qv = _embed_text(q)
    cv = _embed_text(c)
    if qv is not None and cv is not None and BgeCodeEmbedder is not None:
        try:
            sim = float(BgeCodeEmbedder.cosine(qv, cv))
            return max(0.0, min(120.0, sim * 120.0))
        except Exception:
            pass

    # Deterministic fallback: token-overlap only (no fuzzy heuristics).
    qt = set(semantic_tokens(q))
    ct = set(semantic_tokens(c))
    if not qt or not ct:
        return 0.0
    inter = len(qt.intersection(ct))
    union = len(qt.union(ct))
    jacc = float(inter) / float(max(1, union))
    return max(0.0, min(120.0, jacc * 120.0))


def normalize_action(
    raw_action: Optional[str],
    *,
    actions: Sequence[str],
    aliases: Mapping[str, str],
    fallback: str,
    threshold: float,
    substring_bonus: float = 60.0,
) -> str:
    """Normalize action via exact action, alias map, then semantic fuzzy matching."""
    action = (raw_action or "").strip().lower()
    action_set = set(actions)
    if action in action_set:
        return action
    if action in aliases:
        return aliases[action]
    if not action:
        return fallback

    best = fallback
    best_score = 0.0
    for cand in action_set:
        score = semantic_score(action, cand, substring_bonus=substring_bonus)
        if score > best_score:
            best = cand
            best_score = score
    for alias, mapped in aliases.items():
        score = semantic_score(action, alias, substring_bonus=substring_bonus)
        if score > best_score:
            best = mapped
            best_score = score
    return best if best_score >= threshold else fallback
