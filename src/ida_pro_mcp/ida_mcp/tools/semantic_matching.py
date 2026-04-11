"""Shared semantic tokenization/scoring helpers for tool-side fuzzy matching."""

from __future__ import annotations

import difflib
import re
from typing import Mapping, Optional, Sequence


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
    """Compute semantic similarity score (higher is better)."""
    if not query or not candidate:
        return 0.0
    q = query.strip().lower()
    c = candidate.strip().lower()
    if not q or not c:
        return 0.0

    score = 0.0
    if q == c:
        score += 120.0
    if q in c:
        score += substring_bonus

    qt = set(semantic_tokens(q))
    ct = set(semantic_tokens(c))
    if qt and ct:
        score += (len(qt.intersection(ct)) / max(1, len(qt))) * 45.0

    if include_fuzzy and fuzzy_bonus > 0:
        score += difflib.SequenceMatcher(a=q, b=c).ratio() * fuzzy_bonus
    return score


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
