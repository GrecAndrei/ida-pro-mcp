"""Shared embedding-first semantic helpers for tool-side fuzzy matching."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Optional

try:
    from ida_pro_mcp.services import BgeCodeEmbedder
except Exception:
    try:
        from host.intelligence.core import BgeCodeEmbedder  # type: ignore
    except Exception:
        BgeCodeEmbedder = None  # type: ignore


_EMBEDDER = None
_EMB_CACHE: dict[str, list[float]] = {}
_EMB_CACHE_MAX = 1024

# Deterministic scores at/above this are treated as decisive: native
# embedding rescoring cannot add meaningful signal, so it is skipped to keep
# CPU latency bounded on shared machines.
_DECISIVE_SCORE = 105.0
# Deterministic scores below this mean the texts are essentially unrelated.
# Embedding runs when the cheap score lands in the ambiguous band
# [30, 105): either because one side looks like a phrase (token overlap is a
# poor proxy for meaning there) or because the cheap score itself is already
# inside the band, even for short identifier-like text.
_EMBED_FLOOR = 30.0
# Texts at/above this length (or containing whitespace) count as phrase-like.
_MIN_PHRASE_LEN = 24
# Edit-similarity (Levenshtein) must clear this bar before the fuzzy bonus
# applies, so unrelated short names do not accumulate spurious scores.
_EDIT_SIM_FLOOR = 0.5

# Two-phase rescoring pool cap: at most this many candidates get batched
# embeddings per query; everything else keeps its deterministic score.
DEFAULT_RESCORE_TOP_N = 64
# When the deterministic top score clears this bar and beats the runner-up by
# at least this much, the winner is decisive and embedding rescoring is
# skipped entirely (keeps obvious lookups instant on slow machines).
_DECISIVE_TOP_SCORE = 90.0
_DECISIVE_TOP_GAP = 20.0

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


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


def _cache_key(text: str) -> str:
    return (text or "").strip().lower()[:500]


def _embed_batch(texts: Sequence[str]) -> dict[str, list[float]]:
    """Embed texts with one batched call, returning {key: vector} successes.

    Reuses the process-wide ``_EMB_CACHE`` so repeated queries and candidates
    never trigger a second native inference.
    """
    embedder = _get_embedder()
    if embedder is None:
        return {}
    keys = [_cache_key(t) for t in texts]
    missing: list[tuple[str, str]] = []
    out: dict[str, list[float]] = {}
    for key, txt in zip(keys, texts, strict=False):
        if not (txt or "").strip():
            continue
        cached = _EMB_CACHE.get(key)
        if cached is not None:
            out[key] = cached
        else:
            missing.append((key, txt))
    if not missing:
        return out
    batch_fn = getattr(embedder, "embed_documents", None)
    if batch_fn is None:
        return out
    try:
        results = batch_fn([txt for _, txt in missing])
    except Exception:
        return out
    for (key, _txt), res in zip(missing, results, strict=False):
        if res is None or not getattr(res, "ok", False) or not getattr(res, "vector", None):
            continue
        if len(_EMB_CACHE) >= _EMB_CACHE_MAX:
            try:
                _EMB_CACHE.pop(next(iter(_EMB_CACHE)))
            except Exception:
                _EMB_CACHE.clear()
        _EMB_CACHE[key] = res.vector
        out[key] = res.vector
    return out


def semantic_tokens(text: str) -> list[str]:
    """Extract lowercase alphanumeric tokens (length >= 2) for semantic matching."""
    if not text:
        return []
    return _subword_tokens(text)


# Trailing digit-run on a peripheral/instance name (uart0, gpio2, spi1).  The
# stem must be >= 3 letters so RISC-V ABI register names (x5, a0, t6) and hex
# addresses stay intact while peripheral instances still generalize across
# numbered units (uart0/uart1 both match a "uart" query).
_DIGIT_SUFFIX = re.compile(r"^([a-z]{3,})(\d+)$")


def _subword_tokens(text: str) -> list[str]:
    """Split identifiers into subword tokens (snake_case + camelCase).

    Camel boundaries must be split on the original case: lowercasing first
    (as the old code did) makes the ``[a-z0-9][A-Z]`` lookahead in
    ``_CAMEL_BOUNDARY`` unreachable, so mixed-case identifiers like
    ``getProcAddress`` collapsed to a single token.
    """
    out: list[str] = []
    for part in re.findall(r"[A-Za-z0-9_]+", text):
        for piece in re.split(r"_+", part):
            for word in _CAMEL_BOUNDARY.sub(" ", piece).split():
                word = word.lower()
                if len(word) >= 2:
                    out.append(word)
                    # RISC-V ABI names: split a trailing digit suffix off a
                    # peripheral stem so uart0 and uart2 share the "uart"
                    # token.  Guards keep short register/ABI names (x5, a0)
                    # and full hex addresses intact.
                    suffix = _DIGIT_SUFFIX.match(word)
                    if suffix is not None:
                        stem, digits = suffix.group(1), suffix.group(2)
                        if stem not in out:
                            out.append(stem)
                        if len(digits) >= 2 and digits not in out:
                            out.append(digits)
    return out


def semantic_score(
    query: str,
    candidate: str,
    *,
    substring_bonus: float = 60.0,
    fuzzy_bonus: float = 20.0,
    include_fuzzy: bool = True,
    return_detail: bool = False,
) -> float:
    """Compute semantic similarity score (higher is better, 0..120 scale).

    Deterministic scoring runs first.  Native embedding is consulted when the
    cheap score lands in the ambiguous band (neither decisive nor clearly
    unrelated): for phrase-like text, or when the cheap score itself is high
    enough (>= ``_EMBED_FLOOR``) that a short identifier/action could still
    benefit from embedding.
    """
    if not query or not candidate:
        return {"score": 0.0, "method": "exact"} if return_detail else 0.0
    q = query.strip().lower()
    c = candidate.strip().lower()
    if not q or not c:
        return {"score": 0.0, "method": "exact"} if return_detail else 0.0

    if q == c:
        return {"score": 120.0, "method": "exact"} if return_detail else 120.0

    cheap = semantic_score_cheap(
        query, candidate, substring_bonus=substring_bonus, include_fuzzy=include_fuzzy
    )
    phrase_like = _phrase_like(q) or _phrase_like(c)
    if cheap < _DECISIVE_SCORE and (phrase_like or cheap >= _EMBED_FLOOR):
        emb = _embedding_score(q, c)
        if emb is not None:
            return {"score": emb, "method": "embedding"} if return_detail else emb
    return {"score": cheap, "method": "tfidf_fallback"} if return_detail else cheap


def semantic_score_cheap(
    query: str,
    candidate: str,
    *,
    substring_bonus: float = 60.0,
    fuzzy_bonus: float = 20.0,
    include_fuzzy: bool = True,
) -> float:
    """Deterministic similarity score (0..120) with no native embedding.

    Exact match scores 120; otherwise TF-IDF-style cosine over word n-grams
    (identifiers split into subwords), plus a substring bonus when one text is
    contained in the other and an edit-similarity bonus for close typos.
    """
    if not query or not candidate:
        return 0.0
    q = query.strip().lower()
    c = candidate.strip().lower()
    if not q or not c:
        return 0.0
    if q == c:
        return 120.0

    # Tokenize from the original-case text: camel-boundary splitting is
    # case-aware, so lowercasing first would collapse mixed-case identifiers.
    q_tokens = _ngram_tokens(query)
    c_tokens = _ngram_tokens(candidate)
    if q_tokens and c_tokens:
        score = _tfidf_cosine_score(q_tokens, c_tokens)
    else:
        # Deterministic fallback: token-overlap only.
        qt = set(semantic_tokens(q))
        ct = set(semantic_tokens(c))
        if not qt or not ct:
            return 0.0
        inter = len(qt.intersection(ct))
        union = len(qt.union(ct))
        score = (float(inter) / float(max(1, union))) * 120.0
    if substring_bonus > 0.0 and (q in c or c in q):
        score += substring_bonus
    if include_fuzzy and fuzzy_bonus > 0.0:
        edit_sim = _edit_similarity(q, c)
        if edit_sim >= _EDIT_SIM_FLOOR:
            score += fuzzy_bonus * edit_sim
    return max(0.0, min(120.0, score))


def semantic_scores(
    query: str,
    candidates: Sequence[str],
    *,
    top_n: int = DEFAULT_RESCORE_TOP_N,
    substring_bonus: float = 60.0,
    include_fuzzy: bool = True,
    force_embed: bool = False,
) -> list[float]:
    """Score a candidate pool against a query (parallel to ``candidates``).

    Two-phase scoring keeps native embedding cost bounded regardless of pool
    size:

    1. Every candidate gets a deterministic score.
    2. For phrase-like queries, the top ``top_n`` candidates are re-embedded
       in a single batched call and their scores become embedding-first.

    Identifier-like queries skip phase 2 entirely (unless ``force_embed`` is
    set): token/ngram overlap is already decisive there, and the smart matcher
    filtered candidates first.
    """
    if not candidates:
        return []
    q = (query or "").strip().lower()
    q_orig = (query or "").strip()
    cheap = [
        semantic_score_cheap(
            q_orig, str(c or ""), substring_bonus=substring_bonus, include_fuzzy=include_fuzzy
        )
        for c in candidates
    ]
    if not q or (not force_embed and not _phrase_like(q)):
        return cheap
    embedder = _get_embedder()
    if embedder is None:
        return cheap
    if not force_embed and _winner_decisive(cheap):
        return cheap
    n = max(1, min(int(top_n or DEFAULT_RESCORE_TOP_N), len(candidates)))
    order = sorted(range(len(candidates)), key=lambda i: cheap[i], reverse=True)
    top = order[:n]
    texts = [str(candidates[i]) for i in top]
    if not any((t or "").strip() for t in texts):
        return cheap
    vecs = _embed_batch(texts + [q])
    qv = vecs.get(_cache_key(q))
    if qv is None:
        return cheap
    out = list(cheap)
    for i in top:
        cv = vecs.get(_cache_key(candidates[i]))
        if cv is None:
            continue
        try:
            sim = float(embedder.cosine(qv, cv))
            out[i] = max(0.0, min(120.0, sim * 120.0))
        except Exception:
            continue
    return out


def _embedding_score(query: str, candidate: str) -> Optional[float]:
    """Embedding-first cosine score (0..120) or None when unavailable."""
    vecs = _embed_batch([query, candidate])
    qv = vecs.get(_cache_key(query))
    cv = vecs.get(_cache_key(candidate))
    if qv is None or cv is None:
        return None
    embedder = _get_embedder()
    if embedder is None:
        return None
    try:
        sim = float(embedder.cosine(qv, cv))
    except Exception:
        return None
    return max(0.0, min(120.0, sim * 120.0))


def _phrase_like(text: str) -> bool:
    return " " in text or len(text) >= _MIN_PHRASE_LEN


def _winner_decisive(scores: Sequence[float]) -> bool:
    ranked = sorted((float(s) for s in scores if float(s) > 0.0), reverse=True)
    if not ranked or ranked[0] < _DECISIVE_TOP_SCORE:
        return False
    if len(ranked) == 1:
        return True
    return (ranked[0] - ranked[1]) >= _DECISIVE_TOP_GAP


def _ngram_tokens(text: str) -> list[str]:
    words = _subword_tokens(text)
    toks = list(words)
    toks.extend([" ".join(words[i:i + 2]) for i in range(max(0, len(words) - 1))])
    return toks


def _edit_similarity(a: str, b: str) -> float:
    """Normalized Levenshtein similarity in [0, 1] (1 == identical)."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return 1.0 - (prev[-1] / max(1, len(a)))


def _tfidf_cosine_score(qt: list[str], ct: list[str]) -> float:
    qcnt = Counter(qt)
    ccnt = Counter(ct)
    all_terms = set(qcnt) | set(ccnt)
    qv = {}
    cv = {}
    for t in all_terms:
        df = int(t in qcnt) + int(t in ccnt)
        idf = math.log((2.0 + 1.0) / (df + 1.0)) + 1.0
        qv[t] = qcnt.get(t, 0) * idf
        cv[t] = ccnt.get(t, 0) * idf
    dot = sum(qv[t] * cv[t] for t in all_terms)
    qn = math.sqrt(sum(v * v for v in qv.values()))
    cn = math.sqrt(sum(v * v for v in cv.values()))
    if qn <= 1e-12 or cn <= 1e-12:
        return 0.0
    sim = dot / (qn * cn)
    return max(0.0, min(120.0, sim * 120.0))


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
    # Sort the pool deterministically: on equal scores the first entry wins,
    # and set iteration order is nondeterministic across processes
    # (PYTHONHASHSEED), which would otherwise make the fallback unreliable.
    pool = [(cand, cand) for cand in sorted(action_set)]
    pool.extend((alias, mapped) for alias, mapped in sorted(aliases.items()))
    labels = [label for label, _ in pool]
    scores = semantic_scores(
        action,
        labels,
        top_n=len(labels),
        substring_bonus=substring_bonus,
        force_embed=True,
    )
    for (_label, mapped), score in zip(pool, scores, strict=False):
        if score > best_score:
            best = mapped
            best_score = score
    return best if best_score >= threshold else fallback
