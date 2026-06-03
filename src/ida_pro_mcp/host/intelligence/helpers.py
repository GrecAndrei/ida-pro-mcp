from __future__ import annotations

import difflib
import math
import struct
import time
from typing import Any, Callable, Dict, List, Sequence

def _q(vals: List[float], q: float, default: float = 0.0) -> float:
    if not vals:
        return float(default)
    s = sorted(float(v) for v in vals)
    if len(s) == 1:
        return s[0]
    i = int(round((len(s) - 1) * max(0.0, min(1.0, float(q)))))
    i = max(0, min(len(s) - 1, i))
    return float(s[i])


# Public alias for the quantile helper. ``_q`` is kept for back-compat with
# existing imports; new code should use ``quantile``.
quantile = _q


def dot_product(a: Sequence[float], b: Sequence[float]) -> float:
    """Sum of elementwise products. Equivalent to cosine similarity when
    both inputs are pre-normalized to unit length — the convention used by
    the BgeCodeEmbedder output vectors."""
    try:
        import numpy as np
        return float(np.dot(a, b))
    except ImportError:
        return sum(x * y for x, y in zip(a, b))


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """True cosine similarity with safe zero-norm fallback."""
    dot = dot_product(a, b)
    na = math.sqrt(sum(float(x) * float(x) for x in a))
    nb = math.sqrt(sum(float(x) * float(x) for x in b))
    if na < 1e-9 or nb < 1e-9:
        return 0.0
    return dot / (na * nb)


def pack_floats(vec: Sequence[float]) -> bytes:
    """Pack a list of floats into a raw little-endian float32 blob."""
    return struct.pack(f"{len(vec)}f", *vec)


def unpack_floats(blob: bytes) -> List[float]:
    """Inverse of :func:`pack_floats`."""
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def estimate_tokens(text) -> int:
    """Approximate token count for a string (~4 chars per token).

    Returns 0 for empty / falsy input. This is intentionally a rough
    heuristic — it matches the convention already used in
    ``llm_helpers._estimate_tokens`` and the inline ``len(text) // 4``
    expressions scattered through ``host/context_density.py``.
    """
    return len(text) // 4 if text else 0


def similarity_ratio(a: str, b: str) -> float:
    """Thin wrapper around :class:`difflib.SequenceMatcher` for two-string
    similarity. Returns a float in [0.0, 1.0]."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def best_match(
    query: str,
    choices: List[str],
    *,
    n: int = 1,
    cutoff: float = 0.6,
) -> List[str]:
    """Wrap :func:`difflib.get_close_matches` so callers don't need to
    import difflib directly. Returns at most *n* matches above *cutoff*."""
    return difflib.get_close_matches(query or "", choices, n=n, cutoff=cutoff)


def coerce_int(value, default: int = 0) -> int:
    """Coerce a string / int to an int with a hex prefix fallback.

    Replaces the inline ``int(s, 16) if s.startswith("0x") else int(s)``
    pattern that recurs in ~10 places across the host package. Returns
    *default* if the value can't be parsed as an integer in any base.

    Note: this is intentionally narrower than
    :func:`ida_pro_mcp.ida_mcp.utils.parse_address` — it does not attempt
    symbol resolution. Use ``parse_address`` if you need symbol lookup.
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(s)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_str_list(value, sep: str = ",") -> List[str]:
    """Parse a CSV-style string into a list of trimmed non-empty items.

    If *value* is already a list/tuple, each element is trimmed and
    ``None`` entries are dropped. If *value* is empty / None, returns [].
    Otherwise splits on *sep* and trims.

    Replaces the inline ``[x.strip() for x in s.split(",") if x.strip()]``
    pattern that recurs in ~20 places across the host package.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if x is not None and str(x).strip()]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        return [p.strip() for p in s.split(sep) if p.strip()]
    s = str(value).strip()
    if not s:
        return []
    return [p.strip() for p in s.split(sep) if p.strip()]


def compact_policy_blob(sess_blob: Dict[str, Any]) -> Dict[str, Any]:
    """Bound policy size by pruning low-value/high-cardinality history."""
    out = dict(sess_blob or {})
    rm = dict(out.get("retrieval_metrics") or {})
    ff = dict(out.get("focus_feedback") or {})

    keep_rm: Dict[str, int] = {}
    for src in ("address_linked", "relation_linked", "api_linked", "semantic_linked"):
        for key in ("total", "accepted", "kept"):
            k = f"{src}.{key}"
            if k in rm:
                try:
                    keep_rm[k] = int(rm[k])
                except Exception:
                    pass
    out["retrieval_metrics"] = keep_rm

    keep_ff: Dict[str, int] = {}
    for k in ("suggested", "followed", "successful", "failed"):
        if k in ff:
            try:
                keep_ff[k] = int(ff[k])
            except Exception:
                pass
    action_totals: Dict[str, int] = {}
    for k, v in ff.items():
        if not str(k).startswith("action."):
            continue
        parts = str(k).split(".")
        if len(parts) != 3:
            continue
        ta = parts[1]
        try:
            action_totals[ta] = action_totals.get(ta, 0) + int(v)
        except Exception:
            pass
    top_actions = sorted(action_totals.items(), key=lambda kv: kv[1], reverse=True)[:24]
    top_set = {ta for ta, _ in top_actions}
    for k, v in ff.items():
        if not str(k).startswith("action."):
            continue
        parts = str(k).split(".")
        if len(parts) != 3:
            continue
        ta = parts[1]
        if ta in top_set:
            try:
                keep_ff[k] = int(v)
            except Exception:
                pass
    out["focus_feedback"] = keep_ff

    try:
        thr = float(out.get("semantic_threshold") or 0.5)
    except Exception:
        thr = 0.5
    out["semantic_threshold"] = max(0.35, min(0.75, thr))
    out["schema_version"] = 2
    return out


def prune_policy_store(data: Dict[str, Any], max_sessions: int = 24) -> Dict[str, Any]:
    """Prune policy store to bounded session count and compact blobs."""
    if not isinstance(data, dict):
        return {"schema_version": 2, "sessions": {}}
    sessions = data.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}
    compacted: Dict[str, Dict[str, Any]] = {}
    for sid, blob in sessions.items():
        if not isinstance(blob, dict):
            continue
        compacted[str(sid)] = compact_policy_blob(blob)
    ordered = sorted(
        compacted.items(),
        key=lambda kv: float((kv[1] or {}).get("saved_at") or 0.0),
        reverse=True,
    )[:max(1, max_sessions)]
    return {
        "schema_version": 2,
        "updated_at": time.time(),
        "sessions": {sid: blob for sid, blob in ordered},
    }


def derive_focus_candidates(
    *,
    pack: Dict[str, Any],
    addr: str,
    policy: Dict[str, Dict[str, Any]],
    stats: Dict[str, Any],
    bias_fn: Callable[[str, str], float],
) -> List[Dict[str, Any]]:
    """Return ranked focus candidates (best first)."""
    if not addr:
        return []
    structural = pack.get("structural") or {}
    related = pack.get("related_findings") or []
    apis = pack.get("api_calls") or []
    candidates: List[Dict[str, Any]] = []

    sem_weight = float((policy.get("semantic_linked") or {}).get("weight", 0.9))
    rel_weight = float((policy.get("relation_linked") or {}).get("weight", 1.2))
    api_weight = float((policy.get("api_linked") or {}).get("weight", 1.0))
    sem_hit = float((stats.get("semantic_linked") or {}).get("hit_rate", 0.0))
    rel_hit = float((stats.get("relation_linked") or {}).get("hit_rate", 0.0))
    api_hit = float((stats.get("api_linked") or {}).get("hit_rate", 0.0))
    wvals = [sem_weight, rel_weight, api_weight]
    hvals = [sem_hit, rel_hit, api_hit]
    wq50 = _q(wvals, 0.50, default=1.0)
    wq75 = _q(wvals, 0.75, default=1.1)
    hq50 = _q(hvals, 0.50, default=0.3)
    hq75 = _q(hvals, 0.75, default=0.4)
    weight_gate = wq50 + max(0.0, wq75 - wq50)
    hit_gate = hq50 + max(0.0, hq75 - hq50)

    if related and rel_weight >= weight_gate and rel_hit >= hit_gate:
        bias = bias_fn("code", "callers")
        candidates.append({
            "tool": "code", "action": "callers", "addr": addr,
            "reason": "High-yield relation-linked findings; expand call-chain context",
            "score": round((rel_weight + rel_hit) * bias, 3), "bias": bias,
        })

    entropy = float(structural.get("entropy") or 0.0)
    xor_count = int(structural.get("xor_count") or 0)
    cyclo = int(structural.get("cyclomatic_complexity") or 0)
    struct_sig = (
        min(1.0, entropy / 8.0)
        + min(1.0, xor_count / max(1.0, xor_count + 4.0))
        + min(1.0, cyclo / max(1.0, cyclo + 12.0))
    ) / 3.0
    if struct_sig >= 0.4:
        bias = bias_fn("code", "blocks")
        candidates.append({
            "tool": "code", "action": "blocks", "addr": addr,
            "reason": "Structural complexity/obfuscation indicators are elevated",
            "score": round((1.0 + struct_sig) * bias, 3),
            "bias": bias,
        })

    if apis and api_weight >= wq50 and api_hit >= hq50:
        bias = bias_fn("search", "api")
        candidates.append({
            "tool": "search", "action": "api", "pattern": apis[0],
            "reason": "API-linked retrieval is productive; pivot on top API behavior",
            "score": round((api_weight + api_hit) * bias, 3), "bias": bias,
        })

    sem_ready = sem_weight >= wq50 or sem_hit >= hq50
    # Prefer structural/code pivots when no relational/API evidence exists.
    if sem_ready and (related or apis):
        bias = bias_fn("search", "semantic")
        candidates.append({
            "tool": "search", "action": "semantic", "addr": addr,
            "reason": "Semantic retrieval quality is acceptable; broaden semantic neighborhood",
            "score": round((sem_weight + sem_hit) * bias, 3), "bias": bias,
        })

    bias = bias_fn("code", "callees")
    candidates.append({
        "tool": "code", "action": "callees", "addr": addr,
        "reason": "Default structural pivot to progress analysis graph",
        "score": round(0.5 * bias, 3), "bias": bias,
    })
    candidates.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
    return candidates[:4]
