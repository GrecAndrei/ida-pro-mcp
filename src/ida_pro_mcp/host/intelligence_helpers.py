from __future__ import annotations

import time
from typing import Any, Callable, Dict, List


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

    if related and rel_weight >= 1.1 and rel_hit >= 0.35:
        bias = bias_fn("code", "callers")
        candidates.append({
            "tool": "code", "action": "callers", "addr": addr,
            "reason": "High-yield relation-linked findings; expand call-chain context",
            "score": round((rel_weight + rel_hit) * bias, 3), "bias": bias,
        })

    entropy = float(structural.get("entropy") or 0.0)
    xor_count = int(structural.get("xor_count") or 0)
    cyclo = int(structural.get("cyclomatic_complexity") or 0)
    if entropy >= 6.0 or xor_count >= 4 or cyclo >= 18:
        bias = bias_fn("code", "blocks")
        candidates.append({
            "tool": "code", "action": "blocks", "addr": addr,
            "reason": "Structural complexity/obfuscation indicators are elevated",
            "score": round(max(1.0, entropy / 6.0 + xor_count * 0.2 + cyclo * 0.03) * bias, 3),
            "bias": bias,
        })

    if apis and api_weight >= 1.0 and api_hit >= 0.25:
        bias = bias_fn("search", "api")
        candidates.append({
            "tool": "search", "action": "api", "pattern": apis[0],
            "reason": "API-linked retrieval is productive; pivot on top API behavior",
            "score": round((api_weight + api_hit) * bias, 3), "bias": bias,
        })

    if sem_weight >= 0.95 or sem_hit >= 0.4:
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
