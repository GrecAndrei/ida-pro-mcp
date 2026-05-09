from __future__ import annotations

import math
from typing import Dict, List


def shannon_entropy(byte_hist: List[int], total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in byte_hist:
        if c <= 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


def ascii_run_stats(data: bytes, min_len: int = 6) -> Dict[str, int]:
    runs = 0
    longest = 0
    cur = 0
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur += 1
        else:
            if cur >= min_len:
                runs += 1
                if cur > longest:
                    longest = cur
            cur = 0
    if cur >= min_len:
        runs += 1
        if cur > longest:
            longest = cur
    return {"runs": runs, "longest": longest}


def cluster_pointer_hits(hits: List[Dict], ptr_size: int, max_gap_entries: int = 2) -> List[Dict]:
    """
    Group pointer hits into contiguous clusters to identify table-like regions.
    Input hit item expected shape: {ea, value, score}
    """
    if not hits:
        return []
    hs = sorted(hits, key=lambda x: int(x.get("ea") or 0))
    clusters: List[Dict] = []
    cur = [hs[0]]
    max_gap = max(1, max_gap_entries) * max(1, ptr_size)

    for h in hs[1:]:
        prev = cur[-1]
        if int(h.get("ea") or 0) - int(prev.get("ea") or 0) <= max_gap:
            cur.append(h)
            continue
        clusters.append(_cluster_from(cur, ptr_size))
        cur = [h]
    clusters.append(_cluster_from(cur, ptr_size))
    clusters.sort(key=lambda x: (x["score"], x["entries"]), reverse=True)
    return clusters


def _cluster_from(items: List[Dict], ptr_size: int) -> Dict:
    start = int(items[0].get("ea") or 0)
    end = int(items[-1].get("ea") or 0) + max(1, ptr_size)
    scores = [float(i.get("score") or 0.0) for i in items]
    mean_score = sum(scores) / max(1, len(scores))
    return {
        "start": start,
        "end": end,
        "entries": len(items),
        "score": round(mean_score, 3),
        "targets_preview": [int(i.get("value") or 0) for i in items[:8]],
    }


def build_carve_plan(region_stats: Dict, ptr_count: int, table_count: int) -> Dict:
    """Generate staged carve plan from region/profile signals."""
    unknown_ratio = float(region_stats.get("unknown_ratio") or 0.0)
    entropy = float(region_stats.get("entropy") or 0.0)
    ascii_runs = int(region_stats.get("ascii_runs") or 0)

    phases = []
    if ptr_count > 0 or table_count > 0:
        phases.append({
            "phase": "pointer-first",
            "reason": "pointer/table evidence present",
            "priority": "high",
        })
    if ascii_runs > 0:
        phases.append({
            "phase": "string-pass",
            "reason": "printable runs detected",
            "priority": "medium",
        })
    phases.append({
        "phase": "residual-data",
        "reason": "normalize remaining unknown bytes",
        "priority": "medium" if unknown_ratio > 0.2 else "low",
    })

    risk = "low"
    if entropy >= 7.2:
        risk = "high"
    elif entropy >= 6.0 or unknown_ratio >= 0.45:
        risk = "medium"

    return {
        "risk": risk,
        "unknown_ratio": round(unknown_ratio, 3),
        "entropy": round(entropy, 3),
        "ptr_count": int(ptr_count),
        "table_count": int(table_count),
        "phases": phases,
    }


def region_priority_score(profile: Dict, plan: Dict, cluster_count: int = 0) -> float:
    """Compute triage priority for a firmware region."""
    unknown_ratio = float(profile.get("unknown_ratio") or 0.0)
    entropy = float(profile.get("entropy") or 0.0)
    ptr_density = float(profile.get("pointer_density") or 0.0)
    ascii_runs = int(profile.get("ascii_runs") or 0)
    risk = str(plan.get("risk") or "low")
    risk_boost = 0.0
    if risk == "high":
        risk_boost = 0.35
    elif risk == "medium":
        risk_boost = 0.18
    score = (
        unknown_ratio * 0.28
        + min(1.0, entropy / 8.0) * 0.24
        + min(1.0, ptr_density * 3.0) * 0.22
        + min(1.0, cluster_count / 12.0) * 0.16
        + min(1.0, ascii_runs / 20.0) * 0.10
        + risk_boost
    )
    return round(min(1.99, score), 4)


def rank_region_plans(items: List[Dict], limit: int = 12) -> List[Dict]:
    """Rank campaign/segment region plans by computed priority."""
    ranked = sorted(
        items,
        key=lambda x: (
            float(x.get("priority_score") or 0.0),
            float((x.get("plan") or {}).get("entropy") or 0.0),
            float((x.get("profile") or {}).get("unknown_ratio") or 0.0),
        ),
        reverse=True,
    )
    return ranked[: max(1, int(limit))]
