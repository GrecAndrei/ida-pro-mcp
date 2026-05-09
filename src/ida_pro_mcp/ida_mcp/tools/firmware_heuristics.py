from __future__ import annotations

import math
import hashlib
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


def summarize_campaign_regions(regions: List[Dict]) -> Dict:
    """Aggregate high-level campaign stats across ranked regions."""
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    if not regions:
        return {
            "count": 0,
            "risk_counts": risk_counts,
            "avg_priority": 0.0,
            "max_priority": 0.0,
        }
    total_pri = 0.0
    max_pri = 0.0
    for r in regions:
        p = float(r.get("priority_score") or 0.0)
        total_pri += p
        if p > max_pri:
            max_pri = p
        rk = str((r.get("plan") or {}).get("risk") or "low")
        if rk not in risk_counts:
            rk = "low"
        risk_counts[rk] += 1
    return {
        "count": len(regions),
        "risk_counts": risk_counts,
        "avg_priority": round(total_pri / max(1, len(regions)), 4),
        "max_priority": round(max_pri, 4),
    }


def build_campaign_execution_plan(regions: List[Dict], max_steps: int = 18) -> List[Dict]:
    """
    Build a safe staged execution plan for top campaign regions.
    Defaults to dry-run first to reduce destructive mistakes.
    """
    steps: List[Dict] = []
    for idx, r in enumerate(regions):
        if len(steps) >= max_steps:
            break
        start = r.get("start")
        end = r.get("end")
        seg = r.get("segment") or f"region_{idx + 1}"
        steps.append({
            "step": len(steps) + 1,
            "tool": "firmware_view",
            "action": "campaign",
            "start": start,
            "end": end,
            "note": f"Deep profile and cluster review for {seg}",
        })
        if len(steps) >= max_steps:
            break
        steps.append({
            "step": len(steps) + 1,
            "tool": "firmware_view",
            "action": "smart_carve",
            "start": start,
            "end": end,
            "apply": False,
            "note": f"Dry-run carve for {seg}",
        })
        if len(steps) >= max_steps:
            break
        steps.append({
            "step": len(steps) + 1,
            "tool": "firmware_view",
            "action": "table_candidates",
            "start": start,
            "end": end,
            "note": f"Validate tables/pointers for {seg}",
        })
    return steps[:max_steps]


def region_fingerprint(region: Dict) -> str:
    """Stable region fingerprint for cross-image/cross-session deduping."""
    profile = region.get("profile") or {}
    plan = region.get("plan") or {}
    key = {
        "segment": region.get("segment") or "",
        "entropy": round(float(profile.get("entropy") or 0.0), 2),
        "unknown_ratio": round(float(profile.get("unknown_ratio") or 0.0), 2),
        "pointer_density": round(float(profile.get("pointer_density") or 0.0), 2),
        "ascii_runs": int(profile.get("ascii_runs") or 0),
        "risk": plan.get("risk") or "low",
        "phases": [p.get("phase") for p in (plan.get("phases") or [])[:3]],
    }
    raw = repr(sorted(key.items())).encode()
    return hashlib.sha1(raw).hexdigest()[:16]


def dedup_regions_by_fingerprint(regions: List[Dict]) -> List[Dict]:
    """Keep highest-priority representative per region fingerprint."""
    best: Dict[str, Dict] = {}
    for r in regions:
        fp = region_fingerprint(r)
        cur = best.get(fp)
        if cur is None or float(r.get("priority_score") or 0.0) > float(cur.get("priority_score") or 0.0):
            nr = dict(r)
            nr["fingerprint"] = fp
            best[fp] = nr
    out = list(best.values())
    out.sort(key=lambda x: float(x.get("priority_score") or 0.0), reverse=True)
    return out


def aggregate_fingerprint_scores(rows: List[Dict], limit: int = 24) -> List[Dict]:
    """Aggregate fingerprint evidence across images/sessions for reuse ranking."""
    agg: Dict[str, Dict] = {}
    for r in rows:
        fp = str(r.get("fingerprint") or "")
        if not fp:
            continue
        a = agg.setdefault(fp, {"fingerprint": fp, "count": 0, "priority_sum": 0.0, "max_priority": 0.0, "success": 0, "failure": 0, "examples": []})
        pri = float(r.get("priority_score") or 0.0)
        a["count"] += 1
        a["priority_sum"] += pri
        if pri > a["max_priority"]:
            a["max_priority"] = pri
        if len(a["examples"]) < 3:
            a["examples"].append({
                "segment": r.get("segment"),
                "start": r.get("start"),
                "end": r.get("end"),
                "priority_score": pri,
            })
        outcome = str(r.get("outcome") or "")
        if outcome == "success":
            a["success"] += 1
        elif outcome == "failure":
            a["failure"] += 1
    out = []
    for v in agg.values():
        v["avg_priority"] = round(v["priority_sum"] / max(1, v["count"]), 4)
        succ = int(v.get("success") or 0)
        fail = int(v.get("failure") or 0)
        sr = succ / max(1, succ + fail) if (succ + fail) > 0 else 0.5
        v["success_rate"] = round(sr, 4)
        v["score"] = round(
            v["avg_priority"] * 0.62
            + float(v["max_priority"]) * 0.18
            + min(1.0, v["count"] / 10.0) * 0.08
            + sr * 0.12,
            4,
        )
        out.append(v)
    out.sort(key=lambda x: (x["score"], x["count"]), reverse=True)
    return out[: max(1, int(limit))]


def apply_fingerprint_boost(regions: List[Dict], fp_rank: List[Dict], boost_cap: float = 0.35) -> List[Dict]:
    """Boost region priority scores using prior fingerprint corpus evidence."""
    if not regions or not fp_rank:
        return list(regions)
    fp_map = {str(x.get("fingerprint")): float(x.get("score") or 0.0) for x in fp_rank if x.get("fingerprint")}
    out = []
    for r in regions:
        nr = dict(r)
        fp = str(nr.get("fingerprint") or "")
        base = float(nr.get("priority_score") or 0.0)
        signal = fp_map.get(fp, 0.0)
        boost = min(boost_cap, signal * 0.22)
        if boost > 0:
            nr["priority_boost"] = round(boost, 4)
            nr["priority_score"] = round(base + boost, 4)
        out.append(nr)
    out.sort(key=lambda x: float(x.get("priority_score") or 0.0), reverse=True)
    return out
