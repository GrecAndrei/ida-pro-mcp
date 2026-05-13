try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .memrl import emit_memrl_suggestion
except ImportError:
    try:
        from memrl import emit_memrl_suggestion  # type: ignore[import-not-found]
    except ImportError:
        def emit_memrl_suggestion(*args, **kwargs):  # type: ignore
            return ""

try:
    from .blackboard import BlackboardStore
except ImportError:
    try:
        from blackboard import BlackboardStore  # type: ignore[import-not-found]
    except ImportError:
        BlackboardStore = None  # type: ignore

import json
import os
import time
import uuid

try:
    from .firmware_heuristics import (
        ascii_run_stats,
        build_campaign_execution_plan,
        build_carve_plan,
        cluster_pointer_hits,
        dedup_regions_by_fingerprint,
        aggregate_fingerprint_scores,
        apply_fingerprint_boost,
        rank_region_plans,
        region_fingerprint,
        region_priority_score,
        summarize_campaign_regions,
        shannon_entropy,
    )
except ImportError:
    from firmware_heuristics import (  # type: ignore[import-not-found]
        ascii_run_stats,
        build_campaign_execution_plan,
        build_carve_plan,
        cluster_pointer_hits,
        dedup_regions_by_fingerprint,
        aggregate_fingerprint_scores,
        apply_fingerprint_boost,
        rank_region_plans,
        region_fingerprint,
        region_priority_score,
        summarize_campaign_regions,
        shannon_entropy,
    )


def _is_64bit() -> bool:
    return _inf_is_64bit()


def _fw_state_path() -> str:
    # Use the same XDG-aware runtime directory as the rest of the project
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    root = (
        os.environ.get("IDA_MCP_CACHE_DIR")
        or os.environ.get("IDA_MCP_DATA_DIR")
        or os.path.join(xdg, "ida-pro-mcp")
    )
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "firmware_view_state.json")


def _load_fw_state() -> dict:
    p = _fw_state_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("history", [])
                data.setdefault("contradictions", [])
                data.setdefault("campaigns", {})
                data.setdefault("fingerprint_corpus", [])
                return data
    except Exception:
        pass
    return {"history": [], "contradictions": [], "campaigns": {}, "fingerprint_corpus": []}


def _save_fw_state(state: dict) -> None:
    p = _fw_state_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def _seg_bounds(start: str | None, end: str | None):
    if start is not None or end is not None:
        if start is None or end is None:
            return None, None, make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
        return validate_range(start, end)
    min_ea = _inf_min_ea()
    max_ea = _inf_max_ea()
    if min_ea in (None, idaapi.BADADDR) or max_ea in (None, idaapi.BADADDR):
        return None, None, make_error(
            MCPError.IDA_ERROR,
            "IDB bounds are unavailable; create/open a session before firmware_view range actions",
        )
    return min_ea, max_ea, None


def _item_kind(ea: int) -> str:
    f = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(f):
        return "code"
    if ida_bytes.is_strlit(f):
        return "string"
    if ida_bytes.is_data(f):
        return "data"
    return "unknown"


def _read_u64(ea: int, size: int):
    try:
        if size == 8:
            return ida_bytes.get_qword(ea)
        if size == 4:
            return ida_bytes.get_dword(ea)
        if size == 2:
            return ida_bytes.get_word(ea)
        return ida_bytes.get_byte(ea)
    except Exception:
        return None


def _addr_in_mapped(v: int) -> bool:
    try:
        return idaapi.getseg(v) is not None
    except Exception:
        return False


def _read_bytes_safe(start: int, end: int, cap: int = 1 << 20) -> bytes:
    """Best-effort range read, bounded to avoid huge allocations."""
    size = max(0, min(end - start, cap))
    if size <= 0:
        return b""
    try:
        return ida_bytes.get_bytes(start, size) or b""
    except Exception:
        return b""


def _create_ascii_string(ea: int, length: int) -> bool:
    """Create an ASCII string using the discovered run length when available."""
    target_len = length if length not in (None, idaapi.BADADDR) else idc.BADADDR
    try:
        return bool(idc.create_strlit(ea, target_len, getattr(idc, "STRTYPE_C", 0)))
    except TypeError:
        return bool(idc.create_strlit(ea, target_len))
    except Exception:
        return False


def _record_contradiction(state: dict, ea: int, old: str, new: str, reason: str, confidence: float = 0.7) -> None:
    sev = "low"
    if old == "code" and new in ("ptr", "make_ptr", "data", "make_data", "make_string"):
        sev = "high"
    elif old == "data" and new in ("code", "make_code"):
        sev = "medium"
    state.setdefault("contradictions", []).append(
        {
            "ts": int(time.time()),
            "ea": hex(ea),
            "old": old,
            "new": new,
            "reason": reason,
            "severity": sev,
            "confidence": round(max(0.0, min(1.0, confidence)), 3),
        }
    )


def _parse_executed_feedback(value) -> list:
    """Parse optional executed-step feedback payload for campaign_resume."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            v = json.loads(value)
            return v if isinstance(v, list) else []
        except Exception:
            return []
    return []


def _profile_range(s_ea: int, e_ea: int, ptr_size: int) -> dict:
    """Collect lightweight region profile primitives."""
    raw = _read_bytes_safe(s_ea, e_ea)
    hist = [0] * 256
    for b in raw:
        hist[b] += 1
    total = len(raw)
    ent = shannon_entropy(hist, total)
    ascii_stats = ascii_run_stats(raw, min_len=6)
    ptr_hits = 0
    ea = s_ea
    scanned = 0
    while ea + ptr_size <= e_ea and scanned < 4096:
        v = _read_u64(ea, ptr_size)
        if v is not None and _addr_in_mapped(int(v)):
            ptr_hits += 1
        scanned += 1
        ea += ptr_size
    ptr_density = (ptr_hits / max(1, scanned)) if scanned else 0.0
    # classify content mix (item-kind based)
    unknown = code = data = strings = 0
    ea = s_ea
    while ea < e_ea:
        k = _item_kind(ea)
        if k == "unknown":
            unknown += 1
        elif k == "code":
            code += 1
        elif k == "string":
            strings += 1
        else:
            data += 1
        ea += 1
    total_items = max(1, unknown + code + data + strings)
    return {
        "sampled_bytes": total,
        "entropy": round(ent, 4),
        "ascii_runs": ascii_stats["runs"],
        "longest_ascii_run": ascii_stats["longest"],
        "pointer_density": round(ptr_density, 4),
        "likely_packed": bool(ent >= 7.2 and ascii_stats["runs"] == 0),
        "unknown_ratio": round(unknown / total_items, 4),
        "unknown": unknown,
        "code": code,
        "data": data,
        "strings": strings,
        "ptr_hits_sampled": ptr_hits,
    }


@tool
@idawrite
def firmware_view(
    action: Annotated[Literal["scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates", "smart_carve", "rollback_last", "review_contradictions", "region_profile", "pointer_clusters", "carve_plan", "campaign", "segment_sweep", "multi_region_campaign", "campaign_checkpoint", "campaign_resume", "campaign_feedback", "fingerprint_index_sync", "fingerprint_index_query"], "Action: scan_region|auto_retype|pointer_sweep|recommend|table_candidates|smart_carve|rollback_last|review_contradictions|region_profile|pointer_clusters|carve_plan|campaign|segment_sweep|multi_region_campaign|campaign_checkpoint|campaign_resume|campaign_feedback|fingerprint_index_sync|fingerprint_index_query"],
    start: Annotated[Optional[str], "Range start address"] = None,
    end: Annotated[Optional[str], "Range end address"] = None,
    addr: Annotated[Optional[str], "Anchor address for recommend"] = None,
    campaign_id: Annotated[Optional[str], "Campaign ID for campaign_resume/campaign_checkpoint"] = None,
    stride: Annotated[int, "Pointer scan stride"] = 4,
    limit: Annotated[int, "Maximum suggested/applied items"] = 128,
    apply: Annotated[bool, "Apply suggested conversions (auto_retype)"] = False,
    snapshot_before_apply: Annotated[bool, "Create history snapshot before mutating actions"] = True,
    force: Annotated[bool, "Override contradiction guardrails"] = False,
    min_run: Annotated[int, "Minimum unknown run length"] = 16,
    auto_blackboard: Annotated[bool, "Store outcomes in blackboard"] = True,
    **kwargs,
) -> dict:
    """Smart firmware database shaping for raw blobs.

    Designed for LLM workflows that need IDA's micro-actions at scale:
    - scan_region: score unknown/code/data/string density and propose strategy
    - pointer_sweep: detect pointer-like cells in a range
    - auto_retype: propose/apply byte->ptr/string/code reinterpretations
    - recommend: next-best view actions near an anchor or whole binary
    """
    try:
        state = _load_fw_state()
        s_ea, e_ea, err = _seg_bounds(start, end)
        if err:
            return err

        limit = max(1, min(int(limit), 2048))
        stride = max(1, min(int(stride), 16))
        min_run = max(4, min(int(min_run), 4096))

        ptr_size = 8 if _is_64bit() else 4

        def _log_ml(result: dict, act: str, details: str):
            try:
                sug = emit_memrl_suggestion("firmware_view", act, hex(s_ea), details)
                if sug:
                    result["memrl_suggestion_id"] = sug
            except Exception:
                pass
            if auto_blackboard and BlackboardStore is not None:
                try:
                    store = BlackboardStore()
                    entry_id = store.write(
                        title=f"firmware_view:{act} {hex(s_ea)}-{hex(e_ea)}",
                        content=details,
                        category="firmware_view",
                        addr=hex(s_ea),
                        tags=["firmware", "raw-binary", "view-shaping", act],
                        confidence=0.8,
                    )
                    result["blackboard_entry_id"] = entry_id
                except Exception:
                    pass
            return result

        if action == "scan_region":
            unknown = code = data = strings = 0
            sample = []
            run_start = None
            run_len = 0
            long_runs = []
            ea = s_ea
            while ea < e_ea:
                kind = _item_kind(ea)
                if kind == "unknown":
                    unknown += 1
                    if run_start is None:
                        run_start = ea
                    run_len += 1
                else:
                    if run_start is not None and run_len >= min_run:
                        long_runs.append((run_start, run_len))
                    run_start = None
                    run_len = 0
                    if kind == "code":
                        code += 1
                    elif kind == "string":
                        strings += 1
                    else:
                        data += 1
                if len(sample) < 64 and kind == "unknown":
                    sample.append(hex(ea))
                ea += 1
            if run_start is not None and run_len >= min_run:
                long_runs.append((run_start, run_len))

            total = max(1, unknown + code + data + strings)
            unknown_ratio = unknown / total
            strategy = "mixed"
            if unknown_ratio > 0.55:
                strategy = "aggressive_retype"
            elif unknown_ratio > 0.25:
                strategy = "pointer_first"
            else:
                strategy = "semantic_followup"
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "stats": {
                    "unknown": unknown,
                    "code": code,
                    "data": data,
                    "strings": strings,
                    "unknown_ratio": round(unknown_ratio, 3),
                    "long_unknown_runs": [{"start": hex(x), "len": l} for x, l in long_runs[:limit]],
                },
                "strategy": strategy,
                "next_actions": [
                    f"firmware_view(action='pointer_sweep', start='{hex(s_ea)}', end='{hex(e_ea)}', stride={ptr_size})",
                    f"firmware_view(action='auto_retype', start='{hex(s_ea)}', end='{hex(e_ea)}', apply=false)",
                    f"search(action='semantic', pattern='init parser dispatch checksum', limit=60)",
                ],
            }
            return _log_ml(result, action, f"unknown_ratio={unknown_ratio:.3f}; strategy={strategy}")

        if action == "region_profile":
            prof = _profile_range(s_ea, e_ea, ptr_size)
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "profile": prof,
                "next_actions": [
                    f"firmware_view(action='pointer_clusters', start='{hex(s_ea)}', end='{hex(e_ea)}', stride={ptr_size})",
                    f"firmware_view(action='carve_plan', start='{hex(s_ea)}', end='{hex(e_ea)}')",
                ],
            }
            return _log_ml(result, action, f"entropy={prof['entropy']:.3f}; ptr_density={prof['pointer_density']:.3f}")

        if action == "pointer_sweep":
            candidates = []
            ea = s_ea
            while ea + ptr_size <= e_ea and len(candidates) < limit * 8:
                v = _read_u64(ea, ptr_size)
                if v is not None and _addr_in_mapped(int(v)):
                    score = 0.65
                    if idaapi.get_func(int(v)):
                        score += 0.2
                    if ida_bytes.is_loaded(int(v)):
                        score += 0.1
                    candidates.append({"ea": ea, "value": int(v), "score": round(min(score, 0.99), 3)})
                ea += stride
            candidates.sort(key=lambda x: (x["score"], x["ea"]), reverse=True)
            page = candidates[:limit]
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "pointer_size": ptr_size,
                "count": len(page),
                "total": len(candidates),
                "items": [{"address": hex(i["ea"]), "target": hex(i["value"]), "score": i["score"]} for i in page],
                "next_actions": [
                    "data_ops(action='make_ptr', addr='<top_item.address>')",
                    "data_ops(action='set_repr', addr='<top_item.address>', repr='offset')",
                    "search(action='code_ref', pattern='<top_item.target>', include_context=true)",
                ],
            }
            return _log_ml(result, action, f"ptr_candidates={len(candidates)}")

        if action == "auto_retype":
            if apply and snapshot_before_apply:
                try:
                    import ida_auto
                    ida_auto.auto_wait()
                except Exception:
                    pass
                try:
                    import ida_kernwin
                    ida_kernwin.process_ui_action("UndoCreateSnapshot")
                except Exception:
                    pass
            proposals = []
            applied = 0

            # propose pointers first
            ea = s_ea
            while ea + ptr_size <= e_ea and len(proposals) < limit:
                if _item_kind(ea) == "unknown":
                    v = _read_u64(ea, ptr_size)
                    if v is not None and _addr_in_mapped(int(v)):
                        proposals.append({"ea": ea, "kind": "ptr", "size": ptr_size, "value": int(v), "score": 0.9})
                ea += ptr_size

            # fallback: promote some unknown bytes to code candidates
            if len(proposals) < limit:
                ea = s_ea
                while ea < e_ea and len(proposals) < limit:
                    if _item_kind(ea) == "unknown":
                        mnem = (idc.print_insn_mnem(ea) or "").lower()
                        if mnem:
                            proposals.append({"ea": ea, "kind": "code", "size": 1, "score": 0.55})
                    ea += 1

            if apply:
                for p in proposals:
                    pea = p["ea"]
                    prev_kind = _item_kind(pea)
                    if p["kind"] == "ptr":
                        if prev_kind == "code" and not force:
                            _record_contradiction(state, pea, prev_kind, "ptr", "code_to_ptr_guard", confidence=0.82)
                            continue
                        if ida_bytes.create_data(pea, ida_bytes.qword_flag() if ptr_size == 8 else ida_bytes.dword_flag(), ptr_size, idaapi.BADADDR):
                            try:
                                idc.op_offset(pea, 0, idc.REF_OFF64 if ptr_size == 8 else idc.REF_OFF32, 0, 0, 0)
                            except Exception:
                                pass
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "auto_retype", "ea": hex(pea), "new_kind": "ptr", "prev_kind": prev_kind, "size": ptr_size})
                    elif p["kind"] == "code":
                        if prev_kind == "data" and not force:
                            _record_contradiction(state, pea, prev_kind, "code", "data_to_code_guard", confidence=0.74)
                            continue
                        if idc.create_insn(pea) > 0:
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "auto_retype", "ea": hex(pea), "new_kind": "code", "prev_kind": prev_kind, "size": 1})

                _save_fw_state(state)

            result = {
                "ok": True,
                "action": action,
                "apply": bool(apply),
                "proposals": [
                    {
                        "address": hex(p["ea"]),
                        "kind": p["kind"],
                        "size": p["size"],
                        "score": p["score"],
                        "target": hex(p["value"]) if "value" in p else None,
                    }
                    for p in proposals
                ],
                "count": len(proposals),
                "applied": applied,
                "next_actions": [
                    "firmware_view(action='scan_region', start='<same_start>', end='<same_end>')",
                    "search(action='semantic', pattern='dispatcher parser init table', limit=50)",
                    "llm_helpers(action='next_best_action_recommender', query='raw firmware triage around converted range')",
                ],
            }
            return _log_ml(result, action, f"proposals={len(proposals)}; applied={applied}")

        if action == "table_candidates":
            candidates = []
            ea = s_ea
            while ea + ptr_size * 3 <= e_ea and len(candidates) < limit * 6:
                ptrs = []
                valid = 0
                for i in range(6):
                    p_ea = ea + (i * ptr_size)
                    if p_ea + ptr_size > e_ea:
                        break
                    v = _read_u64(p_ea, ptr_size)
                    if v is None:
                        break
                    ptrs.append(int(v))
                    if _addr_in_mapped(int(v)):
                        valid += 1
                if len(ptrs) >= 4 and valid >= max(3, len(ptrs) - 1):
                    code_targets = sum(1 for v in ptrs if idaapi.get_func(v))
                    score = 0.55 + (valid / len(ptrs)) * 0.25 + (code_targets / max(1, len(ptrs))) * 0.2
                    candidates.append(
                        {
                            "start": ea,
                            "entries": len(ptrs),
                            "valid_ptrs": valid,
                            "code_targets": code_targets,
                            "score": round(min(score, 0.99), 3),
                            "targets_preview": ptrs[:5],
                        }
                    )
                    ea += ptr_size * len(ptrs)
                    continue
                ea += ptr_size
            candidates.sort(key=lambda x: (x["score"], x["entries"], x["start"]), reverse=True)
            page = candidates[:limit]
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "count": len(page),
                "total": len(candidates),
                "items": [
                    {
                        "start": hex(c["start"]),
                        "entries": c["entries"],
                        "valid_ptrs": c["valid_ptrs"],
                        "code_targets": c["code_targets"],
                        "score": c["score"],
                        "targets_preview": [hex(v) for v in c["targets_preview"]],
                    }
                    for c in page
                ],
                "next_actions": [
                    "data_ops(action='make_array', addr='<item.start>', size=<ptr_size>, count=<item.entries>)",
                    "data_ops(action='set_repr', addr='<item.start>', repr='offset')",
                    "search(action='semantic', pattern='switch dispatch jump table parser', limit=40)",
                ],
            }
            return _log_ml(result, action, f"table_candidates={len(candidates)}")

        if action == "pointer_clusters":
            hits = []
            ea = s_ea
            while ea + ptr_size <= e_ea and len(hits) < limit * 12:
                v = _read_u64(ea, ptr_size)
                if v is not None and _addr_in_mapped(int(v)):
                    score = 0.55
                    if idaapi.get_func(int(v)):
                        score += 0.25
                    if ida_bytes.is_loaded(int(v)):
                        score += 0.1
                    hits.append({"ea": ea, "value": int(v), "score": round(min(score, 0.99), 3)})
                ea += max(1, stride)
            clusters = cluster_pointer_hits(hits, ptr_size, max_gap_entries=2)
            page = clusters[:limit]
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "pointer_size": ptr_size,
                "clusters": [
                    {
                        "start": hex(c["start"]),
                        "end": hex(c["end"]),
                        "entries": c["entries"],
                        "score": c["score"],
                        "targets_preview": [hex(v) for v in c["targets_preview"]],
                    }
                    for c in page
                ],
                "count": len(page),
                "total_hits": len(hits),
                "next_actions": [
                    "firmware_view(action='table_candidates', start='<same_start>', end='<same_end>')",
                    "firmware_view(action='carve_plan', start='<same_start>', end='<same_end>')",
                ],
            }
            return _log_ml(result, action, f"clusters={len(clusters)}; hits={len(hits)}")

        if action == "carve_plan":
            prof = _profile_range(s_ea, e_ea, ptr_size)

            # light pointer/table evidence
            ptr_hits = 0
            ea = s_ea
            while ea + ptr_size <= e_ea and ptr_hits < limit * 16:
                v = _read_u64(ea, ptr_size)
                if v is not None and _addr_in_mapped(int(v)):
                    ptr_hits += 1
                ea += ptr_size
            table_ev = 0
            ea = s_ea
            while ea + ptr_size * 4 <= e_ea and table_ev < limit * 4:
                vals = []
                ok = 0
                for i in range(4):
                    vv = _read_u64(ea + i * ptr_size, ptr_size)
                    if vv is None:
                        break
                    vals.append(int(vv))
                    if _addr_in_mapped(int(vv)):
                        ok += 1
                if len(vals) == 4 and ok >= 3:
                    table_ev += 1
                    ea += ptr_size * 4
                else:
                    ea += ptr_size

            plan = build_carve_plan(
                {
                    "unknown_ratio": prof["unknown_ratio"],
                    "entropy": prof["entropy"],
                    "ascii_runs": prof["ascii_runs"],
                },
                ptr_count=ptr_hits,
                table_count=table_ev,
            )
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "plan": plan,
                "next_actions": [
                    "firmware_view(action='smart_carve', start='<same_start>', end='<same_end>', apply=false)",
                    "firmware_view(action='pointer_clusters', start='<same_start>', end='<same_end>')",
                    "firmware_view(action='region_profile', start='<same_start>', end='<same_end>')",
                ],
            }
            return _log_ml(result, action, f"risk={plan.get('risk')}; ptr={ptr_hits}; table={table_ev}")

        if action == "campaign":
            prof = _profile_range(s_ea, e_ea, ptr_size)
            # derive pointer clusters quickly
            hits = []
            ea = s_ea
            while ea + ptr_size <= e_ea and len(hits) < limit * 12:
                v = _read_u64(ea, ptr_size)
                if v is not None and _addr_in_mapped(int(v)):
                    score = 0.55
                    if idaapi.get_func(int(v)):
                        score += 0.25
                    if ida_bytes.is_loaded(int(v)):
                        score += 0.1
                    hits.append({"ea": ea, "value": int(v), "score": round(min(score, 0.99), 3)})
                ea += ptr_size
            clusters = cluster_pointer_hits(hits, ptr_size, max_gap_entries=2)

            plan = build_carve_plan(
                {
                    "unknown_ratio": prof["unknown_ratio"],
                    "entropy": prof["entropy"],
                    "ascii_runs": prof["ascii_runs"],
                },
                ptr_count=prof.get("ptr_hits_sampled", 0),
                table_count=len(clusters),
            )
            pri = region_priority_score(prof, plan, cluster_count=len(clusters))
            recs = [
                {
                    "tool": "firmware_view",
                    "action": "smart_carve",
                    "start": hex(s_ea),
                    "end": hex(e_ea),
                    "apply": False,
                    "reason": "Dry-run carve using staged plan before mutations.",
                },
                {
                    "tool": "firmware_view",
                    "action": "table_candidates",
                    "start": hex(s_ea),
                    "end": hex(e_ea),
                    "reason": "Validate clustered pointers as potential jump/data tables.",
                },
            ]
            if plan.get("risk") == "high":
                recs.insert(0, {
                    "tool": "search",
                    "action": "semantic",
                    "pattern": "decrypt unpack decode stage init",
                    "limit": 80,
                    "reason": "High-risk packed/decoder profile; map behavior before carving.",
                })
            result = {
                "ok": True,
                "action": action,
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "profile": prof,
                "clusters": [
                    {
                        "start": hex(c["start"]),
                        "end": hex(c["end"]),
                        "entries": c["entries"],
                        "score": c["score"],
                    }
                    for c in clusters[: min(limit, 12)]
                ],
                "plan": plan,
                "priority_score": pri,
                "recommendations": recs,
            }
            return _log_ml(result, action, f"priority={pri:.3f}; risk={plan.get('risk')}; clusters={len(clusters)}")

        if action == "segment_sweep":
            segs = []
            seg = idaapi.get_first_seg()
            while seg:
                if seg.end_ea > seg.start_ea:
                    try:
                        sname = idaapi.get_segm_name(seg) or ""
                    except Exception:
                        sname = ""
                    segs.append((int(seg.start_ea), int(seg.end_ea), sname))
                seg = idaapi.get_next_seg(seg.start_ea)
            regions = []
            for ss, ee, name in segs[: max(1, min(limit * 4, 128))]:
                # skip tiny segments
                if ee - ss < 64:
                    continue
                prof = _profile_range(ss, ee, ptr_size)
                plan = build_carve_plan(
                    {
                        "unknown_ratio": prof["unknown_ratio"],
                        "entropy": prof["entropy"],
                        "ascii_runs": prof["ascii_runs"],
                    },
                    ptr_count=prof.get("ptr_hits_sampled", 0),
                    table_count=0,
                )
                pri = region_priority_score(prof, plan, cluster_count=0)
                regions.append(
                    {
                        "segment": name,
                        "start": hex(ss),
                        "end": hex(ee),
                        "profile": {
                            "entropy": prof["entropy"],
                            "unknown_ratio": prof["unknown_ratio"],
                            "pointer_density": prof["pointer_density"],
                            "ascii_runs": prof["ascii_runs"],
                        },
                        "plan": {"risk": plan["risk"], "phases": plan.get("phases", [])[:2]},
                        "priority_score": pri,
                    }
                )
            ranked = rank_region_plans(regions, limit=max(1, min(limit * 2, 48)))
            ranked = dedup_regions_by_fingerprint(ranked)
            ranked = ranked[: max(1, limit)]
            result = {
                "ok": True,
                "action": action,
                "count": len(ranked),
                "regions": ranked,
                "next_actions": [
                    "firmware_view(action='campaign', start='<top_region.start>', end='<top_region.end>')",
                    "firmware_view(action='smart_carve', start='<top_region.start>', end='<top_region.end>', apply=false)",
                ],
            }
            return _log_ml(result, action, f"segments={len(segs)}; ranked={len(ranked)}")

        if action == "multi_region_campaign":
            segs = []
            seg = idaapi.get_first_seg()
            while seg:
                if seg.end_ea > seg.start_ea:
                    try:
                        sname = idaapi.get_segm_name(seg) or ""
                    except Exception:
                        sname = ""
                    segs.append((int(seg.start_ea), int(seg.end_ea), sname))
                seg = idaapi.get_next_seg(seg.start_ea)

            regions = []
            for ss, ee, name in segs[: max(1, min(limit * 4, 128))]:
                if ee - ss < 64:
                    continue
                prof = _profile_range(ss, ee, ptr_size)
                plan = build_carve_plan(
                    {
                        "unknown_ratio": prof["unknown_ratio"],
                        "entropy": prof["entropy"],
                        "ascii_runs": prof["ascii_runs"],
                    },
                    ptr_count=prof.get("ptr_hits_sampled", 0),
                    table_count=0,
                )
                pri = region_priority_score(prof, plan, cluster_count=0)
                regions.append(
                    {
                        "segment": name,
                        "start": hex(ss),
                        "end": hex(ee),
                        "profile": {
                            "entropy": prof["entropy"],
                            "unknown_ratio": prof["unknown_ratio"],
                            "pointer_density": prof["pointer_density"],
                            "ascii_runs": prof["ascii_runs"],
                        },
                        "plan": plan,
                        "priority_score": pri,
                    }
                )

            ranked = rank_region_plans(regions, limit=max(1, min(limit * 2, 48)))
            ranked = dedup_regions_by_fingerprint(ranked)
            # Cross-image fingerprint assist: boost regions with historically
            # high-yield fingerprints from prior campaigns.
            fp_rank = aggregate_fingerprint_scores(state.get("fingerprint_corpus", []), limit=64)
            ranked = apply_fingerprint_boost(ranked, fp_rank, boost_cap=0.35)
            ranked = ranked[: max(1, min(limit, 24))]
            campaign_summary = summarize_campaign_regions(ranked)
            exec_plan = build_campaign_execution_plan(ranked, max_steps=min(32, max(6, limit * 2)))

            result = {
                "ok": True,
                "action": action,
                "summary": campaign_summary,
                "fingerprint_assist": {
                    "enabled": True,
                    "indexed_fingerprints": len(fp_rank),
                },
                "regions": ranked,
                "execution_plan": exec_plan,
                "rollback_guardrails": {
                    "default_apply": False,
                    "require_force_for_code_overwrite": True,
                    "recommend_snapshot": True,
                },
                "next_actions": [
                    "Execute execution_plan step-by-step with apply=false first.",
                    "Re-run firmware_view(action='multi_region_campaign') after dry-runs to reprioritize.",
                ],
            }
            return _log_ml(result, action, f"regions={campaign_summary.get('count',0)}; high={campaign_summary.get('risk_counts',{}).get('high',0)}")

        if action == "campaign_checkpoint":
            # Snapshot current multi-region campaign plan for resumable execution.
            segs = []
            seg = idaapi.get_first_seg()
            while seg:
                if seg.end_ea > seg.start_ea:
                    try:
                        sname = idaapi.get_segm_name(seg) or ""
                    except Exception:
                        sname = ""
                    segs.append((int(seg.start_ea), int(seg.end_ea), sname))
                seg = idaapi.get_next_seg(seg.start_ea)
            regions = []
            for ss, ee, name in segs[: max(1, min(limit * 4, 128))]:
                if ee - ss < 64:
                    continue
                prof = _profile_range(ss, ee, ptr_size)
                plan = build_carve_plan(
                    {"unknown_ratio": prof["unknown_ratio"], "entropy": prof["entropy"], "ascii_runs": prof["ascii_runs"]},
                    ptr_count=prof.get("ptr_hits_sampled", 0),
                    table_count=0,
                )
                pri = region_priority_score(prof, plan, cluster_count=0)
                regions.append(
                    {
                        "segment": name,
                        "start": hex(ss),
                        "end": hex(ee),
                        "profile": {
                            "entropy": prof["entropy"],
                            "unknown_ratio": prof["unknown_ratio"],
                            "pointer_density": prof["pointer_density"],
                            "ascii_runs": prof["ascii_runs"],
                        },
                        "plan": plan,
                        "priority_score": pri,
                    }
                )
            ranked = dedup_regions_by_fingerprint(rank_region_plans(regions, limit=max(1, min(limit * 2, 48))))
            ranked = ranked[: max(1, min(limit, 24))]
            exec_plan = build_campaign_execution_plan(ranked, max_steps=min(48, max(8, limit * 3)))
            cid = str(uuid.uuid4())[:12]
            state.setdefault("campaigns", {})[cid] = {
                "created_at": int(time.time()),
                "cursor": 0,
                "regions": ranked,
                "execution_plan": exec_plan,
                "done": [],
            }
            _save_fw_state(state)
            return {
                "ok": True,
                "action": action,
                "campaign_id": cid,
                "regions": len(ranked),
                "plan_steps": len(exec_plan),
                "next_actions": [
                    f"firmware_view(action='campaign_resume', addr='{cid}')",
                    "firmware_view(action='review_contradictions')",
                ],
            }

        if action == "campaign_resume":
            cid = (campaign_id or addr or "").strip()
            if not cid:
                return make_error(MCPError.INVALID_ARGS, "campaign_resume requires campaign_id=<id>")
            campaigns = state.setdefault("campaigns", {})
            camp = campaigns.get(cid)
            if not camp:
                return make_error(MCPError.NOT_FOUND, f"Unknown campaign_id: {cid}")
            plan = list(camp.get("execution_plan") or [])
            # Optional auto-feedback: executed outcomes from prior chunk.
            executed = _parse_executed_feedback(kwargs.get("executed"))
            ingested = 0
            if executed:
                step_map = {int(st.get("step") or 0): st for st in plan}
                for rec in executed:
                    try:
                        step_id = int(rec.get("step") or 0)
                    except Exception:
                        continue
                    outcome = str(rec.get("outcome") or "").strip().lower()
                    if outcome not in ("success", "failure"):
                        continue
                    st = step_map.get(step_id)
                    if not st:
                        continue
                    fp = str(st.get("fingerprint") or "")
                    if not fp:
                        continue
                    state.setdefault("fingerprint_corpus", []).append(
                        {
                            "ts": int(time.time()),
                            "fingerprint": fp,
                            "priority_score": float(rec.get("priority_score") or 0.5),
                            "outcome": outcome,
                            "segment": rec.get("segment") or "",
                            "start": st.get("start") or "",
                            "end": st.get("end") or "",
                        }
                    )
                    ingested += 1
                corpus = state.setdefault("fingerprint_corpus", [])
                if len(corpus) > 2000:
                    del corpus[:-2000]

            cursor = int(camp.get("cursor") or 0)
            chunk_n = max(1, min(limit, 10))
            chunk = plan[cursor : cursor + chunk_n]
            camp["cursor"] = min(len(plan), cursor + len(chunk))
            regions_by_range = {
                (str(r.get("start")), str(r.get("end"))): str(r.get("fingerprint") or "")
                for r in (camp.get("regions") or [])
            }
            for st in chunk:
                fp = regions_by_range.get((str(st.get("start")), str(st.get("end"))), "")
                if fp:
                    st["fingerprint"] = fp
            for st in chunk:
                camp.setdefault("done", []).append(st.get("step"))
            _save_fw_state(state)
            finished = camp["cursor"] >= len(plan)
            return {
                "ok": True,
                "action": action,
                "campaign_id": cid,
                "finished": finished,
                "cursor": camp["cursor"],
                "total_steps": len(plan),
                "next_chunk": chunk,
                "feedback_ingested": ingested,
                "next_actions": [
                    (f"firmware_view(action='campaign_resume', addr='{cid}')" if not finished else "campaign complete"),
                    "Execute chunk actions manually with apply=false first.",
                ],
            }

        if action == "campaign_feedback":
            fp = str(kwargs.get("fingerprint") or "").strip()
            outcome = str(kwargs.get("outcome") or "").strip().lower()
            if not fp:
                return make_error(MCPError.INVALID_ARGS, "campaign_feedback requires fingerprint=<id>")
            if outcome not in ("success", "failure"):
                return make_error(MCPError.INVALID_ARGS, "campaign_feedback requires outcome=success|failure")
            corpus = state.setdefault("fingerprint_corpus", [])
            corpus.append(
                {
                    "ts": int(time.time()),
                    "fingerprint": fp,
                    "priority_score": float(kwargs.get("priority_score") or 0.5),
                    "outcome": outcome,
                    "segment": kwargs.get("segment") or "",
                    "start": kwargs.get("start") or "",
                    "end": kwargs.get("end") or "",
                }
            )
            if len(corpus) > 2000:
                del corpus[:-2000]
            _save_fw_state(state)
            agg = aggregate_fingerprint_scores(corpus, limit=24)
            top = next((x for x in agg if str(x.get("fingerprint")) == fp), None)
            return {
                "ok": True,
                "action": action,
                "fingerprint": fp,
                "outcome": outcome,
                "corpus_size": len(corpus),
                "updated_score": (top or {}).get("score"),
                "updated_success_rate": (top or {}).get("success_rate"),
            }

        if action == "fingerprint_index_sync":
            # Ingest current ranked regions into cross-image fingerprint corpus.
            segs = []
            seg = idaapi.get_first_seg()
            while seg:
                if seg.end_ea > seg.start_ea:
                    try:
                        sname = idaapi.get_segm_name(seg) or ""
                    except Exception:
                        sname = ""
                    segs.append((int(seg.start_ea), int(seg.end_ea), sname))
                seg = idaapi.get_next_seg(seg.start_ea)
            rows = []
            for ss, ee, name in segs[: max(1, min(limit * 4, 128))]:
                if ee - ss < 64:
                    continue
                prof = _profile_range(ss, ee, ptr_size)
                plan = build_carve_plan(
                    {"unknown_ratio": prof["unknown_ratio"], "entropy": prof["entropy"], "ascii_runs": prof["ascii_runs"]},
                    ptr_count=prof.get("ptr_hits_sampled", 0),
                    table_count=0,
                )
                pri = region_priority_score(prof, plan, cluster_count=0)
                r = {
                    "segment": name,
                    "start": hex(ss),
                    "end": hex(ee),
                    "profile": {
                        "entropy": prof["entropy"],
                        "unknown_ratio": prof["unknown_ratio"],
                        "pointer_density": prof["pointer_density"],
                        "ascii_runs": prof["ascii_runs"],
                    },
                    "plan": {"risk": plan.get("risk"), "phases": plan.get("phases", [])[:2]},
                    "priority_score": pri,
                }
                r["fingerprint"] = region_fingerprint(r)
                rows.append(r)
            rows = dedup_regions_by_fingerprint(rows)
            corpus = state.setdefault("fingerprint_corpus", [])
            now = int(time.time())
            for r in rows[: max(1, min(limit * 2, 64))]:
                corpus.append(
                    {
                        "ts": now,
                        "fingerprint": r.get("fingerprint"),
                        "segment": r.get("segment"),
                        "start": r.get("start"),
                        "end": r.get("end"),
                        "priority_score": r.get("priority_score"),
                    }
                )
            # bounded corpus size
            if len(corpus) > 2000:
                del corpus[:-2000]
            _save_fw_state(state)
            return {
                "ok": True,
                "action": action,
                "ingested": len(rows),
                "corpus_size": len(corpus),
                "next_actions": [
                    "firmware_view(action='fingerprint_index_query')",
                    "firmware_view(action='multi_region_campaign')",
                ],
            }

        if action == "fingerprint_index_query":
            corpus = state.setdefault("fingerprint_corpus", [])
            agg = aggregate_fingerprint_scores(corpus, limit=max(1, min(limit, 48)))
            return {
                "ok": True,
                "action": action,
                "count": len(agg),
                "items": agg,
                "next_actions": [
                    "Use top fingerprints to prioritize campaign regions with similar profiles.",
                    "firmware_view(action='multi_region_campaign')",
                ],
            }

        if action == "smart_carve":
            if apply and snapshot_before_apply:
                try:
                    import ida_auto
                    ida_auto.auto_wait()
                except Exception:
                    pass
                try:
                    import ida_kernwin
                    ida_kernwin.process_ui_action("UndoCreateSnapshot")
                except Exception:
                    pass

            operations = []
            applied = 0

            # Pass 1: pointer-like unknown cells
            ea = s_ea
            while ea + ptr_size <= e_ea and len(operations) < limit:
                if _item_kind(ea) == "unknown":
                    v = _read_u64(ea, ptr_size)
                    if v is not None and _addr_in_mapped(int(v)):
                        operations.append({"ea": ea, "kind": "make_ptr", "score": 0.9, "target": int(v)})
                ea += ptr_size

            # Pass 2: printable-run strings
            ea = s_ea
            while ea < e_ea and len(operations) < limit:
                if _item_kind(ea) != "unknown":
                    ea += 1
                    continue
                run = []
                cur = ea
                while cur < e_ea and len(run) < 96:
                    b = ida_bytes.get_byte(cur)
                    if b == 0:
                        break
                    if b < 0x20 or b > 0x7E:
                        run = []
                        break
                    run.append(b)
                    cur += 1
                if len(run) >= 6 and cur < e_ea and ida_bytes.get_byte(cur) == 0:
                    operations.append({"ea": ea, "kind": "make_string", "score": 0.72, "length": len(run) + 1})
                    ea = cur + 1
                    continue
                ea += 1

            # Pass 3: residual unknown as byte data
            ea = s_ea
            while ea < e_ea and len(operations) < limit:
                if _item_kind(ea) == "unknown":
                    operations.append({"ea": ea, "kind": "make_data", "size": 1, "score": 0.45})
                ea += 1

            if apply:
                for op in operations:
                    oa = op["ea"]
                    k = op["kind"]
                    prev_kind = _item_kind(oa)
                    if prev_kind == "code" and k in ("make_ptr", "make_data", "make_string") and not force:
                        _record_contradiction(state, oa, prev_kind, k, "code_preservation_guard", confidence=0.86)
                        continue
                    if k == "make_ptr":
                        ok = ida_bytes.create_data(oa, ida_bytes.qword_flag() if ptr_size == 8 else ida_bytes.dword_flag(), ptr_size, idaapi.BADADDR)
                        if ok:
                            try:
                                idc.op_offset(oa, 0, idc.REF_OFF64 if ptr_size == 8 else idc.REF_OFF32, 0, 0, 0)
                            except Exception:
                                pass
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "smart_carve", "ea": hex(oa), "new_kind": "ptr", "prev_kind": prev_kind, "size": ptr_size})
                    elif k == "make_string":
                        if _create_ascii_string(oa, int(op.get("length") or idaapi.BADADDR)):
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "smart_carve", "ea": hex(oa), "new_kind": "string", "prev_kind": prev_kind, "size": op.get("length", 1)})
                    elif k == "make_data":
                        if ida_bytes.create_data(oa, ida_bytes.byte_flag(), 1, idaapi.BADADDR):
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "smart_carve", "ea": hex(oa), "new_kind": "data", "prev_kind": prev_kind, "size": 1})

                _save_fw_state(state)

            type_totals = {"make_ptr": 0, "make_string": 0, "make_data": 0}
            for op in operations:
                type_totals[op["kind"]] = type_totals.get(op["kind"], 0) + 1

            result = {
                "ok": True,
                "action": action,
                "apply": bool(apply),
                "range": {"start": hex(s_ea), "end": hex(e_ea)},
                "count": len(operations),
                "applied": applied,
                "type_totals": type_totals,
                "items": [
                    {
                        "address": hex(op["ea"]),
                        "kind": op["kind"],
                        "score": op.get("score"),
                        "target": hex(op["target"]) if op.get("target") is not None else None,
                        "size": op.get("size"),
                    }
                    for op in operations[:limit]
                ],
                "next_actions": [
                    "firmware_view(action='scan_region', start='<same_start>', end='<same_end>')",
                    "firmware_view(action='table_candidates', start='<same_start>', end='<same_end>')",
                    "llm_helpers(action='analysis_dead_end_detector', query='firmware retyping loop', history='smart_carve applied')",
                ],
            }
            return _log_ml(result, action, f"smart_carve_ops={len(operations)}; applied={applied}")

        if action == "rollback_last":
            hist = state.get("history", [])
            if not hist:
                return {"ok": True, "action": action, "rolled_back": 0, "note": "No firmware_view history to rollback."}
            target = hist.pop()
            ea_s = target.get("ea")
            try:
                ea_i, _ = validate_addr(str(ea_s))
            except Exception:
                ea_i = idaapi.BADADDR
            rolled = 0
            if ea_i != idaapi.BADADDR:
                sz = int(target.get("size") or 1)
                if ida_bytes.del_items(ea_i, ida_bytes.DELIT_SIMPLE, max(1, sz)):
                    rolled = 1
                prev = str(target.get("prev_kind") or "unknown")
                if prev == "code":
                    idc.create_insn(ea_i)
                elif prev == "data":
                    ida_bytes.create_data(ea_i, ida_bytes.byte_flag(), 1, idaapi.BADADDR)
            _save_fw_state(state)
            return {
                "ok": True,
                "action": action,
                "rolled_back": rolled,
                "entry": target,
                "remaining_history": len(hist),
                "next_actions": [
                    "firmware_view(action='scan_region', start='<same_start>', end='<same_end>')",
                    "firmware_view(action='review_contradictions')",
                ],
            }

        if action == "review_contradictions":
            items = state.get("contradictions", [])
            weighted = []
            sev_w = {"high": 1.0, "medium": 0.65, "low": 0.35}
            for it in items:
                w = sev_w.get(str(it.get("severity") or "low"), 0.35)
                c = float(it.get("confidence") or 0.5)
                weighted.append((w * c, it))
            weighted.sort(key=lambda x: x[0], reverse=True)
            return {
                "ok": True,
                "action": action,
                "count": len(items),
                "items": [it for _, it in weighted[:limit]],
                "next_actions": [
                    "Re-run with force=true only on verified addresses.",
                    "Use blackboard(action='list', category='firmware_view') to correlate prior decisions.",
                ],
            }

        if action == "recommend":
            anchor = s_ea
            if addr:
                a, aerr = validate_addr(addr)
                if aerr:
                    return aerr
                anchor = a
            around_start = max(idaapi.cvar._inf_min_ea(), anchor - 0x200)
            around_end = min(idaapi.cvar._inf_max_ea(), anchor + 0x200)
            result = {
                "ok": True,
                "action": action,
                "anchor": hex(anchor),
                "recommendations": [
                    {"tool": "firmware_view", "action": "scan_region", "start": hex(around_start), "end": hex(around_end), "reason": "Estimate unknown/data/code mix before deep queries."},
                    {"tool": "firmware_view", "action": "pointer_sweep", "start": hex(around_start), "end": hex(around_end), "stride": ptr_size, "reason": "Find likely tables/vtables/jump pointers."},
                    {"tool": "data_ops", "action": "cycle_data", "addr": hex(anchor), "reason": "Fast local reinterpretation similar to IDA D cycling."},
                    {"tool": "data_ops", "action": "set_repr", "addr": hex(anchor), "repr": "offset", "reason": "Show numeric operands as references for firmware pointers."},
                    {"tool": "search", "action": "semantic", "pattern": "boot init parse table checksum", "limit": 60, "reason": "Switch to semantic discovery after view shaping."},
                ],
            }
            return _log_ml(result, action, f"anchor={hex(anchor)}")

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
