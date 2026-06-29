try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .blackboard import BlackboardStore
except ImportError:
    try:
        from blackboard import BlackboardStore  # type: ignore[import-not-found]
    except ImportError:
        BlackboardStore = None  # type: ignore

import contextlib
import json
import os
import time

try:
    from ..support.firmware_heuristics import (
        aggregate_fingerprint_scores,
        apply_fingerprint_boost,
        ascii_run_stats,
        build_campaign_execution_plan,
        build_carve_plan,
        cluster_pointer_hits,
        dedup_regions_by_fingerprint,
        rank_region_plans,
        region_priority_score,
        shannon_entropy,
        summarize_campaign_regions,
    )
except ImportError:
    from support.firmware_heuristics import (  # type: ignore[import-not-found]
        aggregate_fingerprint_scores,
        apply_fingerprint_boost,
        ascii_run_stats,
        build_campaign_execution_plan,
        build_carve_plan,
        cluster_pointer_hits,
        dedup_regions_by_fingerprint,
        rank_region_plans,
        region_priority_score,
        shannon_entropy,
        summarize_campaign_regions,
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
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("history", [])
                data.setdefault("contradictions", [])
                data.setdefault("campaigns", {})
                data.setdefault("fingerprint_corpus", [])
                return data
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug("Failed to load fw state from %s: %s", p, _e)
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


def _safe_idb_bounds() -> tuple[int | None, int | None]:
    """Return IDB bounds or (None, None) when the session is not fully mapped."""
    min_ea = _inf_min_ea()
    max_ea = _inf_max_ea()
    if min_ea in (None, idaapi.BADADDR) or max_ea in (None, idaapi.BADADDR) or max_ea <= min_ea:
        return None, None
    return int(min_ea), int(max_ea)


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


# =============================================================================
# Chip-aware post-load bootstrap helpers (formerly firmware_bootstrap.py)
# =============================================================================


try:
    from typing import Dict, List
except ImportError:  # Python 3.9+
    pass


def _fwb_safe_bounds() -> tuple[int, int]:
    try:
        mn = int(_inf_min_ea())
        mx = int(_inf_max_ea())
        if mn == 0 and mx == 0:
            raise ValueError("inf returned 0,0")
        return mn, mx
    except Exception:
        for ea in idautils.Segments():
            seg = idaapi.getseg(ea)
            if seg:
                return seg.start_ea, seg.end_ea
        return 0, 0


def _fwb_int_addr(v: Any) -> Optional[int]:
    try:
        from ida_pro_mcp.services import coerce_int
        return coerce_int(v)
    except (TypeError, ValueError):
        return None
    except Exception:
        return None


def _fwb_annotate_mmio(peripherals: List[Dict[str, Any]]) -> Dict[str, Any]:
    annotated = 0
    for p in peripherals:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or p.get("peripheral_name") or "").strip()
        base = _fwb_int_addr(p.get("addr") or p.get("base"))
        if not name or base is None:
            continue
        sym = name.upper().replace(" ", "_")
        if not sym.endswith("_BASE"):
            sym += "_BASE"
        idc.set_name(base, sym, ida_name.SN_FORCE)
        idc.set_cmt(base, f"MMIO base for {name}", 1)
        annotated += 1
    return {"peripherals_annotated": annotated}


def _fwb_define_ascii_strings(limit: int = 256) -> Dict[str, Any]:
    with contextlib.suppress(Exception):
        idaapi.build_strlist()
    defined = idaapi.get_strlist_qty() if hasattr(idaapi, "get_strlist_qty") else 0
    return {"strings_defined": min(defined, limit)}


def _fwb_run_vector_bootstrap() -> Dict[str, Any]:
    res = firmware_view(action="detect_vector_table", auto_blackboard=False)
    vectors = res.get("vectors") if isinstance(res, dict) else []
    if not isinstance(vectors, list):
        vectors = []

    mn, mx = _fwb_safe_bounds()
    created = 0
    entries = 0
    reset_addr = None
    code_failures = []
    func_failures = []

    # Fix ALL segments: ensure CODE type/class/perm so create_insn() and
    # add_func() work. IDA's processor-module loader creates BSS/DATA
    # segments for raw binaries; we upgrade every segment here.
    seg_fix_count = 0
    for seg_ea in idautils.Segments():
        try:
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            cur_class = ida_segment.get_segm_class(seg)
            if cur_class != "CODE":
                ida_segment.set_segm_class(seg, "CODE")
            if seg.type != idaapi.SEG_CODE:
                seg.type = idaapi.SEG_CODE
                ida_segment.update_segm(seg)
            if not (seg.perm & idaapi.SEGPERM_EXEC):
                seg.perm |= idaapi.SEGPERM_EXEC
                ida_segment.update_segm(seg)
            seg_fix_count += 1
        except Exception:
            pass

    handler_addrs = []
    skipped_oob = []
    for vec in vectors:
        if not isinstance(vec, dict):
            continue
        if str(vec.get("type") or "") == "stack_pointer":
            continue
        h = _fwb_int_addr(vec.get("handler") or vec.get("value"))
        if h is None or h < mn or h >= mx:
            skipped_oob.append(hex(vec.get("handler") or vec.get("value") or 0))
            continue
        handler_addrs.append((h, vec))

    if handler_addrs:
        try:
            proc = (_inf_procname() or "").lower()
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug("_inf_procname failed: %s", _e)
        # T=1 (Thumb) only applies to 32-bit ARM; AArch64 has no Thumb mode
        _is_arm32 = "arm" in proc and idaapi.get_inf_structure().is_32bit() if hasattr(idaapi, "get_inf_structure") else "arm" in proc
        if _is_arm32:
            try:
                sr_auto = getattr(idc, "SR_auto", 2)
                idc.split_sreg_range(mn, "T", 1, sr_auto)
            except Exception as _e:
                try:
                    import ida_segregs
                    ida_segregs.split_sreg_range(mn, "T", 1, 2)
                except Exception as _e2:
                    import logging
                    logging.getLogger(__name__).debug("T=1 split_sreg_range failed for mn %s: %s / %s", hex(mn), _e, _e2)
        for h, _ in handler_addrs:
            if _is_arm32:
                try:
                    sr_auto = getattr(idc, "SR_auto", 2)
                    idc.split_sreg_range(h, "T", 1, sr_auto)
                except Exception as _e:
                    try:
                        import ida_segregs
                        ida_segregs.split_sreg_range(h, "T", 1, 2)
                    except Exception as _e2:
                        import logging
                        logging.getLogger(__name__).debug("T=1 split_sreg_range failed for %s: %s / %s", hex(h), _e, _e2)
        for h, _ in handler_addrs:
            if not ida_bytes.is_code(ida_bytes.get_flags(h)):
                created_insn = False
                try:
                    import ida_ua
                    insn_len = ida_ua.create_insn(h)
                    created_insn = insn_len > 0
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug("ida_ua.create_insn failed for %s: %s", hex(h), _e)
                if not created_insn:
                    try:
                        insn_len = idc.create_insn(h)
                        created_insn = insn_len > 0
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug("idc.create_insn failed for %s: %s", hex(h), _e)
                if not created_insn:
                    code_failures.append(hex(h))
                if not created_insn:
                    try:
                        ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, 16)
                        if hasattr(ida_auto, "auto_make_code"):
                            ida_auto.auto_make_code(h)
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug("del_items+auto_make_code failed for %s: %s", hex(h), _e)
                    try:
                        import ida_ua
                        insn_len = ida_ua.create_insn(h)
                        created_insn = insn_len > 0
                    except Exception:
                        created_insn = idc.create_insn(h) > 0

    add_func_results = []
    for h, vec in handler_addrs:
        fn = ida_funcs.get_func(h)
        if not fn:
            ok = ida_funcs.add_func(h)
            if not ok:
                try:
                    bound = min(h + 256, mx)
                    ok = ida_funcs.add_func(h, bound)
                except Exception:
                    pass
            add_func_results.append({"addr": hex(h), "ok": bool(ok), "is_code": ida_bytes.is_code(ida_bytes.get_flags(h))})
            if ok:
                created += 1
                fn = ida_funcs.get_func(h)
            else:
                func_failures.append(hex(h))
        if fn:
            entries += 1
            idx = int(vec.get("index", -1) or -1)
            if idx == 1:
                idc.set_name(fn.start_ea, "Reset_Handler", ida_name.SN_FORCE)
                reset_addr = fn.start_ea
            elif idx > 1:
                nm = str(vec.get("name") or "")
                if nm and nm.endswith("_Handler"):
                    idc.set_name(fn.start_ea, nm, ida_name.SN_FORCE)
    primary_seg_ea = mn if mn > 0 else next(idautils.Segments(), idaapi.BADADDR)
    primary_seg = idaapi.getseg(primary_seg_ea) if primary_seg_ea != idaapi.BADADDR else None
    seg_code_verified = bool(
        primary_seg and primary_seg.type == idaapi.SEG_CODE
    ) if primary_seg else False
    seg_class_verified = str(ida_segment.get_segm_class(primary_seg)) if primary_seg else "N/A"
    seg_count = seg_fix_count

    result = {
        "vectors_detected": len(vectors),
        "entry_points_defined": entries,
        "functions_created": created,
        "segment_code_flag": seg_code_verified,
        "segment_class": seg_class_verified,
        "segments_fixed": seg_count,
        "reset_handler": (hex(reset_addr) if reset_addr is not None else None),
    }
    if code_failures or func_failures or skipped_oob or not seg_code_verified:
        result["_debug"] = {
            "handler_count": len(handler_addrs),
            "segments_fixed": seg_count,
            "primary_seg_code": seg_code_verified,
            "primary_seg_class": seg_class_verified,
            "skipped_oob": skipped_oob[:10],
            "add_func_sample": add_func_results[:10],
            "code_failures": code_failures[:10],
            "func_failures": func_failures[:10],
        }
        if not seg_code_verified:
            result["_debug"]["segment_note"] = (
                "Segment was not CODE after fix attempt. create_insn/add_func will likely fail. "
                "Try setting the processor/loader with -Tbin before calling firmware_view(bootstrap)."
            )
        result["_status"] = "partial" if (created > 0 or entries > 0) else "failed"
    return result


def _fwb_base_bootstrap_report(chip_family: str, load_base: Optional[int], actions: List[str]) -> Dict[str, Any]:
    return {
        "ok": True,
        "chip_family": chip_family,
        "load_base": (hex(int(load_base)) if isinstance(load_base, int) else load_base),
        "actions": list(actions),
        "functions_created": 0,
        "entry_points_defined": 0,
        "peripherals_annotated": 0,
        "strings_defined": 0,
        "reset_handler": None,
        "details": {},
    }


def run_firmware_bootstrap(
    chip_family: str,
    load_base: Optional[int] = None,
    memory_map: Optional[List[Dict[str, Any]]] = None,
    peripheral_addresses: Optional[List[Dict[str, Any]]] = None,
    post_load_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    actions = list(post_load_actions or ["define_vector_table", "annotate_mmio", "reanalyze", "define_strings"])
    report: Dict[str, Any] = _fwb_base_bootstrap_report(chip_family, load_base, actions)
    report["processor"] = str(_inf_procname() or "")

    for action in actions:
        if action == "define_vector_table":
            r = _fwb_run_vector_bootstrap()
            report["details"][action] = r
            report["functions_created"] += int(r.get("functions_created", 0) or 0)
            report["entry_points_defined"] += int(r.get("entry_points_defined", 0) or 0)
            report["reset_handler"] = report.get("reset_handler") or r.get("reset_handler")
        elif action == "annotate_mmio":
            r = _fwb_annotate_mmio(list(peripheral_addresses or []))
            report["details"][action] = r
            report["peripherals_annotated"] += int(r.get("peripherals_annotated", 0) or 0)
        elif action == "reanalyze":
            try:
                import ida_auto as _ida_auto
                mn, mx = _fwb_safe_bounds()
                if mn < mx:
                    if hasattr(_ida_auto, "plan_range"):
                        _ida_auto.plan_range(mn, mx)
                    elif hasattr(_ida_auto, "auto_mark_range"):
                        _ida_auto.auto_mark_range(mn, mx, _ida_auto.AU_FINAL)
                report["details"][action] = {"ok": True, "note": "scheduled (non-blocking)"}
            except Exception as e:
                report["details"][action] = {"ok": False, "error": str(e)}
        elif action == "define_strings":
            r = _fwb_define_ascii_strings()
            report["details"][action] = r
            report["strings_defined"] += int(r.get("strings_defined", 0) or 0)
        else:
            report["details"][action] = {"ok": False, "note": "unknown action"}

    try:
        fn_count = sum(1 for _ in idautils.Functions())
    except Exception:
        fn_count = -1
    report["function_count_after"] = fn_count
    return report


@tool
@idawrite
def firmware_view(
    action: Annotated[Literal["scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates", "smart_carve", "rollback_last", "review_contradictions", "region_profile", "pointer_clusters", "carve_plan", "campaign", "segment_sweep", "multi_region_campaign", "detect_load_address", "detect_vector_table", "detect_mmio", "rtos_scan", "triage_snapshot", "bootstrap"], "Action: scan_region|auto_retype|pointer_sweep|recommend|table_candidates|smart_carve|rollback_last|review_contradictions|region_profile|pointer_clusters|carve_plan|campaign|segment_sweep|multi_region_campaign|detect_load_address|detect_vector_table|detect_mmio|rtos_scan|triage_snapshot|bootstrap"],
    start: Annotated[Optional[str], "Range start address"] = None,
    end: Annotated[Optional[str], "Range end address"] = None,
    addr: Annotated[Optional[str], "Anchor address for recommend"] = None,
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
        range_actions = {
            "scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates",
            "smart_carve", "rollback_last", "review_contradictions", "region_profile",
            "pointer_clusters", "carve_plan", "campaign", "segment_sweep",
            "multi_region_campaign",
        }
        if action in range_actions:
            s_ea, e_ea, err = _seg_bounds(start, end)
            if err:
                return err
        else:
            min_ea, max_ea = _safe_idb_bounds()
            if min_ea is None or max_ea is None:
                s_ea, e_ea = 0, 0
            else:
                s_ea, e_ea = min_ea, max_ea

        limit = max(1, min(int(limit), 2048))
        stride = max(1, min(int(stride), 16))
        min_run = max(4, min(int(min_run), 4096))

        ptr_size = 8 if _is_64bit() else 4

        def _log_ml(result: dict, act: str, details: str):
            _BB = BlackboardStore  # capture at definition time to avoid closure bug
            if auto_blackboard and _BB is not None:
                try:
                    store = _BB()
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
                    "search(action='semantic', pattern='init parser dispatch checksum', limit=60)",
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
                            with contextlib.suppress(Exception):
                                idc.op_offset(pea, 0, idc.REF_OFF64 if ptr_size == 8 else idc.REF_OFF32, 0, 0, 0)
                            applied += 1
                            state["history"].append({"ts": int(time.time()), "action": "auto_retype", "ea": hex(pea), "new_kind": "ptr", "prev_kind": prev_kind, "size": ptr_size})
                    elif p["kind"] == "code":
                        if prev_kind == "data" and not force:
                            _record_contradiction(state, pea, prev_kind, "code", "data_to_code_guard", confidence=0.74)
                            continue
                        # Set Thumb mode for 32-bit ARM before creating instruction
                        try:
                            _proc = (_inf_procname() or "").lower()
                        except Exception:
                            _proc = ""
                        _arm32 = "arm" in _proc and (idaapi.get_inf_structure().is_32bit() if hasattr(idaapi, "get_inf_structure") else True)
                        if _arm32:
                            try:
                                idc.split_sreg_range(pea, "T", 1, getattr(idc, "SR_auto", 2))
                            except Exception:
                                try:
                                    import ida_segregs
                                    ida_segregs.split_sreg_range(pea, "T", 1, 2)
                                except Exception:
                                    pass
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

        if action == "smart_carve":
            if apply and snapshot_before_apply:
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
                            with contextlib.suppress(Exception):
                                idc.op_offset(oa, 0, idc.REF_OFF64 if ptr_size == 8 else idc.REF_OFF32, 0, 0, 0)
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
                    try:
                        _proc = (_inf_procname() or "").lower()
                    except Exception:
                        _proc = ""
                    _arm32 = "arm" in _proc and (idaapi.get_inf_structure().is_32bit() if hasattr(idaapi, "get_inf_structure") else True)
                    if _arm32:
                        try:
                            idc.split_sreg_range(ea_i, "T", 1, getattr(idc, "SR_auto", 2))
                        except Exception:
                            try:
                                import ida_segregs
                                ida_segregs.split_sreg_range(ea_i, "T", 1, 2)
                            except Exception:
                                pass
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
            min_ea = _inf_min_ea()
            max_ea = _inf_max_ea()
            if min_ea in (None, idaapi.BADADDR) or max_ea in (None, idaapi.BADADDR) or max_ea <= min_ea:
                min_ea = max(0, anchor - 0x1000)
                max_ea = anchor + 0x1000
            around_start = max(int(min_ea), anchor - 0x200)
            around_end = min(int(max_ea), anchor + 0x200)
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

        if action == "detect_load_address":
            # Heuristically determine the correct load/base address for a flat binary.
            #
            # Strategy:
            # 1. Cortex-M: bytes[0:4] = initial SP (must be in RAM range),
            #              bytes[4:8] = reset vector (must be in flash range, LSB=1 for Thumb)
            # 2. Generic: find the base offset where the most pointer-like values
            #    become self-referential (point back into the binary)
            # 3. Known MCU fingerprinting: match entropy/size patterns to known chips
            import struct as _struct

            min_ea, max_ea = _safe_idb_bounds()
            if min_ea is None or max_ea is None:
                return {
                    "ok": True,
                    "binary_size": "0x0",
                    "current_base": None,
                    "candidates": [],
                    "size_hints": [],
                    "note": "IDB bounds unavailable in current session; open or map a binary to run load-address heuristics.",
                }
            binary_size = max_ea - min_ea
            candidates = []

            # --- Cortex-M detection ---
            # Read first 8 bytes
            first8 = ida_bytes.get_bytes(min_ea, 8)
            if first8 and len(first8) == 8:
                sp_val = _struct.unpack_from("<I", first8, 0)[0]
                reset_val = _struct.unpack_from("<I", first8, 4)[0]
                reset_addr = reset_val & ~1  # clear Thumb bit
                is_thumb = bool(reset_val & 1)

                # Cortex-M RAM spans 0x20000000-0x40080000 (SRAM through CCM/DTCM/ITCM).
                # Common flash ranges: 0x08000000-0x08200000 (STM32), 0x00000000-0x00200000
                sp_in_ram = 0x20000000 <= sp_val <= 0x40080000
                reset_in_flash = (
                    (0x08000000 <= reset_addr <= 0x08200000) or
                    (0x00000000 <= reset_addr <= 0x00200000) or
                    (0x10000000 <= reset_addr <= 0x10200000)
                )

                if sp_in_ram and reset_in_flash:
                    # The binary is likely loaded at the flash base
                    # Determine which flash base makes reset_addr point into the binary
                    for flash_base in (0x08000000, 0x00000000, 0x10000000, 0x20000000):
                        if flash_base <= reset_addr < flash_base + binary_size:
                            candidates.append({
                                "base": hex(flash_base),
                                "confidence": 0.92,
                                "method": "cortex_m_vector_table",
                                "evidence": f"SP=0x{sp_val:08x} (RAM), reset_vector=0x{reset_val:08x} ({'Thumb' if is_thumb else 'ARM'})",
                                "arch": "ARM Cortex-M",
                                "thumb": is_thumb,
                                "reset_handler": hex(reset_addr),
                            })
                            break

            # --- Generic: pointer density analysis ---
            # Try candidate bases and score by how many 4-byte values become valid pointers
            if not candidates:
                # Sample 256 bytes from start, middle, end
                sample_eas = [min_ea, min_ea + binary_size // 2, max(min_ea, max_ea - 256)]
                ptr_candidates = {}
                for sample_ea in sample_eas:
                    chunk = ida_bytes.get_bytes(sample_ea, min(256, max_ea - sample_ea)) or b""
                    for i in range(0, len(chunk) - 3, 4):
                        v = _struct.unpack_from("<I", chunk, i)[0]
                        # Try common bases
                        for base in (0x00000000, 0x08000000, 0x10000000, 0x20000000,
                                     0x40000000, 0x80000000, 0xBFC00000):
                            if base <= v < base + binary_size:
                                ptr_candidates[base] = ptr_candidates.get(base, 0) + 1

                if ptr_candidates:
                    best_base = max(ptr_candidates, key=ptr_candidates.get)
                    score = ptr_candidates[best_base]
                    if score >= 3:
                        candidates.append({
                            "base": hex(best_base),
                            "confidence": min(0.85, 0.5 + score * 0.05),
                            "method": "pointer_density",
                            "evidence": f"{score} pointer-like values resolve to binary range at this base",
                            "arch": "unknown",
                        })

            # --- Known MCU fingerprinting by size ---
            size_hints = []
            if 0x10000 <= binary_size <= 0x20000:
                size_hints.append("STM32F0/F1 (64-128KB flash)")
            elif 0x20000 <= binary_size <= 0x80000:
                size_hints.append("STM32F4/F7 or nRF52 (128KB-512KB flash)")
            elif 0x80000 <= binary_size <= 0x200000:
                size_hints.append("ESP32 / STM32H7 / i.MX RT (512KB-2MB flash)")
            elif binary_size > 0x200000:
                size_hints.append("Linux firmware / router / large SoC")

            result = {
                "ok": True,
                "binary_size": hex(binary_size),
                "current_base": hex(min_ea),
                "candidates": candidates,
                "size_hints": size_hints,
                "note": (
                    "If current_base is wrong, use Edit→Segments→Rebase in IDA "
                    "or set the correct base when loading. "
                    "For Cortex-M: base is typically 0x08000000 (STM32) or 0x00000000."
                ),
            }
            if candidates:
                best = candidates[0]
                result["recommended_base"] = best["base"]
                result["recommended_arch"] = best.get("arch", "")
                if best.get("thumb"):
                    result["recommended_note"] = (
                        f"Set processor to ARM, Thumb mode. "
                        f"Rebase to {best['base']}. "
                        f"Reset handler at {best.get('reset_handler', '?')}."
                    )
            return result

        if action == "detect_vector_table":
            # Find the interrupt vector table and extract all entry points.
            #
            # Cortex-M: IVT at load base. Entry 0 = SP, entries 1+ = function pointers (LSB=1 Thumb).
            # ARM Linux: exception vectors at 0x00000000 or 0xFFFF0000 (high vectors).
            # MIPS: exception vectors at 0x80000000, 0xBFC00000.
            # Generic: find dense cluster of valid function pointers near binary start.
            import struct as _struct

            min_ea, max_ea = _safe_idb_bounds()
            if min_ea is None or max_ea is None:
                return {
                    "ok": True,
                    "arch_hint": "unknown",
                    "ivt_addr": None,
                    "vectors": [],
                    "entry_count": 0,
                    "entry_points": [],
                    "note": "IDB bounds unavailable in current session; map a binary before vector-table detection.",
                }
            binary_size = max_ea - min_ea
            ptr_size = 8 if _is_64bit() else 4
            proc = (_inf_procname() or "").lower()

            vectors = []
            ivt_addr = None
            arch_hint = ""

            def _normalize_handler(raw_v: int):
                """Map vector value to IDB EA when possible, including base-normalized raw blobs."""
                tgt = raw_v & ~1
                if min_ea <= tgt < max_ea:
                    return tgt, None
                # Derive a likely image base from upper bits and map to file offset.
                base = raw_v & 0xFFFF0000
                off = tgt - base
                if 0 <= off < binary_size:
                    return min_ea + off, base
                return None, None

            # Detect raw binary (IDA defaults to metapc/x86 when format unknown)
            filetype_id = _inf_filetype_id() if callable(_inf_filetype_id) else 0
            try:
                filetype_id = _inf_filetype_id()
            except Exception:
                filetype_id = 0
            is_raw = filetype_id in (0, 2)  # 0=unknown, 2=IDP (raw)

            # Cortex-M: read up to 256 entries from min_ea.
            # Also try when proc is metapc (IDA default for raw binaries) since
            # raw ARM firmware gets loaded as x86 until processor is set.
            if "arm" in proc or not proc or (is_raw and "metapc" in proc):
                chunk = ida_bytes.get_bytes(min_ea, min(256 * 4, binary_size)) or b""
                if len(chunk) >= 8:
                    sp_val = _struct.unpack_from("<I", chunk, 0)[0]
                    # SP plausibility: non-zero, 4-byte aligned, not all-ones.
                    # Covers standard Cortex-M SRAM (0x20000000+), vendor SRAM
                    # (e.g. AIC8800D80 at 0x1a0000), and ITCM/CCM ranges.
                    sp_plausible = (
                        sp_val not in {0, 4294967295} and sp_val & 3 == 0 and (1048576 <= sp_val <= 1074266112 or 1610612736 <= sp_val <= 2684354560)
                    )
                    thumb_like = 0
                    for i in range(1, min(32, len(chunk) // 4)):
                        vv = _struct.unpack_from("<I", chunk, i * 4)[0]
                        if vv & 1:
                            thumb_like += 1
                    # With a plausible SP, require >=4 Thumb-bit entries (strong signal).
                    # Without a recognised SP, require >=16 to avoid false positives.
                    looks_like_arm_ivt = (sp_plausible and thumb_like >= 4) or (not sp_plausible and thumb_like >= 16)

                    if looks_like_arm_ivt:
                        arch_hint = "ARM Cortex-M (IVT at binary start)"
                        ivt_addr = min_ea
                        # Standard Cortex-M vector names
                        _CORTEX_M_VECTORS = [
                            "Initial_SP", "Reset_Handler", "NMI_Handler", "HardFault_Handler",
                            "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler",
                            "Reserved_7", "Reserved_8", "Reserved_9", "Reserved_10",
                            "SVC_Handler", "DebugMon_Handler", "Reserved_13",
                            "PendSV_Handler", "SysTick_Handler",
                        ]
                        for i in range(min(64, len(chunk) // 4)):
                            v = _struct.unpack_from("<I", chunk, i * 4)[0]
                            if i == 0:
                                vectors.append({
                                    "index": 0, "addr": hex(min_ea + i * 4),
                                    "value": hex(v), "name": "Initial_SP",
                                    "type": "stack_pointer",
                                    "note": f"Initial stack pointer = 0x{v:08x}",
                                })
                                continue
                            func_addr, derived_base = _normalize_handler(v)
                            is_thumb = bool(v & 1)
                            if func_addr is not None:
                                name = _CORTEX_M_VECTORS[i] if i < len(_CORTEX_M_VECTORS) else f"IRQ{i - 16}_Handler"
                                rec = {
                                    "index": i, "addr": hex(min_ea + i * 4),
                                    "value": hex(v), "name": name,
                                    "handler": hex(func_addr),
                                    "thumb": is_thumb,
                                    "type": "exception_vector" if i < 16 else "irq_vector",
                                }
                                if derived_base is not None:
                                    rec["derived_image_base"] = hex(derived_base)
                                    rec["mapped_from_raw"] = True
                                vectors.append(rec)

            # MIPS: check for exception vectors
            if "mips" in proc:
                arch_hint = "MIPS"
                for vec_base in (0x80000000, 0xBFC00000, min_ea):
                    if min_ea <= vec_base < max_ea:
                        ivt_addr = vec_base
                        vectors.append({"addr": hex(vec_base), "name": "MIPS_reset_vector", "type": "reset"})
                        vectors.append({"addr": hex(vec_base + 0x180), "name": "MIPS_interrupt_vector", "type": "interrupt"})
                        vectors.append({"addr": hex(vec_base + 0x200), "name": "MIPS_tlb_vector", "type": "tlb"})
                        break

            # Generic fallback: find dense cluster of valid function pointers
            if not vectors:
                arch_hint = "generic"
                chunk = ida_bytes.get_bytes(min_ea, min(512, binary_size)) or b""
                for i in range(0, len(chunk) - ptr_size + 1, ptr_size):
                    v = _struct.unpack_from("<I", chunk, i)[0] if ptr_size == 4 else _struct.unpack_from("<Q", chunk, i)[0]
                    mapped_v, derived_base = _normalize_handler(v)
                    if mapped_v is not None:
                        func = idaapi.get_func(mapped_v)
                        if func or ida_bytes.is_code(ida_bytes.get_flags(mapped_v)):
                            vectors.append({
                                "index": i // ptr_size,
                                "addr": hex(min_ea + i),
                                "handler": hex(mapped_v),
                                "value": hex(v),
                                "name": idc.get_name(mapped_v) or f"entry_{i // ptr_size}",
                                "type": "function_pointer",
                            })

            # Write entry points to blackboard
            if vectors:
                try:
                    from blackboard import BlackboardStore as _BBStore  # type: ignore
                    store = _BBStore()
                    for v in vectors[:32]:
                        handler = v.get("handler") or v.get("value", "")
                        if handler and handler != "0x0":
                            store.write(
                                title=f"Entry point: {v['name']}",
                                category="hypothesis",
                                addr=handler,
                                content=f"Vector table entry {v.get('index', '?')} at {v['addr']}",
                                tags=["vector_table", "entry_point", "auto"],
                                confidence=0.85,
                                source="firmware_view",
                                source_type="engine_firmware",
                                embed=False,
                            )
                except Exception:
                    pass

            return {
                "ok": True,
                "arch_hint": arch_hint,
                "ivt_addr": hex(ivt_addr) if ivt_addr else None,
                "vectors": vectors,
                "entry_count": len(vectors),
                "entry_points": [v.get("handler") or v.get("value") for v in vectors
                                 if v.get("type") not in ("stack_pointer",) and v.get("handler")],
                "note": (
                    f"Found {len(vectors)} vector table entries. "
                    "Entry points written to blackboard. "
                    "NEXT: code(action='smart_decompile', addrs='<reset_handler>') on Reset_Handler."
                ),
            }

        if action == "detect_mmio":
            # Find MMIO peripheral registers by identifying pointer-like values
            # that point OUTSIDE the binary's address range.
            # Cross-reference with known peripheral base addresses for common MCUs.
            import struct as _struct

            min_ea, max_ea = _safe_idb_bounds()
            if min_ea is None or max_ea is None:
                return {
                    "ok": True,
                    "likely_chip_family": "unknown",
                    "peripheral_count": 0,
                    "peripherals": [],
                    "note": "IDB bounds unavailable in current session; map a binary before MMIO discovery.",
                }
            binary_size = max_ea - min_ea

            # Known peripheral base addresses for common MCUs
            # Format: (base, end, name, chip_family)
            _KNOWN_PERIPHERALS = [
                # STM32 (APB1/APB2/AHB)
                (0x40000000, 0x40007FFF, "STM32_APB1", "STM32"),
                (0x40010000, 0x40017FFF, "STM32_APB2", "STM32"),
                (0x40020000, 0x4007FFFF, "STM32_AHB1", "STM32"),
                (0x50000000, 0x5007FFFF, "STM32_AHB2", "STM32"),
                # nRF52
                (0x40000000, 0x40FFFFFF, "nRF52_peripherals", "nRF52"),
                # ESP32
                (0x3FF00000, 0x3FFFFFFF, "ESP32_peripherals", "ESP32"),
                (0x60000000, 0x6FFFFFFF, "ESP32_IO_MUX", "ESP32"),
                # RP2040
                (0x40000000, 0x4007FFFF, "RP2040_APB", "RP2040"),
                (0x50000000, 0x503FFFFF, "RP2040_AHB", "RP2040"),
                # Generic ARM Cortex-M peripheral space
                (0x40000000, 0x5FFFFFFF, "ARM_peripheral_space", "generic_cortex_m"),
                # ARM system control
                (0xE0000000, 0xFFFFFFFF, "ARM_system_space", "generic_cortex_m"),
                # MIPS KSEG1 (uncached peripheral space)
                (0xA0000000, 0xBFFFFFFF, "MIPS_KSEG1_peripherals", "MIPS"),
            ]

            # Scan all code for immediate values and data references outside binary range
            mmio_accesses: dict = {}  # addr → {count, from_funcs, peripheral_name}

            def _record_mmio(v: int, ea: int):
                """Record a peripheral address hit."""
                if not v or (min_ea <= v < max_ea):
                    return
                for pbase, pend, pname, pfamily in _KNOWN_PERIPHERALS:
                    if pbase <= v <= pend:
                        key = v & ~0xFFF  # group by 4KB page
                        if key not in mmio_accesses:
                            mmio_accesses[key] = {
                                "base": hex(key),
                                "count": 0,
                                "peripheral_name": pname,
                                "chip_family": pfamily,
                                "example_addrs": [],
                                "from_funcs": set(),
                            }
                        mmio_accesses[key]["count"] += 1
                        if len(mmio_accesses[key]["example_addrs"]) < 5:
                            mmio_accesses[key]["example_addrs"].append(hex(v))
                        func = idaapi.get_func(ea)
                        if func:
                            mmio_accesses[key]["from_funcs"].add(
                                idc.get_func_name(func.start_ea)
                            )
                        break

            code_bytes_found = False
            # Pass 1: scan decoded instruction operands (post-analysis binaries)
            import ida_ua
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                ea = seg.start_ea
                while ea < seg.end_ea:
                    flags = ida_bytes.get_flags(ea)
                    if ida_bytes.is_code(flags):
                        code_bytes_found = True
                        insn = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn, ea) > 0:
                            for op in insn.ops:
                                v = None
                                if op.type == ida_ua.o_imm:
                                    v = op.value
                                elif op.type in (ida_ua.o_mem, ida_ua.o_displ):
                                    v = op.addr
                                _record_mmio(v, ea)
                        ea = idc.next_head(ea, seg.end_ea)
                    else:
                        ea += 1

            # Pass 2: raw 4-byte word scan when IDA hasn't run auto-analysis yet.
            # Reads all aligned words and checks if any fall in peripheral ranges.
            # This is intentionally coarser (no function context), but catches
            # firmware loaded as raw blobs before code is defined.
            if not code_bytes_found:
                scan_limit = binary_size
                chunk_size = 4096
                offset = 0
                while offset < scan_limit:
                    chunk = ida_bytes.get_bytes(min_ea + offset, min(chunk_size, scan_limit - offset)) or b""
                    for i in range(0, len(chunk) - 3, 4):
                        v = _struct.unpack_from("<I", chunk, i)[0]
                        _record_mmio(v, min_ea + offset + i)
                    offset += len(chunk)
                    if not chunk:
                        break

            # Convert sets to lists for JSON serialization
            peripherals = []
            for _key, info in sorted(mmio_accesses.items(), key=lambda x: -x[1]["count"]):
                peripherals.append({
                    "base": info["base"],
                    "access_count": info["count"],
                    "peripheral_name": info["peripheral_name"],
                    "chip_family": info["chip_family"],
                    "example_registers": info["example_addrs"],
                    "accessed_from": sorted(info["from_funcs"])[:5],
                })

            # Detect chip family from peripheral pattern
            chip_votes: dict = {}
            for p in peripherals:
                fam = p["chip_family"]
                chip_votes[fam] = chip_votes.get(fam, 0) + p["access_count"]
            likely_chip = max(chip_votes, key=chip_votes.get) if chip_votes else "unknown"

            # Write to knowledge graph
            if peripherals:
                try:
                    from blackboard import BlackboardStore as _BBStore  # type: ignore
                    store = _BBStore()
                    for p in peripherals[:10]:
                        store.write(
                            title=f"MMIO: {p['peripheral_name']} @ {p['base']}",
                            category="ioc",
                            addr=p["base"],
                            content=f"Accessed {p['access_count']} times from: {', '.join(p['accessed_from'][:3])}",
                            tags=["mmio", "peripheral", p["chip_family"], "auto"],
                            confidence=0.75,
                            ioc_type="mmio_observed",
                            ioc_value=p["peripheral_name"],
                            source="firmware_view",
                            source_type="engine_firmware",
                            embed=False,
                        )
                except Exception:
                    pass

            return {
                "ok": True,
                "likely_chip_family": likely_chip,
                "peripheral_count": len(peripherals),
                "scan_coverage": {
                    "bytes_scanned": int(scan_limit if not code_bytes_found else binary_size),
                    "bytes_total": int(binary_size),
                    "mode": "raw_word_scan" if not code_bytes_found else "decoded_operands",
                },
                "peripherals": peripherals[:20],
                "note": (
                    f"Found {len(peripherals)} MMIO peripheral regions. "
                    f"Likely chip family: {likely_chip}. "
                    "Peripheral addresses written to blackboard as IOC entries. "
                    "Functions accessing MMIO are likely drivers/HAL — analyze them next. "
                    "NEXT: taint(action='report') to trace MMIO reads to dangerous sinks."
                ),
            }

        if action == "rtos_scan":
            # Identify likely RTOS family by symbols/strings and infer task entry loops.
            names = []
            try:
                for _ea, nm in idautils.Names():
                    if nm:
                        names.append(str(nm))
            except Exception:
                names = []
            svals = []
            try:
                for s in idautils.Strings():
                    try:
                        svals.append(str(s))
                    except Exception:
                        continue
                    if len(svals) >= 5000:
                        break
            except Exception:
                svals = []
            blob = "\n".join(names[:5000] + svals[:5000]).lower()

            score_freertos = sum(1 for k in ("xtaskcreate", "pvportmalloc", "vtaskdelay", "xqueuereceive") if k in blob)
            score_threadx = sum(1 for k in ("tx_thread_create", "tx_queue_receive", "tx_semaphore_get", "tx_thread_sleep") if k in blob)
            if score_freertos > score_threadx and score_freertos > 0:
                rtos = "FreeRTOS"
            elif score_threadx > 0:
                rtos = "ThreadX"
            else:
                rtos = "unknown"

            tasks = []
            funcs_seen = 0
            for fea in idautils.Functions():
                funcs_seen += 1
                if funcs_seen > 6000:
                    break
                fn = ida_funcs.get_func(fea)
                if not fn:
                    continue
                has_loop = False
                has_blocking = False
                try:
                    for ins in idautils.FuncItems(fea):
                        for xr in idautils.XrefsFrom(ins, 0):
                            if not xr.iscode:
                                continue
                            tf = ida_funcs.get_func(xr.to)
                            if tf and tf.start_ea == fea:
                                has_loop = True
                            tname = (idc.get_name(xr.to) or "").lower()
                            if any(k in tname for k in ("xqueuereceive", "vtaskdelay", "osdelay", "tx_queue_receive", "tx_thread_sleep")):
                                has_blocking = True
                        if has_loop and has_blocking:
                            break
                except Exception:
                    pass
                if has_loop and has_blocking:
                    tasks.append({
                        "name": idc.get_func_name(fea) or f"sub_{fea:x}",
                        "entry_addr": hex(fea),
                        "stack_size": None,
                        "priority": None,
                    })
                if len(tasks) >= limit:
                    break

            conf = 0.2 + (0.3 if rtos != "unknown" else 0.0) + min(0.5, len(tasks) * 0.03)
            return {
                "ok": True,
                "action": action,
                "rtos_detected": rtos,
                "tasks": tasks,
                "confidence": round(min(1.0, conf), 3),
            }

        if action == "triage_snapshot":
            # One-shot firmware orientation bundle so users/agents can start from
            # a compact, actionable snapshot instead of orchestrating three calls.
            load = firmware_view(action="detect_load_address", auto_blackboard=False)
            vectors = firmware_view(action="detect_vector_table", auto_blackboard=False)
            mmio = firmware_view(action="detect_mmio", auto_blackboard=False)
            rtos_map = firmware_view(action="rtos_scan", auto_blackboard=False, limit=min(limit, 64))

            load_candidates = len(load.get("candidates", []) if isinstance(load, dict) else [])
            vector_entries = int(vectors.get("entry_count", 0) if isinstance(vectors, dict) else 0)
            mmio_regions = int(mmio.get("peripheral_count", 0) if isinstance(mmio, dict) else 0)
            likely_chip = (mmio.get("likely_chip_family") if isinstance(mmio, dict) else None) or "unknown"
            rtos_name = (rtos_map.get("rtos_detected") if isinstance(rtos_map, dict) else None) or "unknown"

            confidence = 0.2
            if load_candidates > 0:
                confidence += 0.3
            if vector_entries > 0:
                confidence += 0.3
            if mmio_regions > 0:
                confidence += 0.2
            if likely_chip != "unknown":
                confidence += 0.1
            if rtos_name != "unknown":
                confidence += 0.1
            confidence = round(min(1.0, confidence), 3)

            findings = []
            if load_candidates:
                findings.append(f"Load-address candidates: {load_candidates}")
            if vector_entries:
                findings.append(f"Vector/entry points found: {vector_entries}")
            if mmio_regions:
                findings.append(f"MMIO peripheral regions found: {mmio_regions}")
            if likely_chip != "unknown":
                findings.append(f"Likely chip family: {likely_chip}")
            if rtos_name != "unknown":
                findings.append(f"Likely RTOS: {rtos_name}")
            if not findings:
                findings.append("No strong firmware fingerprints yet; likely unmapped or non-firmware image.")

            next_actions = []
            if load_candidates == 0:
                next_actions.append("firmware_view(action='scan_region')")
            else:
                next_actions.append("firmware_view(action='detect_vector_table')")
            if vector_entries > 0:
                next_actions.append("code(action='smart_decompile', addrs='<reset_or_entry_handler>')")
            if mmio_regions > 0:
                next_actions.append("taint(action='report')")
            else:
                next_actions.append("firmware_view(action='detect_mmio')")
            if rtos_name == "unknown":
                next_actions.append("firmware_view(action='rtos_scan')")
            next_actions.append("firmware_view(action='carve_plan')")

            result = {
                "ok": True,
                "action": action,
                "confidence": confidence,
                "summary": {
                    "load_candidates": load_candidates,
                    "vector_entries": vector_entries,
                    "mmio_regions": mmio_regions,
                    "likely_chip_family": likely_chip,
                    "rtos_map": {
                        "rtos_detected": rtos_name,
                        "tasks": (rtos_map.get("tasks", []) if isinstance(rtos_map, dict) else [])[:20],
                        "confidence": rtos_map.get("confidence", 0.0) if isinstance(rtos_map, dict) else 0.0,
                    },
                },
                "findings": findings,
                "subresults": {
                    "load_address": load,
                    "vector_table": vectors,
                    "mmio": mmio,
                    "rtos_scan": rtos_map,
                },
                "next_actions": next_actions,
            }
            return _log_ml(result, action, f"triage_confidence={confidence}; vectors={vector_entries}; mmio={mmio_regions}")

        if action == "bootstrap":
            # Explicit bootstrap entrypoint for already-loaded binaries.
            # `run_firmware_bootstrap` is defined in this module (formerly in
            # the deleted `firmware_bootstrap.py` tool).
            try:
                from ida_pro_mcp.services import infer_binary_arch_profile
            except Exception:
                try:
                    from host.arch_profile import infer_binary_arch_profile  # type: ignore
                except Exception:
                    infer_binary_arch_profile = None  # type: ignore

            chip = str(kwargs.get("chip_family") or "").strip()
            load_base = kwargs.get("load_base")
            memory_map = kwargs.get("memory_map")
            periph = kwargs.get("peripheral_addresses")
            actions = kwargs.get("post_load_actions")
            if not chip and infer_binary_arch_profile is not None:
                try:
                    idb_path = idc.get_idb_path() or ""
                    bpath = idb_path[:-4] if idb_path.lower().endswith(".i64") else idb_path
                    if bpath:
                        prof = infer_binary_arch_profile(bpath)
                        chip = str(prof.get("chip_family") or "").strip() or chip
                        load_base = load_base if load_base is not None else prof.get("load_base")
                        memory_map = memory_map if memory_map is not None else prof.get("memory_map")
                        periph = periph if periph is not None else prof.get("peripheral_addresses")
                        actions = actions if actions is not None else prof.get("post_load_actions")
                except Exception:
                    pass

            report = run_firmware_bootstrap(
                chip_family=chip or "unknown",
                load_base=load_base if isinstance(load_base, int) else None,
                memory_map=memory_map if isinstance(memory_map, list) else None,
                peripheral_addresses=periph if isinstance(periph, list) else None,
                post_load_actions=actions if isinstance(actions, list) else None,
            )
            return _log_ml(
                {"ok": True, "bootstrap_report": report},
                action,
                f"chip={report.get('chip_family')} funcs={report.get('functions_created', 0)}",
            )

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
