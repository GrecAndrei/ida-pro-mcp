from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover - non-IDA test fallback
        def tool(f):  # type: ignore
            return f
        def idawrite(f):  # type: ignore
            return f
        class _DummyErr:
            IDA_ERROR = "IDA_ERROR"
        MCPError = _DummyErr()  # type: ignore
        def handle_error(e):  # type: ignore
            return {"ok": False, "error": str(e)}


def _safe_bounds() -> tuple[int, int]:
    try:
        mn = int(_inf_min_ea())
        mx = int(_inf_max_ea())
        return mn, mx
    except Exception:
        return 0, 0


def _int_addr(v: Any) -> Optional[int]:
    try:
        if isinstance(v, str):
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        return int(v)
    except Exception:
        return None


def _run_vector_bootstrap() -> Dict[str, Any]:
    try:
        from .firmware_view import firmware_view
    except Exception:
        from firmware_view import firmware_view  # type: ignore

    res = firmware_view(action="detect_vector_table", auto_blackboard=False)
    vectors = res.get("vectors") if isinstance(res, dict) else []
    if not isinstance(vectors, list):
        vectors = []

    mn, mx = _safe_bounds()
    created = 0
    entries = 0
    reset_addr = None
    code_failures = []
    func_failures = []

    # Fix segment class: ensure segments are CODE not DATA for firmware
    try:
        seg = idaapi.getseg(mn)
        if seg:
            cur_class = ida_segment.get_segm_class(seg)
            if cur_class != "CODE" or not ida_segment.is_spec_segm(mn):
                ida_segment.set_segm_class(seg, "CODE")
    except Exception:
        pass

    handler_addrs = []
    skipped_oob = []
    for vec in vectors:
        if not isinstance(vec, dict):
            continue
        if str(vec.get("type") or "") == "stack_pointer":
            continue
        h = _int_addr(vec.get("handler") or vec.get("value"))
        if h is None or h < mn or h >= mx:
            skipped_oob.append(hex(vec.get("handler") or vec.get("value") or 0))
            continue
        handler_addrs.append((h, vec))

    if handler_addrs:
        # Thumb bootstrap for Cortex-M handlers — set T=1 segment register
        # for all address space so create_insn uses Thumb decoding.
        try:
            proc = (_inf_procname() or "").lower()
        except Exception:
            proc = ""
        if "arm" in proc:
            try:
                sr_auto = getattr(idc, "SR_auto", 2)
                idc.split_sreg_range(mn, "T", 1, sr_auto)
            except Exception:
                try:
                    import ida_segregs
                    ida_segregs.split_sreg_range(mn, "T", 1, 2)
                except Exception:
                    pass
        for h, _ in handler_addrs:
            if "arm" in proc:
                try:
                    sr_auto = getattr(idc, "SR_auto", 2)
                    idc.split_sreg_range(h, "T", 1, sr_auto)
                except Exception:
                    try:
                        import ida_segregs
                        ida_segregs.split_sreg_range(h, "T", 1, 2)
                    except Exception:
                        pass
        for h, _ in handler_addrs:
            if not ida_bytes.is_code(ida_bytes.get_flags(h)):
                created_insn = False
                try:
                    import ida_ua
                    insn_len = ida_ua.create_insn(h)
                    created_insn = insn_len > 0
                except Exception:
                    pass
                if not created_insn:
                    try:
                        insn_len = idc.create_insn(h)
                        created_insn = insn_len > 0
                    except Exception:
                        pass
                if not created_insn:
                    code_failures.append(hex(h))
                # Undefine bytes then retry for stubborn addresses
                if not created_insn:
                    try:
                        ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, 16)
                        if hasattr(ida_auto, "auto_make_code"):
                            ida_auto.auto_make_code(h)
                    except Exception:
                        pass
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
    result = {
        "vectors_detected": len(vectors),
        "entry_points_defined": entries,
        "functions_created": created,
        "reset_handler": (hex(reset_addr) if reset_addr is not None else None),
    }
    if code_failures or func_failures or skipped_oob:
        result["_debug"] = {
            "handler_count": len(handler_addrs),
            "skipped_oob": skipped_oob[:10],
            "add_func_sample": add_func_results[:10],
            "code_failures": code_failures[:10],
            "func_failures": func_failures[:10],
        }
        result["_status"] = "partial" if (created > 0 or entries > 0) else "failed"
    return result


def _annotate_mmio(peripherals: List[Dict[str, Any]]) -> Dict[str, Any]:
    annotated = 0
    for p in peripherals:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or p.get("peripheral_name") or "").strip()
        base = _int_addr(p.get("addr") or p.get("base"))
        if not name or base is None:
            continue
        sym = name.upper().replace(" ", "_")
        if not sym.endswith("_BASE"):
            sym += "_BASE"
        idc.set_name(base, sym, ida_name.SN_FORCE)
        idc.set_cmt(base, f"MMIO base for {name}", 1)
        annotated += 1
    return {"peripherals_annotated": annotated}


def _define_ascii_strings(limit: int = 256) -> Dict[str, Any]:
    # Use IDA's built-in string scanner rather than a byte-by-byte loop.
    try:
        idaapi.build_strlist()
    except Exception:
        pass
    defined = idaapi.get_strlist_qty() if hasattr(idaapi, "get_strlist_qty") else 0
    return {"strings_defined": min(defined, limit)}


def run_firmware_bootstrap(
    chip_family: str,
    load_base: Optional[int] = None,
    memory_map: Optional[List[Dict[str, Any]]] = None,
    peripheral_addresses: Optional[List[Dict[str, Any]]] = None,
    post_load_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    actions = list(post_load_actions or ["define_vector_table", "annotate_mmio", "reanalyze", "define_strings"])
    report: Dict[str, Any] = _base_bootstrap_report(chip_family, load_base, actions)
    report["processor"] = str(_inf_procname() or "")

    for action in actions:
        if action == "define_vector_table":
            r = _run_vector_bootstrap()
            report["details"][action] = r
            report["functions_created"] += int(r.get("functions_created", 0) or 0)
            report["entry_points_defined"] += int(r.get("entry_points_defined", 0) or 0)
            report["reset_handler"] = report.get("reset_handler") or r.get("reset_handler")
        elif action == "annotate_mmio":
            r = _annotate_mmio(list(peripheral_addresses or []))
            report["details"][action] = r
            report["peripherals_annotated"] += int(r.get("peripherals_annotated", 0) or 0)
        elif action == "reanalyze":
            # Schedule a non-blocking re-analysis pass. Do NOT call auto_wait()
            # here — it blocks the main thread in the socket-server context and
            # crashes IDA. Use plan_range (fire-and-forget) so IDA's idle loop
            # picks it up after this RPC call returns.
            try:
                import ida_auto as _ida_auto
                mn, mx = _safe_bounds()
                if mn < mx:
                    if hasattr(_ida_auto, "plan_range"):
                        _ida_auto.plan_range(mn, mx)
                    elif hasattr(_ida_auto, "auto_mark_range"):
                        _ida_auto.auto_mark_range(mn, mx, _ida_auto.AU_FINAL)
                report["details"][action] = {"ok": True, "note": "scheduled (non-blocking)"}
            except Exception as e:
                report["details"][action] = {"ok": False, "error": str(e)}
        elif action == "define_strings":
            r = _define_ascii_strings()
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


def _base_bootstrap_report(chip_family: str, load_base: Optional[int], actions: List[str]) -> Dict[str, Any]:
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


@tool
@idawrite
def firmware_bootstrap(
    chip_family: str = "",
    load_base: Optional[int] = None,
    memory_map: Optional[List[Dict[str, Any]]] = None,
    peripheral_addresses: Optional[List[Dict[str, Any]]] = None,
    post_load_actions: Optional[List[str]] = None,
    **kwargs,
) -> dict:
    """Run chip-aware post-load firmware bootstrap and return a structured report."""
    try:
        cf = chip_family or str(kwargs.get("chip_family") or "").strip() or "unknown"
        return run_firmware_bootstrap(
            chip_family=cf,
            load_base=load_base,
            memory_map=memory_map,
            peripheral_addresses=peripheral_addresses,
            post_load_actions=post_load_actions,
        )
    except Exception as e:
        return handle_error(e)
