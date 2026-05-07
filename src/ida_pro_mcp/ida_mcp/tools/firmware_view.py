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


def _fw_state_path() -> str:
    root = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp")
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
                return data
    except Exception:
        pass
    return {"history": [], "contradictions": []}


def _save_fw_state(state: dict) -> None:
    p = _fw_state_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def _seg_bounds(start: str | None, end: str | None):
    if start is not None or end is not None:
        if start is None or end is None:
            return None, None, make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
        return validate_range(start, end)
    min_ea = idaapi.cvar.inf.min_ea
    max_ea = idaapi.cvar.inf.max_ea
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


@tool
@idawrite
def firmware_view(
    action: Annotated[Literal["scan_region", "auto_retype", "pointer_sweep", "recommend", "table_candidates", "smart_carve", "rollback_last", "review_contradictions"], "Action: scan_region|auto_retype|pointer_sweep|recommend|table_candidates|smart_carve|rollback_last|review_contradictions"],
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
        s_ea, e_ea, err = _seg_bounds(start, end)
        if err:
            return err

        limit = max(1, min(int(limit), 2048))
        stride = max(1, min(int(stride), 16))
        min_run = max(4, min(int(min_run), 4096))

        inf = idaapi.get_inf_structure()
        ptr_size = 8 if inf.is_64bit() else 4

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
                    f"search(action='semantic', query='init parser dispatch checksum', limit=60)",
                ],
            }
            return _log_ml(result, action, f"unknown_ratio={unknown_ratio:.3f}; strategy={strategy}")

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
                            state["contradictions"].append({"ts": int(time.time()), "ea": hex(pea), "old": prev_kind, "new": "ptr", "reason": "code_to_ptr_guard"})
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
                            state["contradictions"].append({"ts": int(time.time()), "ea": hex(pea), "old": prev_kind, "new": "code", "reason": "data_to_code_guard"})
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
                    "search(action='semantic', query='dispatcher parser init table', limit=50)",
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
                    "search(action='semantic', query='switch dispatch jump table parser', limit=40)",
                ],
            }
            return _log_ml(result, action, f"table_candidates={len(candidates)}")

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
                        state["contradictions"].append({"ts": int(time.time()), "ea": hex(oa), "old": prev_kind, "new": k, "reason": "code_preservation_guard"})
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
                        if idc.create_strlit(oa, idc.BADADDR):
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
            return {
                "ok": True,
                "action": action,
                "count": len(items),
                "items": items[-limit:],
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
            around_start = max(idaapi.cvar.inf.min_ea, anchor - 0x200)
            around_end = min(idaapi.cvar.inf.max_ea, anchor + 0x200)
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
