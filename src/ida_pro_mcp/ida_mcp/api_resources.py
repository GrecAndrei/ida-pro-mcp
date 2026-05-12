"""MCP resources exposing IDA analysis state as navigable URIs."""

from __future__ import annotations

from typing import Any, Dict, List

import ida_funcs
import ida_gdl
import ida_hexrays
import ida_lines
import ida_name
import idaapi
import idautils
import idc

from .rpc import resource
from .sync import idaread
from .tools.blackboard import BlackboardStore
from .tools.classify import classify
from .tools.mbagcn import mbagcn


def _parse_addr(addr: str) -> int:
    try:
        return int(addr, 0)
    except Exception as exc:
        raise ValueError(f"invalid address: {addr}") from exc


def _hx(ea: int) -> str:
    return hex(int(ea))


def _func_or_error(addr: str):
    ea = _parse_addr(addr)
    f = ida_funcs.get_func(ea)
    if not f:
        return ea, None, {"error": f"function not found at {_hx(ea)}"}
    return ea, f, None


@resource("/functions")
@idaread
def res_functions() -> Dict[str, Any]:
    out = []
    for ea in idautils.Functions():
        out.append({"address": _hx(ea), "name": ida_name.get_ea_name(ea) or f"sub_{ea:x}"})
    return {"count": len(out), "functions": out}


@resource("/functions/{addr}")
@idaread
def res_function_detail(addr: str) -> Dict[str, Any]:
    ea, f, err = _func_or_error(addr)
    if err:
        return err
    bb_count = None
    try:
        bb_count = sum(1 for _ in ida_gdl.FlowChart(f))
    except Exception:
        pass
    return {
        "address": _hx(f.start_ea),
        "start": _hx(f.start_ea),
        "end": _hx(f.end_ea),
        "name": ida_name.get_ea_name(f.start_ea) or f"sub_{f.start_ea:x}",
        "size": int(f.end_ea - f.start_ea),
        "basic_block_count": bb_count,
    }


@resource("/functions/{addr}/pseudocode")
@idaread
def res_function_pseudocode(addr: str) -> Dict[str, Any]:
    ea, f, err = _func_or_error(addr)
    if err:
        return err
    if ida_hexrays.init_hexrays_plugin():
        try:
            cfunc = ida_hexrays.decompile(f.start_ea)
            if cfunc:
                lines = [ida_lines.tag_remove(s.line) for s in cfunc.get_pseudocode()]
                return {"address": _hx(f.start_ea), "mode": "pseudocode", "text": "\n".join(lines)}
        except Exception:
            pass
    dis = []
    for head in idautils.FuncItems(f.start_ea):
        if idc.is_code(idc.get_full_flags(head)):
            dis.append(f"{_hx(head)}: {idc.generate_disasm_line(head, 0) or ''}")
    return {"address": _hx(f.start_ea), "mode": "disassembly", "text": "\n".join(dis)}


@resource("/functions/{addr}/disasm")
@idaread
def res_function_disasm(addr: str) -> Dict[str, Any]:
    ea, f, err = _func_or_error(addr)
    if err:
        return err
    dis = []
    for head in idautils.FuncItems(f.start_ea):
        if idc.is_code(idc.get_full_flags(head)):
            dis.append({"address": _hx(head), "line": idc.generate_disasm_line(head, 0) or ""})
    return {"address": _hx(f.start_ea), "count": len(dis), "instructions": dis}


@resource("/functions/{addr}/xrefs_to")
@idaread
def res_function_xrefs_to(addr: str) -> Dict[str, Any]:
    ea, f, err = _func_or_error(addr)
    if err:
        return err
    refs = []
    for xr in idautils.XrefsTo(f.start_ea):
        refs.append({"from": _hx(xr.frm), "to": _hx(xr.to), "caller": ida_name.get_ea_name(ida_funcs.get_func(xr.frm).start_ea) if ida_funcs.get_func(xr.frm) else None})
    return {"address": _hx(f.start_ea), "count": len(refs), "xrefs_to": refs}


@resource("/functions/{addr}/xrefs_from")
@idaread
def res_function_xrefs_from(addr: str) -> Dict[str, Any]:
    ea, f, err = _func_or_error(addr)
    if err:
        return err
    refs = []
    for head in idautils.FuncItems(f.start_ea):
        for xr in idautils.XrefsFrom(head):
            refs.append({"from": _hx(xr.frm), "to": _hx(xr.to), "target_name": ida_name.get_ea_name(xr.to) or None})
    return {"address": _hx(f.start_ea), "count": len(refs), "xrefs_from": refs}


@resource("/functions/{addr}/classification")
@idaread
def res_function_classification(addr: str) -> Dict[str, Any]:
    _ea, _f, err = _func_or_error(addr)
    if err:
        return err
    return classify(action="function", addr=addr)


@resource("/functions/{addr}/similar")
@idaread
def res_function_similar(addr: str) -> Dict[str, Any]:
    _ea, _f, err = _func_or_error(addr)
    if err:
        return err
    return mbagcn(action="similar", addr=addr, top_k=10)


@resource("/blackboard")
@idaread
def res_blackboard() -> Dict[str, Any]:
    store = BlackboardStore()
    rows = store.list(limit=100)
    return {"count": len(rows), "entries": [{"id": r["id"], "title": r["title"], "confidence": r.get("confidence", 0.0)} for r in rows]}


@resource("/blackboard/{id}")
@idaread
def res_blackboard_entry(id: str) -> Dict[str, Any]:
    store = BlackboardStore()
    row = store.read(id)
    if not row:
        return {"error": f"blackboard entry not found: {id}"}
    return row


@resource("/blackboard/search/{query}")
@idaread
def res_blackboard_search(query: str) -> Dict[str, Any]:
    store = BlackboardStore()
    q = query.lower()
    rows = [r for r in store.list(limit=200) if q in (r.get("title") or "").lower() or q in (r.get("content") or "").lower() or any(q in t.lower() for t in r.get("tags", []))]
    return {"query": query, "count": len(rows), "results": rows}


@resource("/analysis/interesting")
@idaread
def res_analysis_interesting() -> Dict[str, Any]:
    ranked: List[Dict[str, Any]] = []
    for ea in idautils.Functions():
        name = ida_name.get_ea_name(ea) or f"sub_{ea:x}"
        size = ida_funcs.calc_func_size(ida_funcs.get_func(ea)) if ida_funcs.get_func(ea) else 0
        score = float(size)
        if any(k in name.lower() for k in ["decrypt", "alloc", "exec", "auth", "check"]):
            score += 300.0
        ranked.append({"address": _hx(ea), "name": name, "score": score, "size": int(size)})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return {"count": min(len(ranked), 25), "functions": ranked[:25]}
