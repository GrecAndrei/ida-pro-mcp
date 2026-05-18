from __future__ import annotations

import hashlib
from typing import Annotated, Any, Dict, List, Literal, Optional

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ida_pro_mcp.host.arch_profile import infer_binary_arch_profile
    from ida_pro_mcp.host.chip_db import get_chip_family_catalog
    from ida_pro_mcp.host.symbol_db import SymbolDB
except ImportError:
    from host.arch_profile import infer_binary_arch_profile  # type: ignore[import-not-found]
    from host.chip_db import get_chip_family_catalog  # type: ignore[import-not-found]
    from host.symbol_db import SymbolDB  # type: ignore[import-not-found]


def _collect_string_refs(func_ea: int, limit: int = 24) -> List[str]:
    out: List[str] = []
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return out
    seen = set()
    for item_ea in idautils.FuncItems(fn.start_ea):
        for ref in idautils.DataRefsFrom(item_ea):
            s = idc.get_strlit_contents(ref, -1, idc.STRTYPE_C)
            if not s:
                continue
            txt = s.decode(errors="ignore").strip()
            if not txt or txt in seen:
                continue
            seen.add(txt)
            out.append(txt[:120])
            if len(out) >= limit:
                return out
    return out


def _fingerprint_function(func_ea: int) -> Dict[str, Any]:
    callers = sorted({ida_funcs.get_func(x).start_ea for x in idautils.CodeRefsTo(func_ea, 0) if ida_funcs.get_func(x)})
    callees = set()
    fn = ida_funcs.get_func(func_ea)
    if fn:
        for item_ea in idautils.FuncItems(fn.start_ea):
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                cf = ida_funcs.get_func(ref)
                if cf and cf.start_ea != fn.start_ea:
                    callees.add(cf.start_ea)
    strs = _collect_string_refs(func_ea)
    callgraph_payload = "|".join([f"c:{hex(x)}" for x in callers[:32]] + [f"d:{hex(x)}" for x in sorted(callees)[:64]])
    callgraph_hash = hashlib.sha1(callgraph_payload.encode("utf-8")).hexdigest()
    fp_payload = callgraph_payload + "||" + "|".join(sorted(strs)[:32])
    fingerprint = hashlib.sha1(fp_payload.encode("utf-8")).hexdigest()
    return {
        "fingerprint": fingerprint,
        "callgraph_hash": callgraph_hash,
        "strings": strs,
    }


@tool
@idawrite
def knowledge(
    action: Annotated[Literal["chip_identify", "symbol_lookup", "import_symbols", "export_session", "chip_families"],
                      "Action: chip_identify|symbol_lookup|import_symbols|export_session|chip_families"],
    query: Annotated[Optional[str], "Fuzzy query for symbol_lookup"] = None,
    min_confidence: Annotated[float, "Minimum confidence threshold for import/export"] = 0.8,
    limit: Annotated[int, "Max rows"] = 50,
    db_path: Annotated[Optional[str], "Optional symbol DB path"] = None,
    **kwargs,
) -> dict:
    try:
        sdb = SymbolDB(db_path)

        if action == "chip_identify":
            idb_path = idc.get_idb_path() or ""
            input_path = idb_path[:-4] if idb_path.lower().endswith(".i64") else idb_path
            if not input_path:
                return make_error(MCPError.IDA_ERROR, "Could not resolve input binary path")
            profile = infer_binary_arch_profile(input_path)
            return {"ok": True, "profile": profile}

        if action == "chip_families":
            families = get_chip_family_catalog()
            stats = sdb.stats_by_chip()
            stat_map = {str(s.get("chip_family") or "").lower(): int(s.get("symbol_count") or 0) for s in stats}
            for f in families:
                f["match_stats"] = {"symbol_count": stat_map.get(str(f.get("chip_family", "")).lower(), 0)}
            return {"ok": True, "families": families, "count": len(families)}

        if action == "symbol_lookup":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query is required for symbol_lookup")
            rows = sdb.query_symbols(query, limit=max(1, min(int(limit), 200)))
            return {"ok": True, "matches": rows, "count": len(rows)}

        if action == "export_session":
            chip_family = kwargs.get("chip_family") or ""
            idb_path = idc.get_idb_path() or ""
            exported = 0
            for f_ea in idautils.Functions():
                name = idc.get_func_name(f_ea) or ""
                if not name or name.startswith("sub_"):
                    continue
                fp = _fingerprint_function(f_ea)
                row = {
                    "symbol_name": name,
                    "source_session": kwargs.get("session_id") or "",
                    "source_binary": idb_path,
                    "source_addr": hex(f_ea),
                    "chip_family": chip_family,
                    "fingerprint": fp["fingerprint"],
                    "callgraph_hash": fp["callgraph_hash"],
                    "strings": fp["strings"],
                    "confidence": 1.0,
                }
                rid = sdb.upsert_symbol(row)
                if rid:
                    exported += 1
            return {"ok": True, "exported": exported, "db_path": sdb.db_path}

        if action == "import_symbols":
            imported = 0
            proposals = []
            for f_ea in idautils.Functions():
                cur_name = idc.get_func_name(f_ea) or ""
                if cur_name and not cur_name.startswith("sub_"):
                    continue
                fp = _fingerprint_function(f_ea)
                matches = sdb.lookup_by_fingerprint(fp["fingerprint"], limit=5)
                if not matches:
                    continue
                best = matches[0]
                conf = float(best.get("confidence", 0.0) or 0.0)
                if conf < float(min_confidence):
                    continue
                target_name = str(best.get("symbol_name") or "").strip()
                if not target_name:
                    continue
                ok = bool(idc.set_name(f_ea, target_name, ida_name.SN_FORCE))
                proposals.append({
                    "addr": hex(f_ea),
                    "name": target_name,
                    "confidence": conf,
                    "applied": ok,
                    "source_binary": best.get("source_binary"),
                })
                if ok:
                    imported += 1
            return {
                "ok": True,
                "imported": imported,
                "proposals": proposals[: max(1, min(int(limit), 500))],
                "db_path": sdb.db_path,
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
