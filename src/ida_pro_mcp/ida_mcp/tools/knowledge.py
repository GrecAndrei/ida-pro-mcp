from __future__ import annotations

import hashlib
from typing import Annotated, Any, Dict, List, Literal, Optional

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ida_pro_mcp.services import SymbolDB
except ImportError:
    from host.stores.symbol_db import SymbolDB  # type: ignore[import-not-found]

try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]


def _collect_string_refs(func_ea: int, limit: int = 24) -> List[str]:
    out: List[str] = []
    fn_start = _compat.get_func_start(func_ea)
    if fn_start is None:
        return out
    seen = set()
    for item_ea in idautils.FuncItems(fn_start):
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
    callers = sorted({start for x in idautils.CodeRefsTo(func_ea, 0) if (start := _compat.get_func_start(x)) is not None})
    callees = set()
    fn_start = _compat.get_func_start(func_ea)
    if fn_start is not None:
        for item_ea in idautils.FuncItems(fn_start):
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                cf_start = _compat.get_func_start(ref)
                if cf_start is not None and cf_start != fn_start:
                    callees.add(cf_start)
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
    action: Annotated[Literal["symbol_lookup", "import_symbols", "export_session"],
                      "Action: symbol_lookup|import_symbols|export_session"],
    query: Annotated[Optional[str], "Fuzzy query for symbol_lookup"] = None,
    min_confidence: Annotated[float, "Minimum confidence threshold for import/export"] = 0.8,
    limit: Annotated[int, "Max rows"] = 50,
    db_path: Annotated[Optional[str], "Optional symbol DB path"] = None,
    **kwargs,
) -> dict:
    try:
        sdb = SymbolDB(db_path)

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
