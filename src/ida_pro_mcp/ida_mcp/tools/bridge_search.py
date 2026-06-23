"""
Bridge-conditioned multi-hop search for discovering indirect relationships.

Deterministic multi-hop retrieval that finds structurally related functions
through shared bridge entities (APIs, strings, xrefs).  Uses SchemaBoot's
SQLite index as the bridge source.  No LLM required.

Bridge-conditioned multi-hop retrieval:
  s(q, b, c) = conditional utility of candidate c given query q and bridge b.

This module is a thin shim: the actual algorithm lives in
``ida_pro_mcp.host.intelligence_bridge_retrieval.MultiHopBridgeIndex``.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore
if "idawrite" not in globals():
    idawrite = lambda f: f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore

from ida_pro_mcp.services import (
    MultiHopBridgeIndex,
    _resolve_schemaboot_db_path,
)


@tool
def bridge_search(
    action: str = "search",
    query_constraints: Optional[Dict[str, Any]] = None,
    func_ea: Optional[str] = None,
    func_name: Optional[str] = None,
    bridge_types: Optional[List[str]] = None,
    top_k: int = 20,
    hops: int = 2,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Multi-hop bridge-conditioned search for indirect relationships.

    Actions:
      - search: SchemaBoot-constrained search using bridge-conditioned multi-hop ranking.
      - bridges: enumerate candidate bridges for a seed function (by address or name).

    Args:
        action: ``search`` or ``bridges``.
        query_constraints: dict of SchemaBoot-style attribute filters for seed selection.
        func_ea: seed function address (hex string) for ``action="bridges"``.
        func_name: seed function name for ``action="bridges"``.
        bridge_types: ``["apis"]``, ``["strings"]`` or both.
        top_k: max candidates to return (default 20).
        hops: number of hops (2 = standard, >2 = extended).
        db_path: override path to SchemaBoot SQLite DB.
    """
    if MultiHopBridgeIndex is None:
        return {"ok": False, "error": "MultiHopBridgeIndex not importable"}

    bt = bridge_types or ["apis", "strings"]
    try:
        bt = [b for b in bt if b in ("apis", "strings")]
        if not bt:
            bt = ["apis", "strings"]
    except TypeError:
        bt = ["apis", "strings"]

    if action == "bridges" and not func_ea and not func_name:
        return {
            "ok": True,
            "action": "bridges",
            "candidates": [],
            "bridges": {},
            "bridge_types": bt,
            "func_ea": None,
            "func_name": None,
            "top_k": int(top_k),
            "note": "no seed function specified; returning empty bridges",
        }

    dbp = db_path
    if not dbp and _resolve_schemaboot_db_path is not None:
        try:
            dbp = _resolve_schemaboot_db_path()
        except Exception:
            dbp = None
    if not dbp or not os.path.exists(dbp):
        return {"ok": False, "error": f"SchemaBoot DB not found: {dbp!r}"}

    try:
        idx = MultiHopBridgeIndex(dbp)
    except Exception as exc:
        return {"ok": False, "error": f"index init failed: {exc}"}

    if action == "search":
        if not query_constraints:
            return {"ok": False, "error": "query_constraints required for action='search'"}
        try:
            res = idx.search_via_bridges(
                query_constraints=query_constraints,
                bridge_types=bt,
                top_k=int(top_k),
                hops=int(hops),
            )
        except Exception as exc:
            return {"ok": False, "error": f"search failed: {exc}"}
        return {
            "ok": True,
            "action": "search",
            "candidates": res.get("candidates", []),
            "bridges": res.get("bridges", {}),
            "bridge_types": bt,
            "hops": int(hops),
            "top_k": int(top_k),
        }

    if action == "bridges":
        try:
            res = idx.extract_bridges(
                func_ea=func_ea,
                func_name=func_name,
                bridge_types=bt,
                top_k=int(top_k),
            )
        except Exception as exc:
            return {"ok": False, "error": f"bridges failed: {exc}"}
        return {
            "ok": True,
            "action": "bridges",
            "candidates": res.get("candidates", []),
            "bridges": res.get("bridges", {}),
            "bridge_types": bt,
            "func_ea": func_ea,
            "func_name": func_name,
            "top_k": int(top_k),
        }

    return {"ok": False, "error": f"unknown action: {action!r}"}
