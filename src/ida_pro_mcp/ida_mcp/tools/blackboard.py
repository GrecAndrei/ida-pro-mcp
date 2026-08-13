"""
Blackboard: thin IDA-side bridge to the analysis-memory subsystem.

The host server is the single authority for blackboard actions: a dict-driven
action dispatcher in ``host/server/server_blackboard.py`` routes every
``blackboard`` MCP call over the rewritten store, and owns the crawler, the
phase machine, the policy gate, the trace module, and the workspace export/
import round-trip.

This module is deliberately small. It only keeps the three integration seams
that other IDA-side modules call directly:

  ``BlackboardStore``       - the IDA-side subclass (embedder wiring) that
                              calc/gadgets/code_helpers/search/intelligence
                              import via ``from .blackboard import BlackboardStore``
                              (and the guarded flat fallback form).
  ``related_by_behavior``   - internal action called directly by
                              ``intelligence.blackboard_search``.
  ``CrawlerProbe``          - a thin crawler-probe adapter the host crawler
                              orchestrator imports to run in-IDA xref/symbol
                              probes without knowing tool payload shapes.

``blackboard(action=...)`` calls for any other action are routed by the host;
an in-process call for a removed/unknown action returns ACTION_NOT_FOUND.

Categories are a plain string tag (region, ioc, dead_end, dependency,
data_flow, contradiction, hypothesis, ...). The phantom auto-capture
categories of the legacy engine were dropped together with it; the ``calc``
persistence capture is now opt-in (``persist=True``) and lives in
``calc._calc_persist_capture``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

try:
    from ._common import (
        Any,
        IDAError,
        MCPError,
        Optional,
        ida_funcs,
        idaread,
        idautils,
        idawrite,
        make_error,
        tool
    )
except ImportError:
    # Host loads this file via spec_from_file_location as `_host_blackboard`,
    # which has no package parent — relative `_common` cannot resolve.
    pass

if "tool" not in globals():
    def tool(f):
        return f  # type: ignore
if "idaread" not in globals():
    def idaread(f):
        return f  # type: ignore
if "idawrite" not in globals():
    def idawrite(f):
        return f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore

# The host loads this module standalone via `spec_from_file_location` (module
# name `_host_blackboard`) where `_common` is not importable; provide the same
# error envelope the real `_common` exports so the thin bridge and the
# crawler-probe adapter degrade cleanly instead of raising NameError.
if "make_error" not in globals():
    def make_error(code, message, **kw):  # type: ignore[no-redef]
        return {"ok": False, "code": code, "message": message, **kw}
if "MCPError" not in globals():
    class MCPError:  # type: ignore[no-redef]  # noqa: D401
        INVALID_ARGS = "INVALID_ARGS"
        ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
        NOT_FOUND = "NOT_FOUND"
        IDA_ERROR = "IDA_ERROR"

try:
    from ida_pro_mcp.services import BlackboardStore as _BaseBlackboardStore
except ImportError:
    try:
        from host.blackboard_store import BlackboardStore as _BaseBlackboardStore  # type: ignore
    except ImportError:
        raise


def _get_embedder():
    try:
        from ida_pro_mcp.services import BgeCodeEmbedder
        return BgeCodeEmbedder()
    except ImportError:
        try:
            from host.intelligence.core import BgeCodeEmbedder  # type: ignore
            return BgeCodeEmbedder()
        except ImportError:
            return None


class BlackboardStore(_BaseBlackboardStore):
    def _get_embedder(self):
        return _get_embedder()


# ─────────────────────────────────────────────────────────────────────────────
# related_by_behavior — internal recall action used by intelligence.search
# ─────────────────────────────────────────────────────────────────────────────

def _related_by_behavior(
    store,
    *,
    query: str,
    top_k: int = 10,
    threshold: float = 0.4,
    category: Optional[str] = None,
    include_resolved: bool = False,
    include_contradicted: bool = False,
) -> Dict[str, Any]:
    """Semantic recall of entries related to ``query`` by behavior.

    Internal action: called directly by ``intelligence.blackboard_search``,
    not exposed on the host action enum. The response shape is pinned —
    ``{ok, behavior, results, count}`` with each result carrying
    ``{entry_id, title, addr, category, confidence, similarity, tags}`` —
    so ``intelligence.blackboard_search`` keeps working unchanged.
    """
    try:
        thr = float(threshold or 0.4)
    except (TypeError, ValueError):
        thr = 0.4
    try:
        top = max(1, int(top_k or 10))
    except (TypeError, ValueError):
        top = 10
    hits = store.semantic_search(
        query=query,
        top_k=top,
        threshold=max(0.0, thr),
        category=category,
        include_resolved=include_resolved,
        include_contradicted=include_contradicted,
    )
    out: List[Dict[str, Any]] = []
    for h in hits:
        tags = h.get("tags") or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        out.append(
            {
                "entry_id": h.get("id"),
                "title": h.get("title"),
                "addr": h.get("addr"),
                "category": h.get("category"),
                "confidence": h.get("confidence"),
                "similarity": h.get("similarity"),
                "tags": tags,
            }
        )
    return {"ok": True, "behavior": query, "results": out, "count": len(out)}


# ─────────────────────────────────────────────────────────────────────────────
# MCP tool — thin bridge
# ─────────────────────────────────────────────────────────────────────────────

@tool
def blackboard(
    action: str = "related_by_behavior",
    db_path: str = "",
    **kwargs,
) -> dict:
    """
    Thin IDA-side bridge to the analysis-memory (blackboard) subsystem.

    The host server is the single authority for blackboard actions; only
    ``related_by_behavior`` is handled in-IDA (it is called directly by
    ``intelligence(action='blackboard_search')``). Every other action is
    dispatched by the host, and a call for a removed/unknown action returns
    ACTION_NOT_FOUND.

    Categories are a plain string tag (region, ioc, dead_end, dependency,
    data_flow, contradiction, hypothesis, ...).

    Internal action:
      related_by_behavior - semantic recall of entries related to `query`;
                            returns {ok, behavior, results, count}.
    """
    if action == "related_by_behavior":
        query = str(kwargs.get("query") or "").strip()
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required for related_by_behavior")
        store = BlackboardStore(db_path=db_path or None)
        return _related_by_behavior(
            store,
            query=query,
            top_k=kwargs.get("top_k", 10),
            threshold=kwargs.get("threshold", 0.4),
            category=kwargs.get("category") or None,
            include_resolved=bool(kwargs.get("include_resolved", False)),
            include_contradicted=bool(kwargs.get("include_contradicted", False)),
        )
    return make_error(
        MCPError.ACTION_NOT_FOUND,
        f"Unknown action: {action}",
        hint="Blackboard actions are dispatched by the host server; only related_by_behavior is handled in-IDA.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Crawler-probe adapter — in-IDA xref/symbol probes for the host orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def _probe_addr(addr: Any) -> str:
    """Normalize an address to a canonical ``0x...`` string, or ``""``."""
    if addr is None:
        return ""
    if isinstance(addr, int):
        return hex(addr)
    text = str(addr).strip().lower()
    if not text:
        return ""
    if text.startswith("0x"):
        body = text[2:].lstrip("0") or "0"
        return "0x" + body
    return text


def _rpc_probe(rpc_fn, tool_name: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run one tool-RPC probe; return the response dict or None on failure."""
    try:
        res = rpc_fn(tool_name, payload)
        return res if isinstance(res, dict) else None
    except Exception:
        return None


class CrawlerProbe:
    """Thin crawler-probe adapter for in-IDA xref/symbol probes.

    The host crawler orchestrator imports this to probe the live IDA session
    without knowing tool payload shapes. Two modes:

    * ``rpc_fn`` provided — probes run through the host tool-RPC bridge, the
      same ``rpc_fn(tool, payload) -> dict`` convention the host store already
      uses for ``targets(strategy, rpc_fn=...)``.
    * no ``rpc_fn``       — probes run directly against the IDA SDK when this
      module is loaded inside IDA; the SDK imports are lazy so the module still
      imports in a standalone interpreter, where probes return empty results.

    Every method returns plain dict/list values and never raises: a failed or
    unavailable probe yields an empty result set, so the crawler can treat it
    as "nothing discovered". Addresses are normalized to canonical ``0x...``.
    """

    def __init__(self, rpc_fn=None):
        self._rpc_fn = rpc_fn

    def xrefs_to(self, addr, limit: int = 64) -> List[Dict[str, Any]]:
        """Addresses that reference ``addr``. Returns ``[{addr, kind, name}]``."""
        addr_str = _probe_addr(addr)
        if not addr_str:
            return []
        if self._rpc_fn is not None:
            res = _rpc_probe(
                self._rpc_fn,
                "code",
                {"action": "xrefs_to", "addrs": addr_str, "max_items": max(1, int(limit))},
            )
            return self._parse_xref_lines(res.get("xrefs"), limit) if res else []
        return self._ida_xrefs_to(addr_str, limit)

    def symbols(self, name: str = "", limit: int = 64) -> List[Dict[str, Any]]:
        """Resolve functions whose name matches ``name`` (substring, case-insensitive).

        Returns ``[{addr, name}]``.
        """
        name = str(name or "").strip()
        if not name:
            return []
        if self._rpc_fn is not None:
            res = _rpc_probe(
                self._rpc_fn,
                "data",
                {
                    "action": "functions",
                    "query": name,
                    "structured": True,
                    "count": max(1, int(limit)),
                    "named_only": True,
                },
            )
            return self._parse_function_items(res, limit) if res else []
        return self._ida_symbols(name, limit)

    def function_probe(self, addr) -> Dict[str, Any]:
        """Compact classification probe for one function.

        Returns ``{addr, name, behavior_tags, callees}`` (empty-safe): the
        information the crawler needs to propose a hypothesis entry for a
        newly discovered address. ``callees`` is a list of ``{addr, name}``.
        """
        addr_str = _probe_addr(addr)
        if not addr_str:
            return {"addr": "", "name": "", "behavior_tags": [], "callees": []}
        if self._rpc_fn is not None:
            res = _rpc_probe(
                self._rpc_fn,
                "code",
                {"action": "smart_decompile", "addr": addr_str, "details": False},
            )
            if not res:
                return {"addr": addr_str, "name": "", "behavior_tags": [], "callees": []}
            callees = []
            for c in res.get("callees") or []:
                if isinstance(c, dict):
                    c_addr = _probe_addr(c.get("addr") or c.get("ea"))
                    c_name = str(c.get("name") or c_addr or "")
                    if c_addr:
                        callees.append({"addr": c_addr, "name": c_name})
            return {
                "addr": _probe_addr(res.get("addr") or addr_str),
                "name": str(res.get("name") or ""),
                "behavior_tags": list(res.get("behavior_tags") or []),
                "callees": callees,
            }
        return self._ida_function_probe(addr_str)

    # -- parsing helpers (rpc mode) -----------------------------------------

    @staticmethod
    def _parse_xref_lines(text, limit: int) -> List[Dict[str, Any]]:
        """Parse the ``code(xrefs_to)`` text format: ``addr  kind  name``."""
        out: List[Dict[str, Any]] = []
        if not isinstance(text, str):
            return out
        for line in text.splitlines():
            if len(out) >= limit:
                break
            parts = [p for p in line.strip().split() if p]
            if not parts:
                continue
            entry = {"addr": _probe_addr(parts[0]), "kind": "", "name": ""}
            if len(parts) >= 2:
                entry["kind"] = parts[1]
            if len(parts) >= 3:
                entry["name"] = " ".join(parts[2:])
            if entry["addr"]:
                out.append(entry)
        return out

    @staticmethod
    def _parse_function_items(res: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        """Parse the ``data(functions, structured=True)`` ``items`` list."""
        out: List[Dict[str, Any]] = []
        items = res.get("items") or []
        if not isinstance(items, list):
            return out
        for item in items:
            if len(out) >= limit:
                break
            if not isinstance(item, dict):
                continue
            raw = item.get("addr") or item.get("ea")
            a = _probe_addr(raw)
            if not a:
                continue
            out.append({"addr": a, "name": str(item.get("name") or a)})
        return out

    # -- direct-IDA helpers (module loaded inside IDA) -----------------------

    @staticmethod
    def _ida_xrefs_to(addr_str: str, limit: int) -> List[Dict[str, Any]]:
        try:
            import ida_funcs  # type: ignore[import-not-found]
            import idautils  # type: ignore[import-not-found]
            from ida_mcp import compat as _compat  # type: ignore[import-not-found]

            ea = int(addr_str, 16)
            out: List[Dict[str, Any]] = []
            for x in idautils.XrefsTo(ea, 0):
                if len(out) >= limit:
                    break
                fn_start = _compat.get_func_start(x.frm)
                name = ida_funcs.get_func_name(fn_start) if fn_start is not None else ""
                out.append(
                    {
                        "addr": hex(x.frm),
                        "kind": "code" if x.iscode else "data",
                        "name": name or "",
                    }
                )
            return out
        except Exception:
            return []

    @staticmethod
    def _ida_symbols(name: str, limit: int) -> List[Dict[str, Any]]:
        try:
            import ida_funcs  # type: ignore[import-not-found]
            import idautils  # type: ignore[import-not-found]

            needle = name.lower()
            out: List[Dict[str, Any]] = []
            for ea in idautils.Functions():
                if len(out) >= limit:
                    break
                nm = ida_funcs.get_func_name(ea) or ""
                if needle in nm.lower():
                    out.append({"addr": hex(ea), "name": nm})
            return out
        except Exception:
            return []

    @staticmethod
    def _ida_function_probe(addr_str: str) -> Dict[str, Any]:
        try:
            import ida_funcs  # type: ignore[import-not-found]
            import idautils  # type: ignore[import-not-found]
            from ida_mcp import compat as _compat  # type: ignore[import-not-found]

            ea = int(addr_str, 16)
            func_start = _compat.get_func_start(ea)
            name = ida_funcs.get_func_name(ea) or ""
            callees: List[Dict[str, Any]] = []
            if func_start is not None:
                seen = set()
                for item in idautils.FuncItems(func_start):
                    for xref in idautils.XrefsFrom(item, 0):
                        if not xref.iscode:
                            continue
                        t_ea = _compat.get_func_start(xref.to)
                        if t_ea is None or t_ea == func_start:
                            continue
                        if t_ea in seen:
                            continue
                        seen.add(t_ea)
                        callees.append({"addr": hex(t_ea), "name": ida_funcs.get_func_name(t_ea) or ""})
            return {"addr": addr_str, "name": name, "behavior_tags": [], "callees": callees[:16]}
        except Exception:
            return {"addr": addr_str, "name": "", "behavior_tags": [], "callees": []}


# Module-level default instance the host orchestrator can bind an rpc_fn to:
#   crawler_probe = CrawlerProbe(rpc_fn=lambda tool, payload: self.call_tool(tool, idb_ref, **payload))
crawler_probe = CrawlerProbe()
