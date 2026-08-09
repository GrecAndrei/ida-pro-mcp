"""IDA event hooks: auto-analysis-finished + function-created.

Installed once when the ``idb`` tool module is first imported (tool-module
init). Each hook:

- appends a bounded, in-memory event record to ``EVENT_RING`` (max 500) —
  read back through ``read_events()`` / ``idb(action='events')``;
- invalidates the shared tool-result cache so a post-analysis read never
  serves a stale pre-analysis snapshot;
- best-effort pushes an SSE notification to any connected MCP SSE client.

The SSE push is deliberately best-effort. The zeromcp server exposes
per-connection ``send_event()`` but no broadcast/emitter helper, so this
module lazily resolves the MCP server singleton and iterates its live
connection registry. When no server is running (or none is reachable) the
push degrades to a no-op and the event stays record-only in the ring.

Every hook body is wrapped in try/except: a recording failure must never
propagate into IDA's analysis loop.
"""

from __future__ import annotations

import time
from collections import deque

try:
    import ida_idp
except Exception:  # standalone / non-IDA runtime
    ida_idp = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Event ring
# ---------------------------------------------------------------------------

EVENT_RING_MAX = 500
"""Maximum number of events retained in the ring (bounded memory)."""

EVENT_RING: "deque[dict]" = deque(maxlen=EVENT_RING_MAX)
"""Bounded ring of recorded analysis events, oldest-first."""


def _fmt_addr(address) -> str:
    """Render an address as a hex string; ``''`` for no-address events."""
    if address is None:
        return ""
    try:
        ea = int(address)
    except (TypeError, ValueError):
        return ""
    if ea < 0:
        return ""
    return hex(ea)


def record_event(type_: str, address=None, name: str = "") -> dict:
    """Append one event, invalidate the tool cache, and best-effort SSE-push.

    Never raises: internal failures (cache resolution, SSE push) are swallowed
    so hooks and callers can rely on recording being side-effect-safe.
    """
    event = {
        "type": type_,
        "address": _fmt_addr(address),
        "name": name or "",
        "timestamp": round(time.time(), 3),
    }
    EVENT_RING.append(event)
    _invalidate_tool_cache()
    _sse_emit(event)
    return event


def read_events(limit: int = 50) -> tuple[list[dict], int]:
    """Return ``(events, total)`` — the most recent events, newest first.

    ``total`` is the number of events currently held in the ring; ``events``
    is at most ``limit`` items (empty when ``limit`` is 0).
    """
    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 50
    # Guard limit==0 explicitly: ``seq[-0:]`` is the whole sequence, not empty.
    events = list(EVENT_RING)[-limit:] if limit > 0 else []
    events.reverse()  # newest first
    return events, len(EVENT_RING)


# ---------------------------------------------------------------------------
# Shared tool-cache invalidation
# ---------------------------------------------------------------------------


def _invalidate_tool_cache() -> None:
    """Invalidate the shared tool-result cache (best effort).

    Resolves the same ``_tool_cache`` singleton that ``@idaread``/``@idawrite``
    use, so a hook-triggered invalidation clears exactly what reads consult.
    Mirrors sync.py's multi-path resolution.
    """
    resolver = None
    for modname in ("ida_pro_mcp.ida_mcp.sync", "ida_mcp.sync", "sync"):
        try:
            mod = __import__(modname, fromlist=["_tool_cache"])
            resolver = getattr(mod, "_tool_cache", None)
            if resolver is not None:
                break
        except Exception:
            continue
    if resolver is None:
        return
    try:
        cache = resolver()
        if cache is not None:
            invalidate = getattr(cache, "invalidate_all", None)
            if callable(invalidate):
                invalidate()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Best-effort SSE emitter (stub-level integration)
# ---------------------------------------------------------------------------


def _resolve_mcp_server():
    """Lazily resolve the MCP server singleton, or ``None``."""
    for modname in ("ida_pro_mcp.ida_mcp.rpc", "ida_mcp.rpc", "rpc"):
        try:
            mod = __import__(modname, fromlist=["MCP_SERVER"])
            return getattr(mod, "MCP_SERVER", None)
        except Exception:
            continue
    return None


def _sse_emit(event: dict) -> None:
    """Best-effort push of an analysis event to connected SSE clients.

    The zeromcp server exposes per-connection ``send_event()`` but no broadcast
    helper, so we iterate its live connection registry directly. Any failure —
    no server, no connections, a dead socket — is swallowed; the event stays
    record-only in the ring.
    """
    try:
        server = _resolve_mcp_server()
        if server is None:
            return
        conns = getattr(server, "_sse_connections", None)
        if not isinstance(conns, dict):
            return
        for conn in list(conns.values()):
            try:
                send = getattr(conn, "send_event", None)
                if callable(send):
                    send("analysis", event)
            except Exception:
                continue
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def _func_name(ea) -> str:
    """Best-effort function name at ``ea`` (``''`` when unknown)."""
    try:
        import idc

        name = idc.get_func_name(ea)
        if name:
            return name
    except Exception:
        pass
    try:
        import idaapi

        name = idaapi.get_func_name(ea)
        if name:
            return name
    except Exception:
        pass
    return ""


_IDB_HOOKS_BASE = getattr(ida_idp, "IDB_Hooks", None) if ida_idp is not None else None


if _IDB_HOOKS_BASE is not None:

    class EventHooks(_IDB_HOOKS_BASE):  # type: ignore[no-redef, misc]
        """IDB_Hooks subclass recording analysis lifecycle + function creation.

        Installed at tool-module init via ``install_hooks()``. Each hook body
        is wrapped so a recording failure never breaks IDA's analysis loop.
        """

        def __init__(self):
            super().__init__()

        def auto_empty_finally(self):  # noqa: N802 - IDA hook name
            try:
                record_event("auto_analysis_finished", None, "")
            except Exception:
                pass

        def func_created(self, func_ea):  # noqa: N802 - IDA hook name
            try:
                record_event("function_created", func_ea, _func_name(func_ea))
            except Exception:
                pass

else:

    class EventHooks:  # type: ignore[no-redef]
        """Standalone fallback with the same recording API (no IDA wiring).

        Present so tests and host-side tooling can exercise the recording
        behaviour without a live IDA / ``ida_idp``.
        """

        def auto_empty_finally(self):  # noqa: N802 - IDA hook name
            try:
                record_event("auto_analysis_finished", None, "")
            except Exception:
                pass

        def func_created(self, func_ea):  # noqa: N802 - IDA hook name
            try:
                record_event("function_created", func_ea, _func_name(func_ea))
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

_INSTALLED_HOOKS = None


def install_hooks():
    """Install the event hooks once (idempotent).

    Returns the installed ``EventHooks`` instance, or ``None`` when the real
    IDB_Hooks wiring is unavailable (standalone/host runtime). Never raises.
    """
    global _INSTALLED_HOOKS
    if _INSTALLED_HOOKS is not None:
        return _INSTALLED_HOOKS
    if _IDB_HOOKS_BASE is None or not hasattr(_IDB_HOOKS_BASE, "hook"):
        return None
    try:
        instance = EventHooks()
        instance.hook()
        _INSTALLED_HOOKS = instance
    except Exception:
        _INSTALLED_HOOKS = None
    return _INSTALLED_HOOKS


def unhook_hooks():
    """Unhook the installed EventHooks instance (idempotent)."""
    global _INSTALLED_HOOKS
    if _INSTALLED_HOOKS is not None:
        try:
            _INSTALLED_HOOKS.unhook()
        except Exception:
            pass
        _INSTALLED_HOOKS = None


# Installed at tool-module init. Guarded so a hook-wiring failure never breaks
# tool import (the ring still records via record_event()).
install_hooks()
