"""Regression tests for t19_sync_cache.

Coverage:
- bypass_sync() is thread-scoped, not process-global: while a background
  crawler thread holds the block open, unrelated calls on other threads must
  still go through execute_sync serialization (previously the env var leaked
  and every concurrent RPC tool call dropped the safety wrapper too).
- The holder thread's own wrapped calls still bypass execute_sync (the
  crawler's intended path).
- is_bypass_sync() still honors an externally-set IDA_MCP_BYPASS_SYNC env var.
- The thread-local flag is restored after the block exits.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IDA_MCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp"


def _register_ida_mcp_pkg():
    """Register ``ida_pro_mcp.ida_mcp`` as a stub package pointing at the real
    source dir so standalone loads can resolve submodules via sys.modules."""
    pkg = sys.modules.get("ida_pro_mcp") or types.ModuleType("ida_pro_mcp")
    pkg.__path__ = [str(REPO / "src" / "ida_pro_mcp")]
    sys.modules["ida_pro_mcp"] = pkg
    sub = sys.modules.get("ida_pro_mcp.ida_mcp") or types.ModuleType("ida_pro_mcp.ida_mcp")
    sub.__path__ = [str(IDA_MCP)]
    sys.modules["ida_pro_mcp.ida_mcp"] = sub
    return sub


def _install_ida_stubs():
    """Install minimal ida_* stubs so sync.py can import outside IDA."""
    stubs = {}
    for name in ("ida_kernwin", "idaapi"):
        m = sys.modules.get(name) or types.ModuleType(name)
        sys.modules[name] = m
        stubs[name] = m
    ida_kernwin = sys.modules["ida_kernwin"]
    ida_kernwin.MFF_FAST = 0
    ida_kernwin.MFF_READ = 1
    ida_kernwin.MFF_WRITE = 2
    ida_kernwin.execute_sync = lambda fn, flags=0: fn()
    idaapi = sys.modules["idaapi"]
    idaapi.get_kernel_version = lambda: "9.2"
    idaapi.MFF_FAST = 0
    idaapi.MFF_READ = 1
    idaapi.MFF_WRITE = 2
    idaapi.execute_sync = lambda fn, flags=0: fn()
    idaapi.is_batch = lambda: False
    return stubs


def _load_standalone(relpath: str, name: str):
    path = IDA_MCP / f"{relpath}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "ida_pro_mcp.ida_mcp"
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_sync():
    """Load sync.py standalone (with stubbed ida_*, rpc, and cache modules)."""
    _install_ida_stubs()
    _register_ida_mcp_pkg()

    cache = _load_standalone("cache", "t19_cache_ut")
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    sys.modules["ida_pro_mcp.ida_mcp.cache"] = cache

    sync = _load_standalone("sync", "t19_sync_ut")
    sync.ida_kernwin.execute_sync = lambda fn, flags=0: fn()
    sync.idaapi.is_batch = lambda: False
    return sync, cache


def _run_worker(fn, timeout: float = 5.0):
    result = {}
    def worker():
        try:
            result["value"] = fn()
        except Exception as e:  # pragma: no cover - surfaced via result
            result["error"] = e
    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=timeout)
    assert not t.is_alive(), "worker thread must not hang"
    if "error" in result:
        raise result["error"]
    return result.get("value")


# ---------------------------------------------------------------------------
# bypass_sync: thread-scoped, not process-global
# ---------------------------------------------------------------------------

def test_bypass_sync_does_not_leak_to_other_threads():
    """While one thread holds bypass_sync, a call on another thread must still
    go through execute_sync (the safety wrapper). This is the race the fix
    closes: the crawler holds the block for its whole loop."""
    sync, _ = _load_sync()
    entered = threading.Event()
    release = threading.Event()

    def holder():
        with sync.bypass_sync(reason="background crawler"):
            entered.set()
            release.wait(timeout=5.0)

    t_holder = threading.Thread(target=holder)
    t_holder.start()
    try:
        assert entered.wait(timeout=5.0), "holder thread never entered bypass"
        # The main test thread must not see another thread's bypass.
        assert sync.is_bypass_sync() is False

        exec_calls = []
        sync.ida_kernwin.execute_sync = lambda fn, flags=0: (exec_calls.append(flags), fn())

        def call_wrapped():
            return sync._sync_wrapper(lambda: {"ok": True}, sync.IDASafety.SAFE_READ)

        value = _run_worker(call_wrapped)
        assert value == {"ok": True}
        # The unrelated thread's call was serialized through execute_sync, not
        # dropped to a direct ff() call by a leaked process-global flag.
        assert exec_calls, "unrelated thread must not bypass execute_sync"
    finally:
        release.set()
        t_holder.join(timeout=5.0)


def test_bypass_sync_applies_to_holder_thread():
    """The holder thread's own wrapped calls still bypass execute_sync — the
    crawler's intended path (it runs off the main thread and cannot block on
    execute_sync)."""
    sync, _ = _load_sync()
    exec_calls = []

    def run():
        sync.ida_kernwin.execute_sync = lambda fn, flags=0: (exec_calls.append(flags), fn())
        with sync.bypass_sync(reason="crawler"):
            assert sync.is_bypass_sync() is True
            return sync._sync_wrapper(lambda: {"ok": True}, sync.IDASafety.SAFE_READ)

    value = _run_worker(run)
    assert value == {"ok": True}
    assert exec_calls == [], "holder thread's own calls should bypass execute_sync"


def test_bypass_sync_restores_flag_after_block():
    """After the block exits, is_bypass_sync() is False again on that thread."""
    sync, _ = _load_sync()

    def run():
        assert sync.is_bypass_sync() is False
        with sync.bypass_sync(reason="x"):
            assert sync.is_bypass_sync() is True
        return sync.is_bypass_sync()

    assert _run_worker(run) is False


def test_bypass_sync_nested_restores_prior_state():
    """Nested bypass blocks restore the prior flag rather than force False."""
    sync, _ = _load_sync()

    def run():
        with sync.bypass_sync(reason="outer"):
            with sync.bypass_sync(reason="inner"):
                pass
            # Outer bypass still active after inner exits.
            assert sync.is_bypass_sync() is True
        return sync.is_bypass_sync()

    assert _run_worker(run) is False


# ---------------------------------------------------------------------------
# is_bypass_sync: env-var backward compatibility
# ---------------------------------------------------------------------------

def test_is_bypass_sync_honors_env_var(monkeypatch):
    """An externally-set IDA_MCP_BYPASS_SYNC=1 still forces a global bypass."""
    sync, _ = _load_sync()
    monkeypatch.setenv("IDA_MCP_BYPASS_SYNC", "1")
    assert sync.is_bypass_sync() is True
    monkeypatch.delenv("IDA_MCP_BYPASS_SYNC")
    assert sync.is_bypass_sync() is False


# ---------------------------------------------------------------------------
# cache: shared-singleton invalidation still works alongside sync
# ---------------------------------------------------------------------------

def test_idaread_idawrite_share_tool_cache():
    """@idaread/@idawrite still resolve one TOOL_CACHE and writes invalidate
    it — unchanged behavior, verified in the same module as the bypass fix."""
    sync, cache = _load_sync()
    assert sync._tool_cache() is cache.TOOL_CACHE

    @sync.idaread
    def read_tool(addr):
        return {"ok": True, "addr": addr}

    @sync.idawrite
    def write_tool(addr):
        return {"ok": True, "addr": addr}

    read_tool("0x401000")
    assert cache.TOOL_CACHE.stats()["entries"] >= 1
    write_tool("0x401000")
    assert cache.TOOL_CACHE.stats()["entries"] == 0
