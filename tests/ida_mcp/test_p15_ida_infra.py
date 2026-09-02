"""Regression tests for p15_ida_infra fixes.

Coverage:
- error_handling.make_error carries the required ``category`` key.
- parse_address_safe rejects float addresses instead of truncating.
- cache.invalidate_all physically clears entries (stats/entries == 0).
- sync: nested execute_sync fails cleanly (no hang, in-flight marker cleared).
- sync: idaread/idawrite resolve the SAME TOOL_CACHE singleton.
- taint_registry: command_injection bucket no longer contaminated by the
  "injection" substring; bounded sinks (strncpy/strncat/snprintf) are not
  dual-classified as dangerous sinks + safe functions.
- crypto_registry: CRC32 polynomial labels are not swapped.
- semantic_matching.normalize_action tie-breaking is order-independent.
- mcp_http origin/host checks accept IPv6 loopback + missing Origin.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import threading
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IDA_MCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp"


def _load_standalone(relpath: str, name: str):
    """Load an ida_mcp source module standalone (no package init).

    ``__package__`` is pinned so ``from .rpc import ...`` style relative
    imports resolve through the stub package below instead of failing.
    """
    path = IDA_MCP / f"{relpath}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "ida_pro_mcp.ida_mcp"
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_worker(fn):
    result = {}

    def run():
        try:
            result["value"] = fn()
        except BaseException as exc:  # surfaced in the calling thread
            result["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive(), "worker did not terminate"
    if "error" in result:
        raise result["error"]
    return result.get("value")


def _register_ida_mcp_pkg():
    """Register ``ida_pro_mcp.ida_mcp`` as a stub package pointing at the real
    source dir so standalone loads can resolve ``ida_pro_mcp.ida_mcp.*``
    submodules (via sys.modules) without importing the real package init."""
    pkg = sys.modules.get("ida_pro_mcp") or types.ModuleType("ida_pro_mcp")
    pkg.__path__ = [str(REPO / "src" / "ida_pro_mcp")]
    sys.modules["ida_pro_mcp"] = pkg
    sub = sys.modules.get("ida_pro_mcp.ida_mcp") or types.ModuleType("ida_pro_mcp.ida_mcp")
    sub.__path__ = [str(IDA_MCP)]
    sys.modules["ida_pro_mcp.ida_mcp"] = sub
    return sub


def _install_ida_stubs():
    """Install minimal ida_* stubs so ida_mcp runtime modules can import."""
    stubs = {}
    for name in ("ida_kernwin", "idaapi"):
        m = stubs.get(name) or types.ModuleType(name)
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


def _load_error_handling():
    # Install a clean `idc` stub (get_name_ea_simple resolves nothing) so the
    # canonical address parser's symbol-resolution step falls through to
    # bare-hex rather than inheriting an in-place-mutated idc from an earlier
    # test in the session (e.g. test_swarm_t14 sets idc.get_name_ea_simple on
    # the shared module object, which the per-test sys.modules snapshot cannot
    # undo).
    _install_ida_stubs()
    idc = types.ModuleType("idc")
    idc.BADADDR = -1
    idc.get_name_ea_simple = lambda name: -1
    sys.modules["idc"] = idc
    return _load_standalone("error_handling", "p15_error_handling_ut")


# ---------------------------------------------------------------------------
# error_handling: category envelope + float address rejection
# ---------------------------------------------------------------------------

def test_make_error_includes_category():
    eh = _load_error_handling()
    err = eh.make_error(eh.MCPError.FILE_NOT_FOUND, "missing")
    assert err["error"] is True
    assert err["code"] == "FILE_NOT_FOUND"
    assert err["category"] == "user"
    assert "hint" in err


def test_make_error_policy_category_for_governance():
    eh = _load_error_handling()
    err = eh.make_error(eh.MCPError.GOVERNANCE_BLOCKED, "blocked")
    assert err["category"] == "policy"


def test_make_error_default_category_is_runtime():
    eh = _load_error_handling()
    err = eh.make_error(eh.MCPError.UNKNOWN, "boom")
    assert err["category"] == "runtime"


def test_parse_address_safe_rejects_float():
    eh = _load_error_handling()
    addr, err = eh.parse_address_safe(4198400.9)  # float form of 0x401000
    assert addr is None
    assert err is not None
    assert err["code"] == eh.MCPError.ADDRESS_INVALID


def test_make_error_always_emits_recoverable():
    eh = _load_error_handling()
    for code in (eh.MCPError.INVALID_ARGS, eh.MCPError.UNKNOWN, eh.MCPError.ADDRESS_INVALID):
        err = eh.make_error(code, "x")
        assert "recoverable" in err
        assert err["recoverable"] is False
    ok = eh.make_error(eh.MCPError.RPC_TIMEOUT, "t", recoverable=True)
    assert ok["recoverable"] is True


def test_parse_address_canonical_bare_hex_maps_inside_image(monkeypatch):
    """A bare all-digit token is read as hex when the value maps in the image."""
    eh = _load_error_handling()
    # Default image range is the full address space, so any hex value maps.
    addr, err = eh.parse_address_canonical("401000")
    assert err is None
    assert addr == 0x401000
    # parse_address_safe delegates to the same policy.
    addr2, err2 = eh.parse_address_safe("401000")
    assert err2 is None
    assert addr2 == 0x401000


def test_parse_address_canonical_bare_hex_unmapped_requires_0x_prefix(monkeypatch):
    """An ambiguous bare digit string outside the image is refused with a
    'use 0x prefix' hint instead of silently guessing decimal or hex."""
    eh = _load_error_handling()
    # Simulate an opaque RISC-V raw blob mapped only in a small window.
    monkeypatch.setattr(eh, "_image_min_ea", lambda: 0x800)
    monkeypatch.setattr(eh, "_image_max_ea", lambda: 0x1800)
    addr, err = eh.parse_address_canonical("401000")  # 0x401000 not in [0x800, 0x1800)
    assert addr is None
    assert err is not None
    assert err["code"] == eh.MCPError.ADDRESS_INVALID
    assert "0x prefix" in err.get("hint", "")
    # A bare token that *does* map inside the window still resolves as hex.
    addr_ok, err_ok = eh.parse_address_canonical("1000")
    assert err_ok is None
    assert addr_ok == 0x1000
    # Explicit 0x always wins regardless of the mapping.
    addr_x, err_x = eh.parse_address_canonical("0x401000")
    assert err_x is None
    assert addr_x == 0x401000


def test_parse_address_canonical_weird_types_rejected(monkeypatch):
    eh = _load_error_handling()
    for bad in (True, 3.14, {}, ["0x401000"], b"401000"):
        addr, err = eh.parse_address_canonical(bad)
        assert addr is None, bad
        assert err is not None and err["code"] == eh.MCPError.ADDRESS_INVALID, bad
    addr_none, err_none = eh.parse_address_canonical(None)
    assert addr_none is None
    assert err_none["code"] == eh.MCPError.MISSING_REQUIRED_ARG
    addr_neg, err_neg = eh.parse_address_canonical(-1)
    assert addr_neg is None
    assert err_neg["code"] == eh.MCPError.ADDRESS_INVALID


# ---------------------------------------------------------------------------
# cache: invalidate_all physically clears entries
# ---------------------------------------------------------------------------

def _load_cache():
    return _load_standalone("cache", "p15_cache_ut")


def test_cache_invalidate_all_clears_entries_physically():
    cache = _load_cache()
    inst = cache.ToolResultCache()
    inst.put("code", {"x": 1}, {"a": 1})
    inst.put("code", {"x": 2}, {"a": 2})
    assert inst.stats()["entries"] == 2
    inst.invalidate_all()
    assert inst.stats()["entries"] == 0
    assert inst.get("code", {"x": 1}) is None


# ---------------------------------------------------------------------------
# events: a recorded hook event invalidates the shared TOOL_CACHE singleton
# ---------------------------------------------------------------------------

def _load_events_with_shared_cache():
    """Load support/events.py wired to the same cache/sync pair the tools use.

    The IDA event hooks (auto-analysis-finished / function-created) must
    invalidate exactly the TOOL_CACHE singleton that @idaread/@idawrite
    consult, otherwise a post-analysis read serves stale pre-analysis data.
    """
    _install_ida_stubs()
    _register_ida_mcp_pkg()
    cache = _load_cache()
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    sys.modules["ida_pro_mcp.ida_mcp.cache"] = cache
    sync = _load_standalone("sync", "p15_sync_ut")
    # Register the sync instance under the name events._invalidate_tool_cache
    # resolves first, so both it and sync._tool_cache() hit the same cache.
    sys.modules["ida_pro_mcp.ida_mcp.sync"] = sync
    events = _load_standalone("support/events", "p15_events_ut")
    return events, cache


def test_events_record_invalidates_shared_tool_cache():
    events, cache = _load_events_with_shared_cache()
    events.EVENT_RING.clear()
    cache.TOOL_CACHE.put("code", {"x": 1}, {"a": 1})
    cache.TOOL_CACHE.put("data", {"x": 2}, {"a": 2})
    assert cache.TOOL_CACHE.stats()["entries"] == 2
    events.record_event("function_created", 0x401000, "sub_401000")
    # The event hook cleared the exact cache singleton @idaread/@idawrite use.
    assert cache.TOOL_CACHE.stats()["entries"] == 0
    # The event is recorded even though no SSE server/connections exist.
    assert len(events.EVENT_RING) == 1
    assert events.EVENT_RING[0]["type"] == "function_created"


# ---------------------------------------------------------------------------
# sync: nested execute_sync guard + shared TOOL_CACHE + timeout knob
# ---------------------------------------------------------------------------

def _load_sync_with_cache():
    """Load sync.py standalone with a registered cache module.

    Returns (sync_mod, cache_mod). The cache module is registered as
    ``ida_pro_mcp.ida_mcp.cache`` (the editable-install resolution path), so
    ``_tool_cache()`` resolves it — verifying idaread/idawrite share one
    singleton.
    """
    _install_ida_stubs()
    _register_ida_mcp_pkg()
    cache = _load_cache()

    # sync.py imports McpToolError from .rpc — provide a stub.
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    sys.modules["ida_pro_mcp.ida_mcp.cache"] = cache

    sync = _load_standalone("sync", "p15_sync_ut")
    return sync, cache


def test_sync_nested_execute_sync_fails_cleanly():
    sync, _ = _load_sync_with_cache()
    sync.ida_kernwin.execute_sync = lambda fn, flags=0: fn()
    sync.idaapi.is_batch = lambda: False

    captured = {}

    def outer_fn():
        # Nested execute_sync while the outer callback is in-flight.
        try:
            sync._sync_wrapper(lambda: {"ok": True}, sync.IDASafety.SAFE_READ)
            captured["inner"] = "ok"
        except sync.IDASyncError:
            captured["inner"] = "raised"
        return {"ok": True, "inner": captured.get("inner")}

    result = {}

    def worker():
        try:
            result["value"] = sync._sync_wrapper(outer_fn, sync.IDASafety.SAFE_READ)
            result["outer"] = "ok"
        except sync.IDASyncError:
            result["outer"] = "raised"

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "nested execute_sync must not hang the thread"
    # Inner nested call raised IDASyncError; the outer call completed cleanly.
    assert captured["inner"] == "raised"
    assert result["outer"] == "ok"
    # The in-flight marker must be cleared so later calls are not blocked.
    assert sync._in_flight == set()


def test_sync_reentrancy_guard_reports_call_name():
    sync, _ = _load_sync_with_cache()
    sync.ida_kernwin.execute_sync = lambda fn, flags=0: fn()
    sync.idaapi.is_batch = lambda: False

    calls = []

    def inner():
        return {"ok": True}

    def outer_fn():
        calls.append(threading.current_thread().name)
        return sync._sync_wrapper(inner, sync.IDASafety.SAFE_READ)

    result = {}

    def worker():
        try:
            sync._sync_wrapper(outer_fn, sync.IDASafety.SAFE_READ)
            result["outer"] = "ok"
        except sync.IDASyncError as e:
            result["outer"] = str(e)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "nested execute_sync must not hang the thread"
    assert "outer_fn" in result.get("outer", ""), result
    assert sync._in_flight == set()


def test_sync_is_batch_missing_attribute_falls_back_to_cvar():
    """IDA 9.x removed ``idaapi.is_batch()``; ``_sync_wrapper`` must still work.

    Regression for a real runtime failure: on IDA 9.3 the sync deadlock guard
    called ``idaapi.is_batch()`` and died with "module 'idaapi' has no
    attribute 'is_batch'".  The test stubs the exact 9.x condition — the
    attribute absent from ``idaapi`` — and asserts the cvar.batch fallback
    keeps the wrapper functional from a worker thread.
    """
    sync, _ = _load_sync_with_cache()
    # 9.x runtime: is_batch() no longer exists on idaapi.
    del sync.idaapi.is_batch
    # 9.x runtime: batch state is exposed via ida_kernwin.cvar.batch.
    kernwin = sync.ida_kernwin
    if not hasattr(kernwin, "cvar"):
        kernwin.cvar = types.SimpleNamespace(batch=False)
    else:
        kernwin.cvar.batch = False

    assert sync._is_batch() is False

    result = {}

    def worker():
        try:
            result["value"] = sync._sync_wrapper(lambda: {"ok": True}, sync.IDASafety.SAFE_READ)
        except Exception as e:  # pragma: no cover - surfaced via result
            result["error"] = e

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "_sync_wrapper must not hang without is_batch()"
    assert "error" not in result, f"missing is_batch() broke sync: {result.get('error')!r}"
    assert result.get("value") == {"ok": True}


def test_sync_is_batch_prefers_idaapi_callable():
    """When ``idaapi.is_batch()`` exists (IDA 7.x), it takes precedence."""
    sync, _ = _load_sync_with_cache()
    sync.idaapi.is_batch = lambda: True
    assert sync._is_batch() is True
    sync.idaapi.is_batch = lambda: False
    assert sync._is_batch() is False


def test_idaread_and_idawrite_share_same_tool_cache():
    sync, cache = _load_sync_with_cache()
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
    # The write invalidated the exact cache instance reads use, and the
    # physical clear drops the entries immediately.
    assert cache.TOOL_CACHE.stats()["entries"] == 0


def test_sync_timeout_env_knob(monkeypatch):
    sync, _ = _load_sync_with_cache()
    monkeypatch.setenv("IDA_MCP_SYNC_TIMEOUT", "5")
    assert sync._sync_timeout() == 5.0
    monkeypatch.setenv("IDA_MCP_SYNC_TIMEOUT", "0.5")
    assert sync._sync_timeout() == 1.0  # floored at 1s
    monkeypatch.setenv("IDA_MCP_SYNC_TIMEOUT", "abc")
    assert sync._sync_timeout() == 30.0  # invalid -> default
    for raw in ("nan", "inf", "-inf"):
        monkeypatch.setenv("IDA_MCP_SYNC_TIMEOUT", raw)
        assert sync._sync_timeout() == 30.0  # non-finite -> default
    monkeypatch.delenv("IDA_MCP_SYNC_TIMEOUT")
    assert sync._sync_timeout() == 30.0


def test_sync_kernel_version_and_batch_fallback_edges():
    sync, _ = _load_sync_with_cache()
    sync.idaapi.get_kernel_version = lambda: "9"
    assert sync._parse_kernel_version() == (9, 0)
    assert sync.IDAError("message").message == "message"

    del sync.idaapi.is_batch
    sync.ida_kernwin.cvar = None
    assert sync._is_batch() is False


def test_sync_wrapper_handles_bypass_batch_invalid_mode_and_sdk_exception():
    sync, _ = _load_sync_with_cache()
    sync.idaapi.is_batch = lambda: False
    sync.ida_kernwin.execute_sync = lambda fn, flags=0: fn()
    assert sync._sync_wrapper(lambda: {"main": True}, sync.IDASafety.SAFE_READ) == {"main": True}

    sync.idaapi.is_batch = lambda: True
    result = _run_worker(lambda: sync._sync_wrapper(lambda: {"batch": True}, sync.IDASafety.SAFE_READ))
    assert result == {"batch": True}

    sync.idaapi.is_batch = lambda: False

    def invalid():
        return sync._sync_wrapper(lambda: None, sync.IDASafety.SAFE_NONE)

    with pytest.raises(sync.IDASyncError, match="Invalid safety mode"):
        _run_worker(invalid)

    def raises():
        raise ValueError("from IDA callback")

    with pytest.raises(ValueError, match="from IDA callback"):
        _run_worker(lambda: sync._sync_wrapper(raises, sync.IDASafety.SAFE_READ))


def test_sync_wrapper_timeout_does_not_wait_forever(monkeypatch):
    sync, _ = _load_sync_with_cache()
    sync.idaapi.is_batch = lambda: False
    sync.ida_kernwin.execute_sync = lambda _fn, _flags=0: None
    monkeypatch.setattr(sync, "_sync_timeout", lambda: 0.001)

    with pytest.raises(sync.IDASyncError, match="timed out"):
        _run_worker(lambda: sync._sync_wrapper(lambda: None, sync.IDASafety.SAFE_READ))


def test_sync_cache_hit_non_dict_and_legacy_write_invalidation(monkeypatch):
    sync, cache = _load_sync_with_cache()
    cache.TOOL_CACHE.clear()

    @sync.idaread
    def read(addr, count=10):
        return {"ok": True, "addr": addr, "count": count}

    first = read("0x401000", count=10)
    second = read(0x401000)
    assert "_cache_hit" not in first
    assert second["_cache_hit"] is True
    assert second["addr"] == "0x401000"

    @sync.idaread
    def scalar(value):
        return value

    scalar("value")
    assert scalar("value") == "value"

    class LegacyCache:
        def __init__(self):
            self.invalidated = False

        def invalidate_all(self):
            self.invalidated = True

    legacy = LegacyCache()
    monkeypatch.setattr(sync, "_tool_cache", lambda: legacy)

    @sync.idawrite
    def write(value):
        return {"ok": True, "value": value}

    assert write("x")["ok"] is True
    assert legacy.invalidated is True


def test_sync_cache_key_signature_fallbacks(monkeypatch):
    sync, _ = _load_sync_with_cache()

    def tool(addr, count=10):
        return addr, count

    assert sync._signature_defaults(tool) == {"count": 10}
    monkeypatch.setattr(sync.inspect, "signature", lambda _fn: (_ for _ in ()).throw(TypeError("opaque")))
    assert sync._signature_defaults(object()) == {}
    key = sync._cache_key_kwargs(object(), {"x": "1"}, ("positional",))
    assert key["_arg_0"] == "positional"


# ---------------------------------------------------------------------------
# taint_registry: clean command_injection bucket + no dual-classified sinks
# ---------------------------------------------------------------------------

def _load_taint():
    return _load_standalone("support/taint_registry", "p15_taint_ut")


def test_taint_command_injection_bucket_not_contaminated():
    reg = _load_taint()
    bucket = reg.DANGEROUS_APIS_CATEGORIZED["command_injection"]
    # These live in injection-flavoured but distinct categories.
    assert "WriteProcessMemory" not in bucket
    assert "LoadLibrary" not in bucket
    assert "LoadLibraryA" not in bucket
    assert "UART_Transmit" not in bucket
    # Genuine command-execution sinks are present.
    assert "system" in bucket
    assert "popen" in bucket
    assert "CreateProcess" in bucket
    assert "ShellExecute" in bucket
    # And every categorized API is still a real sink (reverse invariant kept).
    deprecated_crypto = {"MD5Init", "MD5Update", "SHA1Init", "DES_ecb_encrypt", "RC4"}
    for apis in reg.DANGEROUS_APIS_CATEGORIZED.values():
        for api in set(apis) - deprecated_crypto:
            assert api in reg.DANGEROUS_SINKS


def test_taint_bounded_sinks_not_dual_classified():
    reg = _load_taint()
    safe = set(reg.MITIGATION_CHECKS["safe_functions"])
    sinks = set(reg.DANGEROUS_SINKS.keys())
    # Bounded variants are mitigations, not sinks — no contradiction.
    assert "snprintf" in safe
    assert "strncat" in safe
    assert "strncpy" in safe
    assert sinks.isdisjoint(safe)
    assert "snprintf" not in reg.DANGEROUS_APIS_CATEGORIZED["format_string"]


# ---------------------------------------------------------------------------
# crypto_registry: CRC32 labels not swapped
# ---------------------------------------------------------------------------

def _load_crypto():
    return _load_standalone("support/crypto_registry", "p15_crypto_ut")


def test_crc32_polynomial_labels_correct():
    reg = _load_crypto()
    # 0x04C11DB7 is the normal (non-reflected) polynomial; 0xEDB88320 the
    # bit-reversed form used by table-driven implementations.
    assert reg.CRYPTO_CONSTANT_NAMES[0x04C11DB7] == "CRC32_POLY"
    assert reg.CRYPTO_CONSTANT_NAMES[0xEDB88320] == "CRC32_POLY_REV"


def test_crypto_dead_constant_sets_removed():
    reg = _load_crypto()
    for name in ("PACKER_SIGNATURES", "KNOWN_HASH_CONSTANTS", "ANTI_DEBUG_APIS",
                 "ANTI_VM_STRINGS", "GAME_ANTI_CHEAT", "HASH_RESOLVE_FUNCS",
                 "PACKER_DISPLAY_NAMES"):
        assert not hasattr(reg, name), f"{name} should have been removed"


# ---------------------------------------------------------------------------
# semantic_matching: normalize_action deterministic tie-breaking
# ---------------------------------------------------------------------------

def _load_semantic():
    return _load_standalone("support/semantic_matching", "p15_semantic_ut")


def test_normalize_action_order_independent(monkeypatch):
    sm = _load_semantic()
    # Force the deterministic cheap-scoring path so the test never depends on
    # whether a native embedder is installed.
    monkeypatch.setattr(sm, "_get_embedder", lambda: None)
    actions = ("eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops")
    # "offst" is a close typo of "offset" (edit-sim 0.83) and beats every
    # other candidate, so the winner must be stable regardless of pool order.
    kwargs = {"aliases": {"compute": "eval"}, "fallback": "eval", "threshold": 10.0}
    results = {
        sm.normalize_action("offst", actions=actions, **kwargs)
        for _ in range(20)
    }
    assert results == {"offset"}

    shuffled = ("resolve", "bitops", "offset", "align", "convert", "eval", "deref", "chain")
    assert sm.normalize_action("offst", actions=shuffled, **kwargs) == "offset"


# ---------------------------------------------------------------------------
# prompts: workflow steps must reference real tools (no dead compare/debug/trace)
# ---------------------------------------------------------------------------

def _load_prompts():
    _register_ida_mcp_pkg()
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")

    def prompt(f):
        return f

    rpc_stub.prompt = prompt
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    return _load_standalone("prompts", "p15_prompts_ut")


def test_prompts_workflows_reference_real_tools():
    mod = _load_prompts()
    diff_text = mod.workflow("diff")[0]["content"]["text"]
    debug_text = mod.workflow("debug")[0]["content"]["text"]
    # Dead tool references (compare/debug/trace are not public operations)
    # must not reappear in the guides.
    assert "compare(action=" not in diff_text
    assert 'memory(action="compare"' in diff_text
    assert "debug(action=" not in debug_text
    assert "trace(action=" not in debug_text
    assert 'misc(action="python"' in debug_text
    # The task annotation advertises the renamed diff task, not the removed
    # compare task.
    anno = str(inspect.signature(mod.workflow).parameters["task"].annotation)
    assert "diff" in anno
    assert "compare" not in anno


# ---------------------------------------------------------------------------
# mcp_http: origin/host checks accept IPv6 loopback + missing Origin
# ---------------------------------------------------------------------------

def _make_handler(port: int = 8080, headers: dict | None = None, mcp_server: object | None = None):
    """Build a fake self so the _check_origin/_check_host methods can run."""
    handler = type("FakeHandler", (), {})()
    handler.server_port = port
    handler.headers = headers or {}
    handler.mcp_server = mcp_server or type("S", (), {})()
    handler.sent = {}

    def send_error(code, msg):
        handler.sent = {"code": code, "msg": msg}

    handler.send_error = send_error

    def _local_endpoints(self):
        return (
            f"127.0.0.1:{self.server_port}",
            f"localhost:{self.server_port}",
            f"[::1]:{self.server_port}",
        )

    handler._local_endpoints = types.MethodType(_local_endpoints, handler)
    return handler


def _load_mcp_http_methods():
    """Import mcp_http standalone and bind the two check methods.

    mcp_http has import-time side effects (``handle_enabled_tools`` runs at
    module scope), so ``MCP_SERVER.tools`` must carry a real ``methods`` dict
    and ``config_json_get`` must return a value without IDA/zeromcp present.
    """
    _install_ida_stubs()
    _register_ida_mcp_pkg()

    ida_netnode = types.ModuleType("ida_netnode")
    fake_node = types.SimpleNamespace(
        getblob=lambda *a, **k: None,
        setblob=lambda *a, **k: None,
    )
    ida_netnode.netnode = lambda *a, **k: fake_node
    sys.modules["ida_netnode"] = ida_netnode

    def _passthrough(f):
        return f

    sync_stub = types.ModuleType("ida_pro_mcp.ida_mcp.sync")
    sync_stub.idaread = _passthrough
    sync_stub.idawrite = _passthrough
    sys.modules["ida_pro_mcp.ida_mcp.sync"] = sync_stub

    registry = types.SimpleNamespace(methods={})
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.MCP_SERVER = types.SimpleNamespace(tools=registry)
    rpc_stub.MCP_UNSAFE = frozenset()
    rpc_stub.McpHttpRequestHandler = type("McpHttpRequestHandler", (), {})
    rpc_stub.McpRpcRegistry = type("McpRpcRegistry", (), {})
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub

    m = _load_standalone("mcp_http", "p15_mcp_http_ut")
    return m


def test_origin_check_accepts_localhost_forms():
    mod = _load_mcp_http_methods()
    cls = mod.IdaMcpHttpRequestHandler

    # Missing Origin (curl/scripts) is allowed.
    assert cls._check_origin(_make_handler(headers={})) is True
    # IPv4 loopback and hostname.
    assert cls._check_origin(_make_handler(headers={"Origin": "http://127.0.0.1:8080"})) is True
    assert cls._check_origin(_make_handler(headers={"Origin": "http://localhost:8080"})) is True
    # IPv6 loopback.
    assert cls._check_origin(_make_handler(headers={"Origin": "http://[::1]:8080"})) is True
    # Attacker-controlled origin is rejected.
    h = _make_handler(headers={"Origin": "http://evil.com"})
    assert cls._check_origin(h) is False
    assert h.sent["code"] == 403


def test_host_check_accepts_ipv6_loopback():
    mod = _load_mcp_http_methods()
    cls = mod.IdaMcpHttpRequestHandler
    assert cls._check_host(_make_handler(headers={"Host": "127.0.0.1:8080"})) is True
    assert cls._check_host(_make_handler(headers={"Host": "[::1]:8080"})) is True
    h = _make_handler(headers={"Host": "evil.com:8080"})
    assert cls._check_host(h) is False
    assert h.sent["code"] == 403


def test_mcp_http_policy_rendering_and_config_get(monkeypatch):
    mod = _load_mcp_http_methods()
    cls = mod.IdaMcpHttpRequestHandler
    h = _make_handler()
    h.mcp_server.cors_localhost = "LOCAL"

    monkeypatch.setattr(mod, "config_json_get", lambda key, default: "unrestricted" if key == "cors_policy" else default)
    cls.update_cors_policy(h)
    assert h.mcp_server.cors_allowed_origins == "*"
    monkeypatch.setattr(mod, "config_json_get", lambda key, default: "local" if key == "cors_policy" else default)
    cls.update_cors_policy(h)
    assert h.mcp_server.cors_allowed_origins == "LOCAL"
    monkeypatch.setattr(mod, "config_json_get", lambda key, default: "direct" if key == "cors_policy" else default)
    cls.update_cors_policy(h)
    assert h.mcp_server.cors_allowed_origins is None

    rendered = []
    h.send_response = lambda code: rendered.append(("response", code))
    h.send_header = lambda key, value: rendered.append((key, value))
    h.end_headers = lambda: rendered.append(("end",))
    h.wfile = types.SimpleNamespace(write=lambda body: rendered.append(("body", body)))
    cls._send_html(h, 200, "<h1>config</h1>")
    assert ("response", 200) in rendered
    assert any(item[0] == "X-Frame-Options" and item[1] == "DENY" for item in rendered)
    assert ("body", b"<h1>config</h1>") in rendered


def test_mcp_http_get_and_post_dispatch_boundaries(monkeypatch):
    from tests.ida_mcp.test_swarm_t18_zeromcp import _load_mcp_http, _make_config_handler

    mod, _ = _load_mcp_http()
    cls = mod.IdaMcpHttpRequestHandler
    h = _make_config_handler(mod)
    h._local_endpoints = mod.IdaMcpHttpRequestHandler._local_endpoints.__get__(h)
    h._check_host = mod.IdaMcpHttpRequestHandler._check_host.__get__(h)
    h._check_origin = mod.IdaMcpHttpRequestHandler._check_origin.__get__(h)
    h.path = "/config.html"
    h.headers["Host"] = "127.0.0.1:13337"
    h._handle_config_get = lambda: setattr(h, "config_get_called", True)
    cls.do_GET(h)
    assert h.config_get_called is True

    bad = _make_config_handler(mod)
    bad._local_endpoints = mod.IdaMcpHttpRequestHandler._local_endpoints.__get__(bad)
    bad._check_host = mod.IdaMcpHttpRequestHandler._check_host.__get__(bad)
    bad.path = "/config.html"
    bad.headers["Host"] = "evil.example"
    cls.do_GET(bad)
    assert any(item[0] == "error" and item[1] == 403 for item in bad.sent)

    post = _make_config_handler(mod, body=b"cors_policy=direct")
    post._local_endpoints = mod.IdaMcpHttpRequestHandler._local_endpoints.__get__(post)
    post._check_origin = mod.IdaMcpHttpRequestHandler._check_origin.__get__(post)
    post.path = "/config"
    post.headers["Origin"] = "http://127.0.0.1:13337"
    post._handle_config_post = lambda: setattr(post, "config_post_called", True)
    cls.do_POST(post)
    assert post.config_post_called is True
