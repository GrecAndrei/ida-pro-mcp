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
- firmware_heuristics: regions with no fingerprint evidence get no boost.
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
    monkeypatch.delenv("IDA_MCP_SYNC_TIMEOUT")
    assert sync._sync_timeout() == 30.0


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
# firmware_heuristics: no boost without fingerprint evidence
# ---------------------------------------------------------------------------

def _load_firmware():
    return _load_standalone("support/firmware_heuristics", "p15_fw_ut")


def test_fingerprint_boost_absent_evidence_no_boost():
    fw = _load_firmware()
    regions = [
        {"fingerprint": "known_fp", "priority_score": 0.5},
        {"fingerprint": "unknown_fp", "priority_score": 0.5},
    ]
    fp_rank = [{"fingerprint": "known_fp", "score": 90.0}]
    out = fw.apply_fingerprint_boost(regions, fp_rank, boost_cap=0.35)
    by_fp = {r["fingerprint"]: r for r in out}
    # Known fingerprint got boosted above base.
    assert by_fp["known_fp"]["priority_score"] > 0.5
    assert by_fp["known_fp"].get("priority_boost", 0.0) > 0
    # Unknown fingerprint: no boost at all.
    assert "priority_boost" not in by_fp["unknown_fp"]
    assert by_fp["unknown_fp"]["priority_score"] == 0.5


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
