"""Additional protocol and shared-helper coverage under the fake IDA SDK."""

from __future__ import annotations

import builtins
import queue
import runpy
import sys
import types
from pathlib import Path
from typing import TypedDict

import pytest

from ida_pro_mcp.ida_mcp import rpc, sync, utils


class _Options(TypedDict):
    enabled: bool


def test_rpc_flat_plugin_import_uses_compatibility_fallback(monkeypatch):
    class _Server:
        def __init__(self, *_args, **_kwargs):
            pass

    fake_zeromcp = types.ModuleType("zeromcp")
    fake_zeromcp.McpHttpRequestHandler = type("McpHttpRequestHandler", (), {})
    fake_zeromcp.McpRpcRegistry = type("McpRpcRegistry", (), {})
    fake_zeromcp.McpServer = _Server
    fake_zeromcp.McpToolError = type("McpToolError", (Exception,), {})
    fake_version = types.ModuleType("_version")
    fake_version.__version__ = "flat-test"
    monkeypatch.setitem(sys.modules, "zeromcp", fake_zeromcp)
    monkeypatch.setitem(sys.modules, "_version", fake_version)

    namespace = runpy.run_path(str(Path(rpc.__file__)), run_name="flat_rpc_test")
    assert namespace["__version__"] == "flat-test"
    assert namespace["MCP_SERVER"].__class__ is _Server


def test_utils_final_bitness_and_frame_version_fallbacks(monkeypatch):
    original_import = builtins.__import__

    def without_common(name, *args, **kwargs):
        if name.endswith("tools._common"):
            raise ImportError("common helper unavailable")
        return original_import(name, *args, **kwargs)

    def no_inf_structure():
        return object()

    monkeypatch.setattr(builtins, "__import__", without_common)
    monkeypatch.setattr(utils.idaapi, "get_inf_structure", no_inf_structure)
    assert utils.is_64bit() is False

    import ida_pro_mcp.ida_mcp.sync as loaded_sync

    monkeypatch.setattr(loaded_sync, "ida_major", 8)
    assert utils.get_stack_frame_variables_internal(0x1000, False) == []

    class _TruthyTinfo:
        def __init__(self, name=None):
            self.name = name

        def get_named_type(self, *_args):
            return False

        def __bool__(self):
            return self.name == "named-by-constructor"

    monkeypatch.setattr(utils.ida_typeinf, "tinfo_t", _TruthyTinfo)
    assert utils.get_type_by_name("named-by-constructor").name == "named-by-constructor"


def test_sync_cache_and_execution_failure_boundaries(monkeypatch):
    original_import = builtins.__import__

    def no_cache(name, *args, **kwargs):
        if name in {"ida_mcp.ida_mcp.cache", "cache", "ida_pro_mcp.ida_mcp.cache"}:
            raise ImportError("cache unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_cache)
    assert sync._tool_cache() is None
    assert sync._signature_defaults(object()) == {}

    def no_batch():
        return False

    def no_bypass():
        return False

    def short_timeout():
        return 0.001

    monkeypatch.setattr(sync, "_is_batch", no_batch)
    monkeypatch.setattr(sync, "_sync_timeout", short_timeout)
    monkeypatch.setattr(sync, "is_bypass_sync", no_bypass)
    monkeypatch.setattr(sync.ida_kernwin, "execute_sync", lambda *_args: None)

    def work():
        return "never called"

    class _EmptyQueue:
        def put(self, _value):
            pass

        def get(self, timeout=None):
            raise queue.Empty

    def make_empty_queue():
        return _EmptyQueue()

    main_thread = object()

    def worker_thread():
        return object()

    def fake_main_thread():
        return main_thread

    fake_threading = types.SimpleNamespace(
        current_thread=worker_thread,
        main_thread=fake_main_thread,
    )
    monkeypatch.setitem(sync._sync_wrapper.__globals__, "_is_batch", no_batch)
    monkeypatch.setitem(sync._sync_wrapper.__globals__, "_sync_timeout", short_timeout)
    monkeypatch.setitem(sync._sync_wrapper.__globals__, "is_bypass_sync", no_bypass)
    monkeypatch.setitem(sync._sync_wrapper.__globals__, "threading", fake_threading)
    monkeypatch.setitem(sync._sync_wrapper.__globals__, "queue", types.SimpleNamespace(
        Queue=make_empty_queue,
        Empty=queue.Empty,
    ))

    with pytest.raises(sync.IDASyncError, match="timed out"):
        sync._sync_wrapper(work, sync.IDASafety.SAFE_READ)

    with pytest.raises(sync.IDASyncError, match="Invalid safety mode"):
        sync._sync_wrapper(work, sync.IDASafety.SAFE_NONE)


def test_jsonrpc_notifications_and_nullable_union_typed_dict():
    from tests.ida_mcp.test_p16_zeromcp import _load_pkg

    jr, _ = _load_pkg()
    registry = jr.JsonRpcRegistry()

    def optional(value: int | None = None):
        return value

    def maybe_options(value: dict | str):
        return value

    def typed_union(value: _Options | str):
        return value

    def explode():
        raise RuntimeError("boom")

    registry.method(optional)
    registry.method(maybe_options)
    registry.method(typed_union)
    registry.method(explode)

    missing_method = registry.dispatch({"jsonrpc": "2.0", "id": 1})
    assert missing_method["error"]["code"] == -32600
    wrong_method = registry.dispatch({"jsonrpc": "2.0", "method": 3, "id": 2})
    assert wrong_method["error"]["code"] == -32600
    assert registry.dispatch({"jsonrpc": "2.0", "method": "missing"}) is None
    assert registry.dispatch({"jsonrpc": "2.0", "method": "explode"}) is None

    assert registry.dispatch({"jsonrpc": "2.0", "method": "optional", "params": {"value": None}, "id": 3})["result"] is None
    assert registry.dispatch({"jsonrpc": "2.0", "method": "maybe_options", "params": {"value": "text"}, "id": 4})["result"] == "text"
    assert registry.dispatch({"jsonrpc": "2.0", "method": "typed_union", "params": {"value": "text"}, "id": 5})["result"] == "text"


def test_mcp_http_invalid_origin_and_real_server_port_property(monkeypatch):
    from tests.ida_mcp.test_p15_ida_infra import _load_mcp_http_methods

    mod = _load_mcp_http_methods()
    cls = mod.IdaMcpHttpRequestHandler
    handler = types.SimpleNamespace(
        headers={"Origin": "http://[invalid"},
        send_error=lambda code, message: setattr(handler, "error", (code, message)),
        mcp_server=types.SimpleNamespace(cors_allowed_origins=None),
        server=types.SimpleNamespace(server_port=4321),
    )
    assert cls._check_origin(handler) is False
    assert handler.error[0] == 403
    assert cls.server_port.__get__(handler, cls) == 4321


def test_mcp_http_constructor_tolerates_connection_without_timeout(monkeypatch):
    from tests.ida_mcp.test_p15_ida_infra import _load_mcp_http_methods

    mod = _load_mcp_http_methods()
    cls = mod.IdaMcpHttpRequestHandler
    monkeypatch.setattr(mod.McpHttpRequestHandler, "__init__", lambda *_args: None)
    monkeypatch.setattr(cls, "update_cors_policy", lambda _self: None)
    monkeypatch.setattr(cls, "_sync_enabled_tools", lambda _self: None)
    handler = object.__new__(cls)
    handler.connection = types.SimpleNamespace(settimeout=lambda _seconds: (_ for _ in ()).throw(OSError("closed")))
    cls.__init__(handler, None, None, None)
