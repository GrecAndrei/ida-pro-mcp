"""Deep offline coverage for shared IDA error and validation boundaries."""

from __future__ import annotations

import builtins
import errno
import os
import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from tests.ida_mcp.test_p15_ida_infra import _load_error_handling  # noqa: E402


def test_error_envelopes_and_exception_classification_cover_fallbacks():
    eh = _load_error_handling()
    plain = eh.make_error("CUSTOM_CODE", "message")
    assert "hint" not in plain
    assert plain["category"] == "runtime"
    detailed = eh.make_error(eh.MCPError.INVALID_ARGS, "bad", details={"field": "x"})
    assert detailed["details"] == {"field": "x"}

    assert eh._sanitize_exception_message(TypeError("missing positional argument: x"))
    assert eh._sanitize_exception_message(TypeError("unexpected keyword argument 'x'"))
    assert "Type mismatch" in eh._sanitize_exception_message(
        TypeError("'str' > 'int' not supported between instances")
    )
    assert eh._sanitize_exception_message(TypeError("ordinary type error")) == "ordinary type error"
    assert eh._sanitize_exception_message(AttributeError("broken")) == "broken"
    assert "IDA API not available" in eh._sanitize_exception_message(
        AttributeError("module has no attribute 'new_api'")
    )
    assert eh._sanitize_exception_message(KeyError("name")) == "Key not found: 'name'"
    assert eh._sanitize_exception_message(ValueError("bad value")) == "bad value"
    assert eh._sanitize_exception_message(OverflowError("large")) == "Value out of range: large"

    assert eh._timeout_code_for_context("decompile") == eh.MCPError.DECOMPILER_TIMEOUT
    assert eh._timeout_code_for_context("run", "emulation stalled") == eh.MCPError.EMULATION_TIMEOUT
    assert eh._timeout_code_for_context("search") == eh.MCPError.SEARCH_TIMEOUT
    assert eh._timeout_code_for_context("other") == eh.MCPError.RPC_TIMEOUT
    assert eh._is_timeout_exception(TimeoutError("slow")) is True
    class TimedOSError(OSError):
        @property
        def errno(self):
            return errno.ETIMEDOUT

    assert eh._is_timeout_exception(TimedOSError("slow")) is True
    assert eh._is_timeout_exception(RuntimeError("slow")) is False
    assert eh._classify_error_code(RuntimeError("decompiler failed"), None) == eh.MCPError.DECOMPILER_FAILED
    assert eh._classify_error_code(RuntimeError("emulator failed"), None) == eh.MCPError.EMULATION_ERROR
    assert eh._classify_error_code(RuntimeError("novel"), None) == eh.MCPError.UNKNOWN

    try:
        raise TimeoutError("decompile hung")
    except TimeoutError as exc:
        result = eh.handle_error(exc, context="code")
    assert result["code"] == eh.MCPError.DECOMPILER_TIMEOUT
    assert result["recoverable"] is True
    assert "details" in result


def test_image_range_helpers_use_idaapi_fallback_and_default_paths(monkeypatch):
    eh = _load_error_handling()
    ida_ida = types.ModuleType("ida_ida")
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    idaapi = sys.modules["idaapi"]

    monkeypatch.setattr(
        ida_ida,
        "inf_get_min_ea",
        lambda: (_ for _ in ()).throw(RuntimeError("old API")),
        raising=False,
    )
    monkeypatch.setattr(
        idaapi,
        "get_inf_structure",
        lambda: types.SimpleNamespace(min_ea=0x1000),
        raising=False,
    )
    assert eh._image_min_ea() == 0x1000

    monkeypatch.setattr(
        ida_ida,
        "inf_get_max_ea",
        lambda: (_ for _ in ()).throw(RuntimeError("old API")),
        raising=False,
    )
    monkeypatch.setattr(
        idaapi,
        "get_inf_structure",
        lambda: types.SimpleNamespace(max_ea=0x9000),
        raising=False,
    )
    assert eh._image_max_ea() == 0x9000

    monkeypatch.setattr(
        idaapi,
        "get_inf_structure",
        lambda: (_ for _ in ()).throw(RuntimeError("no info")),
        raising=False,
    )
    assert eh._image_min_ea() == 0
    assert eh._image_max_ea() == (1 << 64) - 1

    monkeypatch.delattr(ida_ida, "inf_get_min_ea", raising=False)
    monkeypatch.delattr(ida_ida, "inf_get_max_ea", raising=False)

    def empty_inf():
        return types.SimpleNamespace()

    monkeypatch.setattr(idaapi, "get_inf_structure", empty_inf, raising=False)
    assert eh._image_min_ea() == 0
    assert eh._image_max_ea() == (1 << 64) - 1


def test_address_validation_and_range_failures_are_structured(monkeypatch):
    eh = _load_error_handling()
    assert eh.parse_address_canonical(0x401000) == (0x401000, None)
    assert eh.parse_address_canonical("")[1]["code"] == eh.MCPError.MISSING_REQUIRED_ARG
    assert eh.parse_address_canonical("0xnot-hex")[1]["code"] == eh.MCPError.ADDRESS_INVALID

    idc = sys.modules["idc"]
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: 0x402000, raising=False)
    assert eh.parse_address_canonical("known_symbol") == (0x402000, None)
    monkeypatch.setattr(
        idc,
        "get_name_ea_simple",
        lambda _name: (_ for _ in ()).throw(RuntimeError("symbol lookup")),
        raising=False,
    )
    assert eh.parse_address_canonical("unknown_symbol")[1]["code"] == eh.MCPError.ADDRESS_INVALID

    idaapi = sys.modules["idaapi"]
    ida_bytes = types.ModuleType("ida_bytes")
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
    monkeypatch.setattr(eh, "parse_address_safe", lambda _value: (0x401000, None))
    monkeypatch.setattr(idaapi, "is_mapped", lambda _ea: True, raising=False)
    monkeypatch.setattr(ida_bytes, "get_flags", lambda _ea: 0, raising=False)
    monkeypatch.setattr(ida_bytes, "is_code", lambda _flags: False, raising=False)
    addr, error = eh.validate_addr("0x401000", require_code=True)
    assert addr is None
    assert error["code"] == eh.MCPError.ADDRESS_NOT_CODE

    compat = types.SimpleNamespace(get_func_start=lambda _ea: None)
    monkeypatch.setattr(eh, "_compat", compat)
    addr, error = eh.validate_addr("0x401000", require_func=True)
    assert addr is None
    assert error["code"] == eh.MCPError.FUNCTION_NOT_FOUND

    monkeypatch.setattr(idaapi, "is_mapped", lambda _ea: False, raising=False)
    assert eh.validate_addr("0x401000")[1]["code"] == eh.MCPError.ADDRESS_NOT_MAPPED
    monkeypatch.setattr(idaapi, "is_mapped", lambda _ea: True, raising=False)
    monkeypatch.setattr(ida_bytes, "is_code", lambda _flags: True, raising=False)
    monkeypatch.setattr(eh, "_compat", types.SimpleNamespace(get_func_start=lambda _ea: 0x401000))
    assert eh.validate_addr("0x401000", require_code=True, require_func=True) == (0x401000, None)

    monkeypatch.setattr(
        idaapi,
        "is_mapped",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("SDK failure")),
        raising=False,
    )
    addr, error = eh.validate_addr("0x401000")
    assert addr is None
    assert error["code"] == eh.MCPError.UNKNOWN

    original_import = builtins.__import__

    def import_without_ida_bytes(name, *args, **kwargs):
        if name in {"ida_bytes", "idaapi"}:
            raise ImportError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_ida_bytes)
    assert eh.validate_addr("0x401000") == (0x401000, None)

    calls = iter([(0x1000, None), (None, {"code": eh.MCPError.ADDRESS_INVALID})])
    monkeypatch.setattr(eh, "parse_address_safe", lambda _value: next(calls))
    assert eh.validate_range("start", "end")[2]["code"] == eh.MCPError.ADDRESS_INVALID
    monkeypatch.setattr(eh, "parse_address_safe", lambda value: (value, None))
    assert eh.validate_range(0x2000, 0x1000)[2]["code"] == eh.MCPError.INVALID_ARG_VALUE
    assert eh.validate_range(0, 0x10000001)[2]["code"] == eh.MCPError.SIZE_LIMIT_EXCEEDED
    calls = iter([(None, {"code": eh.MCPError.ADDRESS_INVALID})])
    monkeypatch.setattr(eh, "parse_address_safe", lambda _value: next(calls))
    assert eh.validate_range("start", "end")[2]["code"] == eh.MCPError.ADDRESS_INVALID
    monkeypatch.setattr(eh, "parse_address_safe", lambda value: (value, None))
    assert eh.validate_range(0x1000, 0x2000) == (0x1000, 0x2000, None)


def test_debugger_path_and_argument_helpers_cover_state_matrix(monkeypatch):
    eh = _load_error_handling()
    dbg = types.ModuleType("ida_dbg")
    dbg.DSTATE_NOTASK = 0
    monkeypatch.setitem(sys.modules, "ida_dbg", dbg)
    monkeypatch.setattr(dbg, "is_debugger_on", lambda: False, raising=False)
    monkeypatch.setattr(dbg, "get_process_state", lambda: "running", raising=False)
    assert eh.check_debugger(require_active=True) is None
    assert eh.check_debugger(require_active=False)["code"] == eh.MCPError.DEBUGGER_ACTIVE

    monkeypatch.setattr(dbg, "get_process_state", lambda: dbg.DSTATE_NOTASK, raising=False)
    assert eh.check_debugger(require_active=True)["code"] == eh.MCPError.DEBUGGER_NOT_RUNNING
    monkeypatch.setattr(
        dbg,
        "get_process_state",
        lambda: (_ for _ in ()).throw(RuntimeError("state unavailable")),
        raising=False,
    )
    assert eh.check_debugger(require_active=True)["code"] == eh.MCPError.DEBUGGER_NOT_RUNNING
    monkeypatch.setattr(dbg, "get_process_state", lambda: None, raising=False)
    assert eh.check_debugger(require_active=True)["code"] == eh.MCPError.DEBUGGER_NOT_RUNNING
    monkeypatch.setattr(dbg, "get_process_state", None, raising=False)
    assert eh.check_debugger(require_active=True)["code"] == eh.MCPError.DEBUGGER_NOT_RUNNING
    monkeypatch.setattr(dbg, "is_debugger_on", lambda: True, raising=False)
    assert eh.check_debugger(require_active=False)["code"] == eh.MCPError.DEBUGGER_ACTIVE

    original_import = builtins.__import__

    def import_without_debugger(name, *args, **kwargs):
        if name == "ida_dbg":
            raise ImportError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_debugger)
    assert eh.check_debugger() is None

    assert eh.validate_path_safe("")[1]["code"] == eh.MCPError.MISSING_REQUIRED_ARG
    assert eh.validate_path_safe("a\x00b")[1]["code"] == eh.MCPError.INVALID_ARG_VALUE
    assert eh.validate_path_safe("../secret")[1]["code"] == eh.MCPError.PATH_TRAVERSAL
    assert eh.validate_path_safe("/tmp/file", allow_absolute=False)[1]["code"] == eh.MCPError.PATH_TRAVERSAL
    assert eh.validate_path_safe("a/b") == ("a/b", None)

    original_normpath = os.path.normpath
    monkeypatch.setattr(os.path, "normpath", lambda _path: (_ for _ in ()).throw(RuntimeError("path")))
    try:
        normalized, error = eh.validate_path_safe("safe")
    finally:
        os.path.normpath = original_normpath
    assert normalized is None
    assert error["code"] == eh.MCPError.UNKNOWN

    assert eh.require_arg("value", "name") is None
    assert eh.require_arg(" ", "name")["code"] == eh.MCPError.MISSING_REQUIRED_ARG
    assert eh.require_arg(None, "name", hint="supply it")["hint"] == "supply it"
    assert eh.require_one_of(first=None, second="ok") is None
    assert eh.require_one_of(first=None, second=" ")["code"] == eh.MCPError.MISSING_REQUIRED_ARG
    assert eh.validate_count(None) is None
    assert eh.validate_count(-1)["code"] == eh.MCPError.INVALID_ARG_VALUE
    assert eh.validate_count(11, max_count=10)["code"] == eh.MCPError.SIZE_LIMIT_EXCEEDED


def test_action_validation_uses_difflib_when_services_matcher_is_unavailable(monkeypatch):
    eh = _load_error_handling()
    services = types.ModuleType("ida_pro_mcp.services")
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    assert eh.validate_action("search", ["search", "symbols"]) is None
    error = eh.validate_action("serch", ["search", "symbols"], tool_name="demo")
    assert error["code"] == eh.MCPError.ACTION_NOT_FOUND
    assert "Did you mean" in error["hint"]
    error = eh.validate_action("zzzz", ["search"], tool_name="demo")
    assert "Valid actions" in error["hint"]

    services.best_match = lambda *_args, **_kwargs: ["search"]
    error = eh.validate_action("srch", ["search"])
    assert error["hint"].startswith("Did you mean")
