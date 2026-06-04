from __future__ import annotations

import importlib.util
import os
import sys
import types
import typing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CODE_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"


def _load_code_module():
    old_modules = dict(sys.modules)
    mock_common = types.ModuleType("_common")
    mock_common.validate_addr = lambda addr, *a, **kw: (0x401000, None)
    mock_common.make_error = lambda *a, **kw: {"error": True, "args": a, "kwargs": kw}
    mock_common.handle_error = lambda *a, **kw: {"error": True}

    class MockMCPError:
        INVALID_ARGS = "INVALID_ARGS"
        DECOMPILER_FAILED = "DECOMPILER_FAILED"
        DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
        FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"

    mock_common.MCPError = MockMCPError
    mock_common.ERROR_HINTS = {}
    mock_common.normalize_list_input = lambda val: [val] if not isinstance(val, list) else val
    mock_common.get_prototype = lambda *a: "void func()"
    mock_common.tool = lambda fn: fn
    mock_common.idaread = lambda fn: fn
    mock_common.Annotated = typing.Annotated
    mock_common.Optional = typing.Optional
    mock_common.Literal = typing.Literal
    mock_common.Union = typing.Union
    mock_common.Any = typing.Any
    mock_common.hex_ea = lambda ea: hex(int(ea))

    sys.modules["_common"] = mock_common
    for name in [
        "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
        "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
        "ida_hexrays", "ida_frame", "ida_struct", "ida_lines",
        "ida_ua", "ida_kernwin",
    ]:
        mod = sys.modules.setdefault(name, types.ModuleType(name))
        setattr(mock_common, name, mod)
    sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF

    spec = importlib.util.spec_from_file_location("_code_enrichment_test", CODE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod, old_modules


def test_build_decompile_enrichment_registers_scoped_survey_and_shared_fields():
    mod, old_modules = _load_code_module()
    try:
        sys.modules["idc"].get_idb_path = lambda: "/tmp/test.idb"
        sys.modules["idautils"].CodeRefsTo = lambda ea, flow: [0x5000]
        sys.modules["idautils"].FuncItems = lambda ea: [0x401000]
        sys.modules["idautils"].CodeRefsFrom = lambda ea, flow: [0x6000]

        class _Func:
            def __init__(self, start_ea):
                self.start_ea = start_ea

        sys.modules["ida_funcs"].get_func = lambda ea: _Func(ea)
        sys.modules["ida_funcs"].get_func_name = lambda ea: f"sub_{ea:x}"

        saved = {}

        class FakeSurveyStore:
            def __init__(self, context_key=""):
                saved["context_key"] = context_key

            def get_survey(self, addr):
                return None

            def save_survey(self, **kwargs):
                saved["survey"] = kwargs

        host_pkg = types.ModuleType("host")
        survey_mod = types.ModuleType("host.survey_store")
        survey_mod.SurveyStore = FakeSurveyStore
        host_pkg.survey_store = survey_mod
        sys.modules["host"] = host_pkg
        sys.modules["host.survey_store"] = survey_mod

        mod._extract_var_rename_hints = lambda cfunc: [
            {"var": "v1", "suggested": "pkt_buf", "reason": "mock"}
        ]
        mod._get_blackboard_context_for_addr = lambda addr_hex: [{"title": "known", "category": "hypothesis"}]

        class MockCFunc:
            def __str__(self):
                return "int v1 = recv(sock, buf, len, 0); memcpy(dst, v1, len); switch(v1) { case 1: break; }"

        enrichment = mod._build_decompile_enrichment(
            0x401000,
            MockCFunc(),
            str(MockCFunc()),
            detailed_dangerous=True,
            include_switch_cases=True,
            api_limit=15,
        )

        assert "recv" in enrichment["api_calls"]
        assert "memcpy" in enrichment["api_calls"]
        assert enrichment["var_rename_hints"][0]["var"] == "v1"
        assert enrichment["blackboard_context"][0]["title"] == "known"
        assert enrichment["complexity"]["switch_cases"] == 1
        assert saved["context_key"] == "/tmp/test.idb"
        assert saved["survey"]["addr"] == "0x401000"
        assert saved["survey"]["variables"] == ["v1"]
        assert saved["survey"]["dependencies"] == ["0x5000", "0x6000"]
    finally:
        sys.modules.clear()
        sys.modules.update(old_modules)


def test_code_decompile_and_smart_decompile_use_shared_enrichment_helper():
    text = CODE_PATH.read_text(encoding="utf-8")
    assert "_build_decompile_enrichment(" in text
    assert "elif action == \"smart_decompile\":" in text
    assert "enrichment = _build_decompile_enrichment(" in text
    assert "_register_survey_if_needed(" in text
    assert "SurveyStore(context_key=idc.get_idb_path() or \"\")" in text
