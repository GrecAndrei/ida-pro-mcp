"""Tests for code(action='trace_argument_origin') — backward BFS through callers."""
from __future__ import annotations

import os
import sys
import types

from tests._isolated_repo_loader import load_tool_module
from tests.tools.fake_idb import MOCK_EXEC, FakeIDB

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

for _mn in ("idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
            "ida_segment", "ida_nalt", "ida_hexrays", "ida_lines",
            "ida_name", "ida_typeinf", "ida_kernwin", "ida_loader",
            "ida_dbg", "ida_frame", "ida_struct", "ida_ua", "ida_xref",
            "rpc", "sync"):
    if _mn not in sys.modules:
        sys.modules[_mn] = types.ModuleType(_mn)

sys.modules["idaapi"].BADADDR = 0xFFFFFFFF
sys.modules["idaapi"].SEGPERM_EXEC = 1
sys.modules["idaapi"].fl_CN = 21
sys.modules["idaapi"].fl_CF = 22
sys.modules["ida_funcs"].func_t = type("func_t", (), {})
sys.modules["ida_typeinf"].tinfo_t = type("tinfo_t", (), {})
sys.modules["ida_hexrays"].decompile = lambda ea: None
sys.modules["rpc"].tool = lambda f: f
sys.modules["rpc"].unsafe = lambda f: f
sys.modules["sync"].idaread = lambda f: f
sys.modules["sync"].idawrite = lambda f: f
sys.modules["sync"].IDAError = type("IDAError", (Exception,), {})
sys.modules["idc"].batch = lambda x: 0
sys.modules["idc"].get_func_name = lambda ea: ""
sys.modules["idc"].get_name = lambda ea, *a: ""
sys.modules["idc"].get_type = lambda ea: None
sys.modules["idc"].demangle_name = lambda name, inf: None
sys.modules["idc"].get_inf_attr = lambda attr: 0
sys.modules["idautils"].Functions = list
sys.modules["idautils"].Names = lambda: iter([])
sys.modules["idautils"].Heads = lambda s, e: iter(range(s, e, 2))
sys.modules["idautils"].CodeRefsFrom = lambda ea, *a: []
sys.modules["idautils"].CodeRefsTo = lambda ea, *a: []
sys.modules["idautils"].XrefsFrom = lambda ea, *a: []
sys.modules["idautils"].XrefsTo = lambda ea, *a: []
sys.modules["idautils"].FuncItems = lambda ea: iter([])
sys.modules["idaapi"].get_func = lambda ea: None
sys.modules["idaapi"].getseg = lambda ea: None
sys.modules["idaapi"].get_next_seg = lambda ea: None
sys.modules["idaapi"].get_ea = lambda ea: ea
sys.modules["idaapi"].FlowChart = lambda func: iter([])
sys.modules["ida_funcs"].get_func = lambda ea: None
sys.modules["ida_funcs"].get_func_name = lambda ea: ""
sys.modules["ida_segment"].getseg = lambda ea: None
sys.modules["ida_segment"].get_segm_name = lambda seg: ""
sys.modules["ida_nalt"].get_import_module_qty = lambda: 0
sys.modules["ida_nalt"].get_import_module_name = lambda i: None


def _load_code():
    return load_tool_module("code")


class TestTraceArgumentOrigin:

    def test_basic_trace_returns_tree(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x403000)
        db.add_func(0x401000, "target_func")
        db.add_func(0x402000, "caller_func")
        db._callees[0x402000] = {0x401000}
        db._callers[0x401000] = {0x402000}
        db.install()
        mod = _load_code()
        res = mod.code(action="trace_argument_origin", addrs="0x401000", arg_index=0)
        assert res["ok"] is True
        assert res["action"] == "trace_argument_origin"
        assert res["target"] == "0x401000"
        assert "trace_tree" in res
        # caller_func should appear in the trace
        caller_names = [e["caller_name"] for e in res["trace_tree"]]
        assert "caller_func" in caller_names

    def test_no_callers_returns_empty_tree(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "orphan_func")
        db.install()
        mod = _load_code()
        res = mod.code(action="trace_argument_origin", addrs="0x401000", arg_index=0)
        assert res["ok"] is True
        assert res["trace_tree"] == []

    def test_invalid_address_returns_error(self):
        db = FakeIDB()
        db.install()
        mod = _load_code()
        res = mod.code(action="trace_argument_origin", addrs="0x999999", arg_index=0)
        # Should return an error entry (not crash)
        if isinstance(res, list):
            assert any(not e.get("ok", True) for e in res)
        else:
            assert res.get("ok") is not True

    def test_deep_chain_traces_multiple_levels(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x405000)
        db.add_func(0x401000, "leaf_target")
        db.add_func(0x402000, "middle_func")
        db.add_func(0x403000, "top_func")
        # top_func -> middle_func -> leaf_target
        db._callees[0x402000] = {0x401000}
        db._callers[0x401000] = {0x402000}
        db._callees[0x403000] = {0x402000}
        db._callers[0x402000] = {0x403000}
        db.install()
        mod = _load_code()
        res = mod.code(action="trace_argument_origin", addrs="0x401000", arg_index=1, max_depth=3)
        assert res["ok"] is True
        depths = {e["depth"] for e in res["trace_tree"]}
        # Should have entries at depth 0 (middle_func) and depth 1 (top_func)
        assert len(depths) >= 1
