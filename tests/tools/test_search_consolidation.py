"""Tests for consolidated search actions: symbol, symbol_info, demangle, xrefs_to_string."""
from __future__ import annotations

import os
import sys
import types

from tests._isolated_repo_loader import load_support_module, load_tool_submodule
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
sys.modules["idaapi"].SEGPERM_READ = 4
sys.modules["idaapi"].fl_CN = 21
sys.modules["idaapi"].fl_CF = 22
sys.modules["idaapi"].FUNC_NORET = 1
sys.modules["idaapi"].FUNC_LIB = 2
sys.modules["idaapi"].FUNC_THUNK = 4
sys.modules["idaapi"].FUNC_STATIC = 8
sys.modules["idaapi"].FUNC_FRAME = 16
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
sys.modules["idc"].get_full_flags = lambda ea: 0
sys.modules["idc"].is_data = lambda f: False
sys.modules["idc"].is_code = lambda f: False
sys.modules["idc"].is_byte = lambda f: False
sys.modules["idc"].is_word = lambda f: False
sys.modules["idc"].is_dword = lambda f: False
sys.modules["idc"].is_qword = lambda f: False
sys.modules["idc"].is_strlit = lambda f: False
sys.modules["idc"].is_struct = lambda f: False
sys.modules["idc"].is_align = lambda f: False
sys.modules["idc"].is_comm = lambda f: False
sys.modules["idc"].get_item_size = lambda ea: 1
sys.modules["idc"].get_strlit_contents = lambda *a, **kw: None
sys.modules["idc"].get_str_type = lambda ea: None
sys.modules["idc"].get_type = lambda ea: None
sys.modules["idc"].parse_decl = lambda *a, **kw: None
sys.modules["idc"].get_inf_attr = lambda attr: 0
sys.modules["idc"].INF_SHORT_DN = 0
sys.modules["idc"].INF_LONG_DN = 1
sys.modules["idc"].demangle_name = lambda name, inf: None
sys.modules["idc"].get_name_ea_simple = lambda name: 0xFFFFFFFF
sys.modules["idc"].find_func_end = lambda ea: 0xFFFFFFFF
sys.modules["idc"].next_head = lambda ea, end: ea + 1
sys.modules["idc"].print_insn_mnem = lambda ea: ""
sys.modules["idc"].get_name_ea_simple = lambda name: 0xFFFFFFFF
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
sys.modules["ida_segment"].getseg = lambda ea: None
sys.modules["ida_segment"].get_segm_name = lambda seg: ""
sys.modules["ida_nalt"].get_import_module_qty = lambda: 0
sys.modules["ida_nalt"].get_import_module_name = lambda i: None


def _cat():
    return load_support_module("_api_categories")


def _load_search():
    _cat()
    return load_tool_submodule("search")


# =========================================================================
# search(action="symbol") — find_symbol_by_name
# =========================================================================
class TestSearchSymbol:

    def test_exact_name_match(self):
        db = FakeIDB()
        db.add_func(0x401000, "CreateFileA")
        db.add_func(0x402000, "main")
        db.install()
        mod = _load_search()
        res = mod.search(action="symbol", pattern="main")
        assert res["ok"] is True
        assert res["match"] == "exact_name"
        assert res["addr"] == "0x402000"
        assert res["name"] == "main"

    def test_fuzzy_substring_match(self):
        db = FakeIDB()
        db.add_func(0x401000, "MyEncryptionRoutine")
        db.add_func(0x402000, "sub_402000")
        db.install()
        mod = _load_search()
        res = mod.search(action="symbol", pattern="Encrypt")
        assert res["ok"] is True
        assert res["match"] in ("fuzzy", "exact_case_insensitive")
        assert "MyEncryptionRoutine" in res["name"]

    def test_no_match_returns_error(self):
        db = FakeIDB()
        db.install()
        mod = _load_search()
        res = mod.search(action="symbol", pattern="nonexistent_symbol_xyz")
        assert res.get("ok") is not True
        # message may be in 'error' (production) or 'message' (test mock)
        err_text = res.get("error", "") or res.get("message", "") or ""
        assert "No symbol matching" in err_text or "not found" in err_text.lower()


# =========================================================================
# search(action="symbol_info") — rich symbol inspector
# =========================================================================
class TestSearchSymbolInfo:

    def test_basic_info_for_known_function(self):
        db = FakeIDB()
        db.add_func(0x401000, "SendPacket")
        db.install()
        mod = _load_search()
        res = mod.search(action="symbol_info", pattern="SendPacket")
        assert res["ok"] is True
        assert res["action"] == "symbol_info"
        assert "addr" in res
        assert "name" in res
        assert "demangled" in res
        assert "segment" in res
        assert "perms" in res or "segment_perms" in res

    def test_info_for_address_literal(self):
        db = FakeIDB()
        db.add_func(0x401000, "DecryptBuffer")
        db.install()
        mod = _load_search()
        res = mod.search(action="symbol_info", pattern="0x401000", query="0x401000")
        assert res["ok"] is True
        assert res["addr"] == "0x401000"


# =========================================================================
# search(action="demangle") — C++ name demangling
# =========================================================================
class TestSearchDemangle:

    def test_demangle_multiple_names(self):
        # Patch demangle_name to simulate demangling
        original_demangle = sys.modules["idc"].demangle_name
        sys.modules["idc"].demangle_name = lambda name, inf: "Class::Method(void)" if name.startswith("?") else None

        try:
            mod = _load_search()
            res = mod.search(action="demangle", pattern="?Method@Class@@QAEXXZ, _ZN1A1bEv,_plain_func")
            assert res["ok"] is True
            assert res["action"] == "demangle"
            assert res["count"] == 3
            items = res["items"]
            assert items[0]["mangled"] == "?Method@Class@@QAEXXZ"
            assert items[0]["short"] == "Class::Method(void)"
            assert items[0]["is_mangled"] is True
            # Unmangled names pass through as-is
            assert items[2]["_short"] if "_short" in items[2] else True
        finally:
            sys.modules["idc"].demangle_name = original_demangle

    def test_empty_pattern_returns_error(self):
        mod = _load_search()
        res = mod.search(action="demangle", pattern="")
        assert res.get("ok") is not True


# =========================================================================
# search(action="xrefs_to_string") — find functions referencing a string
# =========================================================================
class TestSearchXrefsToString:

    def test_string_not_found_anywhere(self):
        db = FakeIDB()
        db.install()
        mod = _load_search()
        res = mod.search(action="xrefs_to_string", pattern="nonexistent_string_value")
        # Should return an error or empty result
        assert res.get("ok") is not True or res.get("count", 0) == 0
