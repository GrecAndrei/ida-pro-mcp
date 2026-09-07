"""Deep boundary and error branch tests for the types tool."""

from __future__ import annotations

import builtins
import importlib
import struct
import sys
from types import SimpleNamespace

from tests.fakes.ida_fake import (
    BT_ENUM,
    BT_INT8,
    BT_STRUCT,
    BT_TYPEDEF,
    BT_UNION,
    FakeTinfo,
    edm_t,
    udm_t,
)

types_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_types_mapping_and_declaration_syntax(monkeypatch):
    assert types_module._is_fully_mapped(0x1000, 0.5) is False

    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda *_args: True)
    assert _ok(types_module.types(action="parse_decl", type_str="int"))

    assert types_module.types(action="set_prototype", addr="invalid", decl="int f()")["error"] is True

    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda *_args: None)
    assert types_module.types(action="declare", decl="!!!invalid")["error"] is True

    class FakeNamelessTinfo(FakeTinfo):
        def get_type_name(self):
            return None

    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", lambda: FakeNamelessTinfo(kind=BT_STRUCT))
    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda tif, *_: tif)
    monkeypatch.setattr(types_module.ida_typeinf, "alloc_type_ordinal", lambda *_: 1)
    monkeypatch.setattr(types_module.ida_typeinf, "set_numbered_type", lambda *_: True)
    res_named = types_module.types(action="declare", decl="struct HiddenName { int a; };")
    assert res_named["ok"] is True
    assert res_named["name"] == "HiddenName"

    assert types_module.types(action="apply", addr="invalid", decl="int")["error"] is True

    monkeypatch.setattr(types_module._compat, "get_func_start", lambda _ea: None)
    monkeypatch.setattr(types_module, "validate_addr", lambda _addr: (0x1000, None))
    res_local = types_module.types(action="apply", addr="0x1000", decl="int", kind="local", name="var")
    assert res_local["error"] is True
    assert "FUNCTION_NOT_FOUND" in res_local["code"] or "not inside a function" in res_local["message"]


def test_types_get_typedef_chain_exceptions(monkeypatch):
    calls_step = [0]

    class ExplodingTypedefTinfo(FakeTinfo):
        def __init__(self, *args, **kwargs):
            super().__init__(kind=BT_TYPEDEF)

        def is_struct(self):
            return False

        def is_union(self):
            return False

        def is_enum(self):
            return False

        def is_func(self):
            return False

        def is_typedef(self):
            return True

        def get_next_type_name(self):
            raise RuntimeError("name error")

        def get_next_type(self, _nxt):
            calls_step[0] += 1
            if calls_step[0] == 1:
                return True
            raise RuntimeError("next error")

    def resolve_typedef(_name, target):
        target.is_struct = lambda: False
        target.is_union = lambda: False
        target.is_enum = lambda: False
        target.is_func = lambda: False
        target.is_typedef = lambda: True
        return True

    monkeypatch.setattr(types_module, "_resolve_type_by_name", resolve_typedef)
    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", ExplodingTypedefTinfo)

    res = types_module.types(action="get", name="TypeDefBoom")
    assert res.get("ok") is True, res

    def fake_tinfo_outer(*args, **kwargs):
        if args:
            raise RuntimeError("tinfo constructor boom")
        return ExplodingTypedefTinfo()

    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", fake_tinfo_outer)
    res_outer = types_module.types(action="get", name="TypeDefOuterBoom")
    assert res_outer["ok"] is True


def test_types_declare_ordinal_exceptions(monkeypatch):
    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda tif, *_: tif)
    monkeypatch.setattr(types_module.ida_typeinf, "alloc_type_ordinal", lambda *_: 1)
    monkeypatch.setattr(types_module.ida_typeinf, "set_numbered_type", lambda *_: False)

    class CheckTinfo:
        def get_ordinal(self):
            raise RuntimeError("ordinal failed")

    monkeypatch.setattr(types_module.ida_typeinf, "get_named_type", lambda *_args: CheckTinfo(), raising=False)
    res1 = types_module.types(action="declare", decl="struct FailOrd { int a; };", name="FailOrd")
    assert res1["ok"] is True

    monkeypatch.setattr(types_module.ida_typeinf, "get_named_type", lambda *_args: (_ for _ in ()).throw(RuntimeError("get_named_type failed")), raising=False)
    res2 = types_module.types(action="declare", decl="struct FailLookup { int a; };", name="FailLookup")
    assert res2["error"] is True


def test_types_struct_search_name_match(monkeypatch, fresh_fake_idb):
    struct_tinfo = FakeTinfo(lib=fresh_fake_idb.type_lib, name="SearchTargetStruct", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(struct_tinfo)

    monkeypatch.setattr(types_module.ida_typeinf, "get_ordinal_qty", lambda *_: 1, raising=False)
    monkeypatch.setattr(types_module.ida_typeinf, "get_ordinal_count", lambda *_: 1, raising=False)

    class CustomTinfo(FakeTinfo):
        def get_numbered_type(self, _til, _ord):
            return True

        def is_struct(self):
            return True

        def is_union(self):
            return False

        def get_type_name(self):
            return "SearchTargetStruct"

    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", CustomTinfo)
    res = types_module.types(action="search_structs", query="SearchTarget*")
    assert res["ok"] is True
    assert any(m["name"] == "SearchTargetStruct" and m["match"] == "name" for m in res["matches"])


def test_types_struct_dump_non_printable_and_empty_bytes(monkeypatch, fresh_fake_idb):
    buf_type = FakeTinfo(kind=BT_INT8)
    buf_type.get_size = lambda: 48
    st = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="DumpTestStruct",
        kind=BT_STRUCT,
        members=[udm_t("buf", buf_type, 0, 48)],
    )
    st.get_size = lambda: 48
    fresh_fake_idb.type_lib.register(st)

    monkeypatch.setattr(types_module, "parse_address", lambda _addr: 0x1000)
    monkeypatch.setattr(types_module.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(types_module, "_is_fully_mapped", lambda *_args: True)

    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: b"\x00\xff\xfe\x00" * 12)
    res1 = types_module.types(action="read_struct", addr="0x1000", name="DumpTestStruct")
    assert res1["ok"] is True
    assert "..." in res1["fields"][0]["value"]

    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: [0x1, 0x2])
    res2 = types_module.types(action="read_struct", addr="0x1000", name="DumpTestStruct")
    assert res2["ok"] is True

    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: None)
    res3 = types_module.types(action="read_struct", addr="0x1000", name="DumpTestStruct")
    assert res3["ok"] is True
    assert "[48 bytes]" in res3["fields"][0]["value"]


def test_types_diff_and_visualize_failures(monkeypatch, fresh_fake_idb):
    assert types_module.types(action="diff", name="NonExistentA", other_name="NonExistentB")["error"] is True

    st = FakeTinfo(lib=fresh_fake_idb.type_lib, name="ExistingA", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(st)
    assert types_module.types(action="diff", name="ExistingA", other_name="NonExistentB")["error"] is True

    enum_a = FakeTinfo(lib=fresh_fake_idb.type_lib, name="EnumA", kind=BT_ENUM, members=[edm_t("X", 1)])
    enum_b = FakeTinfo(lib=fresh_fake_idb.type_lib, name="EnumB", kind=BT_ENUM, members=[edm_t("Y", 2)])
    fresh_fake_idb.type_lib.register(enum_a)
    fresh_fake_idb.type_lib.register(enum_b)

    monkeypatch.setattr(FakeTinfo, "get_enum_details", lambda self, *args: self.get_type_name() != "EnumA")
    diff_res = types_module.types(action="diff", name="EnumA", other_name="EnumB")
    assert "Failed to retrieve enum member details" in diff_res.get("error", "")

    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda *_args: False)
    assert types_module.types(action="visualize", name="ExistingA")["error"] is True


def test_types_propagate_limits_and_errors(monkeypatch, fresh_fake_idb):
    st = FakeTinfo(lib=fresh_fake_idb.type_lib, name="PropTarget", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(st)

    assert types_module.types(action="propagate", seed_addr=None, type_name="PropTarget")["error"] is True

    monkeypatch.setattr(types_module, "validate_addr", lambda _addr: (0x1000, None))
    monkeypatch.setattr(types_module, "_is_data_location", lambda _ea: True)

    xrefs = [SimpleNamespace(frm=0x2000 + i, type=1, iscode=False) for i in range(5005)]
    monkeypatch.setattr(types_module.idautils, "XrefsTo", lambda *_args: xrefs)
    res_cap = types_module.types(action="propagate", addr="0x1000", name="PropTarget")
    assert res_cap["ok"] is True

    dup_xrefs = [
        SimpleNamespace(frm=0x3000, type=1, iscode=False),
        SimpleNamespace(frm=0x3000, type=1, iscode=False),
    ]
    monkeypatch.setattr(types_module.idautils, "XrefsTo", lambda *_args: dup_xrefs)
    res_dup = types_module.types(action="propagate", addr="0x1000", name="PropTarget")
    assert res_dup["ok"] is True

    sing_xref = [SimpleNamespace(frm=0x4000, type=1, iscode=False)]
    monkeypatch.setattr(types_module.idautils, "XrefsTo", lambda *_args: sing_xref)
    monkeypatch.setattr(types_module.ida_typeinf, "apply_tinfo", lambda *_args: (_ for _ in ()).throw(RuntimeError("apply boom")))
    res_err = types_module.types(action="propagate", addr="0x1000", name="PropTarget")
    assert res_err["ok"] is True
    assert res_err["skipped"] == 1
    assert res_err["locations"][0]["status"] == "error"


def test_types_type_graph_deep_branches(monkeypatch, fresh_fake_idb):
    assert types_module.types(action="type_graph", name="NonExistentTypeGraph")["error"] is True

    root_tif = FakeTinfo(lib=fresh_fake_idb.type_lib, name="RootGraphStruct", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(root_tif)

    calls = [0]

    def custom_resolve(name, target):
        calls[0] += 1
        if name == "RootGraphStruct":
            target.get_type_name = lambda: "RootGraphStruct"
            target.is_struct = lambda: True
            target.is_union = lambda: False
            target.get_size = lambda: 16
            return True
        if name == "MissingDep":
            return False
        if name == "NonStructDep":
            target.is_struct = lambda: False
            target.is_union = lambda: False
            return True
        return False

    monkeypatch.setattr(types_module, "_resolve_type_by_name", custom_resolve)

    def make_member_type(name):
        return SimpleNamespace(
            get_type_name=lambda: name,
            is_ptr=lambda: False,
            is_array=lambda: False,
            is_struct=lambda: True,
            is_union=lambda: False,
        )

    udt_data = [
        SimpleNamespace(name="m1", type=make_member_type("MissingDep"), is_gap=lambda: False),
        SimpleNamespace(name="m2", type=make_member_type("NonStructDep"), is_gap=lambda: False),
    ]

    class MockUDT:
        def size(self):
            return len(udt_data)

        def __getitem__(self, i):
            return udt_data[i]

    monkeypatch.setattr(types_module.ida_typeinf, "udt_type_data_t", MockUDT)
    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda self, udt: True)

    res = types_module.types(action="type_graph", name="RootGraphStruct", max_depth=3)
    assert res.get("ok") is True, res


def test_types_vtable_extract_branches(monkeypatch):
    assert types_module.types(action="vtable", addr="invalid")["error"] is True

    monkeypatch.setattr(types_module.idc, "get_name_ea_simple", lambda _name: types_module.idaapi.BADADDR)
    monkeypatch.setattr(types_module.idautils, "Names", lambda: [(0x2000, "_ZTV7MyClass")])
    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: b"")
    res_partial = types_module.types(action="vtable", name="MyClass")
    assert res_partial["ok"] is True

    monkeypatch.setattr(types_module, "validate_addr", lambda _addr: (0x5000, None))
    ptr_size = 8 if types_module._inf_is_64bit() else 4
    endian = ">" if types_module._inf_is_be() else "<"
    fmt = f"{endian}Q" if ptr_size == 8 else f"{endian}I"

    raw_unloaded = struct.pack(fmt, 0x9000)
    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: raw_unloaded)
    monkeypatch.setattr(types_module.ida_bytes, "is_loaded", lambda ea: ea != 0x9000)
    res_unloaded = types_module.types(action="vtable", addr="0x5000")
    assert res_unloaded["ok"] is True
    assert len(res_unloaded["entries"]) == 0

    raw_self = struct.pack(fmt, 0x5000)
    monkeypatch.setattr(types_module.ida_bytes, "get_bytes", lambda *_args: raw_self)
    monkeypatch.setattr(types_module.ida_bytes, "is_loaded", lambda _ea: True)
    res_self = types_module.types(action="vtable", addr="0x5000")
    assert res_self["ok"] is True
    assert len(res_self["entries"]) == 0


def test_types_struct_and_enum_member_rename_and_revalue_errors(monkeypatch, fresh_fake_idb):
    assert types_module.types(action="struct_member_rename", struct_name="NonExistentStruct", member_name="m", new_name="n")["error"] is True
    assert types_module.types(action="struct_member_set_type", struct_name="NonExistentStruct", member_name="m", type_str="int")["error"] is True
    assert types_module.types(action="enum_member_rename", enum_name="NonExistentEnum", member_name="m", new_name="n")["error"] is True
    assert types_module.types(action="enum_member_revalue", enum_name="MyEnum", member_name="")["error"] is True

    enum_tinfo = FakeTinfo(lib=fresh_fake_idb.type_lib, name="RevalEnum", kind=BT_ENUM, members=[edm_t("VAL1", 10)])
    fresh_fake_idb.type_lib.register(enum_tinfo)

    monkeypatch.delattr(types_module.ida_typeinf, "set_enum_member_value", raising=False)
    monkeypatch.setattr(enum_tinfo, "del_edm", lambda *args: 0)
    monkeypatch.setattr(enum_tinfo, "add_edm", lambda *args: (_ for _ in ()).throw(RuntimeError("add_edm error")))

    res_add_fail = types_module._revalue_enum_member(enum_tinfo, "VAL1", 20)
    assert res_add_fail["error"] is True
    assert "add_edm failed" in res_add_fail["message"]


def test_types_til_export_and_import_deep_branches(monkeypatch, tmp_path, fresh_fake_idb):
    monkeypatch.setattr(types_module, "validate_path_safe", lambda _p: (None, {"error": True, "message": "bad path"}))
    assert types_module.types(action="til_export", path="/bad/path")["error"] is True
    assert types_module.types(action="til_import", path="/bad/path")["error"] is True

    monkeypatch.setattr(types_module, "validate_path_safe", lambda p: (p, None))
    monkeypatch.setattr(types_module.ida_typeinf, "get_ordinal_qty", lambda *_: 3, raising=False)
    monkeypatch.setattr(types_module.ida_typeinf, "get_ordinal_count", lambda *_: 3, raising=False)

    class ExportTestTinfo(FakeTinfo):
        def __init__(self, ord_num):
            super().__init__(kind=BT_STRUCT)
            self.ord_num = ord_num

        def get_numbered_type(self, _til, num):
            return num != 1

        def get_type_name(self):
            return f"Type_{self.ord_num}"

        def is_typedef(self):
            return self.ord_num == 2

        def __str__(self):
            return ""

    call_exp = [0]

    def make_exp_tinfo():
        call_exp[0] += 1
        return ExportTestTinfo(call_exp[0])

    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", make_exp_tinfo)
    monkeypatch.setattr(types_module.ida_typeinf, "print_tinfo", lambda *_a: "")

    out_file = tmp_path / "export_test.h"
    res_exp = types_module.types(action="til_export", path=str(out_file))
    assert res_exp["ok"] is True

    monkeypatch.setattr("builtins.open", lambda *_a, **_kw: (_ for _ in ()).throw(PermissionError("denied")))
    assert types_module.types(action="til_export", path=str(out_file))["error"] is True
    assert types_module.types(action="til_import", path=str(out_file))["error"] is True
    monkeypatch.undo()

    hdr_file = tmp_path / "import_test.h"
    hdr_file.write_text(
        "/* Exported from IDA type library. Import with types(action='til_import'). */\n\n"
        "struct A { int x; };\n\n"
        "struct B { int y; };\n\n"
        "struct C { int z; };\n",
        encoding="utf-8",
    )

    calls = [0]

    def fake_parse_decl(tif, til, blk, flags):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("parse crash")
        if calls[0] == 2:
            return None
        return "C"

    def fake_set_named_type(til, name, ntf):
        raise RuntimeError("save crash")

    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", fake_parse_decl)
    tinfo_inst = FakeTinfo(kind=BT_STRUCT)
    tinfo_inst.set_named_type = fake_set_named_type
    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", lambda: tinfo_inst)

    res_imp = types_module.types(action="til_import", path=str(hdr_file))
    assert res_imp["error"] is True
    assert "Type library import" in res_imp["message"]


def test_types_helpers_type_kind_and_struc_lookup(monkeypatch):
    union_tif = FakeTinfo(kind=BT_UNION)
    assert types_module._type_kind(union_tif) == "union"

    monkeypatch.setattr(types_module.idc, "get_struc_id", lambda _name: 0, raising=False)
    monkeypatch.setattr(types_module.ida_struct, "get_struc_id", lambda _name: types_module.idaapi.BADADDR, raising=False)
    assert types_module._struct_sptr("invalid_name") is None

    monkeypatch.setattr(types_module.idc, "get_struc_id", lambda _name: 0x1234, raising=False)
    monkeypatch.setattr(types_module.ida_struct, "get_struc", lambda _sid: (_ for _ in ()).throw(RuntimeError("struc fail")), raising=False)
    assert types_module._struct_sptr("exploding") is None


def test_types_parse_member_type_and_struct_sptr_errors(monkeypatch, fresh_fake_idb):
    class ThrowNamedTinfo(FakeTinfo):
        def get_named_type(self, _til, _name):
            if _name == "uint8_t":
                return True
            raise RuntimeError("lookup error")

        def create_array(self, _base, _n):
            raise RuntimeError("array error")

    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", ThrowNamedTinfo)
    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda tif, *_: True)
    # Covers create_array exception (lines 1869-1870)
    types_module._parse_member_type("uint8_t[16]", None)
    # Covers get_named_type exception (lines 1852-1853)
    types_module._parse_member_type("custom_type", None)

    class ZeroSizeTinfo(FakeTinfo):
        def get_size(self):
            return 0

    monkeypatch.setattr(types_module.ida_typeinf, "parse_decl", lambda tif, *_: True)
    monkeypatch.setattr(types_module.ida_typeinf, "tinfo_t", ZeroSizeTinfo)
    tif, err = types_module._parse_member_type("zero_type", None)
    assert tif is None and err["error"] is True

    record = FakeTinfo(lib=fresh_fake_idb.type_lib, name="target_struct_err", kind=BT_STRUCT, members=[udm_t("id", FakeTinfo(kind=BT_INT8), 0, 1)])
    fresh_fake_idb.type_lib.register(record)

    monkeypatch.setattr(types_module, "_parse_member_type", lambda *_a: (None, {"error": True, "message": "bad type"}))
    assert types_module._add_struct_member(record, "target_struct_err", "m", 0, "bad", None)[1]["error"] is True
    assert types_module._set_struct_member_type(record, "target_struct_err", "id", "bad")[2]["error"] is True

    monkeypatch.setattr(types_module, "_parse_member_type", lambda *_a: (FakeTinfo(kind=BT_INT8), None))
    monkeypatch.setattr(types_module, "_has_classic_struct_api", lambda: True)
    monkeypatch.setattr(types_module, "_struct_sptr", lambda _name: None)
    assert types_module._del_struct_member(record, "target_struct_err", "id")[1]["error"] is True
    assert types_module._rename_struct_member(record, "target_struct_err", "id", "renamed")[1]["error"] is True
    assert types_module._set_struct_member_type(record, "target_struct_err", "id", "int")[2]["error"] is True


def test_types_set_udm_type_shift_fallback_branches(monkeypatch, fresh_fake_idb):
    record = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="shift_struct",
        kind=BT_STRUCT,
        members=[
            udm_t("m0", FakeTinfo(kind=BT_INT8), 0, 1),
            udm_t("m1", FakeTinfo(kind=BT_INT8), 8, 1),
        ],
    )
    fresh_fake_idb.type_lib.register(record)

    monkeypatch.setattr(types_module, "_has_classic_struct_api", lambda: False)
    large_tinfo = FakeTinfo(kind=BT_STRUCT)
    large_tinfo.get_size = lambda: 8
    monkeypatch.setattr(types_module, "_parse_member_type", lambda *_a: (large_tinfo, None))
    monkeypatch.setattr(record, "set_udm_type", lambda *args: 1)

    # 1. get_udt_details fails on line 2004 (2nd call returns False)
    calls_fail_first = [0]

    def mock_get_udt_fail_line_2004(udt):
        calls_fail_first[0] += 1
        if calls_fail_first[0] == 1:
            udt.extend([
                SimpleNamespace(name="m0", size=8, type=large_tinfo, offset=0),
                SimpleNamespace(name="m1", size=8, type=large_tinfo, offset=8),
            ])
            return True
        return False

    monkeypatch.setattr(record, "get_udt_details", mock_get_udt_fail_line_2004)
    assert types_module._set_struct_member_type(record, "shift_struct", "m0", "large_type")[2]["error"] is True

    # 2. While loop break on line 2018 (3rd call returns False) and tail add_udm fails on line 2029
    calls_break_2018 = [0]

    def mock_get_udt_break_2018(udt):
        calls_break_2018[0] += 1
        if calls_break_2018[0] <= 2:
            udt.extend([
                SimpleNamespace(name="m0", size=8, type=large_tinfo, offset=0),
                SimpleNamespace(name="m1", size=8, type=large_tinfo, offset=8),
            ])
            return True
        return False

    add_calls = [0]

    def mock_add_udm(name, *args):
        add_calls[0] += 1
        if name == "m0":
            return 0
        return 1

    monkeypatch.setattr(record, "get_udt_details", mock_get_udt_break_2018)
    monkeypatch.setattr(record, "add_udm", mock_add_udm)
    assert types_module._set_struct_member_type(record, "shift_struct", "m0", "large_type")[2]["error"] is True

    # 3. del_udm fails in while loop (line 2022)
    def mock_get_udt_del_fail(udt):
        udt.extend([
            SimpleNamespace(name="m0", size=8, type=large_tinfo, offset=0),
            SimpleNamespace(name="m1", size=8, type=large_tinfo, offset=8),
        ])
        return True

    monkeypatch.setattr(record, "get_udt_details", mock_get_udt_del_fail)
    monkeypatch.setattr(record, "del_udm", lambda *args: 1)
    assert types_module._set_struct_member_type(record, "shift_struct", "m0", "large_type")[2]["error"] is True

    # 4. Exception in outer try block (lines 2033-2034)
    def mock_get_udt_outer_boom(udt):
        raise RuntimeError("udt outer boom")

    monkeypatch.setattr(types_module, "_udt_member", lambda tif, mname: (0, 0))
    monkeypatch.setattr(record, "get_udt_details", mock_get_udt_outer_boom)
    assert types_module._set_struct_member_type(record, "shift_struct", "m0", "large_type")[2]["error"] is True


def test_types_import_fallbacks_reload(monkeypatch):
    orig_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "ida_struct":
            raise ImportError("no ida_struct")
        if name.endswith("utils") or "utils" in name:
            raise RuntimeError("no utils")
        return orig_import(name, *args, **kwargs)

    sys.modules[types_module.__name__] = types_module
    monkeypatch.setattr(builtins, "__import__", fake_import)
    importlib.reload(types_module)
    assert types_module.ida_struct is None
    monkeypatch.undo()
    sys.modules[types_module.__name__] = types_module
    importlib.reload(types_module)
