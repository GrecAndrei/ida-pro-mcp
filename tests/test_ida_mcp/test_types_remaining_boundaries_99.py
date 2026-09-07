"""Boundary and compatibility coverage for the type tool."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from tests.fakes.ida_fake import (
    BT_ENUM,
    BT_INT8,
    BT_STRUCT,
    BT_TYPEDEF,
    FakeTinfo,
    edm_t,
    udm_t,
)

types_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_mapping_and_data_guards_fail_closed(monkeypatch):
    assert types_module._is_fully_mapped(0, -1) is False
    assert types_module._is_fully_mapped(0, 0) is True

    monkeypatch.setattr(types_module.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(types_module._compat, "get_segment", lambda _ea: SimpleNamespace(end_ea=0x20))
    assert types_module._is_fully_mapped(0x10, 0x10) is True
    assert types_module._is_fully_mapped(0x10, 0x11) is False
    monkeypatch.setattr(types_module.ida_bytes, "is_loaded", lambda _ea: (_ for _ in ()).throw(RuntimeError("sdk")))
    assert types_module._is_fully_mapped(0x10, 1) is False

    monkeypatch.setattr(types_module._compat, "get_func_start", lambda _ea: 0x10)
    assert types_module._is_data_location(0x10) is False
    monkeypatch.setattr(types_module._compat, "get_func_start", lambda _ea: None)
    monkeypatch.setattr(types_module.ida_bytes, "get_flags", lambda _ea: 0)
    assert types_module._is_data_location(0x20) is False
    monkeypatch.setattr(types_module.ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(types_module.ida_bytes, "is_data", lambda _flags: True)
    assert types_module._is_data_location(0x20) is True
    monkeypatch.setattr(types_module.ida_bytes, "get_flags", lambda _ea: (_ for _ in ()).throw(RuntimeError("flags")))
    assert types_module._is_data_location(0x20) is False


def test_type_import_and_apply_failure_boundaries(monkeypatch, fresh_fake_idb):
    import ida_hexrays
    import ida_typeinf

    assert types_module.types(action="import_header") ["error"] is True
    monkeypatch.setattr(types_module.idc, "parse_decls", lambda *_args: 0)
    assert _ok(types_module.types(action="import_header", decl="struct Header { int x; };"))["errors"] == 0
    monkeypatch.setattr(types_module.idc, "parse_decls", lambda *_args: 2)
    assert types_module.types(action="import_header", decl="broken") ["error"] is True

    assert types_module.types(action="apply", addr="0x140001000") ["error"] is True
    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: False)
    assert types_module.types(action="apply", addr="0x140001000", decl="int", kind="function")["error"] is True
    assert types_module.types(action="apply", addr="0x140003000", decl="int", kind="global")["error"] is True

    cfunc = SimpleNamespace(lvars=[SimpleNamespace(name=f"local_{i}") for i in range(12)])
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: cfunc)
    monkeypatch.setattr(ida_hexrays, "modify_user_lvars", lambda *_args: False, raising=False)
    missing = types_module.types(action="apply", addr="0x140001004", decl="int", kind="local", name="missing")
    assert missing["error"] is True and "Available locals" in missing["message"]
    failed = types_module.types(action="apply", addr="0x140001004", decl="int", kind="local", name="local_1")
    assert failed["error"] is True
    monkeypatch.setattr(ida_hexrays, "modify_user_lvars", lambda *_args: (_ for _ in ()).throw(RuntimeError("modifier")), raising=False)
    assert types_module.types(action="apply", addr="0x140001004", decl="int", kind="local", name="local_1")["error"] is True


def test_type_infer_and_read_struct_reject_bad_runtime_states(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import ida_typeinf
    import idc

    monkeypatch.setattr(types_module, "parse_address", lambda _addr: types_module.idaapi.BADADDR)
    assert types_module.types(action="infer", addr="not-an-address")["error"] is True
    monkeypatch.setattr(types_module, "parse_address", lambda _addr: 0x140001000)
    monkeypatch.setattr(idc, "get_frame_id", lambda _ea: (_ for _ in ()).throw(RuntimeError("frame")), raising=False)
    monkeypatch.setattr(types_module._compat, "get_func_info", lambda _ea: (_ for _ in ()).throw(RuntimeError("func")))
    assert _ok(types_module.types(action="infer", addr="0x140001000"))["inferred_types"] == []
    monkeypatch.setattr(idc, "get_frame_id", lambda _ea: types_module.idaapi.BADADDR)
    monkeypatch.setattr(types_module._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda *_args: (_ for _ in ()).throw(RuntimeError("tinfo")))
    assert _ok(types_module.types(action="infer", addr="0x140001000"))["confidence"] == 0.0

    assert types_module.types(action="read_struct", addr="0x140003000", name="int8_t")["error"] is True
    record = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="bad_read",
        kind=BT_STRUCT,
        members=[udm_t("x", FakeTinfo(kind=BT_INT8, size=1), offset=0, size=1)],
    )
    fresh_fake_idb.type_lib.register(record)
    monkeypatch.setattr(FakeTinfo, "get_size", lambda self: -1 if self.name == "bad_read" else 1)
    assert types_module.types(action="read_struct", addr="0x140003000", name="bad_read")["error"] is True
    monkeypatch.setattr(FakeTinfo, "get_size", lambda self: 1)
    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda *_args: False)
    assert types_module.types(action="read_struct", addr="0x140003000", name="bad_read")["error"] is True
    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda self, udt: (udt.extend(self.members) or True))
    monkeypatch.setattr(types_module.ida_bytes, "get_byte", lambda _ea: (_ for _ in ()).throw(RuntimeError("read")))
    read_error = types_module.types(action="read_struct", addr="0x140003000", name="bad_read")
    assert _ok(read_error)["fields"][0]["value"] == "?(read error)"


def test_type_compare_enum_lookup_and_graph_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    original_udt_details = FakeTinfo.get_udt_details
    original_enum_details = FakeTinfo.get_enum_details

    left = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="left_struct",
        kind=BT_STRUCT,
        members=[udm_t("same", FakeTinfo(kind=BT_INT8, size=1), offset=0, size=1)],
    )
    right = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="right_struct",
        kind=BT_STRUCT,
        members=[udm_t("same", FakeTinfo(kind=BT_INT8, size=1), offset=4, size=1)],
    )
    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="flags_e",
        kind=BT_ENUM,
        members=[edm_t("READ", 1), edm_t("WRITE", 2), edm_t("NEG", -1)],
    )
    for tif in (left, right, enum):
        fresh_fake_idb.type_lib.register(tif)
    changed = _ok(types_module.types(action="diff", name="left_struct", other_name="right_struct"))
    assert changed["summary"]["changed_fields"] == 1
    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda *_args: False)
    assert types_module.types(action="diff", name="left_struct", other_name="right_struct")["error"]
    monkeypatch.setattr(FakeTinfo, "get_udt_details", original_udt_details)

    exact = _ok(types_module.types(action="enum_values", name="flags_e", value=1))
    assert exact["value_lookup"]["match_type"] == "exact"
    assert _ok(types_module.types(action="enum_values", name="flags_e", value=3))["value_lookup"]["match_type"] == "bitmask"
    assert _ok(types_module.types(action="enum_values", name="flags_e", value=8))["value_lookup"]["match_type"] == "no_match"
    monkeypatch.setattr(FakeTinfo, "get_enum_details", lambda *_args: False)
    assert types_module.types(action="enum_values", name="flags_e")["error"] is True
    monkeypatch.setattr(FakeTinfo, "get_enum_details", original_enum_details)

    root = FakeTinfo(lib=fresh_fake_idb.type_lib, name="empty_root", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(root)
    assert "no dependent" in _ok(types_module.types(action="type_graph", name="empty_root", max_depth=-1))["visual"]
    monkeypatch.setattr(FakeTinfo, "get_udt_details", lambda *_args: False)
    graph = _ok(types_module.types(action="type_graph", name="empty_root"))
    assert graph["nodes"] and graph["edges"] == []
    monkeypatch.setattr(FakeTinfo, "get_udt_details", original_udt_details)


def test_type_member_helpers_cover_classic_and_unavailable_apis(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    record = fresh_fake_idb.type_lib.get("target_struct")
    assert record is not None
    original_add_udm = FakeTinfo.add_udm
    monkeypatch.setattr(types_module, "_has_classic_struct_api", lambda: False)
    monkeypatch.delattr(FakeTinfo, "add_udm", raising=False)
    assert types_module._add_struct_member(record, "target_struct", "no_api", -1, "int", None)[1]["error"]
    monkeypatch.setattr(FakeTinfo, "add_udm", lambda *_args: (_ for _ in ()).throw(RuntimeError("add")), raising=False)
    assert types_module._add_struct_member(record, "target_struct", "boom", -1, "int", None)[1]["error"]
    monkeypatch.setattr(FakeTinfo, "add_udm", original_add_udm, raising=False)

    monkeypatch.setattr(types_module, "_struct_sptr", lambda _name: None)
    monkeypatch.setattr(types_module, "_has_classic_struct_api", lambda: True)
    assert types_module._add_struct_member(record, "target_struct", "classic", -1, "int", None)[1]["error"]
    monkeypatch.setattr(types_module, "_has_classic_struct_api", lambda: False)
    monkeypatch.delattr(FakeTinfo, "del_udm", raising=False)
    assert types_module._del_struct_member(record, "target_struct", "id")[1]["error"]
    monkeypatch.delattr(FakeTinfo, "rename_udm", raising=False)
    assert types_module._rename_struct_member(record, "target_struct", "id", "renamed")[1]["error"]
    monkeypatch.delattr(FakeTinfo, "set_udm_type", raising=False)
    assert types_module._set_struct_member_type(record, "target_struct", "id", "int")[2]["error"]

    enum = fresh_fake_idb.type_lib.get("mode_e")
    if enum is None:
        enum = FakeTinfo(lib=fresh_fake_idb.type_lib, name="mode_e", kind=BT_ENUM, members=[edm_t("A", 1)])
        fresh_fake_idb.type_lib.register(enum)
    monkeypatch.delattr(ida_typeinf, "add_enum_member", raising=False)
    monkeypatch.delattr(FakeTinfo, "add_edm", raising=False)
    assert types_module._add_enum_member(enum, "B", 2)["error"]
    monkeypatch.delattr(FakeTinfo, "rename_edm", raising=False)
    assert types_module._rename_enum_member(enum, "A", "AA")["error"]
    monkeypatch.delattr(FakeTinfo, "del_edm", raising=False)
    assert types_module._revalue_enum_member(enum, "A", 2)["error"]


@pytest.mark.parametrize("code", [-99, -1, 0, 1, 99])
def test_struct_error_text_is_total(code):
    assert types_module._struc_error_text(code)
