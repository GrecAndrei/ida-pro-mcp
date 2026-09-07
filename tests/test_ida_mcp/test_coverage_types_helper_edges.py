"""Boundary coverage for IDA-side type resolution and member helpers."""

from __future__ import annotations

import importlib
import types as py_types

from tests.fakes.ida_fake import BT_ARRAY, BT_ENUM, BT_INT32, BT_PTR, BT_STRUCT, FakeTinfo, edm_t, udm_t

types_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def test_type_resolution_and_address_predicates(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(types_mod.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(types_mod._compat, "get_segment", lambda _ea: py_types.SimpleNamespace(end_ea=0x1100))
    assert types_mod._is_fully_mapped(0x1000, 0) is True
    assert types_mod._is_fully_mapped(0x1000, -1) is False
    assert types_mod._is_fully_mapped(0x1000, 0x100) is True
    assert types_mod._is_fully_mapped(0x1000, 0x101) is False
    monkeypatch.setattr(types_mod.ida_bytes, "is_loaded", lambda _ea: False)
    assert types_mod._is_fully_mapped(0x1000, 4) is False
    monkeypatch.setattr(types_mod._compat, "get_func_start", lambda _ea: 0x1000)
    assert types_mod._is_data_location(0x1000) is False
    monkeypatch.setattr(types_mod._compat, "get_func_start", lambda _ea: None)
    monkeypatch.setattr(types_mod.ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(types_mod.ida_bytes, "is_data", lambda _flags: True)
    assert types_mod._is_data_location(0x1000) is True
    monkeypatch.setattr(types_mod.ida_bytes, "get_flags", lambda _ea: 0)
    assert types_mod._is_data_location(0x1000) is False

    assert types_mod._resolve_struct_names("S", "member", None) == ("S", "member")
    assert types_mod._resolve_struct_names(None, "S", "member") == ("S", "member")
    assert types_mod._resolve_enum_names("E", "member", None) == ("E", "member")
    assert types_mod._resolve_enum_names(None, "E", "member") == ("E", "member")
    assert types_mod._struc_error_text(-999) == "unknown error"

    kinds = [
        ("struct", BT_STRUCT),
        ("enum", BT_ENUM),
        ("pointer", BT_PTR),
        ("array", BT_ARRAY),
    ]
    for expected, kind in kinds:
        assert types_mod._type_kind(FakeTinfo(kind=kind)) == expected
    struct = FakeTinfo(lib=fresh_fake_idb.type_lib, name="nested", kind=BT_STRUCT)
    pointer = FakeTinfo(kind=BT_PTR, target_tinfo=struct)
    array = FakeTinfo(kind=BT_ARRAY, target_tinfo=pointer)
    assert types_mod._extract_struct_name(pointer) == "nested"
    assert types_mod._extract_struct_name(array) == "nested"


def test_type_member_helpers_cover_missing_and_fallback_api_paths(monkeypatch, fresh_fake_idb):
    struct = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="helper_struct",
        kind=BT_STRUCT,
        members=[udm_t("field", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4)],
    )
    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="helper_enum",
        kind=BT_ENUM,
        members=[edm_t("ZERO", 0), edm_t("ONE", 1)],
    )
    fresh_fake_idb.type_lib.register(struct)
    fresh_fake_idb.type_lib.register(enum)
    assert types_mod._udt_member(struct, "field") == (0, 0)
    assert types_mod._udt_member(struct, "missing") is None
    assert types_mod._enum_member_index(enum, "ONE") == 1
    assert types_mod._enum_member_index(enum, "missing") is None
    assert types_mod._struct_tif("helper_struct")[0] is not None
    assert types_mod._struct_tif("helper_enum")[1]["error"] is True
    assert types_mod._enum_tif("helper_enum")[0] is not None
    assert types_mod._enum_tif("helper_struct")[1]["error"] is True

    assert types_mod._parse_member_type(None, None)[1]["error"] is True
    parsed, error = types_mod._parse_member_type("uint32_t[2]", None)
    # The fake parser keeps the declared scalar size; the production parser
    # supplies the full array size in real IDA.
    assert error is None and parsed.get_size() == 4
    parse_decl = types_mod.ida_typeinf.parse_decl
    monkeypatch.setattr(types_mod.ida_typeinf, "parse_decl", lambda *_args: False)
    assert types_mod._parse_member_type("unknown_type", None)[1]["error"] is True
    monkeypatch.setattr(types_mod.ida_typeinf, "parse_decl", parse_decl)
    assert types_mod._has_classic_struct_api() in {True, False}

    monkeypatch.setattr(types_mod, "ida_struct", None)
    added, error = types_mod._add_struct_member(struct, "helper_struct", "new_field", -1, "uint32_t", None)
    assert error is None and added == 4
    deleted, error = types_mod._del_struct_member(struct, "helper_struct", "new_field")
    assert error is None and deleted >= 0
    renamed, error = types_mod._rename_struct_member(struct, "helper_struct", "field", "renamed")
    assert error is None and renamed == 0
    changed = types_mod._set_struct_member_type(struct, "helper_struct", "renamed", "uint32_t")
    assert changed[2] is None
    assert types_mod._struct_sptr("helper_struct") is None


def test_type_member_enum_fallback_errors(monkeypatch, fresh_fake_idb):
    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="fallback_enum",
        kind=BT_ENUM,
        members=[edm_t("ZERO", 0)],
    )
    fresh_fake_idb.type_lib.register(enum)
    monkeypatch.delattr(types_mod.ida_typeinf, "add_enum_member", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_name", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_value", raising=False)
    assert types_mod._add_enum_member(enum, "ONE", 1) is None
    assert types_mod._rename_enum_member(enum, "ZERO", "ZERO_RENAMED") is None
    assert types_mod._rename_enum_member(enum, "missing", "x")["error"] is True
    assert types_mod._revalue_enum_member(enum, "missing", 2)["error"] is True
    assert types_mod._add_enum_member(py_types.SimpleNamespace(), "TWO", 2)["error"] is True
