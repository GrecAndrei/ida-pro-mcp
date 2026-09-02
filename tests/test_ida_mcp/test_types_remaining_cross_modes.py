"""Remaining type-helper compatibility and failure-mode coverage."""

from __future__ import annotations

import importlib
import types as py_types

import pytest

from tests.fakes.ida_fake import (
    BADADDR,
    BT_ARRAY,
    BT_ENUM,
    BT_FUNC,
    BT_INT32,
    BT_PTR,
    BT_STRUCT,
    BT_TYPEDEF,
    FakeTinfo,
    edm_t,
    udm_t,
)

types_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def test_mapping_and_data_helpers_cover_boundaries_and_sdk_failures(monkeypatch):
    segment = py_types.SimpleNamespace(end_ea=0x1010)
    monkeypatch.setattr(types_mod._compat, "get_segment", lambda _ea: segment)
    monkeypatch.setattr(types_mod.ida_bytes, "is_loaded", lambda ea: ea in {0x1000, 0x100F})
    assert types_mod._is_fully_mapped(0x1000, 0x10) is True
    assert types_mod._is_fully_mapped(0x1000, 0x11) is False
    assert types_mod._is_fully_mapped(0x1000, -1) is False
    assert types_mod._is_fully_mapped(0x1000, 0) is True
    monkeypatch.setattr(types_mod._compat, "get_segment", lambda _ea: None)
    assert types_mod._is_fully_mapped(0x1000, 1) is False
    monkeypatch.setattr(types_mod.ida_bytes, "is_loaded", lambda _ea: (_ for _ in ()).throw(RuntimeError("memory")))
    assert types_mod._is_fully_mapped(0x1000, 1) is False

    monkeypatch.setattr(types_mod._compat, "get_func_start", lambda ea: ea if ea == 0x1000 else None)
    monkeypatch.setattr(types_mod.ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(types_mod.ida_bytes, "is_data", lambda flags: flags == 1)
    assert types_mod._is_data_location(0x1000) is False
    assert types_mod._is_data_location(0x1001) is True
    monkeypatch.setattr(types_mod.ida_bytes, "get_flags", lambda _ea: 0)
    assert types_mod._is_data_location(0x1001) is False
    monkeypatch.setattr(types_mod.ida_bytes, "get_flags", lambda _ea: (_ for _ in ()).throw(RuntimeError("flags")))
    assert types_mod._is_data_location(0x1001) is False


def test_type_kind_resolution_and_nested_unwrap_modes(monkeypatch, fresh_fake_idb):
    target = FakeTinfo(lib=fresh_fake_idb.type_lib, name="record_t", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(target)
    for kind, label in (
        (BT_STRUCT, "struct"), (BT_ENUM, "enum"), (BT_FUNC, "function"),
        (BT_TYPEDEF, "typedef"), (BT_PTR, "pointer"), (BT_ARRAY, "array"),
        (BT_INT32, "other"),
    ):
        assert types_mod._type_kind(FakeTinfo(kind=kind)) == label

    pointer = FakeTinfo(kind=BT_PTR, target_tinfo=target, size=8)
    array = FakeTinfo(kind=BT_ARRAY, target_tinfo=pointer, size=16)
    assert types_mod._extract_struct_name(array) == "record_t"
    assert types_mod._extract_struct_name(FakeTinfo(kind=BT_INT32)) is None
    broken = FakeTinfo(kind=BT_PTR)
    monkeypatch.setattr(broken, "get_pointed_object", lambda: None)
    assert types_mod._extract_struct_name(broken) is None

    direct = FakeTinfo()
    monkeypatch.setattr(direct, "get_named_type", lambda *_args: True)
    assert types_mod._resolve_type_by_name("record_t", direct) is True
    fallback = FakeTinfo()
    monkeypatch.setattr(fallback, "get_named_type", lambda *_args: False)
    monkeypatch.setattr(types_mod.ida_typeinf, "get_named_type_tid", lambda _name: target.get_tid())
    assert types_mod._resolve_type_by_name("record_t", fallback) is True
    monkeypatch.setattr(types_mod.ida_typeinf, "get_named_type_tid", lambda _name: BADADDR)
    assert types_mod._resolve_type_by_name("missing", fallback) is False


def test_member_lookup_and_parse_helpers_cover_invalid_and_legacy_shapes(monkeypatch, fresh_fake_idb):
    member_type = FakeTinfo(kind=BT_INT32, size=4)
    record = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="members_t",
        kind=BT_STRUCT,
        members=[udm_t("first", member_type, offset=8, size=4)],
    )
    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="values_e",
        kind=BT_ENUM,
        members=[edm_t("ZERO", 0)],
    )
    fresh_fake_idb.type_lib.register(record)
    fresh_fake_idb.type_lib.register(enum)
    assert types_mod._udt_member(record, "first") == (0, 8)
    assert types_mod._udt_member(record, "missing") is None
    assert types_mod._enum_member_index(enum, "ZERO") == 0
    assert types_mod._enum_member_index(enum, "missing") is None
    monkeypatch.setattr(record, "get_udt_details", lambda _out: False)
    assert types_mod._udt_member(record, "first") is None

    assert types_mod._resolve_struct_names(None, "members_t", None) == ("members_t", None)
    assert types_mod._resolve_struct_names("members_t", "first", None) == ("members_t", "first")
    assert types_mod._resolve_enum_names("values_e", "ZERO", None) == ("values_e", "ZERO")
    assert types_mod._struc_error_text(-2).startswith("invalid member offset")
    assert types_mod._struc_error_text(99) == "unknown error"

    _, missing_error = types_mod._parse_member_type(None, None)
    assert missing_error["error"] is True
    member, error = types_mod._parse_member_type("char[4]", None)
    assert error is None and member.get_size() == 4
    monkeypatch.setattr(types_mod.ida_typeinf, "parse_decl", lambda *_args: False)
    _, error = types_mod._parse_member_type("not_a_type", None)
    assert error["error"] is True
    _, error = types_mod._parse_member_type("int value", None)
    assert error["error"] is True


def test_struct_member_tinfo_fallback_reports_each_sdk_failure(monkeypatch):
    class _MemberType:
        def get_size(self):
            return 4

    member_type = _MemberType()

    class _Tif:
        def __init__(self):
            self.members = [py_types.SimpleNamespace(name="field", offset=16, size=32, type=member_type)]
            self.calls = []
        def get_size(self):
            return 8
        def get_udt_details(self, out):
            out.extend(self.members)
            return True
        def add_udm(self, *args):
            self.calls.append(("add", args))
            return 0
        def del_udm(self, index):
            self.calls.append(("del", index))
            return 0
        def rename_udm(self, index, name):
            self.calls.append(("rename", index, name))
            return 0
        def set_udm_type(self, index, new_type):
            self.calls.append(("set", index, new_type))
            return 0

    tif = _Tif()
    monkeypatch.setattr(types_mod, "_parse_member_type", lambda *_args: (member_type, None))
    monkeypatch.setattr(types_mod, "_has_classic_struct_api", lambda: False)
    assert types_mod._add_struct_member(tif, "record", "new", -1, "int", None) == (4, None)
    assert types_mod._del_struct_member(tif, "record", "field")[0] == 2
    assert types_mod._rename_struct_member(tif, "record", "field", "renamed")[0] == 2
    assert types_mod._set_struct_member_type(tif, "record", "field", "int")[0:2] == (2, 4)
    assert [call[0] for call in tif.calls] == ["add", "del", "rename", "set"]

    monkeypatch.setattr(tif, "add_udm", lambda *_args: (_ for _ in ()).throw(RuntimeError("add")))
    assert types_mod._add_struct_member(tif, "record", "new", 0, "int", None)[1]["error"] is True
    monkeypatch.setattr(tif, "del_udm", lambda *_args: -1)
    assert types_mod._del_struct_member(tif, "record", "field")[1]["error"] is True
    monkeypatch.setattr(tif, "rename_udm", lambda *_args: -1)
    assert types_mod._rename_struct_member(tif, "record", "field", "x")[1]["error"] is True
    monkeypatch.setattr(tif, "set_udm_type", lambda *_args: -1)
    assert types_mod._set_struct_member_type(tif, "record", "field", "int")[2]["error"] is True


def test_enum_member_fallback_and_classic_struct_resolution(monkeypatch):
    class _Enum:
        def __init__(self):
            self.members = [py_types.SimpleNamespace(name="ONE")]
        def get_enum_details(self, out):
            out.extend(self.members)
            return True
        def add_edm(self, *args):
            return None
        def rename_edm(self, *_args):
            return 0
        def del_edm(self, *_args):
            return 0

    enum = _Enum()
    monkeypatch.delattr(types_mod.ida_typeinf, "add_enum_member", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_name", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_value", raising=False)
    assert types_mod._add_enum_member(enum, "TWO", 2) is None
    assert types_mod._rename_enum_member(enum, "ONE", "FIRST") is None
    assert types_mod._revalue_enum_member(enum, "ONE", 2) is None

    monkeypatch.setattr(types_mod, "ida_struct", None)
    assert types_mod._struct_sptr("missing") is None
    classic = py_types.SimpleNamespace(
        get_struc_id=lambda _name: 7,
        get_struc=lambda sid: ("struct", sid),
    )
    monkeypatch.setattr(types_mod, "ida_struct", classic)
    monkeypatch.setattr(types_mod.idc, "get_struc_id", lambda _name: 0, raising=False)
    assert types_mod._struct_sptr("record") == ("struct", 7)

    monkeypatch.setattr(types_mod, "ida_struct", py_types.SimpleNamespace())
    assert types_mod._has_classic_struct_api() is False
