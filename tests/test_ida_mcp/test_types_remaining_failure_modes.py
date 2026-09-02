"""Cover type-library helper failures and compatibility fallbacks."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

from tests.fakes.ida_fake import (
    BT_ENUM,
    BT_INT32,
    BT_STRUCT,
    FakeTinfo,
    edm_t,
    udm_t,
)

types_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def test_type_resolution_and_member_lookup_failures(monkeypatch):
    tif = SimpleNamespace(
        get_named_type=lambda *_args: False,
        get_type_by_tid=lambda _tid: False,
    )
    monkeypatch.setattr(types_mod.ida_typeinf, "get_named_type_tid", lambda _name: 3)
    assert types_mod._resolve_type_by_name("missing", tif) is False

    no_struct, error = types_mod._struct_tif("missing")
    assert no_struct is None and error["error"] is True
    no_enum, error = types_mod._enum_tif("missing")
    assert no_enum is None and error["error"] is True

    member = SimpleNamespace(name="field", offset=8, type=SimpleNamespace(get_size=lambda: 4))
    detail = SimpleNamespace(size=lambda: 1, __getitem__=lambda _self, _idx: member)
    broken = SimpleNamespace(get_udt_details=lambda _out: False)
    assert types_mod._udt_member(broken, "field") is None
    assert types_mod._enum_member_index(SimpleNamespace(get_enum_details=lambda _out: False), "ONE") is None

    assert types_mod._struct_sptr("missing") is None
    assert types_mod._has_classic_struct_api() in (True, False)
    assert detail is not None


def test_struct_member_helpers_report_missing_apis_and_return_codes(monkeypatch):
    member_type = SimpleNamespace(get_size=lambda: 4)

    class Tif:
        def __init__(self):
            self.members = [SimpleNamespace(name="field", offset=16, size=32, type=member_type)]

        def get_size(self):
            return 8

        def get_udt_details(self, out):
            out.extend(self.members)
            return True

    monkeypatch.setattr(types_mod, "_has_classic_struct_api", lambda: False)
    monkeypatch.setattr(types_mod, "_parse_member_type", lambda *_args: (member_type, None))

    no_add = Tif()
    assert types_mod._add_struct_member(no_add, "s", "new", 0, "int", None)[1]["error"] is True
    no_del = Tif()
    assert types_mod._del_struct_member(no_del, "s", "field")[1]["error"] is True
    no_rename = Tif()
    assert types_mod._rename_struct_member(no_rename, "s", "field", "new")[1]["error"] is True
    no_set = Tif()
    assert types_mod._set_struct_member_type(no_set, "s", "field", "int")[2]["error"] is True

    class Editable(Tif):
        def add_udm(self, *_args):
            raise RuntimeError("add failed")

        def del_udm(self, _idx):
            return -1

        def rename_udm(self, _idx, _name):
            return -1

        def set_udm_type(self, _idx, _type):
            return -1

    editable = Editable()
    assert types_mod._add_struct_member(editable, "s", "new", 0, "int", None)[1]["error"] is True
    assert types_mod._del_struct_member(editable, "s", "field")[1]["error"] is True
    assert types_mod._rename_struct_member(editable, "s", "field", "new")[1]["error"] is True
    assert types_mod._set_struct_member_type(editable, "s", "field", "int")[2]["error"] is True


def test_struct_member_resize_fallback_reports_each_recovery_failure(monkeypatch):
    old_type = SimpleNamespace(get_size=lambda: 4)
    new_type = SimpleNamespace(get_size=lambda: 8)

    class Tif:
        def __init__(self, details=True, add_result=0, fail_tail=False):
            self.details = details
            self.members = [
                SimpleNamespace(name="field", offset=0, size=32, type=old_type),
                SimpleNamespace(name="tail", offset=32, size=32, type=old_type),
            ]
            self.add_result = add_result
            self.fail_tail = fail_tail

        def get_udt_details(self, out):
            if not self.details:
                return False
            out.extend(self.members)
            return True

        def set_udm_type(self, *_args):
            return -1

        def del_udm(self, index):
            self.members.pop(index)
            return 0

        def add_udm(self, name, _type, _offset):
            if self.fail_tail and name == "tail":
                raise RuntimeError("tail")
            if self.add_result:
                return self.add_result
            self.members.append(SimpleNamespace(name=name, offset=0, size=64, type=new_type))
            return 0

    monkeypatch.setattr(types_mod, "_has_classic_struct_api", lambda: False)
    monkeypatch.setattr(types_mod, "_parse_member_type", lambda *_args: (new_type, None))
    assert types_mod._set_struct_member_type(Tif(details=False), "s", "field", "long")[2]["error"] is True
    assert types_mod._set_struct_member_type(Tif(add_result=1), "s", "field", "long")[2]["error"] is True
    assert types_mod._set_struct_member_type(Tif(fail_tail=True), "s", "field", "long")[2]["error"] is True


def test_enum_helpers_cover_classic_and_tinfo_error_modes(monkeypatch):
    class Enum:
        def get_tid(self):
            return 4

        def get_enum_details(self, out):
            out.extend([SimpleNamespace(name="ONE")])
            return True

        def add_edm(self, *_args):
            raise RuntimeError("add")

        def rename_edm(self, *_args):
            return -1

        def del_edm(self, *_args):
            return -1

    enum = Enum()
    monkeypatch.delattr(types_mod.ida_typeinf, "add_enum_member", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_name", raising=False)
    monkeypatch.delattr(types_mod.ida_typeinf, "set_enum_member_value", raising=False)
    assert types_mod._add_enum_member(enum, "TWO", 2)["error"] is True
    assert types_mod._rename_enum_member(enum, "ONE", "FIRST")["error"] is True
    assert types_mod._revalue_enum_member(enum, "ONE", 2)["error"] is True

    class NoApi:
        def get_tid(self):
            return 1

    assert types_mod._add_enum_member(NoApi(), "TWO", 2)["error"] is True
    assert types_mod._rename_enum_member(NoApi(), "ONE", "FIRST")["error"] is True
    assert types_mod._revalue_enum_member(NoApi(), "ONE", 2)["error"] is True

    def classic_add(*_args):
        return -1

    def classic_rename(*_args):
        return -1

    def classic_revalue(*_args):
        return -1

    monkeypatch.setattr(types_mod.ida_typeinf, "add_enum_member", classic_add, raising=False)
    monkeypatch.setattr(types_mod.ida_typeinf, "set_enum_member_name", classic_rename, raising=False)
    monkeypatch.setattr(types_mod.ida_typeinf, "set_enum_member_value", classic_revalue, raising=False)
    assert types_mod._add_enum_member(enum, "TWO", 2)["error"] is True
    assert types_mod._rename_enum_member(enum, "ONE", "FIRST")["error"] is True
    assert types_mod._revalue_enum_member(enum, "ONE", 2)["error"] is True


def test_type_actions_cover_partial_read_and_graph_results(monkeypatch, fresh_fake_idb):
    record = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="outer_t",
        kind=BT_STRUCT,
        members=[udm_t("value", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4)],
    )
    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="flags_t",
        kind=BT_ENUM,
        members=[edm_t("A", 1), edm_t("B", 2)],
    )
    fresh_fake_idb.type_lib.register(record)
    fresh_fake_idb.type_lib.register(enum)
    types = types_mod.types

    assert types(action="enum_values", name="flags_t", value=4)["value_lookup"]["match_type"] == "no_match"
    assert types(action="type_graph", name="outer_t")["total_structs"] == 1
    monkeypatch.setattr(types_mod, "_resolve_type_by_name", lambda _name, _tif: False)
    assert types(action="visualize", name="outer_t")["error"] is True
    assert types(action="propagate", addr="bad", name="outer_t")["error"] is True
