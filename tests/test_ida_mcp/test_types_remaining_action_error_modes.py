"""Exercise public type-operation aliases, validation, and compatibility errors."""

from __future__ import annotations

import importlib

from tests.fakes.ida_fake import BT_ENUM, FakeTinfo, edm_t

types_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")
types = types_mod.types


def test_type_action_validation_and_public_aliases(monkeypatch, fresh_fake_idb):
    import ida_typeinf
    import idc

    assert types(action="import_header")["error"] is True
    monkeypatch.setattr(idc, "parse_decls", lambda *_args: 2)
    assert types(action="import_header", decl="struct broken {")["error"] is True
    monkeypatch.setattr(idc, "parse_decls", lambda *_args: 0)
    assert types(action="import_header", decl="struct valid;")["ok"] is True

    original_til = ida_typeinf.get_idati
    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: None)
    assert types(action="list")["error"] is True
    monkeypatch.setattr(ida_typeinf, "get_idati", original_til)
    monkeypatch.delattr(ida_typeinf, "get_ordinal_qty", raising=False)
    monkeypatch.delattr(ida_typeinf, "get_ordinal_count", raising=False)
    assert types(action="list")["error"] is True

    assert types(action="get")["error"] is True
    assert types(action="get", name="missing_type")["error"] is True
    assert types(action="parse_decl")["error"] is True
    assert types(action="set_prototype")["error"] is True
    assert types(action="set_prototype", addr="0x140001000")["error"] is True
    assert types(action="apply")["error"] is True
    assert types(action="apply", addr="0x140001000")["error"] is True
    assert types(action="does_not_exist")["error"] is True

    applied = types(
        action="apply",
        address="0x140003000",
        declaration="int",
        kind="global",
    )
    assert applied["ok"] is True and applied["addr"] == "0x140003000"
    assert types(action="apply", addr="0x140001000", decl="int", kind="bad")["error"] is True


def test_type_parse_and_apply_failure_paths(monkeypatch, fresh_fake_idb):
    import ida_hexrays
    import ida_typeinf

    original_parse = ida_typeinf.parse_decl
    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: False)
    assert types(action="parse_decl", decl="bad ???")["error"] is True
    assert types(action="set_prototype", addr="0x140001000", decl="int f(void)")["error"] is True
    assert types(action="apply", addr="0x140001000", decl="int")["error"] is True
    monkeypatch.setattr(ida_typeinf, "parse_decl", original_parse)

    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: False)
    assert types(action="set_prototype", addr="0x140001000", decl="int f(void)")["error"] is True
    assert types(action="apply", addr="0x140003000", decl="int", kind="global")["error"] is True
    assert types(action="apply", addr="0x140001000", decl="int", kind="function")["error"] is True

    assert types(action="apply", addr="0x140001000", decl="int", kind="local")["error"] is True
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: None)
    assert types(action="apply", addr="0x140001000", decl="int", kind="local", name="x")["error"] is True


def test_struct_and_enum_action_validation_and_resolution_errors(fresh_fake_idb):
    import ida_typeinf

    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="action_enum",
        kind=BT_ENUM,
        members=[edm_t("ZERO", 0)],
    )
    fresh_fake_idb.type_lib.register(enum)

    assert types(action="struct_member_add")["error"] is True
    assert types(action="struct_member_add", struct_name="target_struct")["error"] is True
    assert types(action="struct_member_add", struct_name="missing", member_name="x", size=4)["error"] is True
    assert types(action="struct_member_del")["error"] is True
    assert types(action="struct_member_del", struct_name="target_struct", member_name="missing")["error"] is True
    assert types(action="struct_member_rename", struct_name="target_struct", member_name="id")["error"] is True
    assert types(action="struct_member_set_type", struct_name="target_struct", member_name="id")["error"] is True

    assert types(action="enum_member_add")["error"] is True
    assert types(action="enum_member_add", enum_name="action_enum", member_name="TWO")["error"] is True
    assert types(action="enum_member_add", enum_name="missing", member_name="TWO", enum_value=2)["error"] is True
    assert types(action="enum_member_rename", enum_name="action_enum", member_name="ZERO")["error"] is True
    assert types(action="enum_member_revalue", enum_name="action_enum", member_name="ZERO")["error"] is True
    assert types(action="enum_values")["error"] is True
    assert types(action="enum_values", name="target_struct")["error"] is True
    assert types(action="enum_values", name="missing")["error"] is True

    assert ida_typeinf.get_idati() is fresh_fake_idb.type_lib


def test_infer_read_til_and_vtable_missing_input_paths(monkeypatch, tmp_path, fresh_fake_idb):
    import ida_typeinf

    assert types(action="infer")["error"] is True
    assert types(action="infer", addr="not-an-address")["error"] is True
    assert types(action="read_struct")["error"] is True
    assert types(action="read_struct", addr="0x140003000")["error"] is True
    assert types(action="read_struct", addr="0x99999999", name="target_struct")["error"] is True
    assert types(action="read_struct", addr="0x140003000", name="missing")["error"] is True

    assert types(action="vtable")["error"] is True
    assert types(action="vtable", name="NoSuchClass")["error"] is True
    assert types(action="til_delete")["error"] is True
    assert types(action="til_delete", name="missing")["error"] is True
    assert types(action="til_export")["error"] is True
    assert types(action="til_import")["error"] is True
    assert types(action="til_import", path=str(tmp_path / "missing.h"))["error"] is True

    empty = tmp_path / "empty.h"
    empty.write_text("\n", encoding="utf-8")
    assert types(action="til_import", path=str(empty))["error"] is True

    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: None)
    assert types(action="til_delete", name="x")["error"] is True
    assert types(action="til_export", path=str(tmp_path / "out.h"))["error"] is True
