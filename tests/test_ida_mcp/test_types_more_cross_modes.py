"""Cross-mode type lifecycle and SDK compatibility coverage."""

from __future__ import annotations

import importlib

from tests.fakes.ida_fake import (
    BT_ENUM,
    BT_INT8,
    BT_UNION,
    FakeTinfo,
    edm_t,
    udm_t,
)

types_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")
types = types_mod.types


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_union_visualization_and_type_enumeration_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    union = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="packet_u",
        kind=BT_UNION,
        members=[udm_t("header", FakeTinfo(kind=1, size=4), offset=0, size=4)],
    )
    fresh_fake_idb.type_lib.register(union)
    detail = _ok(types(action="get", name="packet_u"))
    assert detail["kind"] == "union"
    view = _ok(types(action="visualize", name="packet_u"))
    assert view["kind"] == "union"
    assert "UNION packet_u" in view["visual"]

    monkeypatch.delattr(ida_typeinf, "get_ordinal_qty", raising=False)
    monkeypatch.delattr(ida_typeinf, "get_ordinal_count", raising=False)
    missing_list_api = types(action="list")
    missing_search_api = types(action="search_structs", query="header")
    assert missing_list_api["error"] is True
    assert missing_search_api["error"] is True


def test_type_inspection_and_prototype_failure_modes(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    enum = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="broken_enum",
        kind=BT_ENUM,
        members=[edm_t("ONE", 1)],
    )
    fresh_fake_idb.type_lib.register(enum)
    monkeypatch.setattr(FakeTinfo, "get_enum_details", lambda _self, _out: False)
    assert types(action="get", name="broken_enum")["kind"] == "enum"
    assert types(action="enum_values", name="broken_enum")["error"] is True

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: False)
    assert types(action="parse_decl", decl="int value")["error"] is True
    assert types(action="set_prototype", addr="0x140001000", decl="int f(void)")["error"] is True

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: True)
    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: False)
    failed_apply = types(action="set_prototype", addr="0x140001000", decl="int f(void)")
    assert failed_apply["error"] is True
    assert "apply prototype" in failed_apply["message"]


def test_declare_parse_retry_and_save_verification_fallback(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    original_parse = ida_typeinf.parse_decl
    calls = []

    def retry_parse(tif, til, decl, flags=0):
        calls.append(decl)
        if len(calls) == 1:
            return None
        return original_parse(tif, til, decl, flags)

    monkeypatch.setattr(ida_typeinf, "parse_decl", retry_parse)
    declared = _ok(types(action="declare", decl="struct retry_t { int x; }"))
    assert declared["name"] == "retry_t"
    assert calls[-1].endswith(";")

    monkeypatch.setattr(
        ida_typeinf,
        "set_numbered_type",
        lambda *_args: (_ for _ in ()).throw(TypeError("serialized type required")),
    )
    monkeypatch.setattr(
        ida_typeinf,
        "get_named_type",
        lambda _til, name, _flags=0: fresh_fake_idb.type_lib.get(name),
        raising=False,
    )
    saved = _ok(types(action="declare", decl="struct fallback_t { int y; };"))
    assert saved["name"] == "fallback_t"

    monkeypatch.setattr(
        FakeTinfo,
        "set_named_type",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("cannot save")),
    )
    failed = types(action="declare", decl="struct unsaved_t { int z; };", name="unsaved_t")
    assert failed["error"] is True
    assert "cannot save" in failed["message"]


def test_member_edit_and_enum_edit_public_lifecycle(fresh_fake_idb):
    import ida_typeinf

    struct = FakeTinfo(lib=fresh_fake_idb.type_lib, name="editable_u", kind=BT_UNION)
    struct.members.append(udm_t("old", FakeTinfo(kind=1, size=4), offset=0, size=4))
    enum = FakeTinfo(lib=fresh_fake_idb.type_lib, name="editable_e", kind=BT_ENUM, members=[edm_t("ONE", 1)])
    fresh_fake_idb.type_lib.register(FakeTinfo(lib=fresh_fake_idb.type_lib, name="int8_t", kind=BT_INT8, size=1))
    fresh_fake_idb.type_lib.register(struct)
    fresh_fake_idb.type_lib.register(enum)

    added = _ok(types(action="struct_member_add", struct_name="editable_u", member_name="tail", size=2, offset=-1))
    assert added["size"] == 2
    renamed = _ok(types(action="struct_member_rename", struct_name="editable_u", member_name="old", new_name="head"))
    assert renamed["new_name"] == "head"
    typed = _ok(types(action="struct_member_set_type", struct_name="editable_u", member_name="head", type_str="int"))
    assert typed["size"] == 4
    deleted = _ok(types(action="struct_member_del", struct_name="editable_u", member_name="tail"))
    assert deleted["offset"] >= 0

    assert _ok(types(action="enum_member_add", enum_name="editable_e", member_name="TWO", enum_value=2))["value"] == 2
    assert _ok(types(action="enum_member_rename", enum_name="editable_e", member_name="TWO", new_name="SECOND"))["new_name"] == "SECOND"
    assert _ok(types(action="enum_member_revalue", enum_name="editable_e", member_name="SECOND", enum_value=4))["value"] == 4
    assert _ok(types(action="til_delete", name="editable_e"))["deleted"] is True
    assert ida_typeinf.get_idati().get("editable_e") is None


def test_til_export_import_and_foreign_header_error_modes(monkeypatch, tmp_path, fresh_fake_idb):
    import idc

    record = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="carry_t",
        kind=BT_UNION,
        members=[udm_t("value", FakeTinfo(kind=1, size=4), offset=0, size=4)],
    )
    fresh_fake_idb.type_lib.register(record)
    out = tmp_path / "carry.h"
    exported = _ok(types(action="til_export", path=str(out), til_filter="carry"))
    assert exported["exported_count"] == 1
    assert "carry_t" in out.read_text()

    imported = _ok(types(action="til_import", path=str(out)))
    assert imported["errors"] == 0

    foreign = tmp_path / "foreign.h"
    foreign.write_text("struct foreign_t { int value; };\n")
    assert _ok(types(action="til_import", path=str(foreign)))["errors"] == 0
    foreign.write_text("broken ???\n")
    monkeypatch.setattr(idc, "parse_decls", lambda *_args: 3)
    failed = types(action="til_import", path=str(foreign))
    assert failed["error"] is True
