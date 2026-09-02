"""Deep, stateful coverage for type application and type-library carry paths."""

from __future__ import annotations

import importlib

import pytest

from tests.fakes.ida_fake import BT_ENUM, BT_FUNC, BT_INT64, BT_STRUCT, BT_TYPEDEF, FakeTinfo, edm_t

types_tool = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")


def ok(result):
    assert result.get("ok") is True, result
    return result


def test_function_typedef_and_declaration_failure_shapes(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    fn_type = FakeTinfo(lib=fresh_fake_idb.type_lib, name="callback_t", kind=BT_FUNC, decl="int callback_t(int)")
    typedef = FakeTinfo(lib=fresh_fake_idb.type_lib, name="callback_alias", kind=BT_TYPEDEF, decl="typedef callback_t callback_alias;")
    fresh_fake_idb.type_lib.register(fn_type)
    fresh_fake_idb.type_lib.register(typedef)
    assert ok(types_tool.types(action="get", name="callback_t"))["kind"] == "function"
    assert ok(types_tool.types(action="get", name="callback_alias"))["kind"] == "typedef"

    original_parse = ida_typeinf.parse_decl
    calls = []

    def parse_with_retry(tif, til, decl, flags=0):
        calls.append(decl)
        if len(calls) == 1:
            return None
        return original_parse(tif, til, decl, flags)

    monkeypatch.setattr(ida_typeinf, "parse_decl", parse_with_retry)
    retried = types_tool.types(action="declare", decl="struct retry_type { int x; }")
    assert retried["ok"] is True
    assert calls[-1].endswith(";")

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: True)
    unnamed = types_tool.types(action="declare", decl="int", name=None)
    assert unnamed["error"] is True
    assert "determine type name" in unnamed["message"]


def test_prototype_and_apply_paths_report_parse_and_backend_failures(monkeypatch, fresh_fake_idb):
    import ida_hexrays
    import ida_typeinf

    prototype = ok(types_tool.types(action="set_prototype", addr="0x140001000", decl="int f(int x);"))
    assert prototype["addr"] == "0x140001000"

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: None)
    assert types_tool.types(action="set_prototype", addr="0x140001000", decl="broken")["error"] is True
    assert types_tool.types(action="parse_decl", decl="broken")["error"] is True

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda tif, *_args: setattr(tif, "kind", BT_FUNC) or True)
    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: False)
    failed_proto = types_tool.types(action="set_prototype", addr="0x140001000", decl="int f();")
    assert failed_proto["error"] is True
    failed_global = types_tool.types(action="apply", addr="0x140003000", decl="int", kind="global")
    assert failed_global["error"] is True

    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: True)
    assert ok(types_tool.types(action="apply", addr="0x140003000", decl="int", kind="global"))["kind"] == "global"
    assert types_tool.types(action="apply", addr="0x140001000", decl="int", kind="local", name="missing")["error"] is True
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: None)
    assert types_tool.types(action="apply", addr="0x140001000", decl="int", kind="local", name="a1")["error"] is True


def test_struct_and_enum_member_lifecycle_is_persistent(fresh_fake_idb):
    fresh_fake_idb.type_lib.register(
        FakeTinfo(lib=fresh_fake_idb.type_lib, name="uint64_t", kind=BT_INT64, size=8)
    )
    added = ok(types_tool.types(action="struct_member_add", struct_name="target_struct", member_name="status", type_str="uint32_t", offset=-1))
    assert added["size"] == 4
    renamed = ok(types_tool.types(action="struct_member_rename", struct_name="target_struct", member_name="status", new_name="state"))
    assert renamed["old_name"] == "status"
    assert renamed["new_name"] == "state"
    changed = ok(types_tool.types(action="struct_member_set_type", struct_name="target_struct", member_name="state", type_str="uint64_t"))
    assert changed["size"] == 8
    deleted = ok(types_tool.types(action="struct_member_del", struct_name="target_struct", member_name="state"))
    assert deleted["member"] == "state"

    enum = FakeTinfo(lib=fresh_fake_idb.type_lib, name="mode_e", kind=BT_ENUM, members=[edm_t("OFF", 0)])
    fresh_fake_idb.type_lib.register(enum)
    assert ok(types_tool.types(action="enum_member_add", enum_name="mode_e", member_name="ON", enum_value=1))["value"] == 1
    assert ok(types_tool.types(action="enum_member_rename", enum_name="mode_e", member_name="ON", new_name="ACTIVE"))["new_name"] == "ACTIVE"
    assert ok(types_tool.types(action="enum_member_revalue", enum_name="mode_e", member_name="ACTIVE", enum_value=2))["value"] == 2
    values = ok(types_tool.types(action="enum_values", name="mode_e"))
    assert {item["name"] for item in values["members"]} == {"OFF", "ACTIVE"}
    assert types_tool.types(action="enum_member_add", enum_name="mode_e", member_name="ACTIVE", enum_value=3)["error"] is True


def test_struct_visualize_vtable_and_til_carry_errors(monkeypatch, tmp_path, fresh_fake_idb):
    import ida_typeinf

    visual = ok(types_tool.types(action="visualize", name="target_struct"))
    assert "visual" in visual and "fields" in visual
    assert types_tool.types(action="visualize", name="mode_e")["error"] is True

    export_path = tmp_path / "types.h"
    exported = ok(types_tool.types(action="til_export", path=str(export_path), til_filter="target"))
    assert exported["exported_count"] == 1
    assert export_path.exists()
    imported = ok(types_tool.types(action="til_import", path=str(export_path)))
    assert imported["errors"] == 0
    assert types_tool.types(action="til_import", path=str(tmp_path / "missing.h"))["error"] is True
    empty = tmp_path / "empty.h"
    empty.write_text("\n", encoding="utf-8")
    assert types_tool.types(action="til_import", path=str(empty))["error"] is True
    assert ok(types_tool.types(action="til_delete", name="target_struct"))["deleted"] is True
    assert types_tool.types(action="til_delete", name="target_struct")["error"] is True

    # The ordinal API is a version-dependent surface; the action must fail
    # explicitly when it disappears rather than silently exporting nothing.
    monkeypatch.setattr(ida_typeinf, "get_ordinal_qty", None, raising=False)
    monkeypatch.setattr(ida_typeinf, "get_ordinal_count", None, raising=False)
    assert types_tool.types(action="til_export", path=str(tmp_path / "no-api.h"))["error"] is True


def test_vtable_reads_repeated_targets_and_big_endian(monkeypatch, fresh_fake_idb):
    import struct

    base = 0x140003000
    target = 0x140001000
    fresh_fake_idb.patch_bytes(base, struct.pack("<Q", target) + struct.pack("<Q", target) + struct.pack("<Q", 0))
    fresh_fake_idb.set_name(base, "vtable for Demo")
    fresh_fake_idb.set_name(target, "Demo::run(int)")
    result = ok(types_tool.types(action="vtable", addr=hex(base)))
    assert result["count"] == 1
    assert result["entries"][0]["name"] == "Demo::run(int)"

    fresh_fake_idb.endian = "big"
    fresh_fake_idb.patch_bytes(base, struct.pack(">Q", target) + struct.pack(">Q", 0))
    big = ok(types_tool.types(action="vtable", addr=hex(base)))
    assert big["count"] == 1


def test_type_aliases_and_autodetected_apply_modes(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    target = FakeTinfo(lib=fresh_fake_idb.type_lib, name="chain_target", kind=BT_STRUCT)
    alias = FakeTinfo(
        lib=fresh_fake_idb.type_lib,
        name="chain_alias",
        kind=BT_TYPEDEF,
        decl="typedef struct chain_target chain_alias;",
    )
    fresh_fake_idb.type_lib.register(target)
    fresh_fake_idb.type_lib.register(alias)
    monkeypatch.setattr(FakeTinfo, "get_next_type_name", lambda self: "chain_target", raising=False)
    detail = ok(types_tool.types(action="get", name="chain_alias"))
    assert len(detail["typedef_chain"]) == 2
    assert "chain_target" in detail["resolved_type"]

    assert ok(types_tool.types(action="apply", addr="0x140001000", decl="int"))["kind"] == "function"
    assert ok(types_tool.types(action="apply", addr="0x140003000", decl="int"))["kind"] == "global"

    original_set = ida_typeinf.set_numbered_type
    monkeypatch.setattr(ida_typeinf, "set_numbered_type", lambda *_args: (_ for _ in ()).throw(RuntimeError("9.4 API")))
    monkeypatch.setattr(ida_typeinf, "get_named_type", lambda til, name, *_args: til.get(name), raising=False)
    declared = ok(types_tool.types(action="declare", decl="struct fallback_save { int x; };"))
    assert declared["name"] == "fallback_save"
    monkeypatch.setattr(ida_typeinf, "set_numbered_type", original_set)


def test_type_ordinal_and_export_import_fallbacks(monkeypatch, tmp_path, fresh_fake_idb):
    import ida_typeinf
    import idc

    monkeypatch.setattr(ida_typeinf, "get_ordinal_qty", None, raising=False)
    monkeypatch.setattr(ida_typeinf, "get_ordinal_count", None, raising=False)
    assert types_tool.types(action="list")["error"] is True
    assert types_tool.types(action="search_structs", query="id")["error"] is True

    export = tmp_path / "own-format.h"
    export.write_text(
        "/* Exported from IDA type library. Import with types(action='til_import'). */\n\n"
        "struct\n{\nint value;\n} round_trip;\n",
        encoding="utf-8",
    )
    # Restore one ordinal provider for the import path; the own-format parser
    # deliberately does not depend on ordinal enumeration.
    monkeypatch.setattr(ida_typeinf, "get_ordinal_qty", lambda _til=None: 1, raising=False)
    imported = types_tool.types(action="til_import", path=str(export))
    assert imported["ok"] is True
    assert "round_trip" in imported["imported"]

    failed = tmp_path / "bad.h"
    failed.write_text("struct Missing { ??? };", encoding="utf-8")
    monkeypatch.setattr(idc, "parse_decls", lambda *_args: 2, raising=False)
    assert types_tool.types(action="til_import", path=str(failed))["error"] is True


def test_type_member_retype_rebuilds_overlapping_tail(monkeypatch, fresh_fake_idb):
    from tests.fakes.ida_fake import udm_t

    fresh_fake_idb.type_lib.register(FakeTinfo(lib=fresh_fake_idb.type_lib, name="wide_t", kind=BT_INT64, size=8))
    record = fresh_fake_idb.type_lib.get("target_struct")
    record.members.append(udm_t("tail", FakeTinfo(kind=BT_INT64, size=8), offset=16, size=8))
    original = FakeTinfo.set_udm_type

    def reject_in_place(self, *_args):
        return 1

    monkeypatch.setattr(FakeTinfo, "set_udm_type", reject_in_place)
    result = types_tool.types(
        action="struct_member_set_type",
        struct_name="target_struct",
        member_name="id",
        type_str="wide_t",
    )
    assert result["ok"] is True
    assert result["size"] == 8
    assert [member.name for member in record.members] == ["id", "name_ptr", "tail"]
    monkeypatch.setattr(FakeTinfo, "set_udm_type", original)
