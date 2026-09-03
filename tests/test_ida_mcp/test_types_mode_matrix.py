"""Stateful cross-mode coverage for the type-management backend."""

from __future__ import annotations

import struct
import types as py_types

import pytest

from ida_pro_mcp.ida_mcp.tools.types import (
    _extract_struct_name,
    _is_data_location,
    _is_fully_mapped,
    _parse_member_type,
    _resolve_enum_names,
    _resolve_struct_names,
    _struc_error_text,
    types,
)
from tests.fakes.ida_fake import (
    BT_ENUM,
    BT_PTR,
    BT_STRUCT,
    BT_UNION,
    FakeTinfo,
    edm_t,
    udm_t,
)


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


def _types_globals():
    """Return implementation globals regardless of decorator availability."""
    implementation = getattr(types, "__wrapped__", types)
    return implementation.__globals__


def test_import_header_and_parse_error_are_structured(monkeypatch):
    import idc

    _assert_ok(types(action="import_header", decl="struct imported { int value; };") )
    monkeypatch.setattr(idc, "parse_decls", lambda *_args: 2)
    result = types(action="import_header", decl="struct broken { ??? };")
    assert result.get("ok") is not True
    assert "2 errors" in result["message"]
    assert types(action="import_header").get("ok") is not True


def test_list_pagination_and_missing_type_library(monkeypatch):
    import ida_typeinf

    types(action="declare", decl="struct list_a { int a; };")
    types(action="declare", decl="struct list_b { int b; };")
    page = _assert_ok(types(action="list", offset=1, count=1))
    assert len(page["types"]) == 1
    assert page["offset"] == 1
    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: None)
    result = types(action="list")
    assert result.get("ok") is not True
    assert "type library" in result["message"].lower()


def test_type_get_enum_and_enum_lookup_modes():
    import ida_typeinf

    enum = FakeTinfo(lib=ida_typeinf.get_idati(), name="flags_e", kind=BT_ENUM)
    enum.members.extend([edm_t("READ", 1), edm_t("WRITE", 2), edm_t("EXEC", 4)])
    ida_typeinf.get_idati().register(enum)
    detail = _assert_ok(types(action="get", name="flags_e"))
    assert detail["kind"] == "enum"
    exact = _assert_ok(types(action="enum_values", name="flags_e", value=2))
    assert exact["value_lookup"]["match_type"] == "exact"
    bitmask = _assert_ok(types(action="enum_values", name="flags_e", value=3))
    assert bitmask["value_lookup"]["match_type"] == "bitmask"
    partial = _assert_ok(types(action="enum_values", name="flags_e", value=9))
    assert partial["value_lookup"]["match_type"] == "partial_bitmask"
    missing = _assert_ok(types(action="enum_values", name="flags_e", value=8))
    assert missing["value_lookup"]["match_type"] == "no_match"
    assert types(action="enum_values", name="target_struct").get("ok") is not True


def test_apply_function_global_local_and_invalid_kind(monkeypatch):
    import ida_hexrays

    function = _assert_ok(
        types(action="apply", addr="0x140001000", decl="int", kind="function")
    )
    assert function["kind"] == "function"
    global_result = _assert_ok(
        types(action="apply", addr="0x140003000", decl="int", kind="global")
    )
    assert global_result["kind"] == "global"
    cfunc = py_types.SimpleNamespace(lvars=[py_types.SimpleNamespace(name="local_value")])
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: cfunc)
    monkeypatch.setattr(ida_hexrays, "modify_user_lvars", lambda *_args: True, raising=False)
    # ``types`` is wrapped by @idawrite; patch the implementation globals so
    # the local-variable path does not require a real Hex-Rays warning flag.
    monkeypatch.setitem(_types_globals(), "my_modifier_t", lambda *_args: object())
    monkeypatch.setitem(_types_globals(), "refresh_decompiler_ctext", lambda *_args: None)
    local = _assert_ok(
        types(action="apply", addr="0x140001000", decl="int", kind="local", name="local_value")
    )
    assert local["kind"] == "local"
    absent = types(action="apply", addr="0x140001000", decl="int", kind="local", name="missing")
    assert absent.get("ok") is not True
    invalid = types(action="apply", addr="0x140001000", decl="int", kind="bad")
    assert invalid.get("ok") is not True


def test_infer_uses_stack_frame_and_allocator_evidence(monkeypatch):
    import idautils
    import idc

    monkeypatch.setattr(idc, "get_frame_id", lambda _ea: 7, raising=False)
    members = {0: ("first", 4), 4: ("second", 8), 12: ("third", 16)}
    monkeypatch.setattr(idc, "get_first_member", lambda _frame: 0, raising=False)
    monkeypatch.setattr(idc, "get_next_member", lambda _frame, off: {0: 4, 4: 12, 12: -1}[off], raising=False)
    monkeypatch.setattr(idc, "get_member_name", lambda _frame, off: members[off][0], raising=False)
    monkeypatch.setattr(idc, "get_member_size", lambda _frame, off: members[off][1], raising=False)
    inferred = _assert_ok(types(action="infer", addr="0x140001000"))
    assert any(item["kind"] == "stack_frame" for item in inferred["inferred_types"])

    monkeypatch.setattr(idc, "get_frame_id", lambda _ea: 0xFFFFFFFFFFFFFFFF, raising=False)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "call malloc", raising=False)
    inferred_alloc = _assert_ok(types(action="infer", addr="0x140001000"))
    assert any(item["kind"] == "heap_object" for item in inferred_alloc["inferred_types"])


def test_read_struct_rejects_unmapped_and_unknown_inputs():
    assert types(action="read_struct", addr="0x140003000").get("ok") is not True
    assert types(action="read_struct", name="target_struct").get("ok") is not True
    unmapped = types(action="read_struct", addr="0x1000", name="target_struct")
    assert unmapped.get("ok") is not True
    unknown = types(action="read_struct", addr="0x140003000", name="no_such_struct")
    assert unknown.get("ok") is not True


def test_propagate_separates_code_data_and_undefined_origins(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idautils

    # Mark one global as data and make one origin code, one data, and one
    # undefined. The action must only mutate the genuine data origin.
    fresh_fake_idb.patch_bytes(0x140003100, b"\x00" * 8)
    monkeypatch.setattr(ida_bytes, "get_flags", lambda ea: 0x400 if ea == 0x140003100 else 0, raising=False)
    refs = [
        py_types.SimpleNamespace(frm=0x140001008, type=1, iscode=True),
        py_types.SimpleNamespace(frm=0x140003100, type=2, iscode=False),
        py_types.SimpleNamespace(frm=0x140003200, type=3, iscode=False),
    ]
    monkeypatch.setattr(idautils, "XrefsTo", lambda *_args: iter(refs), raising=False)
    result = _assert_ok(types(action="propagate", addr="0x140003000", name="target_struct"))
    assert result["call_sites"]
    assert "0x140003100" in result["propagated_to"]
    assert any(item.get("status") == "skipped" for item in result["locations"])
    assert "without mutation" in result["note"]


def test_type_graph_and_vtable_cover_nested_and_repeated_targets(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import ida_typeinf
    import idc

    child = FakeTinfo(lib=fresh_fake_idb.type_lib, name="child_t", kind=BT_STRUCT)
    child.members.append(udm_t("value", FakeTinfo(kind=1, size=4), offset=0, size=4))
    parent = FakeTinfo(lib=fresh_fake_idb.type_lib, name="parent_t", kind=BT_STRUCT)
    parent.members.append(udm_t("child", child, offset=0, size=8))
    fresh_fake_idb.type_lib.register(child)
    fresh_fake_idb.type_lib.register(parent)
    graph = _assert_ok(types(action="type_graph", name="parent_t", max_depth=3))
    assert {node["name"] for node in graph["nodes"]} == {"parent_t", "child_t"}
    assert graph["edges"][0]["field"] == "child"

    fresh_fake_idb.patch_bytes(0x140002000, struct.pack("<Q", 0x140001050) + struct.pack("<Q", 0))
    idc.set_name(0x140002000, "vtable for Demo")
    vtable = _assert_ok(types(action="vtable", addr="0x140002000"))
    assert vtable["count"] == 1
    assert vtable["entries"][0]["addr"] == "0x140001050"
    assert types(action="vtable", name="NoSuchClass").get("ok") is not True


def test_type_helpers_and_member_type_fallbacks():
    import ida_typeinf

    assert _struc_error_text(-2).startswith("invalid member")
    assert _struc_error_text(123) == "unknown error"
    assert _resolve_struct_names("S", "member", None) == ("S", "member")
    assert _resolve_struct_names(None, "S", "field") == ("S", "field")
    assert _resolve_enum_names("E", "member", None) == ("E", "member")
    assert _resolve_enum_names(None, "E", "flag") == ("E", "flag")
    assert _is_fully_mapped(0x140003000, 4)
    assert not _is_fully_mapped(0x140003000, -1)
    assert _is_fully_mapped(0x140003000, 0)
    assert _is_data_location(0x140003000) is False
    ptr = FakeTinfo(kind=BT_PTR, target_tinfo=FakeTinfo(kind=BT_STRUCT, name="child_t"), size=8)
    assert _extract_struct_name(ptr) == "child_t"
    member, error = _parse_member_type("uint32_t", None)
    assert error is None and member.get_size() == 4
    member, error = _parse_member_type(None, 3)
    assert error is None and member.get_size() > 0
    _, error = _parse_member_type(None, None)
    assert error is not None
    assert ida_typeinf.get_idati()


def test_type_helper_negative_and_parse_fallback_modes(monkeypatch, fresh_fake_idb):
    import importlib

    import ida_typeinf
    import idaapi
    import idc

    module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")
    unresolved = FakeTinfo()
    monkeypatch.setattr(unresolved, "get_named_type", lambda *_args: False)
    monkeypatch.setattr(ida_typeinf, "get_named_type_tid", lambda _name: idaapi.BADADDR)
    assert module._resolve_type_by_name("missing", unresolved) is False
    assert module._type_kind(FakeTinfo(kind=999)) == "other"
    assert module._extract_struct_name(FakeTinfo(kind=BT_UNION, name="union_t")) == "union_t"

    array, error = module._parse_member_type("uint8_t[4]", None)
    assert error is None and array.get_size() == 4
    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: None)
    _, error = module._parse_member_type("not_a_real_type", None)
    assert error and "Failed to parse member type" in error["message"]

    monkeypatch.setattr(idc, "get_frame_id", lambda _ea: (_ for _ in ()).throw(RuntimeError("frame unavailable")), raising=False)
    monkeypatch.setattr(module._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(module.ida_nalt, "get_tinfo", lambda _tif, _ea: True, raising=False)
    inferred = _assert_ok(types(action="infer", addr="0x140003000"))
    assert inferred["inferred_types"][0]["kind"] == "existing"


def test_type_vtable_empty_and_classic_struct_error_modes(monkeypatch, fresh_fake_idb):
    import importlib

    import ida_typeinf

    module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.types")
    base = 0x140003000
    fresh_fake_idb.patch_bytes(base, b"\x00" * 16)
    fresh_fake_idb.set_name(base, "vtable for Empty")
    empty = _assert_ok(types(action="vtable", addr=hex(base)))
    assert empty["count"] == 0

    classic = py_types.SimpleNamespace(
        get_struc_id=lambda _name: 1,
        get_struc=lambda _sid: object(),
        add_struc_member=lambda *_args: -2,
        del_struc_member=lambda *_args: -5,
        set_member_name=lambda *_args: -1,
        get_member=lambda *_args: object(),
        set_member_tinfo=lambda *_args: -4,
    )
    monkeypatch.setattr(module, "ida_struct", classic)
    monkeypatch.setitem(_types_globals(), "ida_struct", classic)
    add_result = types(
        action="struct_member_add", struct_name="target_struct", member_name="new", type_str="int", offset=0
    )
    assert add_result.get("message"), add_result
    assert "invalid member offset" in add_result["message"]
    del_result = types(action="struct_member_del", struct_name="target_struct", member_name="id")
    assert del_result.get("message"), del_result
    assert "member not found" in del_result["message"]
    rename_result = types(
        action="struct_member_rename", struct_name="target_struct", member_name="id", new_name="new"
    )
    assert rename_result.get("message"), rename_result
    assert "already exists" in rename_result["message"]
    set_type_result = types(
        action="struct_member_set_type", struct_name="target_struct", member_name="id", type_str="int"
    )
    assert set_type_result.get("message"), set_type_result
    assert "invalid member type" in set_type_result["message"]

    monkeypatch.setattr(ida_typeinf, "add_enum_member", lambda *_args: -1, raising=False)
    monkeypatch.setattr(ida_typeinf, "set_enum_member_name", lambda *_args: -1, raising=False)
    monkeypatch.setattr(ida_typeinf, "set_enum_member_value", lambda *_args: -1, raising=False)
    enum = FakeTinfo(lib=fresh_fake_idb.type_lib, name="classic_e", kind=BT_ENUM, members=[edm_t("ONE", 1)])
    fresh_fake_idb.type_lib.register(enum)
    assert types(action="enum_member_add", enum_name="classic_e", member_name="TWO", enum_value=2)["error"] is True
    assert types(action="enum_member_rename", enum_name="classic_e", member_name="ONE", new_name="FIRST")["error"] is True
    assert types(action="enum_member_revalue", enum_name="classic_e", member_name="ONE", enum_value=3)["error"] is True
