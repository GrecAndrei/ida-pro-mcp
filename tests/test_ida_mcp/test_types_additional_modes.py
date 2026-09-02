"""Additional type-system coverage across read-only, edit, and carry paths."""

from __future__ import annotations

import pytest

from ida_pro_mcp.ida_mcp.tools.types import (
    _extract_struct_name,
    _resolve_type_by_name,
    _type_kind,
    types,
)
from tests.fakes.ida_fake import (
    BT_ARRAY,
    BT_ENUM,
    BT_FUNC,
    BT_INT8,
    BT_INT16,
    BT_INT32,
    BT_INT64,
    BT_PTR,
    BT_STRUCT,
    BT_TYPEDEF,
    FakeTinfo,
    edm_t,
    udm_t,
)


def test_enum_diff_cross_kind_and_type_kind_helpers(fresh_fake_idb):
    first = FakeTinfo(lib=fresh_fake_idb.type_lib, name="first_e", kind=BT_ENUM)
    first.members.extend([edm_t("A", 1), edm_t("B", 2), edm_t("OLD", 7)])
    second = FakeTinfo(lib=fresh_fake_idb.type_lib, name="second_e", kind=BT_ENUM)
    second.members.extend([edm_t("A", 1), edm_t("B", 4), edm_t("NEW", 9)])
    fresh_fake_idb.type_lib.register(first)
    fresh_fake_idb.type_lib.register(second)

    diff = types(action="diff", name="first_e", other_name="second_e")
    assert diff["summary"] == {
        "common_values": 2,
        "changed_values": 1,
        "values_added": 1,
        "values_removed": 1,
    }
    assert diff["value_changes"][0]["name"] == "B"

    cross = types(action="diff", name="first_e", other_name="target_struct")
    assert cross["type_mismatch"] is True
    assert "enum" in cross["note"] and "struct" in cross["note"]

    kinds = {
        "struct": FakeTinfo(kind=BT_STRUCT),
        "enum": FakeTinfo(kind=BT_ENUM),
        "function": FakeTinfo(kind=BT_FUNC),
        "typedef": FakeTinfo(kind=BT_TYPEDEF),
        "pointer": FakeTinfo(kind=BT_PTR),
        "array": FakeTinfo(kind=BT_ARRAY),
    }
    assert {name: _type_kind(tif) for name, tif in kinds.items()} == {
        "struct": "struct", "enum": "enum", "function": "function",
        "typedef": "typedef", "pointer": "pointer", "array": "array",
    }


def test_type_resolution_tid_fallback_and_nested_struct_name(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    target = FakeTinfo(lib=fresh_fake_idb.type_lib, name="nested_t", kind=BT_STRUCT)
    fresh_fake_idb.type_lib.register(target)
    out = FakeTinfo()
    original_get_named = out.get_named_type
    monkeypatch.setattr(out, "get_named_type", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(ida_typeinf, "get_named_type_tid", lambda _name: target.get_tid())
    assert _resolve_type_by_name("nested_t", out) is True
    # Direct lookup remains the normal path after the fallback probe.
    out.get_named_type = original_get_named
    assert _resolve_type_by_name("nested_t", out) is True

    pointer = FakeTinfo(kind=BT_PTR, target_tinfo=target, size=8)
    array = FakeTinfo(kind=BT_ARRAY, target_tinfo=pointer, size=16)
    assert _extract_struct_name(pointer) == "nested_t"
    assert _extract_struct_name(array) == "nested_t"
    assert _extract_struct_name(FakeTinfo(kind=BT_INT32)) is None


def test_read_struct_covers_scalar_string_binary_and_large_fields(monkeypatch, fresh_fake_idb):
    import ida_typeinf

    field_types = [
        ("byte", FakeTinfo(kind=BT_INT8, size=1)),
        ("word", FakeTinfo(kind=BT_INT16, size=2)),
        ("dword", FakeTinfo(kind=BT_INT32, size=4)),
        ("qword", FakeTinfo(kind=BT_INT64, size=8)),
        ("ptr", FakeTinfo(kind=BT_PTR, size=8)),
        ("raw", FakeTinfo(kind=BT_INT8, size=3)),
        ("large", FakeTinfo(kind=BT_INT8, size=257)),
    ]
    members = []
    offset = 0
    for name, tif in field_types:
        members.append(udm_t(name, tif, offset=offset, size=tif.get_size()))
        offset += tif.get_size()
    record = FakeTinfo(lib=fresh_fake_idb.type_lib, name="all_widths", kind=BT_STRUCT, members=members)
    fresh_fake_idb.type_lib.register(record)
    base = 0x140003100
    raw = bytearray(offset)
    raw[0:1] = b"\x7f"
    raw[1:3] = (0x1234).to_bytes(2, "little")
    raw[3:7] = (0x12345678).to_bytes(4, "little")
    raw[7:15] = (0x123456789ABCDEF0).to_bytes(8, "little")
    raw[15:23] = (0x140002010).to_bytes(8, "little")
    raw[23:26] = b"abc"
    raw[26:] = b"x" * 257
    fresh_fake_idb.patch_bytes(base, raw)

    result = types(action="read_struct", addr=hex(base), name="all_widths")
    assert result["ok"] is True
    values = {field["name"]: field["value"] for field in result["fields"]}
    assert values["byte"] == "0x7f"
    assert values["word"] == "0x1234"
    assert values["dword"] == "0x12345678"
    assert values["qword"] == "0x123456789abcdef0"
    assert values["ptr"] == "0x140002010"
    assert values["raw"] == repr("abc")
    assert values["large"] == "[257 bytes]"

    monkeypatch.setattr(ida_typeinf, "get_idati", lambda: None)
    assert types(action="read_struct", addr=hex(base), name="all_widths")["error"] is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"action": "set_prototype"},
        {"action": "parse_decl"},
        {"action": "declare"},
        {"action": "apply"},
        {"action": "search_structs"},
        {"action": "infer"},
        {"action": "read_struct"},
        {"action": "diff", "name": "target_struct"},
        {"action": "visualize"},
        {"action": "propagate", "addr": "0x140003000"},
        {"action": "enum_values"},
        {"action": "type_graph"},
        {"action": "vtable"},
    ],
)
def test_type_actions_give_actionable_missing_argument_errors(kwargs, fresh_fake_idb):
    result = types(**kwargs)
    assert result["error"] is True
    assert result.get("message")


def test_struct_and_enum_edit_helpers_surface_duplicate_and_missing_errors(fresh_fake_idb):
    assert types(action="struct_member_add", struct_name="target_struct").get("ok") is not True
    assert types(action="struct_member_del", struct_name="target_struct", member_name="missing").get("ok") is not True
    assert types(action="struct_member_rename", struct_name="target_struct", member_name="missing", new_name="x").get("ok") is not True
    assert types(action="struct_member_set_type", struct_name="target_struct", member_name="missing", type_str="int").get("ok") is not True

    enum = FakeTinfo(lib=fresh_fake_idb.type_lib, name="edit_e", kind=BT_ENUM, members=[edm_t("ONE", 1)])
    fresh_fake_idb.type_lib.register(enum)
    assert types(action="enum_member_rename", enum_name="edit_e", member_name="missing", new_name="x").get("ok") is not True
    assert types(action="enum_member_revalue", enum_name="edit_e", member_name="missing", enum_value=2).get("ok") is not True
