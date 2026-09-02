"""Exercise validation and compatibility branches across broad IDA surfaces."""

from __future__ import annotations

from ida_pro_mcp.ida_mcp.tools.funcs import funcs
from ida_pro_mcp.ida_mcp.tools.types import types


def test_types_action_validation_matrix(fresh_fake_idb):
    cases = [
        ("import_header", {}),
        ("get", {}),
        ("set_prototype", {}),
        ("parse_decl", {}),
        ("declare", {}),
        ("apply", {}),
        ("search_structs", {}),
        ("infer", {}),
        ("read_struct", {}),
        ("diff", {}),
        ("visualize", {}),
        ("propagate", {}),
        ("enum_values", {}),
        ("type_graph", {}),
        ("vtable", {}),
        ("struct_member_add", {}),
        ("struct_member_del", {}),
        ("struct_member_rename", {}),
        ("struct_member_set_type", {}),
        ("enum_member_add", {}),
        ("enum_member_rename", {}),
        ("enum_member_revalue", {}),
        ("til_delete", {}),
        ("til_export", {}),
        ("til_import", {}),
    ]
    for action, kwargs in cases:
        result = types(action=action, **kwargs)
        assert isinstance(result, dict), action


def test_types_aliases_and_invalid_target_modes(fresh_fake_idb, tmp_path):
    assert isinstance(types(action="parse_decl", declaration="not valid C"), dict)
    assert types(action="set_prototype", address="bad", declaration="int f(void)")["error"] is True
    assert types(action="apply", address="bad", declaration="int")["error"] is True
    assert types(action="infer", address="not-an-address")["error"] is True
    assert types(action="read_struct", address="0x1000", name="missing")["error"] is True
    assert types(action="diff", name="missing", other_name="also_missing")["error"] is True
    assert types(action="visualize", name="missing")["error"] is True
    assert types(action="propagate", address="bad", name="missing")["error"] is True
    assert types(action="enum_values", name="missing")["error"] is True
    assert types(action="type_graph", name="missing")["error"] is True
    assert types(action="vtable", address="bad")["error"] is True
    assert isinstance(types(action="til_export", path=str(tmp_path / "out.h"), til_filter="*"), dict)
    assert types(action="til_import", path=str(tmp_path / "missing.h"))["error"] is True


def test_funcs_validation_and_alias_modes(fresh_fake_idb):
    for action in ("create", "change", "delete", "set_flags", "info", "metrics", "find_similar", "suggest_names"):
        result = funcs(action=action)
        assert isinstance(result, dict), action
    assert funcs(action="create", address="bad")["error"] is True
    assert funcs(action="delete", address="bad")["error"] is True
    assert funcs(action="change", address="0x140001000")["error"] is True
    assert isinstance(funcs(action="set_flags", address="0x140001000"), dict)
    assert funcs(action="info", address="0x1000")["error"] is True
    assert funcs(action="metrics", address="0x1000")["error"] is True
    assert funcs(action="find_similar", address="bad")["error"] is True
    assert funcs(action="suggest_names", address="bad")["error"] is True
    assert funcs(action="unknown")["error"] is True
