"""Cross-mode coverage for analysis fallbacks and reversible operations."""

from __future__ import annotations

import importlib
import sys
import types

import pytest

analysis_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_set_options_rebase_and_architecture_warning_paths(monkeypatch, fresh_fake_idb):
    import ida_ida
    import idaapi
    import idc

    current = fresh_fake_idb.base
    monkeypatch.setattr(idc, "INF_BASEADDR", 1, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda _key: current, raising=False)
    rebases = []
    monkeypatch.setattr(
        idc,
        "rebase_program",
        lambda delta, flags: rebases.append((delta, flags)),
        raising=False,
    )
    moved = _ok(analysis_mod.analysis(action="set_options", options={"baseaddr": current + 0x1000}))
    assert moved["applied"]["baseaddr"] == current + 0x1000
    assert rebases == [(0x1000, 0)]

    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: 64, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_max_ea", lambda: 0x1_0000, raising=False)
    bits = _ok(analysis_mod.analysis(action="set_architecture", bitness=16))
    assert bits["applied"]["bitness"] == 16
    assert bits["applied"]["bitness_warnings"]

    monkeypatch.setattr(ida_ida, "inf_is_be", lambda: True, raising=False)
    same_endian = _ok(analysis_mod.analysis(action="set_architecture", endian="big"))
    assert same_endian["applied"]["endian"]["note"] == "already set"

    monkeypatch.setattr(ida_ida, "inf_is_be", lambda: False, raising=False)
    monkeypatch.setattr(
        ida_ida,
        "inf_set_be",
        lambda _value: (_ for _ in ()).throw(RuntimeError("endian locked")),
        raising=False,
    )
    failed = analysis_mod.analysis(action="set_architecture", endian="be")
    assert failed["error"] is True
    assert "endian locked" in failed["message"]


def test_loader_options_signature_false_and_write_fallback(monkeypatch, tmp_path):
    import ida_loader

    calls = []

    def three_arg_loader(loader, value, flags=0):
        calls.append((loader, value, flags))
        return True

    monkeypatch.setattr(ida_loader, "set_loader_options", three_arg_loader, raising=False)
    result = _ok(analysis_mod.analysis(action="set_loader_options", loader="elf", value={"x": 1}))
    assert result["result"] is True
    assert calls == [("elf", "x=1", 0)]

    monkeypatch.setattr(ida_loader, "set_loader_options", lambda *_args: False, raising=False)
    failed = analysis_mod.analysis(action="set_loader_options", loader="elf", value="x")
    assert failed["error"] is True
    assert "failed to apply" in failed["message"].lower()

    monkeypatch.delattr(ida_loader, "set_loader_options", raising=False)
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))
    saved = _ok(analysis_mod.analysis(action="set_loader_options", loader="bin", value="base=0"))
    assert saved["fallback"] == "soft_saved"
    assert saved["fallback_path"]


def test_save_make_undefine_and_force_offset_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_auto
    import ida_bytes
    import ida_loader
    import ida_ua
    import idaapi
    import idc

    monkeypatch.setattr(ida_loader, "save_database", lambda *_args: False)
    assert analysis_mod.analysis(action="save_idb", path="out.i64")["error"] is True
    monkeypatch.setattr(ida_loader, "save_database", lambda *_args: True)
    monkeypatch.delattr(idc, "get_idb_path", raising=False)
    monkeypatch.setattr(idaapi, "get_idb_path", lambda: "current.i64", raising=False)
    assert _ok(analysis_mod.analysis(action="save_idb"))["saved_to"] == "current.i64"

    marks = []
    monkeypatch.setattr(ida_bytes, "del_items", lambda *args: marks.append(args))
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: 4)
    monkeypatch.setattr(
        analysis_mod._compat,
        "get_func_info",
        lambda _ea: types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020),
    )
    monkeypatch.setattr(ida_auto, "auto_mark_range", lambda *args: marks.append(args), raising=False)
    made = _ok(analysis_mod.analysis(action="make_code", addr="0x140001000", size=4))
    assert made["insn_len"] == 4
    assert made["requeued_func"] is True

    cleared = _ok(analysis_mod.analysis(action="undefine", addr="0x140001000", size=3))
    assert cleared["cleared_bytes"] == 3

    offsets = []
    monkeypatch.setattr(
        idc,
        "op_offset",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("old signature")),
        raising=False,
    )
    monkeypatch.setattr(idc, "op_plain_offset", lambda *args: offsets.append(args), raising=False)
    offset = _ok(analysis_mod.analysis(action="force_offset", addr="0x140003000", size=4))
    assert offset["ptr_size"] == 4
    assert offsets


def test_analysis_flags_and_entry_point_signature_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_entry
    import ida_ida
    import idaapi
    import idc

    monkeypatch.setattr(idc, "AF_CUSTOM", 0x40, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_af", lambda: 0x40, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_af2", lambda: 0, raising=False)
    current = _ok(analysis_mod.analysis(action="get_af", af_flag="AF_CUSTOM"))
    assert current["enabled"] is True
    assert analysis_mod.analysis(action="get_af", af_flag="AF_UNKNOWN")["error"] is True

    monkeypatch.setattr(ida_ida, "inf_set_af", lambda value: setattr(fresh_fake_idb, "af", value), raising=False)
    disabled = _ok(analysis_mod.analysis(action="set_af", af_flag="AF_CUSTOM", af_value=False))
    assert disabled["current"] is False

    entries = []

    def old_add_entry(ordinal, ea, name):
        entries.append((ordinal, ea, name))
        return True

    monkeypatch.setattr(ida_entry, "add_entry", old_add_entry)
    added = _ok(analysis_mod.analysis(action="add_entry", addr="0x140001050", ordinal=4, name="old_api"))
    assert added["name"] == "old_api"
    assert entries == [(4, 0x140001050, "old_api")]


def test_snapshot_loader_and_undo_modes(monkeypatch):
    import ida_loader

    snapshot_calls = []

    def one_arg_snapshot(name):
        snapshot_calls.append(name)
        return True

    monkeypatch.setattr(ida_loader, "save_snapshot", one_arg_snapshot, raising=False)
    saved = _ok(analysis_mod.analysis(action="snapshot", snapshot_name="one"))
    assert saved["mechanism"] == "ida_loader"
    assert snapshot_calls == ["one"]

    monkeypatch.setattr(ida_loader, "restore_snapshot", lambda _name: True, raising=False)
    restored = _ok(analysis_mod.analysis(action="restore_snapshot", snapshot_id="one"))
    assert restored["snapshot_name"] == "one"
    ordinal_restore = analysis_mod.analysis(action="restore_snapshot", ordinal=1)
    assert ordinal_restore["error"] is True

    undo = types.ModuleType("ida_undo")
    undo_calls = []
    undo.perform_undo = lambda: undo_calls.append("undo") or True
    monkeypatch.setitem(sys.modules, "ida_undo", undo)
    monkeypatch.delattr(ida_loader, "restore_snapshot", raising=False)
    rolled = _ok(analysis_mod.analysis(action="restore_snapshot", ordinal=2))
    assert rolled["mechanism"] == "ida_undo"
    assert len(undo_calls) == 3


def test_auto_wait_fallback_and_unknown_action(monkeypatch):
    import ida_auto
    import idaapi

    monkeypatch.delattr(ida_auto, "auto_is_ok", raising=False)
    states = iter((False, True, True))
    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: next(states), raising=False)
    steps = []
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda *args: steps.append(args), raising=False)
    result = _ok(analysis_mod.analysis(action="auto_wait", timeout_ms=100))
    assert result["analysis_done"] is True
    assert steps
    assert analysis_mod.analysis(action="not-a-real-action")["error"] is True
