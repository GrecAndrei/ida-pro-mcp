"""Behavior coverage for analysis configuration and lifecycle actions."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from tests.fakes.ida_fake import create_sample_c_binary_idb, install_fake_idb

analysis_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


@pytest.fixture(autouse=True)
def sample_idb():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    return db


def test_set_options_rebases_before_persisting_base(monkeypatch):
    attrs = {
        1: 0x140000000,
        2: 0x140001000,
        3: 0x140001000,
        4: 0x140003000,
    }
    monkeypatch.setattr(analysis_mod.idc, "INF_BASEADDR", 1, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "INF_START_EA", 2, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "INF_MIN_EA", 3, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "INF_MAX_EA", 4, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "get_inf_attr", attrs.get, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "set_inf_attr", attrs.__setitem__, raising=False)
    rebases = []
    monkeypatch.setattr(analysis_mod.idc, "rebase_program", lambda delta, flags: rebases.append((delta, flags)) or 1, raising=False)

    result = analysis_mod.analysis(
        action="set_options",
        options={"baseaddr": "0x140001000", "start_ea": "0x140002000"},
    )
    assert result["ok"] is True
    assert result["applied"]["baseaddr"] == 0x140001000
    assert rebases == [(0x1000, 0)]
    assert attrs[2] == 0x140002000

    unaligned = analysis_mod.analysis(
        action="set_options", options={"baseaddr": "0x140000123"}
    )
    assert unaligned["error"] is True
    assert "page-aligned" in unaligned["message"]
    assert analysis_mod.analysis(action="set_options", options=None)["error"] is True


def test_processor_architecture_and_loader_modes(monkeypatch, tmp_path):
    processor_calls = []
    monkeypatch.setattr(analysis_mod.idaapi, "set_processor_type", lambda name, flags: processor_calls.append((name, flags)) or True, raising=False)
    switched = analysis_mod.analysis(action="set_processor", processor="arm")
    assert switched["ok"] is True
    assert processor_calls[-1][0] == "arm"
    assert analysis_mod.analysis(action="set_processor")["error"] is True

    app_bitness = {"value": 32}
    endianness = {"value": False}
    monkeypatch.setattr(analysis_mod.ida_ida, "inf_get_app_bitness", lambda: app_bitness["value"], raising=False)
    monkeypatch.setattr(analysis_mod.ida_ida, "inf_set_app_bitness", lambda value: app_bitness.__setitem__("value", value), raising=False)
    monkeypatch.setattr(analysis_mod.ida_ida, "inf_get_max_ea", lambda: 0x1000, raising=False)
    monkeypatch.setattr(analysis_mod.ida_ida, "inf_is_be", lambda: endianness["value"], raising=False)
    monkeypatch.setattr(analysis_mod.ida_ida, "inf_set_be", lambda value: endianness.__setitem__("value", value), raising=False)
    architecture = analysis_mod.analysis(
        action="set_architecture", processor="riscv", bitness=64, endian="be"
    )
    assert architecture["ok"] is True
    assert architecture["applied"]["bitness"] == 64
    assert architecture["applied"]["endian"] == "be"
    assert architecture["applied"]["arch_hints"]["riscv_note"]
    assert analysis_mod.analysis(action="set_architecture", bitness=48)["error"] is True
    assert analysis_mod.analysis(action="set_architecture", endian="middle")["error"] is True

    loader_calls = []
    monkeypatch.setattr(analysis_mod.ida_loader, "get_loader_name", lambda: "elf", raising=False)
    monkeypatch.setattr(analysis_mod.ida_loader, "set_loader_options", lambda name, value: loader_calls.append((name, value)) or True, raising=False)
    loaded = analysis_mod.analysis(
        action="set_loader_options", value={"base": "0x1000", "flags": 1}
    )
    assert loaded == {"ok": True, "loader": "elf", "result": True}
    assert loader_calls == [("elf", "base=0x1000;flags=1")]
    assert analysis_mod.analysis(action="set_loader_options")["error"] is True

    save_calls = []
    monkeypatch.setattr(analysis_mod.ida_loader, "save_database", lambda path, flags: save_calls.append((path, flags)) or True, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "get_idb_path", lambda: str(tmp_path / "current.i64"), raising=False)
    saved = analysis_mod.analysis(action="save_idb", path=str(tmp_path / "copy.i64"))
    assert saved["saved_to"].endswith("copy.i64")
    in_place = analysis_mod.analysis(action="save_idb")
    assert in_place["saved_to"].endswith("current.i64")
    assert save_calls == [(str(tmp_path / "copy.i64"), 0), (None, 0)]


def test_offset_entry_snapshot_and_make_code_paths(monkeypatch, tmp_path):
    offset_calls = []
    monkeypatch.setattr(analysis_mod.idaapi, "REF_OFF32", 32, raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "REF_OFF64", 64, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "op_offset", lambda *args: offset_calls.append(args), raising=False)
    offset = analysis_mod.analysis(action="force_offset", addr="0x140001000", size=4)
    assert offset["ok"] is True and offset["ptr_size"] == 4
    assert offset_calls

    entries = []
    monkeypatch.setattr(analysis_mod.ida_entry, "get_entry_qty", lambda: 4, raising=False)
    monkeypatch.setattr(analysis_mod.ida_entry, "add_entry", lambda *args: entries.append(args) or True, raising=False)
    entry = analysis_mod.analysis(action="add_entry", addr="0x140001000", name="entry")
    assert entry["ok"] is True and entry["ordinal"] == 4
    assert entries[0][:3] == (4, 0x140001000, "entry")
    assert analysis_mod.analysis(action="add_entry", addr="0x140001000", ordinal="bad")["error"] is True

    snapshots = []
    monkeypatch.setattr(analysis_mod.ida_loader, "save_snapshot", lambda *args: snapshots.append(("save", args)) or True, raising=False)
    monkeypatch.setattr(analysis_mod.ida_loader, "restore_snapshot", lambda *args: snapshots.append(("restore", args)) or True, raising=False)
    snap = analysis_mod.analysis(action="snapshot", snapshot_id="trial")
    restored = analysis_mod.analysis(action="restore_snapshot", snapshot_id="trial")
    assert snap["ok"] is True and restored["ok"] is True
    assert snapshots[0][0] == "save" and snapshots[1][0] == "restore"
    assert analysis_mod.analysis(action="snapshot")["error"] is True
    assert analysis_mod.analysis(action="restore_snapshot")["error"] is True

    deleted = []
    ida_ua = importlib.import_module("ida_ua")
    monkeypatch.setattr(analysis_mod.ida_bytes, "del_items", lambda *args: deleted.append(args), raising=False)
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: 0, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "get_item_size", lambda _ea: 2, raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "BADADDR", -1, raising=False)
    monkeypatch.setattr(analysis_mod._compat, "get_func_info", lambda _ea: SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020))
    monkeypatch.setattr(analysis_mod.idc, "create_insn", lambda _ea: 5, raising=False)
    made = analysis_mod.analysis(action="make_code", addr="0x140001000")
    assert made["ok"] is True and made["insn_len"] == 5
    assert deleted
    cleared = analysis_mod.analysis(action="undefine", addr="0x140001000")
    assert cleared["ok"] is True and cleared["cleared_bytes"] == 2


def test_bounded_auto_wait_pumps_both_sdk_signatures(monkeypatch):
    auto = importlib.import_module("ida_auto")
    states = iter((False, True, True))
    steps = []
    monkeypatch.setattr(auto, "auto_is_ok", lambda: next(states), raising=False)
    monkeypatch.setattr(auto, "auto_make_step", lambda: steps.append("step"), raising=False)
    result = analysis_mod.analysis(action="auto_wait", timeout_ms=100)
    assert result["ok"] is True
    assert result["analysis_done"] is True
    assert result["queue_depth"] == 0
    assert result["timed_out"] is False
    assert steps == ["step"]

    states = iter((False, True, True))
    legacy_steps = []
    monkeypatch.setattr(auto, "auto_is_ok", lambda: next(states), raising=False)

    def legacy_step(*args):
        if not args:
            raise TypeError("legacy signature")
        legacy_steps.append(args)

    monkeypatch.setattr(auto, "auto_make_step", legacy_step, raising=False)
    legacy = analysis_mod.analysis(action="auto_wait", timeout_ms=0)
    assert legacy["analysis_done"] is True
    assert legacy["timed_out"] is True
    assert legacy_steps == [(analysis_mod.idaapi.BADADDR, analysis_mod.idaapi.BADADDR)]
    invalid = analysis_mod.analysis(action="auto_wait", timeout_ms="later")
    assert invalid["error"] is True
