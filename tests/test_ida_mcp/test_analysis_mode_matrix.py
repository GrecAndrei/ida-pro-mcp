"""Cross-mode coverage for analysis control and reversible IDB operations."""

from __future__ import annotations

import importlib
import struct

import pytest

from ida_pro_mcp.host.agent_operations import get_agent_operation
from ida_pro_mcp.ida_mcp.tools.analysis import (
    _bootstrap_raw_entry_points,
    _ensure_entry_point_functions,
    _entry_point_addrs,
    _find_text_segments,
    _is_raw_bin_filetype,
    _raw_mapped_range,
    _segment_code_score,
    analysis,
)

analysis_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


def test_public_analysis_operations_translate_to_legacy_backend():
    for public_name, action in (
        ("ida_save_idb", "save_idb"),
        ("ida_make_code", "make_code"),
        ("ida_undefine", "undefine"),
    ):
        operation = get_agent_operation(public_name)
        assert operation is not None
        backend, args = operation.to_backend_call({"address": "0x140001000", "risk_ack": True})
        assert backend == "analysis"
        assert args["action"] == action
        assert args["address"] == "0x140001000"
        assert args["_risk_ack"] is True


def test_get_options_set_options_and_processor_errors(monkeypatch, fresh_fake_idb):
    import idaapi
    import idc

    options = _assert_ok(analysis(action="get_options"))
    assert options["processor"] == "metapc"
    assert options["app_bitness"] == 64
    assert "file_type_info" in options

    monkeypatch.setattr(idc, "INF_BASEADDR", 7, raising=False)
    monkeypatch.setattr(idc, "INF_START_EA", 8, raising=False)
    monkeypatch.setattr(idc, "INF_MAX_EA", 2, raising=False)
    applied = {}

    def record_attr(key, value):
        applied[key] = value

    monkeypatch.setattr(idc, "set_inf_attr", record_attr, raising=False)
    result = _assert_ok(analysis(action="set_options", options={"start_ea": "0x140001000", "max_ea": 0x140004000}))
    assert result["applied"]["start_ea"] == 0x140001000
    assert applied
    assert analysis(action="set_options", options={"start_ea": "not numeric"}).get("ok") is not True
    assert analysis(action="set_options", options={"baseaddr": fresh_fake_idb.base + 1}).get("ok") is not True

    same = _assert_ok(analysis(action="set_processor", processor="metapc"))
    assert same["note"] == "already set"
    monkeypatch.setattr(idaapi, "set_processor_type", lambda *_args: True)
    changed = _assert_ok(analysis(action="set_processor", processor="arm"))
    assert changed["processor"] == "arm"
    monkeypatch.setattr(idaapi, "set_processor_type", lambda *_args: False)
    assert analysis(action="set_processor", processor="mips").get("ok") is not True
    monkeypatch.setattr(idaapi, "set_processor_type", lambda *_args: (_ for _ in ()).throw(RuntimeError("incompatible")))
    assert analysis(action="set_processor", processor="mips").get("ok") is not True


def test_set_architecture_and_loader_options_cover_aliases_and_fallback(monkeypatch, tmp_path):
    import ida_ida
    import ida_loader
    import idaapi

    arch = _assert_ok(analysis(action="set_architecture", processor="arm", bitness=32, endian="be"))
    assert arch["applied"]["arch_hints"]["ptr_size"] == 4
    assert arch["applied"]["arch_hints"]["default_int_width"] == 4
    assert _assert_ok(analysis(action="set_architecture", processor="mips"))["applied"]["arch_hints"]["ptr_size"] == 4
    assert _assert_ok(analysis(action="set_architecture", processor="riscv", bitness=64))["applied"]["arch_hints"]["ptr_size"] == 8
    assert analysis(action="set_architecture", endian="sideways").get("ok") is not True
    assert analysis(action="set_architecture", bitness=7).get("ok") is not True
    assert analysis(action="set_architecture").get("ok") is not True

    assert analysis(action="set_loader_options").get("ok") is not True
    loader = _assert_ok(analysis(action="set_loader_options", loader="elf", value={"base": "0x1000", "thumb": True}))
    assert loader["loader"] == "elf"
    assert loader["result"] is True

    monkeypatch.delattr(ida_loader, "set_loader_options", raising=False)
    monkeypatch.setattr(idaapi, "get_input_file_path", lambda: "/tmp/sample.bin", raising=False)
    fallback = _assert_ok(analysis(action="set_loader_options", loader="bin", value="offset=0"))
    assert fallback["fallback"] == "soft_saved"
    assert fallback["fallback_path"]
    assert (tmp_path / "unused").exists() is False
    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: 64, raising=False)


def test_reanalysis_state_save_and_code_lifecycle(monkeypatch, fresh_fake_idb, tmp_path):
    import ida_auto
    import ida_loader
    import idaapi

    explicit = _assert_ok(analysis(action="reanalyze", start="0x140001000", end="0x140001020"))
    assert explicit["mode"] == "plan_range"
    assert analysis(action="reanalyze", start="0x140001000").get("ok") is not True
    monkeypatch.setattr(analysis_module, "_auto_reanalyze_text_segments", lambda wait_seconds: {"waited_seconds": 0.0})
    monkeypatch.setattr(analysis_module, "_ensure_entry_point_functions", lambda: {"created": []})
    whole = _assert_ok(analysis(action="analyze", blocking=True, poll_timeout=0))
    assert whole["mode"] == "auto_reanalyze_text_segments"
    state = _assert_ok(analysis(action="state"))
    assert state["analysis_complete"] is True

    saved = _assert_ok(analysis(action="save_idb", path=str(tmp_path / "out.i64")))
    assert saved["saved_to"].endswith("out.i64")
    monkeypatch.setattr(ida_loader, "save_database", lambda *_args: False)
    assert analysis(action="save_idb").get("ok") is not True
    monkeypatch.setattr(ida_loader, "save_database", lambda *_args: (_ for _ in ()).throw(RuntimeError("disk full")))
    assert analysis(action="save_idb").get("ok") is not True

    made = _assert_ok(analysis(action="make_code", address="0x140001000", size=4))
    assert made["insn_len"] > 0
    undefined = _assert_ok(analysis(action="undefine", address="0x140001000", size=2))
    assert undefined["cleared_bytes"] == 2
    monkeypatch.setattr(ida_auto, "auto_mark_range", lambda *_args: None, raising=False)
    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: True, raising=False)


def test_analysis_flags_offsets_entries_snapshots_and_auto_wait(monkeypatch, fresh_fake_idb):
    import ida_auto
    import ida_entry
    import ida_ida
    import idaapi
    import idc

    all_flags = _assert_ok(analysis(action="get_af"))
    assert "af_raw" in all_flags
    monkeypatch.setattr(idc, "AF_MARKCODE", 1, raising=False)
    one = _assert_ok(analysis(action="get_af", af_flag="AF_MARKCODE"))
    assert one["bit"] == "0x1"
    enabled = _assert_ok(analysis(action="set_af", af_flag="AF_MARKCODE", af_value=True))
    assert enabled["current"] is True
    disabled = _assert_ok(analysis(action="set_af", af_flag="AF_MARKCODE", af_value=False))
    assert disabled["current"] is False
    for kwargs in ({}, {"af_flag": "AF_MARKCODE"}, {"af_flag": "AF_MISSING", "af_value": True}):
        assert analysis(action="set_af", **kwargs).get("ok") is not True

    called = []
    monkeypatch.setattr(idaapi, "REF_OFF32", 1, raising=False)
    monkeypatch.setattr(idaapi, "REF_OFF64", 2, raising=False)
    monkeypatch.setattr(idc, "op_offset", lambda *args: called.append(args), raising=False)
    offset = _assert_ok(analysis(action="force_offset", addr="0x140003000", size=8))
    assert offset["ptr_size"] == 8
    assert called
    monkeypatch.delattr(idc, "op_offset", raising=False)
    monkeypatch.delattr(idc, "op_plain_offset", raising=False)
    assert analysis(action="force_offset", addr="0x140003000").get("ok") is not True

    entry = _assert_ok(analysis(action="add_entry", addr="0x140001050", name="helper_entry"))
    assert entry["ordinal"] >= 1
    assert _entry_point_addrs()
    assert analysis(action="add_entry").get("ok") is not True
    monkeypatch.setattr(ida_entry, "add_entry", lambda *_args: False)
    assert analysis(action="add_entry", addr="0x140001060", ordinal=99).get("ok") is not True

    snap = _assert_ok(analysis(action="snapshot", snapshot_name="before"))
    assert snap["mechanism"] == "ida_loader"
    restored = _assert_ok(analysis(action="restore_snapshot", snapshot_id="before"))
    assert restored["snapshot_name"] == "before"
    assert analysis(action="restore_snapshot").get("ok") is not True

    monkeypatch.setattr(ida_auto, "auto_is_ok", lambda: True, raising=False)
    idle = _assert_ok(analysis(action="auto_wait", timeout_ms=0))
    assert idle["analysis_done"] is True
    monkeypatch.setattr(ida_auto, "auto_is_ok", lambda: False, raising=False)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda: None, raising=False)
    limited = _assert_ok(analysis(action="auto_wait", timeout_ms=0))
    assert limited["timed_out"] is True


def test_raw_entry_bootstrap_and_reanalysis_helpers_cover_architecture_modes(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import ida_funcs
    import idaapi
    import idautils
    import idc

    assert _is_raw_bin_filetype() is False
    assert _raw_mapped_range()[0] == 0x140001000
    assert _segment_code_score(0x140001000)[2] >= 1
    assert _find_text_segments()

    # Use an isolated raw-image view to exercise both vector-table and RISC-V
    # branch seeding without depending on the sample PE fixture.
    fresh_fake_idb.processor = "arm"
    fresh_fake_idb.filetype = idaapi.f_BIN
    fresh_fake_idb.base = 0x1000
    raw = bytearray(0x100)
    raw[4:8] = struct.pack("<I", 0x1021)
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda _ea, size: bytes(raw[:size]), raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda attr: idaapi.f_BIN if attr == idc.INF_FILETYPE else 0x1000, raising=False)
    monkeypatch.setattr(idc, "create_insn", lambda _ea: 1, raising=False)
    monkeypatch.setattr(ida_funcs, "add_func", lambda *_args: True, raising=False)
    monkeypatch.setattr(analysis_module._compat, "get_func_start", lambda _ea: None)
    seeded = _bootstrap_raw_entry_points(0x1000, 0x1100)
    assert seeded["seeded_entries"] >= 1

    fresh_fake_idb.processor = "riscv"
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "j", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda *_args: 0x1040, raising=False)
    rv = _bootstrap_raw_entry_points(0x1000, 0x1100)
    assert rv["seeded_entries"] >= 1
    monkeypatch.setattr(idautils, "Functions", lambda: iter(()), raising=False)
    assert _ensure_entry_point_functions()["entry_points_total"] >= 0
