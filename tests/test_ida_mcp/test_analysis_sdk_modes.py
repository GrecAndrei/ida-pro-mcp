"""Cross-version and failure-mode coverage for the analysis control surface."""

from __future__ import annotations

import importlib
import sys
import types

import pytest

from tests.fakes.ida_fake import create_sample_c_binary_idb, install_fake_idb

analysis = importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


@pytest.fixture(autouse=True)
def sample_idb():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    return db


def test_get_options_and_loader_name_compatibility_fallbacks(monkeypatch):
    import ida_ida
    import ida_loader
    import ida_nalt
    import idaapi

    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: (_ for _ in ()).throw(RuntimeError("old SDK")))
    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: (_ for _ in ()).throw(RuntimeError("no bitness")))
    monkeypatch.setattr(ida_loader, "get_loader_name", lambda path: "elf" if path else None, raising=False)
    monkeypatch.delattr(ida_nalt, "get_input_file_path", raising=False)
    monkeypatch.setattr(idaapi, "get_input_file_path", lambda: "/tmp/image.bin", raising=False)

    result = analysis.analysis(action="get_options")
    assert result["ok"] is True
    assert result["loader"] == "elf"
    assert result["app_bitness"] == 64


def test_set_options_and_processor_report_sdk_failures(monkeypatch):
    import ida_ida
    import ida_segment
    import idaapi
    import idc

    monkeypatch.setattr(idc, "INF_BASEADDR", 9, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", lambda _key: (_ for _ in ()).throw(RuntimeError("no IDC")))
    applied = {}
    monkeypatch.setattr(idc, "set_inf_attr", applied.__setitem__, raising=False)
    result = analysis.analysis(action="set_options", options={"unknown": 1, "min_ea": 0x140001000})
    assert result["ok"] is True
    assert result["applied"]["min_ea"] == 0x140001000

    def fail_rebase(*_args):
        raise RuntimeError("rebase unavailable")

    monkeypatch.setattr(idc, "rebase_program", fail_rebase, raising=False)
    monkeypatch.setattr(idaapi, "rebase_program", fail_rebase, raising=False)
    monkeypatch.setattr(ida_segment, "rebase_program", fail_rebase, raising=False)
    failed_rebase = analysis.analysis(action="set_options", options={"baseaddr": 0x140002000})
    assert failed_rebase["error"] is True
    assert "rebase" in failed_rebase["message"].lower()

    monkeypatch.setattr(idaapi, "get_inf_structure", fail_rebase)
    monkeypatch.setattr(idaapi, "set_processor_type", fail_rebase)
    failed_processor = analysis.analysis(action="set_processor", processor="arm")
    assert failed_processor["error"] is True
    assert "unavailable" in failed_processor["message"]


def test_set_gp_and_loader_error_modes(monkeypatch, tmp_path):
    import ida_loader
    import idaapi

    assert analysis.analysis(action="set_gp")["error"] is True
    assert analysis.analysis(action="set_gp", gp="0x1000")["error"] is True
    monkeypatch.setattr(analysis, "is_riscv_family", lambda: True)
    assert analysis.analysis(action="set_gp", gp="not-hex")["error"] is True

    monkeypatch.setattr(ida_loader, "get_loader_name", lambda: None, raising=False)
    assert analysis.analysis(action="set_loader_options", value="x")["error"] is True

    def runtime_failure(*_args, **_kwargs):
        raise RuntimeError("loader rejected options")

    monkeypatch.setattr(ida_loader, "set_loader_options", runtime_failure, raising=False)
    rejected = analysis.analysis(action="set_loader_options", loader="elf", value={"x": 1})
    assert rejected["error"] is True

    calls = []

    def generic_failure(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("signature unavailable")
        raise RuntimeError("second call failed")

    monkeypatch.setattr(ida_loader, "set_loader_options", generic_failure, raising=False)
    retried = analysis.analysis(action="set_loader_options", loader="elf", value="x")
    assert retried["error"] is True
    assert len(calls) == 2

    # The soft persistence fallback is also useful when the cache directory is
    # not writable; it must still return a truthful result envelope.
    monkeypatch.delattr(ida_loader, "set_loader_options", raising=False)
    monkeypatch.setattr(analysis.os, "makedirs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read only")))
    soft = analysis.analysis(action="set_loader_options", loader="bin", value="offset=0")
    assert soft["ok"] is True
    assert soft["fallback_path"] is None
    assert str(tmp_path) not in str(soft)


def test_architecture_error_and_legacy_sdk_modes(monkeypatch):
    import ida_ida
    import idaapi

    monkeypatch.setattr(idaapi, "set_processor_type", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad processor")))
    failed_proc = analysis.analysis(action="set_architecture", processor="arm")
    assert failed_proc["error"] is True

    monkeypatch.setattr(ida_ida, "inf_get_max_ea", lambda: (_ for _ in ()).throw(RuntimeError("max unavailable")), raising=False)
    monkeypatch.setattr(ida_ida, "inf_set_app_bitness", lambda _value: (_ for _ in ()).throw(RuntimeError("bitness locked")), raising=False)
    failed_bits = analysis.analysis(action="set_architecture", bitness=32)
    assert failed_bits["error"] is True

    monkeypatch.delattr(ida_ida, "inf_set_app_bitness", raising=False)
    monkeypatch.delattr(ida_ida, "inf_set_be", raising=False)
    legacy = analysis.analysis(action="set_architecture", bitness=32, endian="le")
    assert legacy["ok"] is True
    assert legacy["applied"]["bitness_applied"] is False
    assert legacy["applied"]["endian_applied"] is False

    # The hint table has separate x86 (32/64) and PowerPC paths.
    monkeypatch.setattr(idaapi, "set_processor_type", lambda *_args: True)
    x86_64 = analysis.analysis(action="set_architecture", processor="x86", bitness=64)
    assert x86_64["applied"]["arch_hints"]["ptr_size"] == 8
    x86_32 = analysis.analysis(action="set_architecture", processor="x86", bitness=32)
    assert x86_32["applied"]["arch_hints"]["ptr_size"] == 4
    ppc = analysis.analysis(action="set_architecture", processor="powerpc")
    assert ppc["applied"]["arch_hints"]["ptr_size"] == 4


@pytest.mark.parametrize("api_name", ["plan_range", "auto_mark_range"])
def test_reanalyze_uses_available_scheduler_api(monkeypatch, api_name):
    import ida_auto
    import idaapi

    monkeypatch.delattr(ida_auto, "plan_range", raising=False)
    monkeypatch.delattr(ida_auto, "auto_mark_range", raising=False)
    calls = []
    if api_name == "auto_mark_range":
        monkeypatch.setattr(ida_auto, api_name, lambda *args: calls.append(args), raising=False)
    else:
        monkeypatch.setattr(idaapi, "auto_mark_range", lambda *args: calls.append(args), raising=False)
    result = analysis.analysis(action="reanalyze", start="0x140001000", end="0x140001100")
    assert result["ok"] is True
    assert result["mode"] in {"auto_mark_range", "idaapi.auto_mark_range"}
    assert calls


def test_reanalyze_blocking_and_state_fail_soft(monkeypatch):
    import ida_auto
    import idaapi
    import idautils

    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: False)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda *_args: (_ for _ in ()).throw(RuntimeError("step failed")), raising=False)
    monkeypatch.setattr(analysis.time, "sleep", lambda _seconds: None)
    blocking = analysis.analysis(
        action="reanalyze",
        start="0x140001000",
        end="0x140001100",
        blocking=True,
        poll_timeout=0.001,
    )
    assert blocking["ok"] is True
    assert blocking["analysis_complete"] is False

    monkeypatch.setattr(idaapi, "get_auto_state", lambda: (_ for _ in ()).throw(RuntimeError("state unavailable")), raising=False)
    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: (_ for _ in ()).throw(RuntimeError("state unavailable")))
    monkeypatch.setattr(idaapi, "get_func_qty", lambda: (_ for _ in ()).throw(RuntimeError("count unavailable")), raising=False)
    state = analysis.analysis(action="state")
    assert state == {
        "ok": True,
        "analysis_complete": False,
        "functions": -1,
        "note": "Analysis still running.",
    }

    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: True)
    monkeypatch.setattr(idautils, "Functions", lambda: (_ for _ in ()).throw(RuntimeError("enumeration failed")))
    whole = analysis.analysis(action="analyze")
    assert whole["ok"] is True
    assert whole["functions"] == 0


def test_code_and_undefine_surface_reports_sdk_failures(monkeypatch):
    import ida_bytes
    import ida_ua
    import idaapi
    import idc

    monkeypatch.setattr(ida_bytes, "del_items", lambda *_args: (_ for _ in ()).throw(RuntimeError("cannot clear")))
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: (_ for _ in ()).throw(RuntimeError("no decoder")))
    monkeypatch.setattr(idc, "create_insn", lambda _ea: (_ for _ in ()).throw(RuntimeError("no decoder")), raising=False)
    failed = analysis.analysis(action="make_code", addr="0x140001000")
    assert failed["error"] is True
    assert "create_insn" in failed["message"]
    undefined = analysis.analysis(action="undefine", addr="0x140001000")
    assert undefined["error"] is True
    assert "del_items" in undefined["message"]


def test_analysis_flags_use_inf_object_compatibility(monkeypatch):
    import ida_ida
    import idaapi
    import idc

    af_state = types.SimpleNamespace(af=0, af2=0)
    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: af_state)
    for name in ("AF_MARKCODE", "AF_USED", "AF_UNK", "AF_CODE", "AF_PROC"):
        monkeypatch.delattr(idc, name, raising=False)
    monkeypatch.setattr(idaapi, "AF_MARKCODE", 1, raising=False)
    monkeypatch.setattr(idaapi, "AF2_TEST", 2, raising=False)
    for name in ("inf_get_af", "inf_get_af2", "inf_set_af", "inf_set_af2"):
        monkeypatch.delattr(idaapi, name, raising=False)
        monkeypatch.delattr(ida_ida, name, raising=False)

    all_flags = analysis.analysis(action="get_af")
    assert all_flags["ok"] is True
    assert "AF_MARKCODE" in all_flags["flags"]
    enabled = analysis.analysis(action="set_af", af_flag="AF_MARKCODE", af_value=True)
    assert enabled["ok"] is True
    assert af_state.af & 1
    assert analysis.analysis(action="get_af", af_flag="AF2_TEST")["enabled"] is False


def test_snapshot_undo_and_auto_wait_failure_modes(monkeypatch):
    import ida_auto
    import ida_loader

    undo_calls = []
    undo = types.ModuleType("ida_undo")
    undo.create_undo_point = lambda *args: undo_calls.append(("create", args)) or True
    undo.perform_undo = lambda: undo_calls.append(("undo", ())) or True
    monkeypatch.setitem(sys.modules, "ida_undo", undo)
    monkeypatch.delattr(ida_loader, "save_snapshot", raising=False)
    monkeypatch.delattr(ida_loader, "restore_snapshot", raising=False)
    saved = analysis.analysis(action="snapshot", snapshot_name="checkpoint")
    restored = analysis.analysis(action="restore_snapshot", snapshot_id="checkpoint")
    assert saved["mechanism"] == "ida_undo"
    assert restored["mechanism"] == "ida_undo"
    assert [name for name, _args in undo_calls] == ["create", "undo"]

    monkeypatch.setattr(ida_auto, "auto_is_ok", lambda: False, raising=False)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda: (_ for _ in ()).throw(RuntimeError("pump failed")), raising=False)
    waited = analysis.analysis(action="auto_wait", timeout_ms=1)
    assert waited["ok"] is True
    assert waited["analysis_done"] is False


def test_raw_analysis_helpers_cover_unknown_arch_and_legacy_info_paths(monkeypatch):
    import ida_ida
    import idaapi
    import idautils

    monkeypatch.setattr(analysis, "get_arch", lambda: "unknown")
    monkeypatch.setattr(analysis.ida_bytes, "get_bytes", lambda _ea, size: b"\x00\x10\x00\x00" + b"\x00" * (size - 4))
    monkeypatch.setattr(analysis.idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF, raising=False)
    assert analysis._bootstrap_raw_entry_points(0x1000, 0x1100)["seeded_entries"] >= 0

    monkeypatch.delattr(idaapi, "inf_get_filetype", raising=False)
    monkeypatch.setattr(analysis.idc, "get_inf_attr", lambda _attr: analysis.idaapi.f_BIN, raising=False)
    assert analysis._is_raw_bin_filetype() is True
    monkeypatch.delattr(analysis.idc, "get_inf_attr", raising=False)
    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: types.SimpleNamespace(filetype=analysis.idaapi.f_BIN))
    assert analysis._is_raw_bin_filetype() is True

    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: (_ for _ in ()).throw(RuntimeError("no inf")))
    monkeypatch.setattr(ida_ida, "inf_get_min_ea", lambda: 0x1000, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_max_ea", lambda: 0x1100, raising=False)
    assert analysis._raw_mapped_range() == (0x1000, 0x1100)
    monkeypatch.delattr(ida_ida, "inf_get_min_ea", raising=False)
    monkeypatch.delattr(ida_ida, "inf_get_max_ea", raising=False)
    monkeypatch.setattr(analysis.idc, "get_inf_attr", lambda key: 0x1000 if key == 1 else 0x1100, raising=False)
    assert analysis._raw_mapped_range() == (0x1000, 0x1100)
    monkeypatch.setattr(idautils, "Segments", lambda: iter(()))


def test_segment_scoring_and_entry_point_failures(monkeypatch):
    import ida_funcs
    import idaapi
    import idautils

    assert analysis._segment_code_score(0xDEAD)[0] == 0
    monkeypatch.setattr(analysis._compat, "get_segment_perm", lambda _ea: 0)
    assert analysis._segment_code_score(0x140001000) == (0, 0, 0)
    monkeypatch.setattr(analysis._compat, "get_segment_perm", lambda _ea: (_ for _ in ()).throw(RuntimeError("perm")))
    assert analysis._segment_code_score(0x140001000) == (0, 0, 0)

    monkeypatch.setattr(idautils, "Segments", lambda: iter((0x140001000, 0x140002000)))
    monkeypatch.setattr(analysis._compat, "get_segment", lambda _ea: None)
    assert analysis._find_text_segments() == []

    monkeypatch.setattr(analysis, "_entry_point_addrs", lambda: [0x140001000, 0x140001040])
    monkeypatch.setattr(analysis._compat, "get_func_start", lambda ea: ea if ea == 0x140001000 else None)
    monkeypatch.setattr(ida_funcs, "add_func", lambda _ea: False)
    result = analysis._ensure_entry_point_functions()
    assert result["skipped_already_func"] == ["0x140001000"]
    assert result["failed"] == ["0x140001040"]
    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: types.SimpleNamespace(filetype=0))
