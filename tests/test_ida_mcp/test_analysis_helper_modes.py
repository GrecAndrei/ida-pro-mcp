"""Exercise the analysis helper fallbacks against the shipped fake SDK."""

from __future__ import annotations

import importlib
import struct
import types

import pytest

analysis = importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


def test_raw_filetype_detection_walks_modern_legacy_and_structure_paths(monkeypatch):
    import idaapi
    import idc

    monkeypatch.setattr(idaapi, "f_BIN", 7, raising=False)
    monkeypatch.setattr(idaapi, "f_BINARY", 8, raising=False)
    monkeypatch.setattr(idaapi, "inf_get_filetype", lambda: 7, raising=False)
    assert analysis._is_raw_bin_filetype() is True

    monkeypatch.setattr(idaapi, "inf_get_filetype", lambda: 99, raising=False)
    assert analysis._is_raw_bin_filetype() is False

    monkeypatch.delattr(idaapi, "inf_get_filetype", raising=False)
    monkeypatch.setattr(
        idc,
        "get_inf_attr",
        lambda key: 8 if key == getattr(idc, "INF_FILETYPE", -1) else None,
        raising=False,
    )
    assert analysis._is_raw_bin_filetype() is True

    monkeypatch.delattr(idc, "get_inf_attr", raising=False)
    monkeypatch.setattr(
        analysis,
        "idaapi",
        types.SimpleNamespace(
            f_BIN=7,
            f_BINARY=8,
            get_inf_structure=lambda: types.SimpleNamespace(filetype=7),
        ),
    )
    assert analysis._is_raw_bin_filetype() is True

    monkeypatch.setattr(
        analysis,
        "idaapi",
        types.SimpleNamespace(
            f_BIN=7,
            f_BINARY=8,
            get_inf_structure=lambda: (_ for _ in ()).throw(RuntimeError("gone")),
        ),
    )
    assert analysis._is_raw_bin_filetype() is False


def test_raw_mapped_range_uses_structure_and_idc_fallbacks(monkeypatch):
    import ida_ida
    import idc

    monkeypatch.setattr(ida_ida, "inf_get_min_ea", lambda: 0x1000, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_max_ea", lambda: 0x2000, raising=False)
    assert analysis._raw_mapped_range() == (0x1000, 0x2000)

    monkeypatch.setattr(ida_ida, "inf_get_min_ea", lambda: 0x3000, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_max_ea", lambda: 0x2000, raising=False)
    monkeypatch.setattr(
        analysis,
        "idaapi",
        types.SimpleNamespace(
            get_inf_structure=lambda: types.SimpleNamespace(min_ea=0x4000, max_ea=0x5000)
        ),
    )
    assert analysis._raw_mapped_range() == (0x4000, 0x5000)

    monkeypatch.setattr(
        analysis,
        "idaapi",
        types.SimpleNamespace(get_inf_structure=lambda: types.SimpleNamespace(min_ea=0x5000, max_ea=0x4000)),
    )
    monkeypatch.setattr(
        idc,
        "get_inf_attr",
        lambda key: {getattr(idc, "INF_MIN_EA", -1): 0x6000, getattr(idc, "INF_MAX_EA", -1): 0x7000}.get(key),  # noqa: PLW0108
        raising=False,
    )
    assert analysis._raw_mapped_range() == (0x6000, 0x7000)

    monkeypatch.setattr(
        idc,
        "get_inf_attr",
        lambda _key: (_ for _ in ()).throw(RuntimeError("no info")),
        raising=False,
    )
    assert analysis._raw_mapped_range() is None


def test_segment_code_score_reports_missing_and_broken_sdk_paths(monkeypatch):
    import ida_bytes
    import idaapi
    import idc

    segment = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
    monkeypatch.setattr(analysis._compat, "get_segment", lambda _ea: None)
    assert analysis._segment_code_score(0x1000) == (0, 0, 0)

    monkeypatch.setattr(analysis._compat, "get_segment", lambda _ea: segment)
    monkeypatch.setattr(analysis._compat, "get_segment_perm", lambda _ea: 0)
    assert analysis._segment_code_score(0x1000) == (0, 0, 0)

    monkeypatch.setattr(
        analysis._compat,
        "get_segment_perm",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("permissions")),
    )
    assert analysis._segment_code_score(0x1000) == (0, 0, 0)

    monkeypatch.setattr(analysis._compat, "get_segment_perm", lambda _ea: idaapi.SEGPERM_EXEC)
    segment.end_ea = segment.start_ea
    assert analysis._segment_code_score(0x1000) == (0, 0, 0)
    segment.end_ea = 0x1008

    monkeypatch.setattr(ida_bytes, "get_flags", lambda _ea: (_ for _ in ()).throw(RuntimeError("flags")))
    assert analysis._segment_code_score(0x1000) == (0, 8, 0)

    monkeypatch.setattr(ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(ida_bytes, "is_code", lambda _flags: (_ for _ in ()).throw(RuntimeError("kind")))
    monkeypatch.setattr(idc, "next_head", lambda _ea, _end: idaapi.BADADDR, raising=False)
    assert analysis._segment_code_score(0x1000) == (0, 8, 0)

    monkeypatch.setattr(ida_bytes, "is_code", lambda _flags: True)
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 4, raising=False)
    monkeypatch.setattr(idc, "next_head", lambda _ea, _end: (_ for _ in ()).throw(RuntimeError("walk")), raising=False)
    assert analysis._segment_code_score(0x1000) == (4, 8, 1)


def test_find_text_segments_deduplicates_and_uses_raw_mapped_fallback(monkeypatch):
    import idaapi
    import idautils

    seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1200)
    seg_small = types.SimpleNamespace(start_ea=0x2000, end_ea=0x2050)
    seg_skip = types.SimpleNamespace(start_ea=0x3000, end_ea=0x3200)
    seg_broken = types.SimpleNamespace(start_ea=0x4000, end_ea=0x4200)
    segmap = {0x1000: seg, 0x1001: seg, 0x2000: seg_small, 0x3000: seg_skip, 0x4000: seg_broken}
    monkeypatch.setattr(idautils, "Segments", lambda: iter(segmap), raising=False)
    monkeypatch.setattr(analysis._compat, "get_segment", lambda ea: segmap.get(ea))  # noqa: PLW0108
    monkeypatch.setattr(
        analysis._compat,
        "get_segment_perm",
        lambda ea: (_ for _ in ()).throw(RuntimeError("perm")) if ea == 0x4000 else idaapi.SEGPERM_EXEC,
    )
    monkeypatch.setattr(
        analysis._compat,
        "get_segment_name",
        lambda ea: ".plt" if ea == 0x3000 else ".text",
    )
    assert analysis._find_text_segments() == [(0x1000, 0x1200, ".text")]

    monkeypatch.setattr(analysis, "_is_raw_bin_filetype", lambda: True)
    monkeypatch.setattr(analysis, "_raw_mapped_range", lambda: (0x5000, 0x5300))
    monkeypatch.setattr(idautils, "Segments", lambda: iter(()), raising=False)
    assert analysis._find_text_segments() == [(0x5000, 0x5300, "<raw-mapped>")]

    monkeypatch.setattr(analysis, "_raw_mapped_range", lambda: (0x5000, 0x5050))
    assert analysis._find_text_segments() == []


def test_auto_reanalyze_falls_back_to_step_pump_and_reports_warning(monkeypatch):
    import ida_auto
    import idaapi

    ranges = [(0x1000, 0x1100, "<raw-mapped>"), (0x2000, 0x2100, ".text")]
    monkeypatch.setattr(analysis, "_find_text_segments", lambda: list(ranges))
    monkeypatch.setattr(analysis, "_is_raw_bin_filetype", lambda: False)
    scores = iter([(1, 10, 1), (2, 10, 2), (3, 10, 3), (5, 10, 5)])
    monkeypatch.setattr(analysis, "_segment_code_score", lambda _ea: next(scores))
    quantities = iter((2, 5))
    monkeypatch.setattr(idaapi, "get_func_qty", lambda: next(quantities), raising=False)
    plans = []
    monkeypatch.setattr(ida_auto, "plan_range", lambda s, e: plans.append((s, e)), raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait_range", lambda *_args: (_ for _ in ()).throw(RuntimeError("stuck")), raising=False)
    state = iter((False, True))
    monkeypatch.setattr(idaapi, "auto_is_ok", lambda: next(state), raising=False)
    steps = []
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda *args: steps.append(args), raising=False)
    monkeypatch.setattr(analysis.time, "sleep", lambda _seconds: None)
    result = analysis._auto_reanalyze_text_segments(wait_seconds=1)

    assert plans == [(0x1000, 0x1100), (0x2000, 0x2100)]
    assert steps
    assert result["warning"]
    assert result["scheduled"] == 2
    assert result["functions_added"] == 3
    assert result["reanalysis_triggered"] is True


def test_auto_reanalyze_handles_raw_bootstrap_and_scheduler_variants(monkeypatch):
    import ida_auto
    import idaapi

    monkeypatch.setattr(analysis, "_find_text_segments", list)
    monkeypatch.setattr(analysis, "_is_raw_bin_filetype", lambda: True)
    monkeypatch.setattr(analysis, "_raw_mapped_range", lambda: (0x1000, 0x1200))
    monkeypatch.setattr(analysis, "_bootstrap_raw_entry_points", lambda *_args: {"seeded_entries": 1})
    monkeypatch.setattr(analysis, "_segment_code_score", lambda _ea: (0, 10, 0))
    monkeypatch.setattr(idaapi, "get_func_qty", lambda: 0, raising=False)
    monkeypatch.delattr(ida_auto, "plan_range", raising=False)
    monkeypatch.delattr(ida_auto, "auto_mark_range", raising=False)
    calls = []
    monkeypatch.setattr(idaapi, "auto_mark_range", lambda *args: calls.append(args), raising=False)
    result = analysis._auto_reanalyze_text_segments(wait_seconds=0)
    assert result["eligible_ranges"] == [{"start": "0x1000", "end": "0x1200", "name": "<raw-mapped>"}]
    assert result["scheduled"] == 1
    assert calls == [(0x1000, 0x1200, idaapi.AU_FINAL)]


def test_entry_point_helpers_cover_skip_create_and_failure_paths(monkeypatch):
    import ida_entry
    import ida_funcs
    import idaapi

    monkeypatch.setattr(ida_entry, "get_entry_qty", lambda: 4, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_ordinal", lambda index: index + 1, raising=False)
    monkeypatch.setattr(
        ida_entry,
        "get_entry",
        lambda ordinal: {1: 0x1000, 2: idaapi.BADADDR, 3: 0x2000, 4: 0x1000}[ordinal],
        raising=False,
    )
    assert analysis._entry_point_addrs() == [0x1000, 0x2000]

    monkeypatch.setattr(ida_entry, "get_entry_qty", lambda: (_ for _ in ()).throw(RuntimeError("entries")), raising=False)
    assert analysis._entry_point_addrs() == []

    monkeypatch.setattr(analysis, "_entry_point_addrs", lambda: [0x1000, 0x2000, 0x3000, 0x4000])
    monkeypatch.setattr(
        analysis._compat,
        "get_func_start",
        lambda ea: 0x1000 if ea == 0x1000 else None,
    )
    monkeypatch.setattr(ida_funcs, "add_func", lambda ea: ea != 0x3000, raising=False)
    result = analysis._ensure_entry_point_functions()
    assert result["skipped_already_func"] == ["0x1000"]
    assert result["created"] == ["0x2000", "0x4000"]
    assert result["failed"] == ["0x3000"]

    monkeypatch.setattr(analysis._compat, "get_func_start", lambda _ea: (_ for _ in ()).throw(RuntimeError("lookup")))
    failed = analysis._ensure_entry_point_functions()
    assert failed["failed"] == ["0x1000", "0x2000", "0x3000", "0x4000"]


def test_bootstrap_raw_entry_points_covers_size_and_instruction_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import ida_funcs
    import ida_ua
    import idaapi
    import idc

    assert analysis._bootstrap_raw_entry_points(0x1000, 0x1004) == {"seeded_entries": 0}
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda *_args: b"short", raising=False)
    assert analysis._bootstrap_raw_entry_points(0x1000, 0x1100) == {"seeded_entries": 0}

    fresh_fake_idb.processor = "riscv"
    raw = bytearray(0x40)
    raw[4:8] = struct.pack("<I", 0x1021)
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda _ea, size: bytes(raw[:size]), raising=False)
    monkeypatch.setattr(analysis, "get_arch", lambda: "riscv")
    monkeypatch.setattr(analysis, "is_riscv_family", lambda _arch=None: True)
    monkeypatch.setattr(analysis, "is_arm_family", lambda _arch=None: False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "not-an-instruction", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda *_args: idaapi.BADADDR, raising=False)
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: (_ for _ in ()).throw(RuntimeError("new API")), raising=False)
    monkeypatch.setattr(idc, "create_insn", lambda _ea: 2, raising=False)
    monkeypatch.setattr(analysis._compat, "get_func_start", lambda _ea: None)
    added = []
    monkeypatch.setattr(ida_funcs, "add_func", lambda *args: added.append(args) or False, raising=False)
    result = analysis._bootstrap_raw_entry_points(0x1000, 0x1100)
    assert result["seeded_entries"] == 0
    assert added
