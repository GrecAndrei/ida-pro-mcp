"""Deep boundary matrix tests for analysis.py reaching 99%+ coverage."""

from __future__ import annotations

import importlib
import struct
import sys
import time
import types

import pytest

from ida_pro_mcp.ida_mcp.tools._common import MCPError
from tests.fakes.ida_fake import BADADDR


def _analysis():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.analysis")


def test_analysis_undefine_validation_errors():
    analysis_mod = _analysis()
    res = analysis_mod.analysis(action="undefine")
    assert res.get("error") is True
    assert "addr required" in res["message"]

    res_invalid = analysis_mod.analysis(action="undefine", addr="not-a-hex")
    assert res_invalid.get("error") is True


def test_analysis_get_af_and_af2_exception_paths(monkeypatch):
    analysis_mod = _analysis()

    class BadInf:
        @property
        def af(self):
            raise RuntimeError("af boom")

        @property
        def af2(self):
            raise RuntimeError("af2 boom")

    monkeypatch.setattr(analysis_mod.idaapi, "get_inf_structure", BadInf)
    monkeypatch.setattr(
        analysis_mod.idaapi,
        "inf_get_af",
        lambda: (_ for _ in ()).throw(RuntimeError("fn boom")),
        raising=False,
    )
    monkeypatch.setattr(
        analysis_mod.idaapi,
        "inf_get_af2",
        lambda: (_ for _ in ()).throw(RuntimeError("fn2 boom")),
        raising=False,
    )

    res = analysis_mod.analysis(action="get_af")
    assert res["ok"] is True
    assert res["af_raw"] == "0x0"
    assert res["af2_raw"] == "0x0"


def test_analysis_set_af_raw_exception_and_failure_paths(monkeypatch):
    analysis_mod = _analysis()

    class ExplodingInf:
        @property
        def af(self):
            raise RuntimeError("getter boom")

        @af.setter
        def af(self, val):
            raise RuntimeError("setter boom")

    monkeypatch.setattr(analysis_mod.idaapi, "get_inf_structure", ExplodingInf)
    monkeypatch.setattr(analysis_mod.idc, "AF_FINAL", 0x1, raising=False)
    import ida_ida
    monkeypatch.setattr(ida_ida, "inf_set_af", lambda _v: (_ for _ in ()).throw(RuntimeError("set af boom")), raising=False)

    # _set_af_raw fails completely -> line 966
    res = analysis_mod.analysis(action="set_af", af_flag="AF_FINAL", af_value=True)
    assert res.get("error") is True
    assert "Could not set" in res["message"]


def test_analysis_force_offset_validation_errors():
    analysis_mod = _analysis()
    res = analysis_mod.analysis(action="force_offset")
    assert res.get("error") is True
    assert "addr required" in res["message"]

    res_invalid = analysis_mod.analysis(action="force_offset", addr="invalid-address")
    assert res_invalid.get("error") is True


def test_analysis_restore_snapshot_exception(monkeypatch):
    analysis_mod = _analysis()
    fake_undo = types.ModuleType("ida_undo")
    fake_undo.perform_undo = lambda: (_ for _ in ()).throw(RuntimeError("undo failed"))
    monkeypatch.setitem(sys.modules, "ida_undo", fake_undo)

    res = analysis_mod.analysis(action="restore_snapshot", snapshot_name="my_snap")
    assert res.get("error") is True
    assert "restore_snapshot failed" in res["message"]


def test_analysis_auto_wait_without_auto_is_ok(monkeypatch):
    analysis_mod = _analysis()
    import ida_auto

    monkeypatch.delattr(ida_auto, "auto_is_ok", raising=False)
    monkeypatch.delattr(analysis_mod.idaapi, "auto_is_ok", raising=False)

    res = analysis_mod.analysis(action="auto_wait", timeout_ms=50)
    assert res["ok"] is True
    assert res["analysis_done"] is True


def test_bootstrap_raw_entry_points_riscv_auipc_and_exceptions(monkeypatch):
    analysis_mod = _analysis()

    raw_data = b"\x00" * 64
    monkeypatch.setattr(analysis_mod.ida_bytes, "get_bytes", lambda _ea, _sz: raw_data)
    monkeypatch.setattr(analysis_mod, "get_arch", lambda: "riscv")

    def fake_print_insn_mnem(ea):
        if ea == 0x1000:
            return "auipc"
        if ea == 0x1004:
            return "jalr"
        return ""

    def fake_get_operand_value(ea, n):
        if ea == 0x1000 and n == 1:
            return 0  # imm=0 -> ra = 0x1000
        if ea == 0x1004 and n == 2:
            return 0x10  # imm12=0x10 -> tgt = 0x1010
        return 0

    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", fake_print_insn_mnem)
    monkeypatch.setattr(analysis_mod.idc, "get_operand_value", fake_get_operand_value)
    monkeypatch.setattr(analysis_mod.idc, "next_head", lambda ea, _end: 0x1004 if ea == 0x1000 else BADADDR)
    monkeypatch.setattr(analysis_mod._compat, "get_func_start", lambda _ea: None)
    monkeypatch.setattr(analysis_mod.idc, "create_insn", lambda _ea: 1)
    monkeypatch.setattr(analysis_mod.ida_funcs, "add_func", lambda *_a: True)

    import ida_entry
    monkeypatch.setattr(ida_entry, "add_entry", lambda *_a: (_ for _ in ()).throw(RuntimeError("add entry failed")))

    res = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert res["seeded_entries"] >= 1

    # Also test sign-extended negative imm20 and imm12
    def fake_get_operand_value_signed(ea, n):
        if ea == 0x1000 and n == 1:
            return 0x80001
        if ea == 0x1004 and n == 2:
            return 0x810
        return 0
    monkeypatch.setattr(analysis_mod.idc, "get_operand_value", fake_get_operand_value_signed)
    res_signed = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert isinstance(res_signed, dict)

    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", lambda _ea: "jal")
    monkeypatch.setattr(analysis_mod.idc, "get_operand_value", lambda *_a: (_ for _ in ()).throw(RuntimeError("op boom")))
    res_jal_err = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert isinstance(res_jal_err, dict)

    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", lambda _ea: "")
    monkeypatch.setattr(analysis_mod.idc, "create_insn", lambda _ea: 0)
    import ida_ua
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: 0)
    res_no_create = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert isinstance(res_no_create, dict)


def test_raw_mapped_range_exception(monkeypatch):
    analysis_mod = _analysis()
    fake_ida_ida = types.ModuleType("ida_ida")
    fake_ida_ida.inf_get_min_ea = lambda: (_ for _ in ()).throw(RuntimeError("min boom"))
    fake_ida_ida.inf_get_max_ea = lambda: 0x2000
    monkeypatch.setitem(sys.modules, "ida_ida", fake_ida_ida)

    res = analysis_mod._raw_mapped_range()
    assert res is None or isinstance(res, tuple)


def test_find_text_segments_name_exception(monkeypatch):
    analysis_mod = _analysis()
    monkeypatch.setattr(analysis_mod.idautils, "Segments", lambda: [0x1000])
    monkeypatch.setattr(analysis_mod._compat, "get_segment", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x2000))
    monkeypatch.setattr(analysis_mod._compat, "get_segment_perm", lambda _ea: analysis_mod.idaapi.SEGPERM_EXEC)
    monkeypatch.setattr(analysis_mod._compat, "get_segment_name", lambda _ea: (_ for _ in ()).throw(RuntimeError("name boom")))

    segs = analysis_mod._find_text_segments()
    assert len(segs) == 1
    assert segs[0][2] == ""


def test_auto_reanalyze_text_segments_boundary_matrix(monkeypatch):
    analysis_mod = _analysis()

    monkeypatch.setattr(analysis_mod, "_find_text_segments", list)
    monkeypatch.setattr(analysis_mod, "_raw_mapped_range", lambda: (0x1000, 0x2000))
    monkeypatch.setattr(analysis_mod, "_bootstrap_raw_entry_points", lambda *_a: (_ for _ in ()).throw(RuntimeError("boot boom")))

    res = analysis_mod._auto_reanalyze_text_segments(wait_seconds=0)
    assert res["scheduled"] == 0

    monkeypatch.setattr(analysis_mod, "_find_text_segments", lambda: [(0x1000, 0x2000, ".text")])
    import ida_auto
    monkeypatch.delattr(ida_auto, "plan_range", raising=False)

    call_count = {"mark": 0}

    def fake_auto_mark_range(s, e, flag):
        call_count["mark"] += 1
        if call_count["mark"] == 1:
            raise RuntimeError("mark boom")

    monkeypatch.setattr(ida_auto, "auto_mark_range", fake_auto_mark_range, raising=False)

    res2 = analysis_mod._auto_reanalyze_text_segments(wait_seconds=0)
    assert isinstance(res2, dict)

    monkeypatch.setattr(analysis_mod, "_find_text_segments", lambda: [(0x1000, 0x2000, ".text"), (0x2000, 0x3000, ".text2")])
    monkeypatch.setattr(ida_auto, "plan_range", lambda s, e: None, raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait_range", lambda s, e: (_ for _ in ()).throw(RuntimeError("wait range failed")), raising=False)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda s, e: (_ for _ in ()).throw(RuntimeError("step boom")), raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "auto_is_ok", lambda: False, raising=False)

    res3 = analysis_mod._auto_reanalyze_text_segments(wait_seconds=0.01)
    assert res3["scheduled"] == 2


def test_ensure_entry_point_functions_add_func_exception(monkeypatch):
    analysis_mod = _analysis()
    monkeypatch.setattr(analysis_mod, "_entry_point_addrs", lambda: [0x1000])
    monkeypatch.setattr(analysis_mod._compat, "get_func_start", lambda _ea: None)
    import ida_funcs
    monkeypatch.setattr(ida_funcs, "add_func", lambda _ea: (_ for _ in ()).throw(RuntimeError("add func boom")))

    res = analysis_mod._ensure_entry_point_functions()
    assert "0x1000" in res["failed"]


def test_get_loader_name_fallbacks_and_type_error(monkeypatch):
    analysis_mod = _analysis()
    import ida_loader
    import ida_nalt

    def fake_get_loader_name(path=None):
        if path is None:
            raise TypeError("missing required path argument")
        raise RuntimeError("cannot read file")

    monkeypatch.setattr(ida_loader, "get_loader_name", fake_get_loader_name)
    monkeypatch.setattr(ida_nalt, "get_input_file_path", lambda: "/tmp/sample.bin", raising=False)

    res = analysis_mod.analysis(action="get_options")
    assert res["ok"] is True
    assert res["loader"] is None


def test_analysis_get_options_and_rebase_edge_cases(monkeypatch):
    analysis_mod = _analysis()
    import ida_ida

    # 1. inf_get_baseaddr raises Exception (lines 231-232)
    monkeypatch.setattr(analysis_mod.idc, "get_inf_attr", lambda _k: None, raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_baseaddr", lambda: (_ for _ in ()).throw(RuntimeError("base boom")), raising=False)
    # 2. idc.set_inf_attr raises Exception (lines 253-254)
    monkeypatch.setattr(analysis_mod.idc, "INF_START_EA", 1, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "set_inf_attr", lambda _k, _v: (_ for _ in ()).throw(RuntimeError("set attr boom")), raising=False)

    res = analysis_mod.analysis(action="set_options", options={"start_ea": 0x1000})
    assert res.get("error") is True
    assert "set attr boom" in res["message"]

    # 3. rebase_program non-callable (line 286)
    monkeypatch.setattr(analysis_mod.idc, "INF_BASEADDR", 10, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "rebase_program", None, raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "rebase_program", None, raising=False)
    import ida_segment
    monkeypatch.setattr(ida_segment, "rebase_program", None, raising=False)
    monkeypatch.setattr(analysis_mod.idc, "set_inf_attr", lambda _k, _v: True, raising=False)
    res_rebase = analysis_mod.analysis(action="set_options", options={"baseaddr": 0x2000})
    assert res_rebase.get("error") is True

    # 4. set_gp with riscv processor (lines 372-373)
    monkeypatch.setattr(analysis_mod, "_inf_procname", lambda: "riscv")
    res_gp = analysis_mod.analysis(action="set_gp", gp="0x2556f0")
    assert isinstance(res_gp, dict)


def test_analysis_reanalyze_entry_point_created_and_raw_blob(monkeypatch):
    analysis_mod = _analysis()

    # Line 640: ep.get("created") populated
    monkeypatch.setattr(analysis_mod, "_auto_reanalyze_text_segments", lambda wait_seconds: {"waited_seconds": 0.1})
    monkeypatch.setattr(analysis_mod, "_ensure_entry_point_functions", lambda: {"created": ["0x1000"]})
    res = analysis_mod.analysis(action="reanalyze", blocking=True)
    assert res["ok"] is True
    assert "entry_point_funcs_created" in res["reanalyze"]

    # Lines 676-677: get_inf_structure raises in raw check
    # Line 679: func_count == 0 and _is_raw calls _bootstrap_raw_entry_points
    class RawInf:
        filetype = getattr(analysis_mod.idaapi, "f_BIN", 0)

    monkeypatch.setattr(analysis_mod.idaapi, "get_inf_structure", RawInf)
    monkeypatch.setattr(analysis_mod.idautils, "Functions", list)
    boot_called = []
    monkeypatch.setattr(analysis_mod, "_bootstrap_raw_entry_points", lambda s, e: boot_called.append((s, e)) or {"seeded_entries": 1})
    res_raw = analysis_mod.analysis(action="reanalyze", start_addr=0x1000, end_addr=0x2000, blocking=False)
    assert res_raw["ok"] is True
    assert len(boot_called) == 1

    # Exception in get_inf_structure
    monkeypatch.setattr(analysis_mod.idaapi, "get_inf_structure", lambda: (_ for _ in ()).throw(RuntimeError("inf boom")))
    res_raw_err = analysis_mod.analysis(action="reanalyze", start_addr=0x1000, end_addr=0x2000, blocking=False)
    assert res_raw_err["ok"] is True


def test_analysis_make_code_validation_errors():
    analysis_mod = _analysis()
    res = analysis_mod.analysis(action="make_code")
    assert res.get("error") is True
    assert "addr required" in res["message"]

    res_inv = analysis_mod.analysis(action="make_code", addr="bad-addr")
    assert res_inv.get("error") is True


def test_analysis_get_af2_import_exception(monkeypatch):
    analysis_mod = _analysis()
    monkeypatch.setattr(analysis_mod.idaapi, "inf_get_af", lambda: 0, raising=False)
    monkeypatch.delattr(analysis_mod.idaapi, "inf_get_af2", raising=False)
    import builtins
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "ida_ida":
            raise ImportError("no ida_ida")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    res = analysis_mod.analysis(action="get_af")
    assert res["ok"] is True


def test_analysis_add_entry_validation_and_exceptions(monkeypatch):
    analysis_mod = _analysis()

    # 1. Invalid addr (line 1031)
    res_bad_addr = analysis_mod.analysis(action="add_entry", addr="not-a-valid-hex")
    assert res_bad_addr.get("error") is True

    # 2. ordinal=None and get_entry_qty raises (lines 1037-1038)
    monkeypatch.setattr(analysis_mod, "validate_addr", lambda ea: (0x1000, None))
    import ida_entry
    monkeypatch.setattr(ida_entry, "get_entry_qty", lambda: (_ for _ in ()).throw(RuntimeError("qty boom")))
    res_no_ord = analysis_mod.analysis(action="add_entry", addr="0x1000")
    assert res_no_ord.get("error") is True
    assert "ordinal required" in res_no_ord["message"]

    # 3. add_entry raises TypeError then Exception (lines 1056-1057)
    def fake_add_entry(*args):
        if len(args) == 4:
            raise TypeError("bad 4-arg")
        raise RuntimeError("bad 3-arg")

    monkeypatch.setattr(ida_entry, "add_entry", fake_add_entry)
    res_type_err = analysis_mod.analysis(action="add_entry", addr="0x1000", ordinal=1)
    assert res_type_err.get("error") is True
    assert "add_entry failed" in res_type_err["message"]

    # 4. add_entry raises Exception directly (lines 1058-1059)
    monkeypatch.setattr(ida_entry, "add_entry", lambda *_a: (_ for _ in ()).throw(RuntimeError("add entry boom")))
    res_add_err = analysis_mod.analysis(action="add_entry", addr="0x1000", ordinal=1)
    assert res_add_err.get("error") is True
    assert "add_entry failed" in res_add_err["message"]


def test_analysis_snapshot_save_failure_and_undo_break(monkeypatch):
    analysis_mod = _analysis()
    import ida_loader

    # 1. save_snapshot raises Exception (lines 1103-1104)
    monkeypatch.setattr(ida_loader, "save_snapshot", lambda *_a: (_ for _ in ()).throw(RuntimeError("save boom")), raising=False)
    res_snap_err = analysis_mod.analysis(action="snapshot", snapshot_name="snap1")
    assert res_snap_err.get("error") is True

    # 2. save_snapshot returns False (line 1106)
    monkeypatch.setattr(ida_loader, "save_snapshot", lambda *_a: False, raising=False)
    res_snap_false = analysis_mod.analysis(action="snapshot", snapshot_name="snap2")
    assert res_snap_false.get("error") is True
    assert "save_snapshot failed" in res_snap_false["message"]

    # 3. restore_snapshot undo returns False (lines 1153 break and 1157)
    monkeypatch.delattr(ida_loader, "restore_snapshot", raising=False)
    fake_undo = types.ModuleType("ida_undo")
    fake_undo.perform_undo = lambda: False
    monkeypatch.setitem(sys.modules, "ida_undo", fake_undo)
    res_undo_false = analysis_mod.analysis(action="restore_snapshot", snapshot_name="snap3")
    assert res_undo_false.get("error") is True


def test_analysis_auto_wait_type_error_and_deadline(monkeypatch):
    analysis_mod = _analysis()
    import ida_auto

    # 1. auto_make_step raises TypeError then Exception (lines 1211-1212)
    call_count = {"step": 0}

    def fake_step(*args):
        call_count["step"] += 1
        if len(args) == 0:
            raise TypeError("no 0-arg")
        raise RuntimeError("2-arg boom")

    monkeypatch.setattr(ida_auto, "auto_is_ok", lambda: False)
    monkeypatch.setattr(ida_auto, "auto_make_step", fake_step)
    res_step = analysis_mod.analysis(action="auto_wait", timeout_ms=100)
    assert res_step["ok"] is True

    # 2. Deadline expiration (lines 1219-1220)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda: None)
    monkeypatch.setattr(time, "time", lambda: 10000000.0)
    res_dead = analysis_mod.analysis(action="auto_wait", timeout_ms=0)
    assert res_dead["ok"] is True
    assert res_dead["timed_out"] is True

    # 3. Outer exception handler in analysis (lines 1239-1240)
    monkeypatch.setattr(analysis_mod, "validate_addr", lambda *_a: (_ for _ in ()).throw(RuntimeError("outer boom")))
    res_outer = analysis_mod.analysis(action="make_code", addr="0x1000")
    assert res_outer.get("error") is True


def test_bootstrap_raw_entry_points_remaining_paths(monkeypatch):
    analysis_mod = _analysis()

    # 1. raw & 0xFFFF0000 base calculation (lines 1281-1284)
    raw_val = 0x80001010
    raw_bytes = b"\x00\x00\x00\x00" + struct.pack("<I", raw_val) + b"\x00" * 56
    monkeypatch.setattr(analysis_mod.ida_bytes, "get_bytes", lambda _ea, _sz: raw_bytes)
    monkeypatch.setattr(analysis_mod, "get_arch", lambda: "arm")
    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", lambda _ea: "")

    # 2. _compat.get_func_start(ea) is not None (lines 1351-1352)
    monkeypatch.setattr(analysis_mod._compat, "get_func_start", lambda ea: ea)

    res_seeded = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x3000)
    assert res_seeded["seeded_entries"] >= 1

    # 3. idc.print_insn_mnem raises (lines 1291-1292)
    monkeypatch.setattr(analysis_mod, "get_arch", lambda: "riscv")
    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", lambda _ea: (_ for _ in ()).throw(RuntimeError("mnem boom")))
    res_mnem_err = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x3000)
    assert isinstance(res_mnem_err, dict)

    # 4. Outer candidate exception (lines 1372-1373)
    def boom_func_start(_ea):
        raise RuntimeError("cand boom")
    monkeypatch.setattr(analysis_mod._compat, "get_func_start", boom_func_start)
    res_cand_err = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x3000)
    assert isinstance(res_cand_err, dict)


def test_auto_reanalyze_text_segments_remaining_exceptions(monkeypatch):
    analysis_mod = _analysis()
    monkeypatch.setattr(analysis_mod, "_find_text_segments", lambda: [(0x1000, 0x2000, ".text")])

    # 1. _segment_code_score raises before and after (lines 1596-1597, 1675-1676)
    monkeypatch.setattr(analysis_mod, "_segment_code_score", lambda _s: (_ for _ in ()).throw(RuntimeError("score boom")))

    # 2. Neither plan_range nor auto_mark_range (line 1608)
    import ida_auto
    monkeypatch.delattr(ida_auto, "plan_range", raising=False)
    monkeypatch.delattr(ida_auto, "auto_mark_range", raising=False)
    monkeypatch.delattr(analysis_mod.idaapi, "auto_mark_range", raising=False)

    res_no_plan = analysis_mod._auto_reanalyze_text_segments(wait_seconds=0)
    assert res_no_plan["scheduled"] == 0

    # 3. Timeout inside range walk (line 1636) and outer exception in wait loop (lines 1658-1659)
    monkeypatch.setattr(analysis_mod, "_segment_code_score", lambda _s: (10, 100, 5))
    monkeypatch.setattr(ida_auto, "plan_range", lambda s, e: None, raising=False)
    monkeypatch.setattr(ida_auto, "auto_wait_range", lambda s, e: None, raising=False)

    time_calls = [0.0, 10.0, 20.0, 30.0]
    monkeypatch.setattr(time, "time", lambda: time_calls.pop(0) if time_calls else 50.0)

    res_timeout = analysis_mod._auto_reanalyze_text_segments(wait_seconds=1.0)
    assert res_timeout["scheduled"] == 1


def test_analysis_final_edge_cases_100(monkeypatch):
    analysis_mod = _analysis()

    # 1. Lines 372-373: set_gp on riscv
    monkeypatch.setattr(analysis_mod, "is_riscv_family", lambda *a: True)
    import ida_pro_mcp.ida_mcp.support.arch_utils as arch_utils
    monkeypatch.setattr(arch_utils, "set_riscv_gp", lambda gp: {"ok": True, "gp": hex(gp)})
    res_gp = analysis_mod.analysis(action="set_gp", gp="0x2556f0")
    assert res_gp["ok"] is True
    assert res_gp["gp"] == "0x2556f0"

    # 2. Lines 929-930 & 935-937: _get_af_raw exception handling in set_af
    import ida_ida
    monkeypatch.setattr(analysis_mod.idc, "AF_USED", 0x1, raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "inf_get_af", lambda: (_ for _ in ()).throw(RuntimeError("raw af boom")), raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_af", lambda: (_ for _ in ()).throw(RuntimeError("raw af boom 2")), raising=False)
    monkeypatch.setattr(analysis_mod.idaapi, "get_inf_structure", lambda: (_ for _ in ()).throw(RuntimeError("inf boom")), raising=False)
    res_af_raw = analysis_mod.analysis(action="set_af", af_flag="AF_USED", af_value=True)
    assert isinstance(res_af_raw, dict)

    # 3. Lines 1154-1155: restore_snapshot ida_undo exception
    import ida_loader
    monkeypatch.delattr(ida_loader, "restore_snapshot", raising=False)
    fake_undo = types.ModuleType("ida_undo")
    fake_undo.perform_undo = lambda: (_ for _ in ()).throw(RuntimeError("undo boom"))
    monkeypatch.setitem(sys.modules, "ida_undo", fake_undo)
    res_undo_err = analysis_mod.analysis(action="restore_snapshot", ordinal=0)
    assert res_undo_err.get("error") is True
    assert "restore_snapshot failed: undo boom" in res_undo_err["message"]

    # 4. Lines 1219-1220: auto_wait timeout when budget_ms > 0
    import ida_auto
    monkeypatch.setattr(ida_auto, "auto_is_ok", lambda: False)
    monkeypatch.setattr(ida_auto, "auto_make_step", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    t_vals = [100.0, 100.0, 200.0]
    monkeypatch.setattr(time, "time", lambda: t_vals.pop(0) if t_vals else 300.0)
    res_wait_timeout = analysis_mod.analysis(action="auto_wait", budget_ms=50)
    assert res_wait_timeout["ok"] is True
    assert res_wait_timeout["timed_out"] is True

    # 5. Lines 1315-1316: _bootstrap_raw_entry_points riscv auipc exception
    monkeypatch.setattr(analysis_mod, "get_arch", lambda: "riscv")
    monkeypatch.setattr(analysis_mod.idc, "print_insn_mnem", lambda _ea: "auipc")
    monkeypatch.setattr(analysis_mod.idc, "get_operand_value", lambda _ea, _n: (_ for _ in ()).throw(RuntimeError("operand boom")))
    res_riscv_err = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert isinstance(res_riscv_err, dict)

    # 6. Line 1363: created == 0 continue in _bootstrap_raw_entry_points
    analysis_mod = _analysis()
    raw_bytes = b"\x00\x00\x00\x00" + struct.pack("<I", 0x1010) + b"\x00" * 56
    monkeypatch.setattr(analysis_mod.ida_bytes, "get_bytes", lambda _ea, _sz: raw_bytes)
    monkeypatch.setattr(analysis_mod, "get_arch", lambda: "arm")
    monkeypatch.setattr(analysis_mod._compat, "get_func_start", lambda _ea: None)
    import ida_ua
    monkeypatch.setattr(ida_ua, "create_insn", lambda _ea: 0)
    monkeypatch.setattr(analysis_mod.idc, "create_insn", lambda _ea: 0)
    res_zero_insn = analysis_mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert res_zero_insn["seeded_entries"] == 0

    # 7. Lines 1576-1577: _bootstrap_raw_entry_points raises in _auto_reanalyze_text_segments
    monkeypatch.setattr(analysis_mod, "_find_text_segments", list)
    monkeypatch.setattr(analysis_mod, "_is_raw_bin_filetype", lambda: True)
    monkeypatch.setattr(analysis_mod, "_raw_mapped_range", lambda: (0x1000, 0x2000))
    monkeypatch.setattr(analysis_mod, "_bootstrap_raw_entry_points", lambda *_a: (_ for _ in ()).throw(RuntimeError("boot boom")))
    res_boot_err = analysis_mod._auto_reanalyze_text_segments(wait_seconds=0)
    assert isinstance(res_boot_err, dict)

    # 8. Lines 1658-1659: outer exception in wait_seconds loop in _auto_reanalyze_text_segments
    monkeypatch.setattr(analysis_mod, "_find_text_segments", lambda: [(0x1000, 0x2000, ".text")])
    monkeypatch.setattr(ida_auto, "plan_range", lambda s, e: None)
    t_state = {"count": 0}

    def controlled_time():
        t_state["count"] += 1
        if t_state["count"] == 1:
            return 100.0
        if t_state["count"] == 2:
            raise RuntimeError("loop boom")
        return 150.0

    monkeypatch.setattr(time, "time", controlled_time)
    res_wait_err = analysis_mod._auto_reanalyze_text_segments(wait_seconds=1.0)
    assert isinstance(res_wait_err, dict)

