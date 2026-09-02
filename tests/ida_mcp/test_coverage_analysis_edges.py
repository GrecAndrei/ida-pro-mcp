"""Boundary and compatibility coverage for analysis controls."""

from __future__ import annotations

import struct
import sys
import types

import pytest

from tests.ida_mcp.test_swarm_t01_analysis_more import _load


@pytest.fixture(autouse=True)
def _restore_import_state():
    before = dict(sys.modules)
    yield
    for name in list(sys.modules):
        if name not in before:
            del sys.modules[name]
    sys.modules.update(before)


def test_get_options_and_set_options_cover_sdk_fallback_errors():
    mod, _inf, _idaapi, idc, ida_ida, loader, _auto = _load()

    def loader_name(_path):
        raise RuntimeError("loader unavailable")

    loader.get_loader_name = loader_name
    mod.ida_nalt.get_input_file_path = lambda: "/tmp/input.bin"
    result = mod.analysis(action="get_options")
    assert result["loader"] is None

    def no_attr(_key):
        raise RuntimeError("no info attribute")

    idc.get_inf_attr = no_attr
    ida_ida.inf_get_baseaddr = lambda: (_ for _ in ()).throw(RuntimeError("no base"))
    result = mod.analysis(action="set_options", options={"start_ea": 0x1200})
    assert result["ok"] is True

    idc.set_inf_attr = lambda *_args: (_ for _ in ()).throw(RuntimeError("read only"))
    result = mod.analysis(action="set_options", options={"start_ea": 0x1300})
    assert result["code"] == "IDA_ERROR"


def test_reanalyze_includes_created_entry_report_and_handles_raw_probe_error():
    mod, inf, idaapi, _idc, _ida_ida, _loader, _auto = _load()
    idaapi.inf_get_min_ea = lambda: 0x1000
    idaapi.inf_get_max_ea = lambda: 0x2000
    mod._auto_reanalyze_text_segments = lambda wait_seconds: {"waited_seconds": 0.25}
    mod._ensure_entry_point_functions = lambda: {"created": ["0x1000"]}
    result = mod.analysis(action="reanalyze", blocking=True, poll_timeout=0)
    assert result["mode"] == "auto_reanalyze_text_segments"
    assert result["reanalyze"]["entry_point_funcs_created"]["created"] == ["0x1000"]

    inf.filetype = 17
    idaapi.f_BIN = 17
    idaapi.f_BINARY = 17
    mod._bootstrap_raw_entry_points = lambda *_args: {"seeded_entries": 2}
    mod.idautils.Functions = lambda: iter([])
    idaapi.get_inf_structure = lambda: (_ for _ in ()).throw(RuntimeError("no inf"))
    result = mod.analysis(action="reanalyze", start="0x1000", end="0x1100")
    assert result["seeded_entries"] == 0

    # The raw check is still usable when the info object is present again.
    idaapi.get_inf_structure = lambda: inf
    result = mod.analysis(action="reanalyze", start="0x1000", end="0x1100")
    assert result["seeded_entries"] == 2


def test_analysis_address_validation_and_entry_registration_signatures():
    mod, _inf, _idaapi, idc, _ida_ida, _loader, _auto = _load()
    mod.validate_addr = lambda _value, **_kwargs: (
        0,
        mod.make_error(mod.MCPError.INVALID_ARGS, "bad address"),
    )
    assert mod.analysis(action="make_code", addr="bad")["error"] is True
    assert mod.analysis(action="undefine", addr="bad")["error"] is True
    assert mod.analysis(action="force_offset", addr="bad")["error"] is True
    assert mod.analysis(action="add_entry", addr="bad")["error"] is True

    mod, _inf, _idaapi, idc, _ida_ida, _loader, _auto = _load()
    entry = sys.modules["ida_entry"]
    entry.get_entry_qty = lambda: (_ for _ in ()).throw(RuntimeError("count unavailable"))
    assert mod.analysis(action="add_entry", addr="0x1200")["code"] == "INVALID_ARGS"
    assert mod.analysis(action="add_entry", addr="0x1200", ordinal="bad")["code"] == "INVALID_ARGS"

    calls = []

    def add_three_args(ordinal, ea, name):
        calls.append((ordinal, ea, name))
        return True

    entry.add_entry = add_three_args
    result = mod.analysis(action="add_entry", addr="0x1200", ordinal=4, name="entry")
    assert result["ok"] is True
    assert calls == [(4, 0x1200, "entry")]

    entry.add_entry = lambda *_args: (_ for _ in ()).throw(RuntimeError("entry failed"))
    assert mod.analysis(action="add_entry", addr="0x1200", ordinal=4)["code"] == "IDA_ERROR"

    def add_four_typeerror(*_args):
        raise TypeError("old binding")

    entry.add_entry = add_four_typeerror
    assert mod.analysis(action="add_entry", addr="0x1200", ordinal=4)["code"] == "IDA_ERROR"
    del idc


def test_snapshot_restore_cover_loader_and_undo_backends():
    mod, _inf, _idaapi, _idc, _ida_ida, loader, _auto = _load()
    assert mod.analysis(action="snapshot")["code"] == "INVALID_ARGS"
    snapshot_calls = []

    def save_one_arg(name):
        snapshot_calls.append(name)
        return True

    loader.save_snapshot = save_one_arg
    result = mod.analysis(action="snapshot", snapshot_name="before-edit")
    assert result["mechanism"] == "ida_loader"
    assert snapshot_calls == ["before-edit"]

    loader.restore_snapshot = lambda _name: True
    result = mod.analysis(action="restore_snapshot", snapshot_id="before-edit")
    assert result["ok"] is True
    assert result["snapshot_name"] == "before-edit"

    del loader.save_snapshot
    del loader.restore_snapshot
    undo = types.ModuleType("ida_undo")
    undo.create_undo_point = lambda *_args: True
    undo.perform_undo = lambda: True
    sys.modules["ida_undo"] = undo
    result = mod.analysis(action="snapshot", snapshot_name="undo-point")
    assert result["mechanism"] == "ida_undo"
    result = mod.analysis(action="restore_snapshot", ordinal=1)
    assert result["mechanism"] == "ida_undo"

    undo.create_undo_point = lambda *_args: (_ for _ in ()).throw(RuntimeError("history off"))
    assert mod.analysis(action="snapshot", snapshot_name="broken")["code"] == "IDA_ERROR"
    undo.perform_undo = lambda: False
    assert mod.analysis(action="restore_snapshot", snapshot_name="missing")["code"] == "IDA_ERROR"


def test_auto_wait_covers_fallback_api_and_signature_variants():
    mod, _inf, idaapi, _idc, _ida_ida, _loader, auto = _load()
    assert mod.analysis(action="auto_wait", timeout_ms="not-an-int")["code"] == "INVALID_ARGS"

    # With no ida_auto.auto_is_ok, the action can use idaapi.auto_is_ok.
    assert mod.analysis(action="auto_wait", timeout_ms=0)["analysis_done"] is True

    state = {"checks": 0}

    def auto_is_ok():
        state["checks"] += 1
        return state["checks"] > 1

    auto.auto_is_ok = auto_is_ok
    auto.auto_make_step = lambda *_args: (_ for _ in ()).throw(TypeError("needs range"))
    mod.time.sleep = lambda _seconds: None
    result = mod.analysis(action="auto_wait", timeout_ms=100)
    assert result["analysis_done"] is True
    assert result["queue_depth"] == 0
    assert state["checks"] >= 2

    auto.auto_is_ok = lambda: False
    auto.auto_make_step = lambda *_args: (_ for _ in ()).throw(RuntimeError("step failed"))
    result = mod.analysis(action="auto_wait", timeout_ms=0)
    assert result["analysis_done"] is False
    assert result["timed_out"] is False


@pytest.mark.parametrize("arch", ["arm", "unknown"])
def test_raw_entry_bootstrap_scans_arm_and_relative_tables(arch):
    mod, _inf, idaapi, idc, _ida_ida, _loader, _auto = _load()
    idaapi.f_BIN = 17
    idaapi.f_BINARY = 17
    target = 0x1234
    raw = struct.pack("<I", target | 1)
    sys.modules["ida_bytes"].get_bytes = lambda *_args: b"\0\0\0\0" + raw + b"\0" * 8
    mod.get_arch = lambda: arch
    mod.is_arm_family = lambda value: value == "arm"
    mod.is_riscv_family = lambda _value: False
    mod._compat.get_func_start = lambda _ea: None
    sys.modules["ida_ua"].create_insn = lambda _ea: 4
    sys.modules["ida_funcs"].add_func = lambda *_args: True
    seeded = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert seeded["seeded_entries"] >= 1

    # A pointer outside the image can still encode an image-relative offset.
    relative = struct.pack("<I", 0x20000801)
    sys.modules["ida_bytes"].get_bytes = lambda *_args: b"\0\0\0\0" + relative + b"\0" * 8
    seeded = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert seeded["seeded_entries"] >= 1


def test_raw_entry_bootstrap_riscv_signed_branches_and_existing_functions():
    mod, _inf, idaapi, idc, _ida_ida, _loader, _auto = _load()
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    sys.modules["ida_bytes"].get_bytes = lambda *_args: b"\0" * 32
    mod.get_arch = lambda: "riscv:rv64"
    mod.is_riscv_family = lambda value: "riscv" in value
    mod.is_arm_family = lambda _value: False
    def mnem(ea):
        if ea == 0x1000:
            return "auipc"
        return "jalr"

    idc.print_insn_mnem = mnem
    idc.get_operand_value = lambda ea, index: (
        0x80000 if ea == 0x1000 and index == 1 else 0x800
    )
    idc.next_head = lambda *_args: 0x1004
    assert mod._bootstrap_raw_entry_points(0x1000, 0x2000)["seeded_entries"] == 0

    # The positive form reaches the target and the existing-function branch.
    idc.get_operand_value = lambda ea, index: (
        0 if ea == 0x1000 and index == 1 else 0x100
    )
    mod._compat.get_func_start = lambda _ea: 0x1000
    result = mod._bootstrap_raw_entry_points(0x1000, 0x2000)
    assert result["seeded_entries"] >= 1

    idc.print_insn_mnem = lambda _ea: (_ for _ in ()).throw(RuntimeError("decode failed"))
    assert mod._bootstrap_raw_entry_points(0x1000, 0x2000)["seeded_entries"] >= 0


def test_text_segment_and_entry_helpers_cover_filter_and_failure_paths():
    mod, _inf, idaapi, _idc, _ida_ida, _loader, _auto = _load()
    segments = {
        0x1000: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1200),
        0x2000: types.SimpleNamespace(start_ea=0x2000, end_ea=0x2200),
        0x3000: types.SimpleNamespace(start_ea=0x3000, end_ea=0x3100),
    }
    mod.idautils.Segments = lambda: iter(segments)
    mod._compat.get_segment = segments.get
    mod._compat.get_segment_perm = lambda ea: idaapi.SEGPERM_EXEC if ea != 0x2000 else 0

    def segment_name(ea):
        if ea == 0x1000:
            raise RuntimeError("name unavailable")
        return ".plt" if ea == 0x2000 else ".text"

    mod._compat.get_segment_name = segment_name
    result = mod._find_text_segments()
    assert result == [(0x1000, 0x1200, ""), (0x3000, 0x3100, ".text")]

    entries = sys.modules["ida_entry"]
    entries.get_entry_qty = lambda: 4
    entries.get_entry_ordinal = lambda index: index
    entries.get_entry = lambda ordinal: {0: 0x1200, 1: 0x1200, 2: idaapi.BADADDR, 3: 0}[ordinal]
    assert mod._entry_point_addrs() == [0x1200]

    funcs = sys.modules["ida_funcs"]
    mod._compat.get_func_start = lambda ea: 0x1200 if ea == 0x1200 else None
    funcs.add_func = lambda ea: ea == 0x1300
    entries.get_entry = lambda ordinal: {0: 0x1200, 1: 0x1300, 2: 0x1400, 3: 0}[ordinal]
    result = mod._ensure_entry_point_functions()
    assert result["skipped_already_func"] == ["0x1200"]
    assert result["created"] == ["0x1300"]
    assert result["failed"] == ["0x1400"]
