"""Offline coverage for analysis controls and raw-binary scheduling modes."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

from tests._isolated_repo_loader import load_ida_module, load_tool_module


def _errors():
    error = load_ida_module("error_handling")
    return {
        "make_error": error.make_error,
        "handle_error": error.handle_error,
        "MCPError": error.MCPError,
        "ERROR_HINTS": error.ERROR_HINTS,
    }


def _module(name, **attrs):
    value = types.ModuleType(name)
    for key, item in attrs.items():
        setattr(value, key, item)
    sys.modules[name] = value
    return value


def _load():
    inf = types.SimpleNamespace(procname="metapc", filetype=1, af=0, af2=0)
    state = {"base": 0x1000, "bitness": 64, "be": False, "attrs": {}}
    idaapi = _module(
        "idaapi",
        BADADDR=0xFFFFFFFFFFFFFFFF,
        SETPROC_LOADER=0,
        SETPROC_LOADER_NON_FATAL=1,
        SEGPERM_EXEC=1,
        REF_OFF32=0x10,
        REF_OFF64=0x20,
        get_inf_structure=lambda: inf,
        get_input_file_path=lambda: "/tmp/input.bin",
        inf_get_start_ea=lambda: 0x1000,
        inf_get_min_ea=lambda: 0x1000,
        inf_get_max_ea=lambda: 0x9000,
        get_func_qty=lambda: 3,
        auto_is_ok=lambda: True,
        set_processor_type=lambda _name, _flags: True,
    )
    idc = _module(
        "idc",
        INF_BASEADDR=1,
        INF_START_EA=2,
        INF_MIN_EA=3,
        INF_MAX_EA=4,
        INF_FILETYPE=5,
        AF_MARKCODE=1,
        AF2_DOEH=2,
        INF_AF=6,
        INF_AF2=7,
        get_inf_attr=lambda key: state["base"] if key == 1 else state["attrs"].get(key, 17),
        set_inf_attr=None,
        get_item_size=lambda _ea: 3,
        get_idb_path=lambda: "/tmp/result.i64",
        get_name_ea_simple=lambda _name: idaapi.BADADDR,
    )
    ida_ida = _module(
        "ida_ida",
        inf_get_app_bitness=lambda: state["bitness"],
        inf_set_app_bitness=lambda value: state.__setitem__("bitness", value),
        inf_get_baseaddr=lambda: state["base"],
        inf_get_min_ea=lambda: 0x1000,
        inf_get_max_ea=lambda: 0x9000,
        inf_is_be=lambda: state["be"],
        inf_set_be=lambda value: state.__setitem__("be", value),
        inf_get_af=lambda: inf.af,
        inf_get_af2=lambda: inf.af2,
        inf_set_af=lambda value: setattr(inf, "af", value),
        inf_set_af2=lambda value: setattr(inf, "af2", value),
    )
    def set_inf_attr(key, value):
        state["attrs"][key] = value

    idc.set_inf_attr = set_inf_attr
    loader = _module(
        "ida_loader",
        get_loader_name=lambda: "elf",
        save_database=lambda _path, _flags: True,
        set_loader_options=lambda _loader, _options, _flags=0: True,
    )
    auto = _module(
        "ida_auto",
        AU_FINAL=4,
        plan_range=lambda *_args: None,
        auto_mark_range=lambda *_args: None,
        auto_make_step=lambda *_args: None,
        auto_wait_range=lambda *_args: None,
    )
    _module("ida_entry", get_entry_qty=lambda: 0, add_entry=lambda *_args: True)
    _module("ida_bytes", DELIT_SIMPLE=1)
    _module("ida_ua", create_insn=lambda _ea: 4)
    _module("ida_segment")
    _module("ida_nalt", get_input_file_path=lambda: "/tmp/input.bin")
    _module("ida_funcs", add_func=lambda *_args: True)
    _module("idautils", Functions=lambda: iter([0x1000]), Segments=lambda: iter([]))
    mod = load_tool_module("analysis", common_overrides=_errors())
    # The isolated loader's common module may retain lightweight placeholder
    # bindings from a prior test module; make the operation and its helpers
    # use this test's coherent fake binding set.
    mod.idaapi = idaapi
    mod.idc = idc
    mod.ida_ida = ida_ida
    mod.ida_loader = loader
    mod.idautils = sys.modules["idautils"]
    mod.ida_bytes = sys.modules["ida_bytes"]
    mod.ida_funcs = sys.modules["ida_funcs"]
    mod.ida_segment = sys.modules["ida_segment"]
    mod.ida_nalt = sys.modules["ida_nalt"]
    idaapi.get_inf_structure = lambda: inf
    idc.get_inf_attr = lambda key: state["base"] if key == 1 else state["attrs"].get(key, 17)
    idc.get_item_size = lambda _ea: 3
    mod.idautils.Functions = lambda: iter([0x1000])
    mod.idautils.Segments = lambda: iter([])
    mod._state = state
    mod._inf_procname = lambda: inf.procname
    mod._inf_filetype_id = lambda: inf.filetype
    mod._inf_bitness = lambda: state["bitness"]
    mod._inf_is_64bit = lambda: state["bitness"] == 64
    mod._inf_is_be = lambda: state["be"]
    mod._filetype_name = lambda value: "raw" if value == 17 else "elf"
    mod._compat.get_func_info = lambda _ea: None
    mod._compat.get_segment = lambda _ea: None
    mod._compat.get_segment_perm = lambda _ea: 0
    mod._compat.get_segment_name = lambda _ea: ""
    mod.validate_addr = lambda value, **_kwargs: (int(value, 0), None)
    return mod, inf, idaapi, idc, ida_ida, loader, auto


def test_set_options_rebases_and_rejects_bad_values():
    mod, _inf, idaapi, idc, _ida_ida, _loader, _auto = _load()
    rebases = []
    idc.rebase_program = lambda delta, flags: rebases.append((delta, flags)) or 1
    result = mod.analysis(action="set_options", options={"baseaddr": "0x3000", "start_ea": "0x1200"})
    assert result["ok"] is True
    assert result["applied"]["baseaddr"] == 0x3000
    assert result["applied"]["start_ea"] == 0x1200
    assert rebases[0][0] == 0x2000
    assert mod.analysis(action="set_options", options={"min_ea": "bad"})["code"] == "INVALID_ARGS"
    assert mod.analysis(action="set_options", options=None)["code"] == "INVALID_ARGS"
    idc.rebase_program = lambda *_args: False
    failed = mod.analysis(action="set_options", options={"baseaddr": 0x5000})
    assert failed["code"] == "IDA_ERROR"
    unaligned = mod.analysis(action="set_options", options={"baseaddr": 0x5001})
    assert unaligned["code"] == "INVALID_ARGS"


def test_get_options_and_architecture_cover_state_and_hints():
    mod, inf, _idaapi, _idc, ida_ida, _loader, _auto = _load()
    options = mod.analysis(action="get_options")
    assert options["ok"] is True
    assert options["loader"] == "elf"
    assert options["file_type_info"]["effective"] == "elf"
    inf.procname = "arm"
    arm = mod.analysis(action="set_architecture", processor="arm", bitness=32, endian="le")
    assert arm["ok"] is True
    assert arm["applied"]["arch_hints"]["ptr_size"] == 4
    inf.procname = "mips"
    mips = mod.analysis(action="set_architecture", processor="mips", bitness=32)
    assert "MIPS" in mips["applied"]["arch_hints"]["disasm_note"]
    inf.procname = "x86"
    x86 = mod.analysis(action="set_architecture", processor="x86", bitness=64)
    assert x86["applied"]["arch_hints"]["ptr_size"] == 8
    assert mod.analysis(action="set_architecture", bitness=17)["code"] == "INVALID_ARGS"
    assert mod.analysis(action="set_architecture", endian="wat")["code"] == "INVALID_ARGS"
    inf.procname = "metapc"
    same = mod.analysis(action="set_processor", processor="metapc")
    assert same["note"] == "already set"
    assert mod.analysis(action="set_architecture")["code"] == "INVALID_ARGS"
    ida_ida.inf_set_app_bitness = lambda _value: (_ for _ in ()).throw(RuntimeError("locked"))
    failed = mod.analysis(action="set_architecture", bitness=32)
    assert failed["code"] == "IDA_ERROR"


def test_loader_options_covers_dict_signature_fallback_and_errors(tmp_path, monkeypatch):
    mod, _inf, idaapi, _idc, _ida_ida, loader, _auto = _load()
    calls = []
    loader.set_loader_options = lambda name, value: calls.append((name, value)) or True
    result = mod.analysis(action="set_loader_options", value={"a": 1, "b": "two"})
    assert result["ok"] is True
    assert calls == [("elf", "a=1;b=two")]
    del loader.set_loader_options
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))
    fallback = mod.analysis(action="set_loader_options", loader="raw", value="mode=bin")
    assert fallback["fallback"] == "soft_saved"
    assert json.loads(Path(fallback["fallback_path"]).read_text())["loader"] == "raw"
    assert mod.analysis(action="set_loader_options", value=None)["code"] == "INVALID_ARGS"
    assert mod.analysis(action="set_loader_options", loader="", value="x")["ok"] is True
    loader.set_loader_options = lambda *_args: (_ for _ in ()).throw(RuntimeError("bad loader"))
    assert mod.analysis(action="set_loader_options", value="x")["code"] == "IDA_ERROR"
    idaapi.get_input_file_path = lambda: "/tmp/input.bin"


def test_make_code_undefine_and_force_offset_cover_fallbacks():
    mod, _inf, _idaapi, idc, _ida_ida, _loader, auto = _load()
    import ida_bytes
    import ida_ua

    deleted = []
    ida_bytes.del_items = lambda *args: deleted.append(args)
    ida_bytes.DELIT_SIMPLE = 1
    ida_ua.create_insn = lambda _ea: 4
    auto.auto_mark_range = lambda *args: deleted.append(("mark", *args))
    mod._compat.get_func_info = lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
    made = mod.analysis(action="make_code", addr="0x1000", size=8)
    assert made["ok"] is True
    assert made["insn_len"] == 4
    assert made["requeued_func"] is True
    undefined = mod.analysis(action="undefine", addr="0x1000")
    assert undefined["cleared_bytes"] == 3
    assert mod.analysis(action="make_code")["code"] == "INVALID_ARGS"
    ida_ua.create_insn = lambda _ea: 0
    idc.create_insn = lambda _ea: 0
    assert mod.analysis(action="make_code", addr="0x1000")["code"] == "IDA_ERROR"
    ida_bytes.del_items = lambda *_args: (_ for _ in ()).throw(RuntimeError("readonly"))
    assert mod.analysis(action="undefine", addr="0x1000")["code"] == "IDA_ERROR"

    offsets = []
    idc.op_offset = lambda *args: offsets.append(args)
    forced = mod.analysis(action="force_offset", addr="0x1000", size=4)
    assert forced["ptr_size"] == 4
    assert offsets
    del idc.op_offset
    idc.op_plain_offset = lambda *args: offsets.append(args)
    assert mod.analysis(action="force_offset", addr="0x1000")["ok"] is True
    del idc.op_plain_offset
    assert mod.analysis(action="force_offset", addr="0x1000")["code"] == "IDA_ERROR"


def test_analysis_flags_cover_idc_and_inf_fallbacks():
    mod, inf, idaapi, idc, ida_ida, _loader, _auto = _load()
    inf.af = 1
    inf.af2 = 0
    specific = mod.analysis(action="get_af", af_flag="AF_MARKCODE")
    assert specific["enabled"] is True
    all_flags = mod.analysis(action="get_af")
    assert all_flags["flags"]["AF2_DOEH"]["enabled"] is False
    set_result = mod.analysis(action="set_af", af_flag="AF_MARKCODE", af_value=False)
    assert set_result["previous"] is True and set_result["current"] is False
    set_af2 = mod.analysis(action="set_af", af_flag="AF2_DOEH", af_value=True)
    assert set_af2["current"] is True
    assert mod.analysis(action="set_af", af_flag="AF_NOPE", af_value=True)["code"] == "INVALID_ARGS"
    assert mod.analysis(action="set_af", af_flag="AF_MARKCODE")["code"] == "INVALID_ARGS"
    assert mod.analysis(action="set_af", af_value=True)["code"] == "INVALID_ARGS"
    idaapi.inf_get_af = lambda: (_ for _ in ()).throw(RuntimeError("no api"))
    idaapi.inf_get_af2 = lambda: (_ for _ in ()).throw(RuntimeError("no api"))
    del ida_ida.inf_set_af
    del ida_ida.inf_set_af2
    assert mod.analysis(action="set_af", af_flag="AF_MARKCODE", af_value=True)["ok"] is True


def test_reanalyze_explicit_and_range_validation_modes():
    mod, inf, idaapi, _idc, _ida_ida, _loader, auto = _load()
    inf.filetype = 1
    auto.plan_range = lambda *args: setattr(auto, "planned", args)
    result = mod.analysis(action="reanalyze", start="0x1000", end="0x1100")
    assert result["mode"] == "plan_range"
    assert auto.planned == (0x1000, 0x1100)
    assert mod.analysis(action="reanalyze", start="0x1000")["code"] == "INVALID_ARGS"
    del auto.plan_range
    auto.auto_mark_range = lambda *args: setattr(auto, "marked", args)
    fallback = mod.analysis(action="run", start="0x1000", end="0x1100")
    assert fallback["mode"] == "auto_mark_range"
    assert mod.analysis(action="analyze", start="bad", end="0x1100")["error"] is True
    idaapi.get_auto_state = lambda: 0
    idaapi.AU_NONE = 0
    state = mod.analysis(action="state")
    assert state["analysis_complete"] is True


def test_raw_range_and_segment_helpers_cover_api_fallbacks():
    mod, inf, idaapi, idc, ida_ida, _loader, _auto = _load()
    idaapi.f_BIN = 17
    idaapi.f_BINARY = 17
    inf.filetype = 17
    idaapi.inf_get_filetype = lambda: 17
    assert mod._is_raw_bin_filetype() is True
    del idaapi.inf_get_filetype
    idc.get_inf_attr = lambda _key: 17
    assert mod._is_raw_bin_filetype() is True
    del idc.get_inf_attr
    assert mod._is_raw_bin_filetype() is True
    ida_ida.inf_get_min_ea = lambda: 0x1000
    ida_ida.inf_get_max_ea = lambda: 0x2000
    assert mod._raw_mapped_range() == (0x1000, 0x2000)
    del ida_ida.inf_get_min_ea
    del ida_ida.inf_get_max_ea
    inf.min_ea = 0x1000
    inf.max_ea = 0x9000
    assert mod._raw_mapped_range() == (0x1000, 0x9000)

    segment = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1200)
    mod._compat.get_segment = lambda _ea: segment
    mod._compat.get_segment_perm = lambda _ea: idaapi.SEGPERM_EXEC
    mod._compat.get_segment_name = lambda _ea: ".text"
    ida_bytes = sys.modules["ida_bytes"]
    ida_bytes.get_flags = lambda _ea: 1
    ida_bytes.is_code = lambda _flags: True
    idc.get_item_size = lambda _ea: 4
    idc.next_head = lambda ea, _end: ea + 4 if ea < 0x1010 else idaapi.BADADDR
    assert mod._segment_code_score(0x1000) == (20, 512, 5)
    mod.idautils.Segments = lambda: iter([0x1000])
    segments = mod._find_text_segments()
    assert segments == [(0x1000, 0x1200, ".text")]
    segment.end_ea = 0x1080
    assert mod._find_text_segments() == [(0x1000, 0x9000, "<raw-mapped>")]
    mod._compat.get_segment_perm = lambda _ea: 0
    assert mod._segment_code_score(0x1000) == (0, 0, 0)


def test_auto_reanalyze_uses_wait_range_then_step_fallback():
    mod, inf, idaapi, _idc, _ida_ida, _loader, auto = _load()
    inf.filetype = 1
    segment = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1300)
    mod._compat.get_segment = lambda _ea: segment
    mod._compat.get_segment_perm = lambda _ea: idaapi.SEGPERM_EXEC
    mod._compat.get_segment_name = lambda _ea: ".text"
    sys.modules["idautils"].Segments = lambda: iter([0x1000])
    ida_bytes = sys.modules["ida_bytes"]
    ida_bytes.get_flags = lambda _ea: 0
    sys.modules["idautils"].Functions = lambda: iter([0x1000])
    scheduled = []
    auto.plan_range = lambda *args: scheduled.append(args)
    auto.auto_wait_range = lambda *args: scheduled.append(("wait", *args))
    result = mod._auto_reanalyze_text_segments(wait_seconds=1)
    assert result["scheduled"] == 1
    assert result["eligible_ranges"][0]["name"] == ".text"
    assert ("wait", 0x1000, 0x1300) in scheduled
    del auto.auto_wait_range
    auto.auto_make_step = lambda *args: scheduled.append(("step", *args))
    idaapi.auto_is_ok = lambda: True
    result = mod._auto_reanalyze_text_segments(wait_seconds=1)
    assert result["scheduled"] == 1
