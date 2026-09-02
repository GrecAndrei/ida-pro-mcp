"""Cross-mode coverage for the shared decompile/context helper layer."""

from __future__ import annotations

import importlib
import types

import pytest

from tests.fakes.ida_fake import BADADDR, create_sample_c_binary_idb


@pytest.fixture
def helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_cfg_and_dataflow_summaries_cover_success_and_fallback(monkeypatch, helpers):
    class Block:
        def __init__(self, start, successors=()):
            self.start_ea = start
            self.end_ea = start + 4
            self._successors = [Block(s) for s in successors]

        def succs(self):
            return iter(self._successors)

    # Use stable block objects so the edge walk sees a loop and an exit.
    exit_block = Block(0x3000)
    loop_block = Block(0x2000, [0x2000])
    loop_block._successors = [loop_block, exit_block]
    entry = Block(0x1000, [0x2000])
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [entry, loop_block, exit_block])
    cfg = helpers._compute_cfg_semantics(types.SimpleNamespace(start_ea=0x1000))
    assert cfg["nodes"] == 3
    assert cfg["edges"] == 3
    assert cfg["back_edges"] == 1
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: None)
    assert helpers._compute_cfg_semantics(types.SimpleNamespace(start_ea=0))[
        "cyclomatic_complexity"
    ] == 1

    cfunc = types.SimpleNamespace(
        lvars=[types.SimpleNamespace(name="arg", is_arg_var=True), types.SimpleNamespace(name="tmp")]
    )
    monkeypatch.setattr(
        helpers,
        "_collect_expr_rows_from_cfunc",
        lambda *_args, **_kwargs: [(0x10, "tmp = arg;"), (0x14, "memcpy(tmp, arg);")],
    )
    dataflow = helpers._build_decompiler_dataflow(cfunc)
    assert dataflow["assignment_edges"] == 1
    assert dataflow["call_edges"] == 2
    assert "arg" in dataflow["argument_variables"]
    assert helpers._build_decompiler_dataflow(types.SimpleNamespace(lvars=[]))["nodes"] == []


def test_structure_summary_collects_calls_control_points_and_details(monkeypatch, helpers):
    class Block:
        start_ea = 0x1000
        end_ea = 0x1010

        def succs(self):
            return iter(())

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [Block()])
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x1050]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1050)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "callee")
    cfunc = types.SimpleNamespace(lvars=[types.SimpleNamespace(name="arg", is_arg_var=True)], body=[])
    monkeypatch.setattr(helpers, "_build_decompiler_dataflow", lambda *_a, **_k: {
        "argument_variables": ["arg"], "top_hubs": [{"node": "arg"}],
        "assignment_edges": 2, "call_edges": 1,
    })
    summary = helpers._build_function_structure_summary(
        types.SimpleNamespace(start_ea=0x1000), cfunc=cfunc, details=True
    )
    assert summary["call_targets"] == ["callee"]
    assert summary["dataflow"]["top_hubs"]
    assert "calls: callee" in summary["evidence"]


def test_variable_hints_use_type_usage_and_argument_fallbacks(helpers):
    class Tinfo:
        def dstr(self):
            return "network_frame_t *"

    class Cfunc:
        type = "int socket_handler(int fd, int size)"

        def __str__(self):
            return "int socket_handler(int a1, int a2) { recv(a1, a2, 4); v2 = recv(v2, 1, 2); }"

    cfunc = Cfunc()
    cfunc.lvars = [
        types.SimpleNamespace(name="v1", type=Tinfo),
        types.SimpleNamespace(name="a1", type=None),
        types.SimpleNamespace(name="a2", type=None),
        types.SimpleNamespace(name="v2", type=None),
        types.SimpleNamespace(name="stable", type=None),
    ]
    hints = helpers._extract_var_rename_hints(cfunc)
    assert {item["suggested"] for item in hints} >= {"frame", "recv_buf"}
    assert helpers._extract_var_rename_hints(types.SimpleNamespace(lvars=[], type="")) == []


def test_firmware_signals_detect_traps_csr_mmio_and_constant_loads(monkeypatch, helpers):
    class FakeInsn:
        def __init__(self):
            self.ops = [types.SimpleNamespace(type=helpers.ida_ua.o_displ)]

    class FakeUA:
        o_displ = 4
        o_mem = 2
        insn_t = FakeInsn

        @staticmethod
        def decode_insn(_insn, _ea):
            return 1

        @staticmethod
        def get_operand_value(_insn, _idx):
            return 0x40001000

    monkeypatch.setattr(helpers, "ida_ua", FakeUA)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x100C))
    mnems = {0x1000: "ecall", 0x1004: "csrrw", 0x1008: "sw"}
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnems.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4)
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: True)
    monkeypatch.setattr(helpers, "is_syscall_mnemonic", lambda m: m == "ecall")
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    signals = helpers._detect_firmware_signals(0x1000)
    assert "syscall:ecall" in signals
    assert "csr_access:csrrw" in signals
    assert "mmio_store:0x40001000" in signals
    monkeypatch.setattr(helpers.ida_ua, "decode_insn", lambda *_args: 0)
    assert helpers._store_memory_target(0x1000) is None


def test_enrichment_and_annotation_keep_human_readable_context(monkeypatch, helpers):
    monkeypatch.setattr(helpers, "_detect_api_calls", lambda *_a, **_k: ["memcpy"])
    monkeypatch.setattr(helpers, "_detect_crypto_hints", lambda *_a, **_k: (["AES"], 2))
    monkeypatch.setattr(helpers, "_detect_dangerous_patterns", lambda *_a, **_k: [{"pattern": "risk", "severity": "high", "detail": "check"}])
    monkeypatch.setattr(helpers, "_extract_var_rename_hints", lambda *_a: [{"var": "v1", "suggested": "buf"}])
    monkeypatch.setattr(helpers, "gather_function_context", lambda *_a, **_k: {"callers": ["main"]})
    monkeypatch.setattr(helpers, "_detect_firmware_signals", lambda *_a, **_k: ["syscall:ecall"])
    monkeypatch.setattr(helpers, "_get_blackboard_context_for_addr", lambda *_a: [{"title": "prior", "category": "note"}])
    monkeypatch.setattr(helpers, "_build_pseudocode_complexity", lambda *_a, **_k: {"lines": 1})
    enrichment = helpers._build_decompile_enrichment(0x1000, object(), "memcpy(x)")
    assert enrichment["api_calls"] == ["memcpy"]
    assert enrichment["firmware_signals"] == ["syscall:ecall"]
    annotated = helpers.annotate_pseudocode(
        "int f() { return 0x1000; }",
        0x1000,
        [{"category": "note", "title": "prior", "confidence": 0.9}],
        [{"pattern": "risk", "severity": "high", "detail": "check"}, "legacy risk"],
    )
    assert "[BB:note] prior" in annotated
    assert "[HIGH] risk" in annotated
    assert "[DANGER] legacy risk" in annotated
    assert helpers.annotate_pseudocode("", 0, [], []) == ""


def test_decompile_diagnostics_cover_unavailable_failed_and_success(monkeypatch, helpers):
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: False)
    cfunc, error = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is None and error.get("error") is True
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", False)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: None)
    cfunc, error = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is None and "Decompilation failed" in error["message"]
    expected = object()
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: expected)
    cfunc, error = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is expected and error is None


def test_disassembly_helpers_cover_styles_comments_bytes_ranges_and_windows(monkeypatch, helpers):
    import idc

    monkeypatch.setattr(idc, "generate_disasm_line", lambda _ea, _flags: "mov eax, ebx")
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "mov")
    monkeypatch.setattr(idc, "get_cmt", lambda _ea, repeat: "repeat" if repeat else "regular")
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 0, raising=False)
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda ea: ea & 0xFF)
    monkeypatch.setattr(idc, "next_head", lambda ea, _end: BADADDR if ea >= 0x1002 else ea + 2)
    monkeypatch.setattr(idc, "prev_head", lambda ea, _start: BADADDR)
    line = helpers._format_disasm_line(0x1000, style="classic", include_bytes=True, include_comments=True)
    assert "0x1000" in line and "bytes=00 01" in line and "regular" in line
    assert helpers._format_disasm_line(0x1000, style="annotated").startswith("*0x1000:")
    assert len(helpers._disasm_range(0x1000, 0x1004, max_items=2, style="csmini", include_bytes=False)) == 2
    window = helpers._disasm_window(0x1000, radius=3, max_items=2, style="csmini", include_bytes=False)
    assert len(window) <= 2
    assert helpers._disasm_range_structured(0x1000, 0x1002, 1)[0]["mnem"] == "mov"


def test_argument_extraction_and_trace_classifies_common_sources(monkeypatch, helpers):
    assert helpers._extract_arg_from_decompiled("foo(a, bar(1, 2), &x)", "foo", 1) == "bar(1, 2)"
    assert helpers._extract_arg_from_decompiled("foo(a)", "foo", 4) is None
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "target")
    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "int target(char *buf)")
    class Parsed:
        def get_func_details(self, fd):
            fd._items = [types.SimpleNamespace(name="buf")]
            return True
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_a: (Parsed(), "target"))
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda *_a: iter([types.SimpleNamespace(frm=0x2004, iscode=True)]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x2000 if ea == 0x2004 else 0x1000)
    class Decompiled:
        def __str__(self):
            return 'target("hello")'
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: Decompiled())
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: "caller" if ea == 0x2000 else "target")
    result = helpers._trace_argument_origin(func, 0, 1, 2)
    assert result["trace_tree"][0]["arg_type"] == "string_literal"


def test_gather_context_collects_callers_callees_strings_and_complexity(monkeypatch, helpers):
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: {
        0x2000: 0x2000, 0x3000: 0x3000,
    }.get(ea, 0x1000))
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    names = {0x2000: "caller", 0x3000: "callee"}
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: names.get(ea, ""))
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_to", lambda _ea: 0x2000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_to", lambda *_a: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_from", lambda _ea: 0x3000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_from", lambda *_a: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_dref_from", lambda _ea: 0x3500, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_dref_from", lambda *_a: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_a: b"shared secret")
    class Iterator:
        def current(self):
            return 0x1000

        def next_code(self):
            return False
    monkeypatch.setattr(helpers.idaapi, "func_item_iterator_t", lambda _func: Iterator(), raising=False)
    monkeypatch.setattr(helpers, "_compute_cfg_semantics", lambda _func: {"nodes": 1})
    result = helpers.gather_function_context(0x1000)
    assert result["callers"] == ["caller"]
    assert result["callees"] == ["callee"]
    assert result["strings"] == ["shared secret"]
    assert result["complexity"]["nodes"] == 1


def test_detector_type_match_and_api_prefilter_paths(monkeypatch, helpers):
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    class Tinfo:
        def get_func_details(self, data):
            data._items = [types.SimpleNamespace(name="buf", type="char *")]
            return True
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo)
    class FuncData:
        def __init__(self):
            self._items = []

        def size(self):
            return len(self._items)

        def __getitem__(self, index):
            return self._items[index]

    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tif, ea: ea == 0x1000)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: "with_buf" if ea == 0x1000 else "")
    matches = helpers._detect_type_matches("char \\*", max_items=10)
    assert matches[0]["name"] == "with_buf"
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_a: iter([]))
    assert helpers._function_may_reference_apis(0x1000, {"memcpy"}, set()) is True
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: (_ for _ in ()).throw(RuntimeError("broken")))
    assert helpers._function_may_reference_apis(0x1000, set(), set()) is True
