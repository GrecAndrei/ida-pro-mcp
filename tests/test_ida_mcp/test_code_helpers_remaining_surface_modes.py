"""Exercise remaining code-helper fallbacks and composed analysis modes."""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_submodule
from tests.fakes.ida_fake import BADADDR


def _module():
    return load_tool_submodule("code_helpers")


def test_dataflow_and_low_level_decoder_fail_closed(monkeypatch):
    helpers = _module()

    class BrokenVisitor:
        def __init__(self, *_args):
            raise RuntimeError("visitor unavailable")

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", BrokenVisitor)
    assert helpers._collect_expr_rows_from_cfunc(types.SimpleNamespace(body=object())) == []

    class BrokenLvars:
        @property
        def lvars(self):
            raise RuntimeError("lvars unavailable")

    assert helpers._build_decompiler_dataflow(BrokenLvars())["nodes"] == []

    class TypeObject:
        def dstr(self):
            raise RuntimeError("bad type")

    class VariableType:
        def __call__(self):
            return TypeObject()

    assert helpers._lvar_type_str(types.SimpleNamespace(type=VariableType())) == ""
    assert helpers._lvar_type_str(types.SimpleNamespace(type=types.SimpleNamespace(dstr=lambda: " char * "))) == "char *"
    opaque = object()
    assert helpers._lvar_type_str(types.SimpleNamespace(type=opaque)) == str(opaque).strip()

    class UA:
        o_displ = 4
        o_mem = 2

        def __init__(self, decoded, ops=(), value=0):
            self.decoded = decoded
            self.ops = list(ops)
            self.value = value

        def insn_t(self):
            return types.SimpleNamespace(ops=self.ops)

        def decode_insn(self, *_args):
            return self.decoded

        def get_operand_value(self, *_args):
            return self.value

    monkeypatch.setattr(helpers, "ida_ua", UA(0))
    assert helpers._store_memory_target(0x1000) is None
    monkeypatch.setattr(helpers, "ida_ua", UA(1, [types.SimpleNamespace(type=1)], 0x4000))
    assert helpers._store_memory_target(0x1000) is None
    monkeypatch.setattr(helpers, "ida_ua", UA(1, [types.SimpleNamespace(type=4)], helpers.idaapi.BADADDR))
    assert helpers._store_memory_target(0x1000) is None
    monkeypatch.setattr(helpers, "ida_ua", UA(1, [types.SimpleNamespace(type=4)], 0x40001000))
    assert helpers._store_memory_target(0x1000) == 0x40001000


def test_firmware_constant_and_string_fallback_modes(monkeypatch):
    helpers = _module()
    fn = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: False)
    monkeypatch.setattr(helpers, "is_syscall_mnemonic", lambda _mnem: False)

    mnems = {0x1000: "", 0x1004: "", 0x1008: "", 0x100C: ""}
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnems.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x100C else BADADDR)
    pseudo = " ".join(f"0x4{i:07x}" for i in range(8))
    fallback = helpers._detect_firmware_signals(0x1000, pseudo)
    assert len(fallback) == 8
    assert fallback[0].startswith("constant_ref:")

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: None)
    assert helpers._detect_firmware_signals(0x1000) == []

    fn = types.SimpleNamespace(start_ea=0x1000, end_ea=0x100C)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: fn)
    sequence = {0x1000: "auipc", 0x1004: "lw", 0x1008: "mov"}
    operands = {
        (0x1000, 0): "a0", (0x1000, 1): 1,
        (0x1004, 1): "a0", (0x1004, 2): 4,
        (0x1008, 0): "a1", (0x1008, 1): 0x3000,
    }
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: sequence.get(ea, "nop"))
    monkeypatch.setattr(helpers.idc, "print_operand", lambda ea, index: str(operands.get((ea, index), "")))
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda ea, index: operands.get((ea, index), 0))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1008 else BADADDR)
    def read_candidate(target):
        return {0x2004: "pcrel", 0x3000: "literal"}.get(target)

    monkeypatch.setattr(helpers, "_read_candidate_string", read_candidate)
    found = helpers._scan_constant_load_strings(0x1000, result_limit=4)
    assert {item["value"] for item in found} == {"pcrel", "literal"}

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: [0x1000])
    monkeypatch.setattr(
        helpers.idautils,
        "XrefsFrom",
        lambda _ea, _flags: [
            types.SimpleNamespace(iscode=True, to=0x2000),
            types.SimpleNamespace(iscode=False, to=0x3000),
            types.SimpleNamespace(iscode=False, to=0x3004),
        ],
    )
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda ea: b"" if ea == 0x3004 else "hello")
    entries = helpers._collect_function_string_entries(0x1000)
    assert entries == [{"addr": "0x3000", "value": "hello"}]

    monkeypatch.setattr(helpers.idautils, "XrefsFrom", lambda *_args: [])
    monkeypatch.setattr(helpers, "_scan_constant_load_strings", lambda *_args: [{"addr": 0x4000, "value": "fallback"}])
    assert helpers._collect_function_string_entries(0x1000) == [{"addr": "0x4000", "value": "fallback"}]


def test_annotation_and_decompiler_diagnostics_cover_success_and_error_paths(monkeypatch):
    helpers = _module()
    comments = {}

    class Visitor:
        def __init__(self, *_args):
            pass

        def apply_to(self, body, *_args):
            for insn in body.insns:
                self.visit_insn(insn)

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda ea, _repeat: comments.get(ea, ""))
    body = types.SimpleNamespace(insns=[types.SimpleNamespace(ea=0x1000), types.SimpleNamespace(ea=BADADDR)])
    comments[0x1000] = "original comment"
    annotated = helpers.annotate_pseudocode("call(); // 0x1000", 0x1000, [], [], types.SimpleNamespace(body=body))
    assert "[IDA] original comment" in annotated
    monkeypatch.setattr(Visitor, "apply_to", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad tree")))
    assert helpers.annotate_pseudocode("return 0;", 0x1000, [], [], types.SimpleNamespace(body=body)) == "return 0;"

    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)
    monkeypatch.setattr(helpers.ida_hexrays, "hexrays_failure_t", lambda: types.SimpleNamespace(code=None, errea=BADADDR, str=""))
    expected = object()
    monkeypatch.setattr(helpers._compat, "decompile_function", lambda *_args: expected)
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is expected and error is None

    failures = [
        types.SimpleNamespace(code=50735, errea=0x1004, str="opcode error"),
        types.SimpleNamespace(code=50736, errea=0x1008, str="retry error"),
    ]
    monkeypatch.setattr(helpers.ida_hexrays, "hexrays_failure_t", lambda: failures.pop(0))
    monkeypatch.setattr(helpers._compat, "decompile_function", lambda *_args: None)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010))
    auto = types.ModuleType("ida_auto")
    auto.plan_range = lambda *_args: None
    monkeypatch.setitem(sys.modules, "ida_auto", auto)
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)
    _, failed = helpers._decompile_with_diagnostics(0x1000)
    assert failed["error"] is True
    assert failed["details"]["failure_ea"] == "0x1008"

    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", False)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: expected)
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is expected and error is None


def test_custom_detector_primitives_cover_negative_and_limit_modes(monkeypatch):
    helpers = _module()
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea if ea == 0x1000 else None)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: [0x1000])
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "xor")
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: "crypto" if ea == 0x1000 else "")
    assert helpers._detect_xor_heavy(threshold=1) == [{"addr": "0x1000", "name": "crypto", "xor_count": 1}]

    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x3000 if name == "_target" else helpers.idaapi.BADADDR)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x3000 if ea == 0x3000 else None)
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_args: [0x4000])
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x3000 if ea == 0x3000 else 0x4000)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "callee")
    assert helpers._detect_callers_of("target")
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_args: [0x4000, 0x5000])
    assert len(helpers._detect_callers_of("target", max_items=1)) == 1

    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x3000 if name == "__target" else helpers.idaapi.BADADDR)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: [0x6000, 0x7000])
    assert helpers._detect_callees_of("target")
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: [0x6000, 0x7000])
    assert len(helpers._detect_callees_of("target", max_items=1)) == 1


def test_api_chain_and_type_matching_tolerate_unavailable_metadata(monkeypatch):
    helpers = _module()
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda _name: (_ for _ in ()).throw(RuntimeError("names unavailable")))
    monkeypatch.setattr(helpers, "_function_may_reference_apis", lambda *_args: True)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: None)
    assert helpers._detect_api_chains(["open", "read"]) == []

    class Details:
        def size(self):
            return 1

        def __getitem__(self, _index):
            return types.SimpleNamespace(name="buf", type="char *")

    class Tinfo:
        def get_func_details(self, _details):
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", Details, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, ea: ea == 0x1000)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "handler")
    matches = helpers._detect_type_matches("char", max_items=1)
    assert matches[0]["param_name"] == "buf"
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda *_args: False)
    assert helpers._detect_type_matches("char") == []
