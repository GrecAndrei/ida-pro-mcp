"""Additional cross-mode tests for code-analysis helper boundaries."""

from __future__ import annotations

import importlib
import types

import ida_hexrays

from tests.fakes.ida_fake import BADADDR, cexpr_t, cfunc_t, cinsn_t, cot_call, cot_obj, cot_var, lvar_t, var_ref_t


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


class _Args(list):
    def size(self):
        return len(self)

    def at(self, index):
        return self[index]


def _var(index, name, ea=0x1000):
    expr = cexpr_t(op=cot_var, v=var_ref_t(index), ea=ea)
    expr.print1 = lambda _tag=None, value=name: value
    return expr


def _call(name, ea=0x1000):
    expr = cexpr_t(op=cot_call, ea=ea, x=cexpr_t(op=cot_obj, obj_ea=ea + 0x1000), a=_Args())
    expr.a = _Args()
    return expr


def test_ctree_row_collection_and_dataflow_tolerate_bad_nodes(monkeypatch):
    helpers = _helpers()

    class Visitor:
        def __init__(self, *_args):
            pass

        def apply_to(self, _body, _parent=None):
            self.visit_expr(types.SimpleNamespace(ea=0x1000, print1=lambda _tag: (_ for _ in ()).throw(RuntimeError("bad text"))))

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    rows = helpers._collect_expr_rows_from_cfunc(types.SimpleNamespace(body=object()))
    assert rows == [(0x1000, "")]

    class RaisingVisitor(Visitor):
        def apply_to(self, _body, _parent=None):
            raise RuntimeError("bad tree")

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", RaisingVisitor)
    assert helpers._collect_expr_rows_from_cfunc(types.SimpleNamespace(body=object())) == []

    cfunc = types.SimpleNamespace(
        lvars=[types.SimpleNamespace(name="", is_arg_var=True), types.SimpleNamespace(name="src", is_arg_var=True)],
    )
    monkeypatch.setattr(helpers, "_collect_expr_rows_from_cfunc", lambda *_a, **_k: [(BADADDR, "dst = src")])
    result = helpers._build_decompiler_dataflow(cfunc)
    assert result["argument_variables"] == ["src"]
    assert result["assignment_edges"] == 0


def test_detector_text_fallback_covers_security_and_safe_forms():
    helpers = _helpers()
    pseudo = (
        'gets(buf); system(cmd); sprintf(out, fmt); malloc(n * 4); '
        'recv(sock, buf, 8); memcpy(out, buf, n); '
        'access(path, 0); fopen(path, "r"); '
        'password = "secret";'
    )
    findings = helpers._detect_dangerous_patterns(
        ["access", "fopen", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
        pseudo,
        detailed=True,
    )
    patterns = {item["pattern"] for item in findings}
    assert {
        "gets_unbounded",
        "command_injection",
        "sprintf_unbounded",
        "integer_overflow_alloc",
        "source_to_sink_flow",
        "toctou_race",
        "hardcoded_secret",
        "process_injection",
        "remote_thread_injection",
    } <= patterns
    flat = helpers._detect_dangerous_patterns([], "safe_call(\"literal\");", detailed=False)
    assert flat == []


def test_candidate_string_and_constant_recovery_cover_instruction_forms(monkeypatch):
    helpers = _helpers()
    loaded = {0x4010: "hello", 0x5000: "world"}
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea in loaded)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda ea, _limit: loaded.get(ea, b""))
    assert helpers._read_candidate_string(None) is None
    assert helpers._read_candidate_string(BADADDR) is None
    assert helpers._read_candidate_string(0x1000) is None
    assert helpers._read_candidate_string(0x4010) == "hello"
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _limit: b"\x01\x02\x03")
    assert helpers._read_candidate_string(0x4010) is None

    sequence = {
        0x1000: ("lui", "r1", 4),
        0x1004: ("addi", "r1", 0x10),
        0x1008: ("lw", "r2", 0),
        0x100C: ("mov", "r3", 0x5000),
        0x1010: ("mov", "r4", 0),
    }
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1014)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: sequence[ea][0])
    monkeypatch.setattr(helpers.idc, "print_operand", lambda ea, index: (
        sequence[ea][1] if index == 0 else sequence[ea][1]
    ))
    monkeypatch.setattr(
        helpers.idc,
        "get_operand_value",
        lambda ea, index: sequence[ea][2] if index in (1, 2) else 0,
    )
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1010 else BADADDR)
    monkeypatch.setattr(helpers, "_read_candidate_string", loaded.get)
    hits = helpers._scan_constant_load_strings(0x1000, result_limit=3)
    assert {hit["value"] for hit in hits} == {"hello", "world"}
    assert helpers._scan_constant_load_strings(0x1000, result_limit=0) == []


def test_string_and_type_searches_handle_invalid_patterns_and_unusable_types(monkeypatch):
    helpers = _helpers()
    string_obj = types.SimpleNamespace(ea=0x4000)
    monkeypatch.setattr(helpers.idautils, "Strings", lambda: iter([string_obj]), raising=False)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: iter(()), raising=False)
    assert helpers._detect_string_refs("[") == []
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([1, 2, 3]))

    class Tinfo:
        def __init__(self, details=True):
            self.details = details

        def get_func_details(self, data):
            if self.details:
                data.items = [types.SimpleNamespace(name="buf", type="char *")]
            return self.details

    class FuncData:
        def __init__(self):
            self.items = []

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    states = iter([False, True, True])
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", lambda: Tinfo(next(states)), raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: f"f{ea}")
    assert helpers._detect_type_matches("char") == [
        {"addr": "0x2", "name": "f2", "param_idx": 0, "param_name": "buf", "param_type": "char *", "matched": "char"},
        {"addr": "0x3", "name": "f3", "param_idx": 0, "param_name": "buf", "param_type": "char *", "matched": "char"},
    ]


def test_compact_xrefs_and_flow_helpers_are_bounded(monkeypatch):
    helpers = _helpers()
    refs = [0x2000, 0x2000, 0x3000, 0x4000]
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_a: iter(refs))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: None if ea == 0x4000 else ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: f"f{ea:x}")
    assert len(helpers._collect_compact_callers(0x1000, scan_limit=3)) == 2

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([1, 2]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x5000, 0x5000]))
    assert helpers._collect_compact_callees(0x1000) == [{"addr": "0x5000", "name": "f5000"}]


def test_decompile_diagnostics_preserves_retry_failure_details(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)

    class Failure:
        code = 50735
        errea = 0x1234
        str = "opcode error"

    monkeypatch.setattr(helpers.ida_hexrays, "hexrays_failure_t", Failure)
    calls = []

    def fail(_ea, _failure, _flags):
        calls.append(True)

    monkeypatch.setattr(helpers._compat, "decompile_function", fail)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: None)
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is None
    assert error["details"]["failure_code"] == 50735
    assert error["details"]["failure_ea"] == "0x1234"
    assert "opcode error" in error["message"]
    assert len(calls) == 1
