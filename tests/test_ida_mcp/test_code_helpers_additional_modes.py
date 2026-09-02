"""Additional offline coverage for code-helper fallbacks and detector modes."""

from __future__ import annotations

import importlib
import sys
import types

from tests.fakes.ida_fake import BADADDR


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_code_helper_rows_flow_targets_and_comments_cover_fallbacks(monkeypatch):
    helpers = _helpers()

    class Expr:
        ea = BADADDR

        def __init__(self, text, fail=False):
            self.text = text
            self.fail = fail

        def print1(self, _tag):
            if self.fail:
                raise RuntimeError("bad ctree text")
            return self.text

    class Visitor:
        def __init__(self, *_args):
            self.count = 0

        def apply_to(self, _body, _parent):
            self.visit_expr(Expr("a = b"))
            self.visit_expr(Expr("broken", fail=True))
            self.visit_expr(Expr("ignored"))

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    monkeypatch.setattr(helpers.ida_hexrays, "CV_FAST", 1, raising=False)
    rows = helpers._collect_expr_rows_from_cfunc(types.SimpleNamespace(body=object()), max_items=2)
    assert rows == [(BADADDR, "a = b"), (BADADDR, "")]

    rows = [(BADADDR, "dst = src"), (0x1000, "call(src, dst)"), (0x1004, "call(src, dst)")]
    monkeypatch.setattr(helpers, "_collect_expr_rows_from_cfunc", lambda *_a, **_k: rows)
    cfunc = types.SimpleNamespace(
        lvars=[
            types.SimpleNamespace(name="dst", is_arg_var=False),
            types.SimpleNamespace(name="src", is_arg_var=True),
        ],
        entry_ea=BADADDR,
    )
    flow = helpers._build_decompiler_dataflow(cfunc, max_items=20)
    assert flow["assignment_edges"] == 1
    assert flow["call_edges"] == 2
    assert any(edge["ea"] is None for edge in flow["edges"])

    monkeypatch.setattr(helpers, "_is_flow_control_mnemonic", lambda _mnem: True)
    monkeypatch.setattr(helpers, "ida_ua", types.SimpleNamespace(o_near=7, o_far=6))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "beq")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, index: 7 if index == 2 else 0)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _index: 0x401000)
    assert helpers._flow_target_ea(0x1000) == 0x401000
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda *_args: 0)
    assert helpers._flow_target_ea(0x1000) is None

    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda *_args: "")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda _ea, repeat: "repeat" if repeat else "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 0)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 0, raising=False)
    assert "<data>" in helpers._format_disasm_line(0x1000, style="unknown", include_comments=True)
    structured = helpers._format_disasm_structured(0x1000)
    assert structured["text"] == "<data>" and structured["comment"] == "repeat"


def test_code_helper_blackboard_and_decompiler_retry_modes(monkeypatch):
    helpers = _helpers()
    entries = [{"title": "network input", "category": "ioc", "confidence": 0.9, "source_type": "scan"}]

    class Store:
        def list(self, **kwargs):
            assert kwargs["addr"] == "0x1000"
            return entries

    monkeypatch.setitem(sys.modules, "blackboard", types.SimpleNamespace(BlackboardStore=Store))
    assert helpers._get_blackboard_context_for_addr("0x1000")[0]["source_type"] == "scan"

    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)
    monkeypatch.setattr(helpers, "time", types.SimpleNamespace(sleep=lambda _seconds: None))
    monkeypatch.setitem(sys.modules, "ida_auto", types.SimpleNamespace(plan_range=lambda *_args: None))
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010))

    class Failure:
        code = 50735
        errea = 0x1004
        str = "not ready"

    failures = [Failure(), Failure()]
    expected = object()

    def decompile(_ea, failure, _flags):
        failure.code = failures.pop(0).code
        return expected if len(failures) == 0 else None

    monkeypatch.setattr(helpers._compat, "decompile_function", decompile)
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is expected and error is None

    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", False)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: object())
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is not None and error is None

    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: (_ for _ in ()).throw(RuntimeError("crash")))
    result, error = helpers._decompile_with_diagnostics(0x1000)
    assert result is None and error["error"] is True


def test_code_helper_detector_success_modes_and_api_chain_order(monkeypatch):
    helpers = _helpers()
    helpers._CUSTOM_DETECTORS.clear()
    real_detect_api_chains = helpers._detect_api_chains
    monkeypatch.setattr(helpers, "_detect_api_chains", lambda *args, **kwargs: [{"name": "chain"}])
    monkeypatch.setattr(helpers, "_detect_string_refs", lambda *args, **kwargs: [{"name": "string"}])
    monkeypatch.setattr(helpers, "_detect_type_matches", lambda *args, **kwargs: [{"name": "typed"}])
    monkeypatch.setattr(helpers, "_detect_xor_heavy", lambda **kwargs: [{"name": "xor"}])
    monkeypatch.setattr(helpers, "_detect_callers_of", lambda *args, **kwargs: [{"name": "caller"}])
    monkeypatch.setattr(helpers, "_detect_callees_of", lambda *args, **kwargs: [{"name": "callee"}])
    assert helpers._run_custom_detector({"rule_type": "api_chain", "apis": "recv, memcpy", "strict_order": False}, 4)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "string_ref", "pattern": "token"}, 4)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "type_match", "type_pattern": "char"}, 4)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "xor_threshold", "threshold": 2}, 4)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "caller_of", "target": "entry"}, 4)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "callee_of", "target": "entry"}, 4)["count"] == 1

    class Visitor:
        def __init__(self, *_args):
            pass

        def apply_to(self, body, _parent):
            for expr in body:
                self.visit_expr(expr)

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_call", 59, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", 53, raising=False)
    target_ea = 0x2000
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: target_ea if name in {"recv", "memcpy"} else BADADDR)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: {0x3000: "recv", 0x4000: "memcpy"}.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "worker")
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
    monkeypatch.setattr(helpers, "_function_may_reference_apis", lambda *_args: True)
    body = [
        types.SimpleNamespace(op=59, x=types.SimpleNamespace(op=53, obj_ea=0x3000)),
        types.SimpleNamespace(op=59, x=types.SimpleNamespace(op=53, obj_ea=0x4000)),
    ]
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: types.SimpleNamespace(body=body))
    strict = real_detect_api_chains(["recv", "memcpy"], strict_order=True)
    assert strict[0]["call_chain"] == ["recv", "memcpy"]
    any_order = real_detect_api_chains(["memcpy", "recv"], strict_order=False)
    assert any_order[0]["name"] == "worker"


def test_code_helper_type_xor_and_reference_detectors_cover_limits(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: "f1" if ea == 0x1000 else "f2")
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x3000 if name == "_target" else BADADDR)
    monkeypatch.setattr(helpers.idc, "get_name", lambda _ea: "")
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda ea: iter([ea, ea + 4]))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: "XOR" if ea == 0x1000 else "nop")
    assert helpers._detect_xor_heavy(threshold=1)[0]["xor_count"] == 1
    assert helpers._function_may_reference_apis(0x1000, {"target"}, set()) is True

    class ParamData(list):
        def size(self):
            return len(self)

    class Tinfo:
        def get_func_details(self, data):
            data.extend([types.SimpleNamespace(name="buf", type="char *")])
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", ParamData, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)
    assert helpers._detect_type_matches("char")[0]["param_name"] == "buf"

    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x2000]))
    assert helpers._detect_callers_of("target")[0]["name"] == "f2"
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x1000]))
    assert helpers._detect_callees_of("target")[0]["name"] == "f1"
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda _name: BADADDR)
    assert helpers._detect_callers_of("missing") == []
    assert helpers._detect_callees_of("missing") == []
