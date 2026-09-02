"""Additional cross-mode coverage for code-helper fallbacks and scanners."""

from __future__ import annotations

import importlib
import types

import pytest

from tests.fakes.ida_fake import BADADDR, BT_INT8, FakeTinfo, cexpr_t, cfunc_t, cot_obj, cot_ref, cot_var, lvar_t, var_ref_t

from . import test_code_helpers_ctree_modes as ctree_modes


@pytest.fixture
def helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_structure_summary_covers_call_limits_control_condition_failures(monkeypatch, helpers):
    class Block:
        start_ea = 0x1000
        end_ea = 0x1004

        def succs(self):
            return iter(())

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [Block()])
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000, 0x1004]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda ea, _flow: iter([0x2000 + ea]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: f"callee_{ea:x}")

    class Expr:
        def print1(self, _tag):
            raise RuntimeError("condition unavailable")

    class Visitor:
        def __init__(self, *_args):
            pass

        def apply_to(self, body, _parent=None):
            for insn in body.insns:
                self.visit_insn(insn)

    hx = helpers.ida_hexrays
    monkeypatch.setattr(hx, "ctree_visitor_t", Visitor)
    monkeypatch.setattr(hx, "CV_FAST", 0, raising=False)
    monkeypatch.setattr(hx, "cit_if", 1, raising=False)
    monkeypatch.setattr(hx, "cit_while", 2, raising=False)
    monkeypatch.setattr(hx, "cit_for", 3, raising=False)
    monkeypatch.setattr(hx, "cit_switch", 4, raising=False)
    monkeypatch.setattr(
        helpers,
        "_build_decompiler_dataflow",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("dataflow unavailable")),
    )
    cfunc = types.SimpleNamespace(
        body=types.SimpleNamespace(
            insns=[
                types.SimpleNamespace(
                    op=hx.cit_if,
                    ea=BADADDR,
                    cif=types.SimpleNamespace(expr=Expr()),
                ),
                types.SimpleNamespace(op=hx.cit_while, ea=0x1010, cwhile=types.SimpleNamespace(expr=None)),
            ]
        )
    )

    summary = helpers._build_function_structure_summary(
        types.SimpleNamespace(start_ea=0x1000), cfunc=cfunc, max_items=1, details=True
    )
    assert summary["call_targets"] == ["callee_3000"]
    assert summary["control_points"][0]["condition"] == ""
    assert "cfg:" in summary["evidence"]
    assert "dataflow" not in summary


def test_variable_hints_cover_argument_and_usage_fallbacks(helpers):
    class Cfunc:
        type = "int socket_handler(int fd, int size)"

        def __str__(self):
            return "int socket_handler(int a1, int a2) { v9 = send(v9, a2); a2 = 0; }"

    class BrokenType:
        def __call__(self):
            raise RuntimeError("type unavailable")

    cfunc = Cfunc()
    cfunc.lvars = [
        types.SimpleNamespace(name="a1", type=BrokenType()),
        types.SimpleNamespace(name="a2", type=None),
        types.SimpleNamespace(name="v9", type=None),
        types.SimpleNamespace(name="stable", type=None),
    ]
    hints = helpers._extract_var_rename_hints(cfunc)
    assert {row["suggested"] for row in hints} >= {"fd", "size", "send_buf"}


def test_firmware_and_candidate_string_helpers_fail_closed_and_fallback(helpers, monkeypatch):
    assert helpers._detect_firmware_signals(0x1000) == []

    class BrokenUA:
        class insn_t:
            pass

        def decode_insn(self, *_args):
            raise RuntimeError("decoder unavailable")

    monkeypatch.setattr(helpers, "ida_ua", BrokenUA())
    assert helpers._store_memory_target(0x1000) is None

    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _n: b"ok\x00")
    assert helpers._read_candidate_string(0x1000) is None
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _n: b"hello\x00")
    assert helpers._read_candidate_string(0x1000) == "hello"
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _n: b"\x01\x02\x03")
    assert helpers._read_candidate_string(0x1000) is None
    assert helpers._read_candidate_string(BADADDR) is None


def test_constant_materialization_zero_immediate_still_advances(monkeypatch, helpers):
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "mov")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, _idx: "a0")
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1004 else BADADDR)
    assert helpers._scan_constant_load_strings(0x1000) == []


def test_ctree_post_analysis_covers_shared_strings_arm_and_int3(monkeypatch, fresh_fake_idb, helpers):
    import idautils
    import idc

    ctree_modes._install_ctree_surface(monkeypatch)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_ref", cot_ref, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", cot_obj, raising=False)
    db = fresh_fake_idb
    target = 0x140010100
    shared_string = cexpr_t(
        op=cot_ref,
        x=cexpr_t(op=cot_obj, obj_ea=0x140020000),
        ea=0x140001010,
    )
    cfunc = cfunc_t(
        entry_ea=0x140001000,
        body=ctree_modes._body([
            ctree_modes._call(db, "gets", [ctree_modes._var(0), shared_string], 0x140001001, target),
        ]),
        lvars=[lvar_t("input_data", FakeTinfo(kind=BT_INT8), is_arg_var=True)],
    )
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [])
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter([0x140002004]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x140003000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "network_dispatch")
    monkeypatch.setattr(helpers.idc, "get_func_attr", lambda *_args: 4, raising=False)
    monkeypatch.setattr(helpers.idaapi, "FUNC_LIB", 4, raising=False)
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 2 | 4)
    monkeypatch.setattr(helpers._compat, "get_segment_name", lambda _ea: ".data")
    monkeypatch.setattr(helpers._compat, "frame_members", lambda _ea: [(0, "__stack_chk_guard", 0, 8, "uint64_t")])
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\xcc\xcc\xcc\xcc")
    monkeypatch.setattr(helpers.idc, "get_str_type", lambda _ea: 1, raising=False)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"http://admin/cmd")
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [types.SimpleNamespace(frm=0x140004000)])
    monkeypatch.setattr(helpers.idaapi, "INF_PROCNAME", 1, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: "arm", raising=False)

    class Block:
        start_ea = 0x140001000
        end_ea = 0x140001008

        def succs(self):
            return []

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [Block()])
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x140001004]))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "BLX", raising=False)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda *_args: 0x50000000, raising=False)
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {row["pattern"] for row in findings}
    assert {"int3_padding", "shared_suspicious_string", "stack_canary_present", "library_func_with_vuln"} <= patterns


def test_dangerous_text_detector_and_ctree_rendering_modes(monkeypatch, helpers):
    pseudo = (
        'strcpy(dst, src); system(cmd); sprintf(dst, fmt); '
        'malloc(n * 8); recv(buf, n); memcpy(buf, src, n); '
        'password = "secret";'
    )
    found_apis = ["access", "open", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
    detailed = helpers._detect_dangerous_patterns(found_apis, pseudo, detailed=True)
    flat = helpers._detect_dangerous_patterns(found_apis, pseudo, detailed=False)
    patterns = {row["pattern"] for row in detailed}
    assert {"source_to_sink_flow", "toctou_race", "hardcoded_secret", "process_injection", "remote_thread_injection"} <= patterns
    assert any("strcpy_unbounded" in row for row in flat)

    monkeypatch.setattr(helpers, "_scan_ctree_vulns", lambda _cfunc: [{"pattern": "ast-risk", "detail": "danger"}])
    assert helpers._detect_dangerous_patterns([], "", detailed=True, cfunc=object()) == [{"pattern": "ast-risk", "detail": "danger"}]
    assert helpers._detect_dangerous_patterns([], "", detailed=False, cfunc=object()) == ["ast-risk — danger"]


def test_disassembly_and_compact_reference_helpers_cover_fallback_names(monkeypatch, helpers):
    monkeypatch.setattr(helpers, "_is_flow_control_mnemonic", lambda _mnem: True)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "jmp")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, idx: 7 if idx == 5 else 0)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda *_args: 0x401000)
    monkeypatch.setattr(helpers.idc, "get_name", lambda _ea: "")
    assert helpers._annotate_branch_target(0x1000, "jmp") == "0x401000"

    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda *_args: "jmp 0x401000")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, idx: "0x401000" if idx == 0 else "")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda *_args: "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda _ea: 0x90)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 0, raising=False)
    structured = helpers._format_disasm_structured(0x1000)
    assert structured["branch_target"] == "0x401000"
    assert structured["bytes"] == "90 90"

    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter([0x2000, 0x2000, 0x3000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: f"f{ea:x}")
    assert len(helpers._collect_compact_callers(0x1000, result_limit=2)) == 2
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda *_args: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_args: iter([0x2000, 0x3000]))
    assert len(helpers._collect_compact_callees(0x1000, result_limit=1)) == 1


def test_custom_detector_and_reference_scans_cover_invalid_and_prefix_modes(monkeypatch, helpers):
    helpers._CUSTOM_DETECTORS.clear()
    assert helpers._run_custom_detector({"register": True, "rule": "bad"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "api_chain"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "string_ref"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "type_match"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "caller_of"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "callee_of"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"rule_type": "unknown"}, 3)["code"] == "INVALID_ARGS"

    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x2000 if name == "_target" else BADADDR)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: None if ea == 0x2000 else ea)
    assert helpers._detect_callers_of("target") == []
    assert helpers._detect_callees_of("target") == []
