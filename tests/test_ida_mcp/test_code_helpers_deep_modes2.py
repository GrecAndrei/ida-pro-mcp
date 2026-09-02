"""Additional mode-matrix coverage for code-helper protocol surfaces."""

from __future__ import annotations

import importlib
import types

import pytest

from tests.fakes.ida_fake import BADADDR


@pytest.fixture
def helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_candidate_strings_and_constant_materialization_cover_all_fallbacks(monkeypatch, helpers):
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea != 0xBAD)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"hello world\0tail")
    assert helpers._read_candidate_string(0x1000) == "hello world"
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\x01\x02\0")
    assert helpers._read_candidate_string(0x1000) is None
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: "text\0")
    assert helpers._read_candidate_string(0x1000) == "text"
    assert helpers._read_candidate_string(BADADDR) is None
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: False)
    assert helpers._read_candidate_string(0x1000) is None

    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1018)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    mnems = iter(["lui", "addi", "auipc", "ld", "mov", "li"])
    operands = {
        0x1000: ["a0", "0x100"],
        0x1004: ["a0", "a0", "-4"],
        0x1008: ["a1", "0x100"],
        0x100C: ["a2", "a1", "8"],
        0x1010: ["a3", "0x2000"],
        0x1014: ["a4", "0"],
    }
    eas = iter([0x1000, 0x1004, 0x1008, 0x100C, 0x1010, 0x1014, 0x1018])
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: next(mnems))
    monkeypatch.setattr(helpers.idc, "print_operand", lambda ea, idx: operands[ea][idx])
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda ea, idx: int(operands[ea][idx], 0))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: next(eas))
    monkeypatch.setattr(helpers, "_read_candidate_string", lambda target: "resolved" if target else None)
    results = helpers._scan_constant_load_strings(0x1000, result_limit=4)
    assert results and results[0]["value"] == "resolved"
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: None)
    assert helpers._scan_constant_load_strings(0x1000) == []


def test_trace_argument_origin_classifies_every_source_and_failure(monkeypatch, helpers):
    target = types.SimpleNamespace(start_ea=0x1000)
    pseudo_by_caller = {
        0x2000: 'target("text")',
        0x2010: "target(123)",
        0x2020: "target(make_value())",
        0x2030: "target(&buffer)",
        0x2040: "target(variable)",
        0x2050: "target()",
        0x2060: "raise_error()",
    }
    refs = [types.SimpleNamespace(frm=ea, iscode=True) for ea in pseudo_by_caller]
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: "target" if ea == 0x1000 else f"caller_{ea:x}")
    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "")
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea, _flow=0: iter(refs))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)

    class Decompiled:
        def __init__(self, text):
            self.text = text

        def __str__(self):
            if self.text == "raise_error()":
                raise RuntimeError("decompile failed")
            return self.text

    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda ea: Decompiled(pseudo_by_caller[ea]))
    result = helpers._trace_argument_origin(target, 0, 0, 10)
    kinds = {entry["arg_type"] for entry in result["trace_tree"]}
    assert {"string_literal", "constant", "function_call", "address_of", "variable", "parse_failed"} <= kinds
    assert any(entry["arg_type"].startswith("decompile_error:") for entry in result["trace_tree"])

    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "int target(char *buf)")
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad prototype")))
    assert helpers._trace_argument_origin(target, 3, 0, 1)["argument_name"] == "arg3"
    assert helpers._trace_argument_origin(target, 0, -1, 1)["trace_tree"] == []


def test_text_danger_detector_reports_sources_secrets_races_and_injection(helpers):
    pseudo = (
        'strcpy(dst, input); system(command); sprintf(out, fmt); '
        'malloc(count * size); recv(sock, input, n); memcpy(dst, input, n); '
        'password = "hardcoded"; VirtualAlloc(0, n); WriteProcessMemory(h, p, input, n);'
    )
    found_apis = ["access", "open", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
    detailed = helpers._detect_dangerous_patterns(found_apis, pseudo, detailed=True)
    patterns = {row["pattern"] for row in detailed}
    assert {
        "strcpy_unbounded", "command_injection", "sprintf_unbounded",
        "integer_overflow_alloc", "source_to_sink_flow", "toctou_race",
        "hardcoded_secret", "process_injection", "remote_thread_injection",
    } <= patterns
    flat = helpers._detect_dangerous_patterns(found_apis, pseudo, detailed=False)
    assert any("command_injection" in row for row in flat)
    assert helpers._detect_dangerous_patterns([], "safe_function()", detailed=True) == []
    assert helpers._build_pseudocode_complexity("switch (x) { case 1: return a ^ b; }", include_switch_cases=True, xor_count=9)["switch_cases"] == 1


def test_custom_detector_dispatch_and_registry_modes(monkeypatch, helpers):
    monkeypatch.setattr(helpers, "_CUSTOM_DETECTORS", {})
    assert helpers.register_detector("Demo", {"type": "xor_threshold"})["ok"] is True
    assert helpers.list_detectors()[0]["name"] == "demo"
    assert helpers._run_custom_detector({"list_detectors": True}, 3)["ok"] is True
    assert helpers._run_custom_detector({"delete_detector": True}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"delete_detector": True, "name": "demo"}, 3)["deleted"] is True
    assert helpers.delete_detector("missing") is False

    monkeypatch.setattr(helpers, "_detect_api_chains", lambda *args, **kwargs: [{"api": "ok"}])
    monkeypatch.setattr(helpers, "_detect_string_refs", lambda *args, **kwargs: [{"string": "ok"}])
    monkeypatch.setattr(helpers, "_detect_type_matches", lambda *args, **kwargs: [{"type": "ok"}])
    monkeypatch.setattr(helpers, "_detect_xor_heavy", lambda *args, **kwargs: [{"xor": 4}])
    monkeypatch.setattr(helpers, "_detect_callers_of", lambda *args, **kwargs: [{"caller": "ok"}])
    monkeypatch.setattr(helpers, "_detect_callees_of", lambda *args, **kwargs: [{"callee": "ok"}])
    assert helpers._run_custom_detector({"rule_type": "api_chain", "apis": "recv, memcpy", "strict_order": False}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "string_ref", "pattern": "secret"}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "type_match", "type": "char"}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "xor_threshold", "threshold": 2}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "caller_of", "function": "main"}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "callee_of", "target": "main"}, 3)["count"] == 1
    assert helpers._run_custom_detector({"rule_type": "unknown"}, 3)["code"] == "INVALID_ARGS"
    assert helpers._run_custom_detector({"register": True, "name": "x", "rule": "bad"}, 3)["code"] == "INVALID_ARGS"


def test_detector_scans_cover_limits_invalid_patterns_and_prefix_resolution(monkeypatch, helpers):
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x3000 if name in {"_target", "__target", "target"} else BADADDR)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x1000 if ea == 0x3000 else (ea if ea in {0x1000, 0x2000} else None))
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _func: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_args: iter([0x2000]))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: f"fn_{ea:x}")
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "xor")
    assert helpers._detect_xor_heavy(threshold=1)[0]["xor_count"] == 1
    assert helpers._detect_callers_of("target")[0]["name"] == "fn_2000"
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter([0x1000]))
    assert helpers._detect_callees_of("target")[0]["name"] == "fn_1000"

    class StringObject:
        ea = 0x4000

        def __str__(self):
            return "[secret"

    string_obj = StringObject()
    monkeypatch.setattr(helpers.idautils, "Strings", lambda: [string_obj], raising=False)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda *_args: [types.SimpleNamespace(frm=0x1000)], raising=False)
    assert helpers._detect_string_refs("[", max_items=1)[0]["string_addr"] == "0x4000"
    monkeypatch.setattr(helpers.idautils, "Strings", lambda: (_ for _ in ()).throw(RuntimeError("no strings")), raising=False)
    assert helpers._detect_string_refs("secret") == []
