"""Boundary and fallback coverage for the composed code-helper surface."""

from __future__ import annotations

import types

from tests.fakes.ida_fake import BADADDR


def test_code_helper_pure_fallbacks_and_expression_rows(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    assert helpers._semantic_pseudocode_summary("if (x) { for (;;) y = *p; } return f();")["pointer_deref_count"] == 1
    assert helpers._sign_extend_imm12(0x7FF) == 0x7FF
    assert helpers._sign_extend_imm12(0xFFF) == -1
    monkeypatch.setattr(helpers._compat, "get_prev_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(helpers._compat, "get_next_func_start", lambda _ea: 0x2000)
    assert helpers._get_prev_func(0x2000) == 0x1000
    assert helpers._get_next_func(0x1000) == 0x2000

    class Expr:
        ea = 0x1000

        @staticmethod
        def print1(_tag):
            return "v1 = arg"

    class Body:
        pass

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", type("Visitor", (), {
        "__init__": lambda self, *_args: None,
        "apply_to": lambda self, _body, _parent: self.visit_expr(Expr()),
    }))
    monkeypatch.setattr(helpers.ida_lines, "tag_remove", lambda text: text)
    rows = helpers._collect_expr_rows_from_cfunc(types.SimpleNamespace(body=Body()))
    assert rows == [(0x1000, "v1 = arg")]

    class CallableType:
        def __call__(self):
            return types.SimpleNamespace(dstr=lambda: "char *")

    assert helpers._lvar_type_str(types.SimpleNamespace(type=CallableType())) == "char *"
    assert helpers._lvar_type_str(types.SimpleNamespace(type=object()))
    assert helpers._lvar_type_str(types.SimpleNamespace(type=lambda: (_ for _ in ()).throw(RuntimeError()))) == ""
    assert helpers._detect_api_calls("memcpy malloc send", limit=2) == ["malloc", "memcpy"]


def test_code_helper_detector_and_signal_fallback_modes(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: None)
    assert helpers._detect_firmware_signals(0x1000) == []
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004))
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: False)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "")
    monkeypatch.setattr(helpers.idc, "next_head", lambda _ea, _end: BADADDR)
    assert helpers._detect_firmware_signals(0x1000, "load 0x40000000") == ["constant_ref:0x40000000"]
    assert helpers._detect_crypto_hints("AES_encrypt(x); x ^= k; y ^= k;", xor_threshold=2)[0]
    assert helpers._detect_dangerous_patterns([], "strcpy(dst, src);", detailed=True)
    assert helpers._detect_dangerous_patterns([], "strcpy(dst, src);", detailed=False)[0].startswith("strcpy_unbounded")
    assert helpers._build_pseudocode_complexity("switch (x) { case 1: break; }", xor_count=9, include_switch_cases=True)["xor_ops"] == 9

    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _n: "text\x00")
    assert helpers._read_candidate_string(0x5000) == "text"
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _n: b"\x01bad")
    assert helpers._read_candidate_string(0x5000) is None
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda *_args: b"x")
    assert helpers._read_candidate_string(0x5000) is None


def test_code_helper_custom_detector_invalid_and_api_chain_modes(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    helpers._CUSTOM_DETECTORS.clear()
    assert helpers.register_detector("Demo", {"type": "string_ref"})["ok"] is True
    assert helpers.list_detectors()[0]["name"] == "demo"
    assert helpers.delete_detector("demo") is True
    assert helpers.delete_detector("demo") is False
    assert helpers._run_custom_detector({"register": True, "rule": "bad"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "api_chain"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "string_ref"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "type_match"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "caller_of"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "callee_of"}, 3)["error"] is True
    monkeypatch.setattr(helpers, "_detect_xor_heavy", lambda **_kwargs: [])
    assert helpers._run_custom_detector({"rule_type": "xor_threshold", "threshold": 2}, 3)["ok"] is True
    assert helpers._detect_callers_of("missing") == []
    assert helpers._detect_callees_of("missing") == []

    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter(()))
    assert helpers._detect_api_chains(["recv"], max_items=2) == []
    assert helpers._detect_string_refs("[") == []
    assert helpers._detect_type_matches("[") == []
    assert helpers._detect_xor_heavy(threshold=1) == []


def test_code_helper_enrichment_no_api_and_structured_disassembly_modes(monkeypatch, fresh_fake_idb):
    import importlib

    helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")
    monkeypatch.setattr(helpers, "_detect_api_calls", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helpers, "_detect_crypto_hints", lambda *_args, **_kwargs: ([], 0))
    monkeypatch.setattr(helpers, "_detect_dangerous_patterns", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helpers, "_extract_var_rename_hints", lambda *_args: [])
    monkeypatch.setattr(helpers, "gather_function_context", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(helpers, "_detect_firmware_signals", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helpers, "_get_blackboard_context_for_addr", lambda *_args: [])
    enriched = helpers._build_decompile_enrichment(0x1000, None, "return 0")
    assert enriched["api_note"].startswith("no libc")

    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "jmp")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, _idx: "0x1000")
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0x140001000)
    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda _ea, _flags: "jmp 0x140001000")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda *_args: "comment")
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda ea: ea & 0xFF)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 0, raising=False)
    structured = helpers._format_disasm_structured(0x140001000)
    assert structured["mnem"] == "jmp"
    assert helpers._is_flow_control_mnemonic("ret") is True
    assert helpers._is_flow_control_mnemonic("") is False
    monkeypatch.setattr(helpers, "_flow_target_ea", lambda _ea: 0x140001000)
    assert helpers._annotate_branch_target(0x140001000, "jmp")
