"""Focused behavioral coverage for stack and low-level search helpers."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

stack_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.stack_analysis")
code_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.search.code")
refs_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.search.refs")


def _stack_fixture(monkeypatch):
    func = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001004)
    members = [
        (0, "arg_0", 0, 8, "int64_t"),
        (1, "__saved_rbx", 8, 8, "qword"),
        (2, " r", 16, 8, "void *"),
        (3, "buf", -16, 16, "char[16]"),
        (4, "ptr", -24, 8, "int *"),
        (5, "flag", -25, 1, "bool"),
        (6, "ratio", -32, 8, "double"),
        (7, "plain", -40, 4, ""),
    ]
    monkeypatch.setattr(stack_mod._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(stack_mod._compat, "frame_members", lambda _ea: list(members))
    monkeypatch.setattr(stack_mod._compat, "frame_size", lambda _ea: 40)
    monkeypatch.setattr(stack_mod._compat, "get_spd", lambda _start, ea: {0x140001000: -8, 0x140001001: 24}.get(ea))
    monkeypatch.setattr(stack_mod._compat, "get_func_start", lambda _ea: 0x140001000)
    monkeypatch.setattr(stack_mod.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)
    monkeypatch.setattr(stack_mod, "get_arch", lambda: "x86_64")
    # Some isolated tool tests install a lightweight _common module before
    # this module is imported.  Rebind the architecture predicate at the
    # fixture boundary so the frame cases stay valid in either import mode.
    monkeypatch.setattr(stack_mod, "is_x86_family", lambda arch: arch in {"x86", "x64", "x86_64"})
    monkeypatch.setattr(stack_mod, "get_callee_saved_registers", lambda _arch: {"__saved_rbx"})
    monkeypatch.setattr(stack_mod, "_inf_bitness", lambda: 64)
    monkeypatch.setattr(stack_mod, "_inf_procname", lambda: "metapc")
    monkeypatch.setattr(stack_mod.idc, "get_screen_ea", lambda: 0x140001000, raising=False)
    monkeypatch.setattr(stack_mod.idc, "next_head", lambda ea, *_args: ea + 1 if ea < 0x140001003 else stack_mod.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(stack_mod.idc, "get_name_ea_simple", lambda name: 0x2000 if name == "__security_cookie" else stack_mod.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(
        stack_mod.idautils,
        "XrefsTo",
        lambda ea, *_args: [SimpleNamespace(frm=0x140001001, iscode=True)] if ea == 0x2000 else [],
        raising=False,
    )
    monkeypatch.setattr(stack_mod.idautils, "Functions", lambda: [0x1000], raising=False)
    return func, members


def test_stack_actions_classify_frames_and_architecture(monkeypatch):
    _stack_fixture(monkeypatch)

    frame = stack_mod.stack_analysis(action="frame", address="0x140001000", limit=3)
    assert frame["ok"] is True
    assert frame["member_count"] == 3
    assert frame["arch"] == {"proc": "METAPC", "bits": 64, "ptr_size": 8}

    buffers = stack_mod.stack_analysis(action="buffers", addr="0x140001000")
    assert buffers["count"] == 1
    assert "buf" in buffers["buffers"]

    alignment = stack_mod.stack_analysis(action="alignment", addr="0x140001000")
    assert alignment["frame_alignment"] == 8
    assert alignment["max_member_alignment"] >= 8

    spills = stack_mod.stack_analysis(action="spills", addr="0x140001000")
    assert spills["count"] == 1
    assert "__saved_rbx" in spills["spills"]

    variables = stack_mod.stack_analysis(action="variables", addr="0x140001000")
    assert variables["count"] == 8
    assert "argument" in variables["variables"]
    assert "pointer" in variables["variables"]
    assert "boolean" in variables["variables"]

    arrays = stack_mod.stack_analysis(action="arrays", addr="0x140001000")
    assert arrays["count"] == 1
    assert "'element_count': 16" in arrays["arrays"]


def test_stack_canary_usage_uninitialized_and_summary(monkeypatch):
    _stack_fixture(monkeypatch)
    ida_ua = stack_mod.ida_ua
    ida_frame = stack_mod.ida_frame
    op = SimpleNamespace(type=ida_ua.o_displ)
    insn = SimpleNamespace(ops=[op])
    monkeypatch.setattr(ida_ua, "insn_t", lambda: insn, raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _out, _ea: 1, raising=False)
    monkeypatch.setattr(ida_frame, "get_stkvar", lambda _insn, _op: (SimpleNamespace(soff=-16), 0), raising=False)
    monkeypatch.setattr(stack_mod.idc, "print_insn_mnem", lambda _ea: "mov", raising=False)

    canary = stack_mod.stack_analysis(action="canary", addr="0x140001000")
    assert canary["has_canary"] is True
    assert canary["canary_type"] == "MSVC_security_cookie"

    usage = stack_mod.stack_analysis(action="usage", addr="0x140001000")
    assert usage["max_spd"] == 24
    assert usage["min_spd"] == -8
    assert usage["has_dynamic_alloc"] is False

    uninitialized = stack_mod.stack_analysis(action="uninitialized", addr="0x140001000")
    assert uninitialized["count"] >= 1
    assert "ptr" in uninitialized["uninitialized"]

    summary = stack_mod.stack_analysis(action="summary", addr="0x140001000")
    assert summary["local_count"] == 5
    assert summary["arg_count"] == 1
    assert summary["saved_reg_count"] == 1
    assert summary["buffer_count"] == 1
    assert summary["has_canary"] is True


def test_stack_error_and_no_frame_paths(monkeypatch):
    func = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001001)
    monkeypatch.setattr(stack_mod._compat, "get_func_info", lambda _ea: None)
    assert stack_mod.stack_analysis(action="frame", addr="0x140001000")["error"] is True
    monkeypatch.setattr(stack_mod.idc, "get_screen_ea", lambda: stack_mod.idaapi.BADADDR, raising=False)
    assert stack_mod.stack_analysis(action="frame")["error"] is True

    monkeypatch.setattr(stack_mod._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(stack_mod._compat, "frame_members", lambda _ea: [])
    monkeypatch.setattr(stack_mod._compat, "frame_size", lambda _ea: 0)
    monkeypatch.setattr(stack_mod.ida_funcs, "get_func_name", lambda _ea: "empty", raising=False)
    no_frame = stack_mod.stack_analysis(action="frame", addr="0x140001000")
    assert no_frame["ok"] is True
    assert "No stack frame" in no_frame["note"]
    assert stack_mod.stack_analysis(action="unknown", addr="0x140001000")["error"] is True


def test_stack_helper_and_compatibility_modes(monkeypatch):
    assert stack_mod._is_store_insn("str") is True
    assert stack_mod._is_store_insn("") is False
    assert stack_mod._is_store_insn("load") is False
    assert stack_mod._store_dest_operand_indices(SimpleNamespace(ops=[1, 2, 3]), "riscv") == [0, 1, 2]
    monkeypatch.setattr(stack_mod, "is_x86_family", lambda arch: arch in {"x86", "x64"})
    assert stack_mod._store_dest_operand_indices(SimpleNamespace(), "x64") == [0]
    assert stack_mod._is_buffer_like("char", 8) is True
    assert stack_mod._is_buffer_like("void *", 32) is False
    assert stack_mod._is_buffer_like("struct item", 16) is True
    assert stack_mod._is_buffer_like("int", 4) is False

    monkeypatch.setattr(stack_mod, "validate_addr", lambda _addr: (None, {"error": True}))
    func, error = stack_mod._get_func_or_error("not-an-address")
    assert func is None and error["error"] is True

    func_obj = SimpleNamespace(start_ea=0x1000)
    monkeypatch.setattr(stack_mod._compat, "frame_members", lambda _ea: [])
    monkeypatch.setattr(stack_mod._compat, "frame_size", lambda _ea: 8)
    assert stack_mod._get_frame_or_error(func_obj) == (True, None)
    monkeypatch.setattr(stack_mod._compat, "frame_size", lambda _ea: 0)
    has_frame, no_frame = stack_mod._get_frame_or_error(func_obj)
    assert has_frame is False and no_frame["ok"] is True
    monkeypatch.setattr(stack_mod, "_inf_bitness", lambda: 32)
    monkeypatch.setattr(stack_mod, "_inf_procname", lambda: "  arm  ")
    assert stack_mod._get_arch_info() == {"proc": "ARM", "bits": 32, "ptr_size": 4}


def test_stack_arrays_variables_and_dynamic_alloc_modes(monkeypatch):
    _stack_fixture(monkeypatch)
    members = [
        (0, "char_block", -8, 8, "char"),
        (1, "short_block", -16, 16, "short"),
        (2, "int_block", -32, 16, "int"),
        (3, "long_block", -48, 16, "long"),
        (4, "struct_block", -64, 16, "struct item"),
        (5, "ptr_block", -80, 24, "void *"),
        (6, "odd_array", -96, 5, "char[]"),
        (7, "unknown", -104, 3, "opaque"),
    ]
    monkeypatch.setattr(stack_mod._compat, "frame_members", lambda _ea: list(members))
    arrays = stack_mod.stack_analysis(action="arrays", addr="0x140001000")
    assert arrays["count"] == 6
    assert "'element_size': 1" in arrays["arrays"]
    assert "'element_size': 2" in arrays["arrays"]
    assert "'element_size': 4" in arrays["arrays"]
    assert "'element_size': 8" in arrays["arrays"]
    assert "'element_count': 0" in arrays["arrays"]

    variables = stack_mod.stack_analysis(action="variables", addr="0x140001000")
    assert "'category': 'byte'" in variables["variables"]
    assert "'category': 'unknown'" in variables["variables"]

    monkeypatch.setattr(stack_mod.idc, "get_name_ea_simple", lambda name: 0x3000 if name == "alloca" else stack_mod.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(
        stack_mod.idautils,
        "XrefsTo",
        lambda ea, *_args: [SimpleNamespace(frm=0x140001002)] if ea == 0x3000 else [],
        raising=False,
    )
    usage = stack_mod.stack_analysis(action="usage", addr="0x140001000")
    assert usage["has_dynamic_alloc"] is True
    assert "alloca" in usage["alloca_calls"]


def test_stack_canary_and_uninitialized_failure_modes(monkeypatch):
    _stack_fixture(monkeypatch)
    monkeypatch.setattr(
        stack_mod.idc,
        "get_name_ea_simple",
        lambda name: 0x3000 if name == "__stack_chk_guard" else stack_mod.idaapi.BADADDR,
        raising=False,
    )
    monkeypatch.setattr(
        stack_mod.idautils,
        "XrefsTo",
        lambda ea, *_args: [SimpleNamespace(frm=0x140001001)] if ea == 0x3000 else [],
        raising=False,
    )
    canary = stack_mod.stack_analysis(action="canary", addr="0x140001000")
    assert canary["canary_type"] == "GCC_stack_chk"

    ua = stack_mod.ida_ua
    monkeypatch.setattr(stack_mod.idc, "print_insn_mnem", lambda _ea: "mov", raising=False)
    monkeypatch.setattr(ua, "decode_insn", lambda _insn, _ea: 0, raising=False)
    assert stack_mod.stack_analysis(action="uninitialized", addr="0x140001000")["count"] >= 1

    op = SimpleNamespace(type=999)
    monkeypatch.setattr(ua, "insn_t", lambda: SimpleNamespace(ops=[op]), raising=False)
    monkeypatch.setattr(ua, "decode_insn", lambda _insn, _ea: 1, raising=False)
    assert stack_mod.stack_analysis(action="uninitialized", addr="0x140001000")["count"] >= 1
    monkeypatch.setattr(stack_mod.ida_frame, "get_stkvar", lambda *_args: (_ for _ in ()).throw(RuntimeError("frame")), raising=False)
    assert stack_mod.stack_analysis(action="uninitialized", addr="0x140001000")["count"] >= 1


def test_stack_outer_error_and_zero_frame_summary(monkeypatch):
    real_get_func_or_error = stack_mod._get_func_or_error
    _stack_fixture(monkeypatch)
    monkeypatch.setattr(stack_mod, "_get_func_or_error", lambda _addr: (_ for _ in ()).throw(RuntimeError("outer")))
    outer_error = stack_mod.stack_analysis(action="summary", addr="0x140001000")
    assert outer_error.get("error")

    monkeypatch.setattr(stack_mod, "_get_func_or_error", real_get_func_or_error)
    _stack_fixture(monkeypatch)
    monkeypatch.setattr(stack_mod._compat, "frame_members", lambda _ea: [])
    monkeypatch.setattr(stack_mod._compat, "frame_size", lambda _ea: 0)
    monkeypatch.setattr(stack_mod.idc, "get_name_ea_simple", lambda _name: stack_mod.idaapi.BADADDR, raising=False)
    summary = stack_mod.stack_analysis(action="summary", addr="0x140001000")
    assert summary["ok"] is True
    assert summary["frame_size"] == 0
    assert summary["has_canary"] is False


def _search_fixture(monkeypatch):
    monkeypatch.setattr(code_mod, "resolve_scan_segments", lambda *_args, **_kwargs: ([(0x1000, 0x1002)], "", ""))
    monkeypatch.setattr(code_mod, "iter_code", lambda *_args, **_kwargs: iter((0x1000, 0x1001)))
    monkeypatch.setattr(code_mod, "iter_segments", lambda *_args, **_kwargs: ((0x1000, 0x1002),))
    monkeypatch.setattr(code_mod.ida_bytes, "is_code", lambda _flags: True, raising=False)
    monkeypatch.setattr(code_mod.ida_bytes, "get_flags", lambda _ea: 1, raising=False)
    monkeypatch.setattr(code_mod.idaapi, "o_void", 0, raising=False)
    monkeypatch.setattr(code_mod.idc, "print_insn_mnem", lambda ea: {0x1000: "mov", 0x1001: "ret"}[ea], raising=False)
    monkeypatch.setattr(code_mod.idc, "next_head", lambda ea, *_args: 0x1001 if ea == 0x1000 else (0x1002 if ea == 0x1001 else code_mod.idaapi.BADADDR), raising=False)
    monkeypatch.setattr(code_mod.idc, "get_operand_type", lambda _ea, idx: code_mod.idaapi.o_void if idx > 1 else idx + 1, raising=False)
    monkeypatch.setattr(code_mod.idc, "print_operand", lambda _ea, idx: ("eax", "[rbp-8]")[idx], raising=False)
    monkeypatch.setattr(code_mod.idc, "get_cmt", lambda ea, kind: "repeatable needle" if ea == 0x1001 and kind == 1 else None, raising=False)
    monkeypatch.setattr(code_mod, "safe_generate_disasm_line", lambda ea: f"<tag>{code_mod.idc.print_insn_mnem(ea)}</tag>")
    monkeypatch.setattr(code_mod.ida_lines, "tag_remove", lambda line: line.replace("<tag>", "").replace("</tag>", ""), raising=False)
    monkeypatch.setattr(code_mod._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(code_mod.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)


def test_search_code_helpers_cover_context_and_pagination(monkeypatch):
    _search_fixture(monkeypatch)
    insns = code_mod.search_insns("mov,ret", None, None, True, 0, 1)
    assert insns["truncated"] is True
    assert "in:handler" in insns["results"]

    text = code_mod.search_text("MOV", False, None, None, True, 0, 10)
    assert text["count"] == 1
    assert "0x1000" in text["results"]

    operands = code_mod.search_operand("rbp", False, None, None, True, 0, 10)
    assert operands["count"] == 2
    assert "[rbp-8]" in operands["results"]

    comments = code_mod.search_comment("needle", False, None, None, 0, 10)
    assert comments["count"] == 1
    assert "repeatable" in comments["results"]


def test_search_refs_regex_and_signature_filters(monkeypatch):
    call_xref_type = next(iter(refs_mod.CALL_XREF_TYPES))
    xrefs = [
        SimpleNamespace(frm=0x1000, to=0x2000, iscode=False, type=0),
        SimpleNamespace(frm=0x1001, to=0x2000, iscode=True, type=call_xref_type),
    ]
    monkeypatch.setattr(refs_mod, "resolve_target", lambda *_a, **_k: (0x2000, None, {}))
    monkeypatch.setattr(refs_mod.idautils, "XrefsTo", lambda *_a, **_k: iter(xrefs), raising=False)
    monkeypatch.setattr(refs_mod.idc, "get_name", lambda ea: "global_data" if ea == 0x1000 else "", raising=False)
    monkeypatch.setattr(refs_mod._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(refs_mod.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)
    monkeypatch.setattr(refs_mod, "safe_generate_disasm_line", lambda _ea: "call target")
    monkeypatch.setattr(refs_mod.ida_lines, "tag_remove", lambda line: line, raising=False)

    data = refs_mod.search_data_ref("global_data", True, 0, 10, 0.0, False)
    assert data["count"] == 1
    assert "global_data" in data["results"]
    code = refs_mod.search_code_ref("target", True, 0, 10, 0.0, False)
    assert code["count"] == 1
    assert "handler" in code["results"]

    monkeypatch.setattr(refs_mod, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1002)], "", ""))
    monkeypatch.setattr(refs_mod, "iter_code", lambda *_a, **_k: iter((0x1000, 0x1001)))
    regex = refs_mod.search_regex("call", False, None, None, True, 0, 10)
    assert regex["count"] == 2
    assert "in:handler" in regex["results"]
    assert refs_mod.search_regex("(", False, None, None, False, 0, 10)["error"] is True
    assert refs_mod.search_regex("(a+)+", False, None, None, False, 0, 10)["error"] is True

    func = SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
    monkeypatch.setattr(refs_mod._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(refs_mod.idautils, "Functions", lambda: [0x1000], raising=False)
    monkeypatch.setattr(refs_mod.idautils, "XrefsFrom", lambda *_a, **_k: [], raising=False)
    monkeypatch.setattr(refs_mod.idautils, "XrefsTo", lambda *_a, **_k: [], raising=False)
    monkeypatch.setattr(refs_mod.ida_funcs, "get_func_name", lambda _ea: "leaf_func", raising=False)
    sig = refs_mod.search_func_by_sig("leaf", 0, 10)
    assert sig["ok"] is True
