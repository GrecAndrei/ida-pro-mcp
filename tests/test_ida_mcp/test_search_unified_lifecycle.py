"""Behavior coverage for the unified search response surface."""

from __future__ import annotations

from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.unified")


def _empty_find_seams(monkeypatch, uni):
    monkeypatch.setattr(uni, "get_cached_strings", list)
    monkeypatch.setattr(uni, "get_cached_imports", list)
    monkeypatch.setattr(uni.idautils, "Segments", list, raising=False)
    monkeypatch.setattr(uni, "resolve_scan_segments", lambda *_a, **_k: ([], "", ""))


def test_find_category_filters_cover_names_strings_imports_and_unknown(monkeypatch):
    uni = _module()
    _empty_find_seams(monkeypatch, uni)
    monkeypatch.setattr(uni.idautils, "Names", lambda: [(0x1000, "decrypt_key")], raising=False)
    monkeypatch.setattr(uni, "demangle_safe", lambda _name: None)
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a: 2)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda _ea: "decrypt_key", raising=False)

    names = uni.search_find(
        "decrypt",
        False,
        None,
        None,
        False,
        True,
        True,
        0,
        10,
        kind="symbols",
    )
    assert names["ok"] is True
    assert names["kind"] == "names"
    assert names["type_totals"]["names"] == 1
    assert names["items"][0]["name"] == "decrypt_key"

    monkeypatch.setattr(uni.idautils, "Names", list, raising=False)
    monkeypatch.setattr(
        uni,
        "get_cached_strings",
        lambda: [{"ea": 0x2000, "string": "decrypt this payload"}],
    )
    strings = uni.search_find(
        "payload", False, None, None, False, True, False, 0, 10, kind="literal"
    )
    assert strings["ok"] is True
    assert strings["kind"] == "strings"
    assert strings["items"][0]["type"] == "strings"

    monkeypatch.setattr(
        uni,
        "get_cached_imports",
        lambda: [{"ea": 0x3000, "name": "DecryptData", "module": "crypto.dll"}],
    )
    imports = uni.search_find(
        "decryptdata", False, None, None, False, True, False, 0, 10, kind="api"
    )
    assert imports["ok"] is True
    assert imports["kind"] == "imports"
    assert "crypto.dll" in imports["results"]

    all_categories = uni.search_find(
        "decryptdata", False, None, None, False, True, False, 0, 10, kind="not-a-kind"
    )
    assert all_categories["ok"] is True
    assert "kind_note" in all_categories


def test_find_comments_and_instructions_include_context_and_timeout_shape(monkeypatch):
    uni = _module()
    _empty_find_seams(monkeypatch, uni)
    monkeypatch.setattr(uni.idautils, "Names", list, raising=False)
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a: 0)
    monkeypatch.setattr(uni.idautils, "Segments", lambda: [0x1000], raising=False)
    monkeypatch.setattr(uni.idc, "get_segm_end", lambda _ea: 0x1002, raising=False)
    monkeypatch.setattr(uni.idautils, "Heads", lambda _start, _end: [0x1000], raising=False)
    monkeypatch.setattr(uni.idc, "get_cmt", lambda _ea, kind: "interesting note" if kind == 0 else None, raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)

    comments = uni.search_find(
        "interesting",
        False,
        None,
        None,
        True,
        True,
        True,
        0,
        10,
        kind="comments",
    )
    assert comments["ok"] is True
    assert comments["items"][0]["type"] == "comments"
    assert "interesting note" in comments["comments"]

    monkeypatch.setattr(uni, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1001)], "raw scan", ""))
    monkeypatch.setattr(uni, "iter_code", lambda *_a, **_k: iter([0x1000]))
    monkeypatch.setattr(uni.idc, "print_insn_mnem", lambda _ea: "mov", raising=False)
    monkeypatch.setattr(uni.idc, "print_operand", lambda _ea, idx: "eax" if idx == 0 else "", raising=False)
    monkeypatch.setattr(uni, "safe_generate_disasm_line", lambda _ea: "<tag>mov eax</tag>")
    monkeypatch.setattr(uni.ida_lines, "tag_remove", lambda line: line.replace("<tag>", "").replace("</tag>", ""), raising=False)
    instructions = uni.search_find(
        "mov",
        False,
        None,
        None,
        False,
        True,
        False,
        0,
        10,
        timeout_ms=0,
        kind="mnemonics",
    )
    assert instructions["ok"] is True
    assert instructions["items"][0]["type"] == "instructions"
    assert instructions["note"] == "raw scan"


def test_find_address_refs_and_identifier_scan_shortcut(monkeypatch):
    uni = _module()
    _empty_find_seams(monkeypatch, uni)
    xref = SimpleNamespace(frm=0x1100, iscode=True)
    monkeypatch.setattr(uni, "looks_like_address", lambda _value: True)
    monkeypatch.setattr(uni, "validate_addr", lambda _value: (0x1000, None))
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda _ea, _flow: [xref], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: 0x1100)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda _ea: "caller", raising=False)
    monkeypatch.setattr(uni, "demangle_safe", lambda _name: None)
    refs = uni.search_find(
        "0x1000", False, None, None, False, True, True, 0, 10, kind="refs"
    )
    assert refs["ok"] is True
    assert refs["items"][0]["type"] == "code_ref"
    assert refs["type_totals"]["code_refs"] == 1

    # Eight symbol hits meet the identifier shortcut threshold and avoid an
    # instruction scan even when every category is requested.
    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni.idautils, "Names", lambda: [(ea, f"target_{ea:x}") for ea in range(0x1000, 0x1080, 0x10)], raising=False)
    shortcut = uni.search_find(
        "target", False, None, None, False, True, False, 0, 8, kind=None
    )
    assert shortcut["ok"] is True
    assert shortcut["insn_scan"] == "skipped"


def test_callers_callees_and_api_usage_return_structured_rows(monkeypatch):
    uni = _module()
    target = SimpleNamespace(frm=0x1100, to=0x1000, iscode=True, type=0)
    callee = SimpleNamespace(frm=0x1004, to=0x2000, iscode=True, type=next(iter(uni.CALL_XREF_TYPES)))
    monkeypatch.setattr(uni, "resolve_target", lambda *_a, **_k: (0x1000, None, {"semantic_score": 0.8}))
    monkeypatch.setattr(uni._compat, "get_func_start", lambda ea: ea if ea in {0x1000, 0x1100, 0x2000} else None)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda ea: {0x1000: "target", 0x1100: "caller", 0x2000: "callee"}.get(ea, ""), raising=False)
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda _ea, _flow: [target], raising=False)
    monkeypatch.setattr(uni.idautils, "FuncItems", lambda _ea: [0x1004], raising=False)
    monkeypatch.setattr(uni.idautils, "XrefsFrom", lambda _ea, _flow: [callee], raising=False)
    monkeypatch.setattr(uni, "safe_generate_disasm_line", lambda _ea: "call callee")
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a: 1)

    callers = uni.search_callers("target", True, 0, 10, 0.0, False, True)
    assert callers["ok"] is True
    assert callers["items"][0]["name"] == "caller"
    assert "callers" not in callers["items"][0]

    callees = uni.search_callees("target", True, 0, 10, 0.0, False, True)
    assert callees["ok"] is True
    assert callees["items"][0]["name"] == "callee"
    assert callees["items"][0]["call_count"] == 1

    monkeypatch.setattr(
        uni,
        "get_cached_imports",
        lambda: [{"ea": 0x2000, "name": "memcpy", "module": "libc.so"}],
    )
    api = uni.search_api("memcpy", True, 0, 10, True, True)
    assert api["ok"] is True
    assert api["matched_apis"][0]["api"] == "memcpy"
    assert api["items"][0]["api"] == "memcpy"
    assert api["total_calls"] == 1
    monkeypatch.setattr(uni, "resolve_target", lambda *_a, **_k: (uni.idaapi.BADADDR, "missing", {}))
    assert uni.search_api("missing", False, 0, 10, False, False)["error"] is True


def test_symbol_demangle_and_symbol_info_modes(monkeypatch):
    uni = _module()
    monkeypatch.setattr(uni.idc, "INF_SHORT_DN", 1, raising=False)
    monkeypatch.setattr(uni.idc, "INF_LONG_DN", 2, raising=False)
    monkeypatch.setattr(uni.idc, "get_inf_attr", lambda attr: attr, raising=False)
    monkeypatch.setattr(uni.idc, "demangle_name", lambda name, kind: f"{name}_demangled_{kind}", raising=False)
    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni.idc, "get_name_ea_simple", lambda name: 0x1000 if name == "_Z3foov" else uni.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(uni.idc, "get_name", lambda _ea: "_Z3foov", raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(uni._compat, "get_segment", lambda _ea: object())
    monkeypatch.setattr(uni._compat, "get_segment_name", lambda _ea: ".text")
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a: 2)
    monkeypatch.setattr(uni, "demangle_safe", lambda name: f"{name}()")

    demangle = uni.search_demangle("_Z3foov,plain", limit=10)
    assert demangle["ok"] is True
    assert demangle["count"] == 2
    assert demangle["items"][0]["short"].endswith("_demangled_1")
    assert uni.search_demangle("")["error"] is True

    exact = uni.search_symbol("_Z3foov", include_alternatives=False)
    assert exact["ok"] is True
    assert exact["match"] == "exact_name"
    assert exact["is_function"] is True
    assert exact["segment"] == ".text"

    monkeypatch.setattr(uni.idc, "get_name_ea_simple", lambda _name: uni.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(uni.idautils, "Names", lambda: [(0x1000, "decrypt_key"), (0x1100, "decrypt_data")], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(
        uni._compat,
        "get_func_info",
        lambda _ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
    )
    fuzzy = uni.search_symbol("decrypt", include_alternatives=True, limit=1)
    assert fuzzy["ok"] is True
    assert fuzzy["match"] == "fuzzy"
    assert fuzzy["total_candidates"] == 2
    assert fuzzy["truncated"] is True

    monkeypatch.setattr(uni.idc, "get_name_ea_simple", lambda name: 0x1000 if name == "_Z3foov" else uni.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(
        uni,
        "make_error",
        lambda code, message, *_args, **_kwargs: {"error": True, "ok": False, "code": code, "message": message},
    )
    assert uni.search_symbol("missing")["error"] is True

    info = uni.search_symbol_info("_Z3foov", include_xrefs=True)
    assert info["ok"] is True
    assert info["function"]["start"] == "0x1000"
    assert "xrefs_to_samples" in info
    assert uni.search_symbol_info("")["error"] is True


def test_find_instruction_and_address_fallback_modes(monkeypatch):
    uni = _module()
    monkeypatch.setattr(uni, "get_cached_strings", list)
    monkeypatch.setattr(uni, "get_cached_imports", list)
    monkeypatch.setattr(uni.idautils, "Names", list, raising=False)
    monkeypatch.setattr(uni, "looks_like_address", lambda _value: True)
    monkeypatch.setattr(uni, "validate_addr", lambda _value: (uni.idaapi.BADADDR, {"error": True}))
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda _ea, _flow: [SimpleNamespace(frm=0x1100, iscode=False)], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda _ea: None)
    address = uni.search_find("0x1000", False, None, None, False, True, True, 0, 10, kind="refs")
    assert address["items"][0]["type"] == "data_ref"

    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni, "resolve_scan_segments", lambda *_a, **_k: ([(0x2000, 0x2003)], "forced", ""))
    monkeypatch.setattr(uni, "iter_code", lambda *_a, **_k: iter([0x2000, 0x2001, 0x2002]))
    monkeypatch.setattr(uni.idc, "print_insn_mnem", lambda ea: {0x2000: "", 0x2001: "MOV", 0x2002: "ret"}[ea], raising=False)
    monkeypatch.setattr(uni.idc, "print_operand", lambda _ea, _idx: None, raising=False)
    monkeypatch.setattr(uni, "safe_generate_disasm_line", lambda _ea: "MOV eax")
    monkeypatch.setattr(uni.ida_lines, "tag_remove", lambda line: line, raising=False)
    instruction = uni.search_find("MOV", True, None, None, False, False, True, 0, 10, kind="instruction")
    assert instruction["items_always"] is True
    assert instruction["type_totals"]["instructions"] == 1


def test_call_graph_and_api_nonmatching_xref_modes(monkeypatch):
    uni = _module()
    call = SimpleNamespace(frm=0x1100, to=0x2000, iscode=True, type=next(iter(uni.CALL_XREF_TYPES)))
    data_ref = SimpleNamespace(frm=0x1200, to=0x2000, iscode=False, type=0)
    monkeypatch.setattr(uni, "resolve_target", lambda *_a, **_k: (0x1000, None, {}))
    monkeypatch.setattr(uni._compat, "get_func_start", lambda ea: ea if ea in {0x1000, 0x1100, 0x2000} else None)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda ea: f"fn_{ea:x}", raising=False)
    monkeypatch.setattr(uni.idc, "get_name", lambda ea: "target" if ea == 0x1000 else "", raising=False)
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda *_a: [data_ref, call], raising=False)
    callers = uni.search_callers("target", False, 0, 10, 0.0, False, False)
    assert callers["ok"] is True and callers["count"] == 1

    non_call = SimpleNamespace(frm=0x1004, to=0x3000, iscode=True, type=0)
    monkeypatch.setattr(uni.idautils, "FuncItems", lambda _ea: [0x1004], raising=False)
    monkeypatch.setattr(uni.idautils, "XrefsFrom", lambda *_a: [non_call, call], raising=False)
    callees = uni.search_callees("target", False, 0, 10, 0.0, False, False)
    assert callees["ok"] is True and callees["count"] == 1

    monkeypatch.setattr(uni, "get_cached_imports", lambda: [
        {"ea": 0x4000, "name": "memcpy", "module": "libc.so"},
        {"ea": 0x4001, "name": "", "module": "libc.so"},
    ])
    monkeypatch.setattr(uni, "semantic_scores", lambda *_a, **_k: [0.5])
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda *_a: [data_ref, call], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda ea: 0x1000 if ea == 0x1100 else None)
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a, **_k: 1)
    api = uni.search_api("memcpy", False, 0, 10, True, False)
    assert api["ok"] is True
    assert "matched_apis" not in api
    assert api["count"] == 1


def test_demangle_symbol_alternatives_and_data_info_modes(monkeypatch):
    uni = _module()
    monkeypatch.setattr(uni.idc, "INF_SHORT_DN", 1, raising=False)
    monkeypatch.setattr(uni.idc, "INF_LONG_DN", 2, raising=False)
    monkeypatch.setattr(uni.idc, "get_inf_attr", lambda _kind: (_ for _ in ()).throw(RuntimeError("old IDA")), raising=False)
    monkeypatch.setattr(uni.idc, "demangle_name", lambda *_args: None, raising=False)
    demangled = uni.search_demangle("first, second", limit=1, offset=1)
    assert demangled["count"] == 1
    assert demangled["items"][0]["short"] == "second"
    assert demangled["items"][0]["is_mangled"] is False

    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni.idc, "get_name_ea_simple", lambda name: 0x1000 if name == "target" else uni.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(uni.idautils, "Names", lambda: [(0x1000, "target"), (0x1100, "target_helper"), (0x1200, "")], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda ea: 0x1000 if ea == 0x1000 else None)
    monkeypatch.setattr(uni._compat, "get_segment", lambda _ea: None)
    monkeypatch.setattr(uni.idc, "get_inf_attr", lambda _kind: 0, raising=False)
    monkeypatch.setattr(uni.idc, "demangle_name", lambda name, _kind: name, raising=False)
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a, **_k: 0)
    exact = uni.search_symbol("target", include_alternatives=True)
    assert exact["alternatives"] == [{"addr": "0x1100", "name": "target_helper", "type": "symbol"}]

    monkeypatch.setattr(uni.idc, "get_name_ea_simple", lambda _name: uni.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(uni.idc, "get_name", lambda _ea: "data", raising=False)
    monkeypatch.setattr(uni._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(uni._compat, "get_segment", lambda _ea: object())
    monkeypatch.setattr(uni._compat, "get_segment_name", lambda _ea: ".data")
    monkeypatch.setattr(uni.idc, "get_full_flags", lambda _ea: 7, raising=False)
    monkeypatch.setattr(uni.idc, "is_data", lambda _flags: True, raising=False)
    monkeypatch.setattr(uni.idc, "is_code", lambda _flags: False, raising=False)
    monkeypatch.setattr(uni.idc, "get_item_size", lambda _ea: 4, raising=False)
    monkeypatch.setattr(uni, "_data_flags", lambda *_a, **_k: ["dword"], raising=False)
    monkeypatch.setattr(uni, "xref_count_limited", lambda *_a, **_k: 0)
    monkeypatch.setattr(uni.idautils, "XrefsFrom", lambda *_a: [object()], raising=False)
    info = uni.search_symbol_info("0x2000")
    assert info["data"]["size"] == 4
    assert info["xrefs_from_count"] == 1


def test_unified_flags_xrefs_string_and_timeout_modes(monkeypatch):
    uni = _module()
    assert uni._perm_str(0x10) == ""
    monkeypatch.setattr(uni._compat, "get_segment_perm", lambda _ea: None)
    assert uni._perm_str(0x10) == ""
    monkeypatch.setattr(uni.idaapi, "FUNC_STATIC", 16, raising=False)
    monkeypatch.setattr(uni.idaapi, "FUNC_NORET", 1, raising=False)
    monkeypatch.setattr(uni.idaapi, "FUNC_LIB", 2, raising=False)
    monkeypatch.setattr(uni.idaapi, "FUNC_THUNK", 4, raising=False)
    monkeypatch.setattr(uni.idaapi, "FUNC_FRAME", 8, raising=False)
    assert set(uni._func_flags(31)) == {"noreturn", "library", "thunk", "static", "frame"}
    assert uni._func_flags(0) == []

    expected_flags = {
        "is_byte": "byte", "is_word": "word", "is_dword": "dword",
        "is_qword": "qword", "is_strlit": "string", "is_struct": "struct",
        "is_align": "align",
    }
    for flag_name in expected_flags:
        for other in ("is_byte", "is_word", "is_dword", "is_qword", "is_strlit", "is_struct", "is_align"):
            monkeypatch.setattr(uni.idc, other, lambda _flags: False, raising=False)
        monkeypatch.setattr(uni.idc, flag_name, lambda _flags: True, raising=False)
        assert uni._data_flags(1) == [expected_flags[flag_name]]
    for flag_name in expected_flags:
        monkeypatch.setattr(uni.idc, flag_name, lambda _flags: False, raising=False)
    monkeypatch.setattr(uni.ida_bytes, "has_cmt", lambda *_a: (_ for _ in ()).throw(RuntimeError("comment API")), raising=False)
    assert uni._data_flags(0, ea=0x10) == ["unknown"]

    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni, "get_cached_strings", lambda: [{"ea": 0x5000, "string": "hello world"}])
    monkeypatch.setattr(uni, "safe_get_strlit_contents", lambda _ea: "hello world")
    xref_one = SimpleNamespace(frm=0x1001, iscode=True)
    xref_duplicate = SimpleNamespace(frm=0x1002, iscode=True)
    xref_data = SimpleNamespace(frm=0x1003, iscode=False)
    xref_other = SimpleNamespace(frm=0x1004, iscode=True)
    monkeypatch.setattr(uni.idautils, "XrefsTo", lambda *_a: [xref_data, xref_one, xref_duplicate, xref_other], raising=False)
    monkeypatch.setattr(uni._compat, "get_func_start", lambda ea: 0x1000 if ea in {0x1001, 0x1002} else None)
    monkeypatch.setattr(uni.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)
    monkeypatch.setattr(uni, "safe_generate_disasm_line", lambda _ea: "lea string")
    monkeypatch.setattr(uni.ida_lines, "tag_remove", lambda line: line, raising=False)
    found = uni.search_xrefs_to_string("hello", include_context=True)
    assert found["items"][0]["xref_count"] == 2
    assert found["items"][0]["xrefs"][0]["context"] == "lea string"

    monkeypatch.setattr(uni, "looks_like_address", lambda _value: True)
    monkeypatch.setattr(uni, "validate_addr", lambda _value: (0x5000, None))
    class _Timeout:
        def __init__(self, _timeout_ms):
            pass

        def check(self):
            raise TimeoutError("budget")

    monkeypatch.setattr(uni, "SearchTimeout", _Timeout)
    timed = uni.search_xrefs_to_string("0x5000", timeout_ms=1)
    assert timed["truncated"] is True
    assert "TIMED OUT" in timed["note"]
    monkeypatch.setattr(uni, "looks_like_address", lambda _value: False)
    monkeypatch.setattr(uni, "get_cached_strings", list)
    assert uni.search_xrefs_to_string("absent")["error"] is True
