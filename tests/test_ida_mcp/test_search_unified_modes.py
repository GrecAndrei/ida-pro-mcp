"""Cross-mode behavior coverage for unified search and symbol inspection."""

from __future__ import annotations

from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.unified")


def test_find_kind_aliases_and_category_boundary_modes():
    uni = _module()
    assert uni.normalize_find_kind(None) == (None, None)
    assert uni.normalize_find_kind("all") == (None, None)
    assert uni.normalize_find_kind("xrefs")[0] == frozenset({"refs"})
    wanted, note = uni.normalize_find_kind("unknown-category")
    assert wanted is None
    assert "unknown-category" in note

    uni.idautils.Names = lambda: [(0x2000, "needle")]
    uni.get_cached_strings = list
    uni.get_cached_imports = list
    uni.demangle_safe = lambda _name: None
    uni.xref_count_limited = lambda *_args: 0
    uni._compat.get_func_start = lambda _ea: None
    uni.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", "no executable range")
    result = uni.search_find("needle", False, None, None, False, True, False, 0, 10, kind="instructions")
    assert result["error"] is True
    assert result["code"] == uni.MCPError.NOT_FOUND


def test_find_handles_data_refs_demangled_names_and_timeout(monkeypatch):
    uni = _module()
    uni.idautils.Names = lambda: [(0x2000, "needle")]
    uni.get_cached_strings = list
    uni.get_cached_imports = list
    uni.demangle_safe = lambda name: f"{name}()"
    uni.xref_count_limited = lambda *_args: 1
    uni._compat.get_func_start = lambda _ea: None
    uni.idautils.XrefsTo = lambda *_args: [SimpleNamespace(frm=0x3000, iscode=False)]
    uni.looks_like_address = lambda _value: True
    uni.validate_addr = lambda _value: (0x2000, None)
    refs = uni.search_find("0x2000", False, None, None, False, True, True, 0, 10, kind="refs")
    assert refs["items"][0]["type"] == "data_ref"

    uni.looks_like_address = lambda _value: False
    class _Timeout:
        def __init__(self, _timeout_ms):
            pass

        def check(self):
            raise TimeoutError("budget")

    monkeypatch.setattr(uni, "SearchTimeout", _Timeout)
    uni.idautils.Names = list
    uni.idautils.Segments = lambda: [0x1000]
    uni.idc.get_segm_end = lambda _ea: 0x1004
    uni.idautils.Heads = lambda *_args: [0x1000]
    uni.idc.get_cmt = lambda *_args: "needle"
    timed = uni.search_find("needle", False, None, None, False, True, False, 0, 10, timeout_ms=10, kind="comments")
    assert timed["timed_out"] is True


def test_find_instruction_scan_and_call_graph_empty_modes(monkeypatch):
    uni = _module()
    uni.idautils.Names = list
    uni.get_cached_strings = list
    uni.get_cached_imports = list
    uni.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1004)], "", "")
    uni.iter_code = lambda *_args, **_kwargs: iter([0x1000, 0x1004])
    uni.idc.print_insn_mnem = lambda _ea: "call"
    uni.idc.print_operand = lambda _ea, _idx: "target"
    uni.safe_generate_disasm_line = lambda _ea: None
    instruction = uni.search_find("call", False, None, None, False, True, False, 0, 10, kind="instructions")
    assert instruction["count"] == 0

    uni.resolve_target = lambda *_args, **_kwargs: (0x1000, None, {})
    uni._compat.get_func_start = lambda _ea: 0x1000
    uni.idautils.XrefsTo = lambda *_args: []
    uni.idc.get_name = lambda _ea: "target"
    empty_callers = uni.search_callers("target", False, 0, 10, 0.0, False, False)
    assert empty_callers["ok"] is True
    assert "no callers" in empty_callers["note"].lower()
    empty_callees = uni.search_callees("target", False, 0, 10, 0.0, False, False)
    assert empty_callees["ok"] is True
    assert "no functions" in empty_callees["note"].lower()

    uni.resolve_target = lambda *_args, **_kwargs: (0x1000, "not found", {})
    assert uni.search_callers("missing", False, 0, 10, 0.0, False, False)["error"] is True
    uni._compat.get_func_start = lambda _ea: None
    uni.resolve_target = lambda *_args, **_kwargs: (0x1000, None, {})
    assert uni.search_callees("target", False, 0, 10, 0.0, False, False)["error"] is True


def test_api_fallback_and_symbol_inspection_modes(monkeypatch):
    uni = _module()
    uni.get_cached_imports = list
    uni.resolve_target = lambda *_args, **_kwargs: (0x4000, None, {"semantic_target": "api", "semantic_module": "lib", "semantic_score": 0.7})
    uni.idc.get_name = lambda _ea: "api"
    uni.idautils.XrefsTo = lambda *_args: []
    uni.xref_count_limited = lambda *_args: 0
    fallback = uni.search_api("api", False, 0, 10, True, True)
    assert fallback["ok"] is True
    assert fallback["matched_apis"][0]["api"] == "api"
    uni.resolve_target = lambda *_args, **_kwargs: (uni.idaapi.BADADDR, "missing", {})
    assert uni.search_api("missing", False, 0, 10, False, False)["error"] is True

    monkeypatch.setattr(uni, "looks_like_address", lambda _value: True)
    monkeypatch.setattr(uni, "validate_addr", lambda _value: (0x4000, None))
    uni.idc.get_name = lambda _ea: "global"
    uni.idc.INF_SHORT_DN = 1
    uni.idc.get_inf_attr = lambda _attr: 0
    uni.idc.demangle_name = lambda name, _attr: name
    uni.idc.get_full_flags = lambda _ea: 0
    uni.idc.is_data = lambda _flags: False
    uni.idc.is_code = lambda _flags: True
    uni._compat.get_func_start = lambda _ea: None
    uni._compat.get_segment = lambda _ea: None
    uni.xref_count_limited = lambda *_args: 0
    address = uni.search_symbol("0x4000", include_alternatives=False)
    assert address["match"] == "address"
    assert address["type"] == "code"
    assert uni.search_symbol_info("")["error"] is True


def test_graph_helpers_and_low_level_flag_modes(monkeypatch):
    uni = _module()
    uni._compat.get_func_start = lambda ea: ea if ea == 0x2000 else None
    uni.ida_funcs.get_func_name = lambda _ea: "callee"
    rows = uni._build_call_graph_rows(0x1000, lambda _func: [(0x2000, 0x2010), (0x2000, 0x2020), (0x3000, 0x2030)])
    assert rows[0x2000]["call_sites"] == [0x2010, 0x2020]
    empty = uni._format_call_graph_response({}, 0x1000, 0x1000, {}, include_context=False, offset=0, limit=10, include_items=False, empty_note="none")
    assert empty["note"] == "none"

    perm = uni.idaapi
    perm.SEGPERM_READ, perm.SEGPERM_WRITE, perm.SEGPERM_EXEC = 1, 2, 4
    uni._compat.get_segment_perm = lambda _ea: 7
    assert uni._perm_str(0x10) == "RWX"
    uni.idaapi.FUNC_NORET = 1
    uni.idaapi.FUNC_LIB = 2
    uni.idaapi.FUNC_THUNK = 4
    uni.idaapi.FUNC_FRAME = 8
    assert set(uni._func_flags(15)) >= {"noreturn", "library", "thunk", "frame"}
    uni.idc.is_byte = lambda _flags: False
    uni.idc.is_word = lambda _flags: False
    uni.idc.is_dword = lambda _flags: False
    uni.idc.is_qword = lambda _flags: False
    uni.idc.is_strlit = lambda _flags: False
    uni.idc.is_struct = lambda _flags: False
    uni.idc.is_align = lambda _flags: False
    uni.ida_bytes.has_cmt = lambda _ea, _rep: True
    assert uni._data_flags(0, ea=0x10) == ["has_comment"]
