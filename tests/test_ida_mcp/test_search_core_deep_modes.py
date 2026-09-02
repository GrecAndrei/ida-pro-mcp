"""Deep, cross-version coverage for the shared search core helpers."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.search import core


def test_database_caches_rebuild_and_bound_imports_and_strings(monkeypatch):
    monkeypatch.setattr(core, "_db_changed", lambda: True)
    monkeypatch.setattr(core, "_MAX_DB_CACHE_ITEMS", 1)
    monkeypatch.setattr(core, "_CONSTANT_DB_CACHE", None)
    monkeypatch.setattr(core, "_IMPORTS_CACHE", None)
    monkeypatch.setattr(core, "_STRINGS_CACHE", None)
    monkeypatch.setattr(core, "build_constant_db", lambda: {7: "SEVEN"})
    assert core.get_cached_constant_db() == {7: "SEVEN"}
    assert core.get_cached_constant_db() == {7: "SEVEN"}

    monkeypatch.setattr(core.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(core.ida_nalt, "get_import_module_name", lambda _idx: None)

    def enum_imports(_idx, callback):
        callback(0x1000, "first", 1)
        callback(0x1001, "second", 2)

    monkeypatch.setattr(core.ida_nalt, "enum_import_names", enum_imports)
    imports = core.get_cached_imports()
    assert imports == [{"ea": 0x1000, "name": "first", "module": "mod_0", "ordinal": 1}]

    monkeypatch.setattr(core, "safe_get_strlist_items", lambda: [SimpleNamespace(ea=1), SimpleNamespace(ea=2)])
    monkeypatch.setattr(core, "safe_get_strlit_contents", lambda ea: "one" if ea == 1 else (_ for _ in ()).throw(RuntimeError("bad")))
    strings = core.get_cached_strings()
    assert strings == [{"ea": 1, "string": "one"}]
    assert core.get_cached_strings() == strings


def test_fingerprint_fallback_and_segment_modes(monkeypatch):
    monkeypatch.setattr(core.ida_nalt, "retrieve_input_file_md5", lambda: b"abc123", raising=False)
    assert core._get_db_fingerprint() == "abc123"
    monkeypatch.setattr(core.ida_nalt, "retrieve_input_file_md5", lambda: (_ for _ in ()).throw(RuntimeError("old IDA")), raising=False)
    monkeypatch.setattr(core.idautils, "Functions", lambda: iter([1, 2]))
    monkeypatch.setattr(core.idautils, "Segments", lambda: iter([1]))
    monkeypatch.setattr(core.idautils, "Names", lambda: iter([("a", "x"), ("b", "y"), ("c", "z")]))
    assert core._get_db_fingerprint() == "fallback:2:1:3"

    segments = {
        0x1000: SimpleNamespace(start_ea=0x1000, end_ea=0x1100),
        0x1100: SimpleNamespace(start_ea=0x1100, end_ea=0x1200),
    }
    monkeypatch.setattr(
        core._compat,
        "get_segment",
        lambda ea: segments.get(ea) or next((s for s in segments.values() if s.start_ea <= ea < s.end_ea), None),
    )
    monkeypatch.setattr(core._compat, "get_segment_perm", lambda _ea: core.idaapi.SEGPERM_EXEC)
    monkeypatch.setattr(core._compat, "get_first_segment_ea", lambda: 0x1000)
    monkeypatch.setattr(core._compat, "get_next_segment_ea", lambda ea: 0x1100 if ea == 0x1100 else None)
    assert list(core.iter_segments(0x1050, 0x1150)) == [(0x1050, 0x1100), (0x1100, 0x1150)]
    monkeypatch.setattr(core._compat, "get_next_segment_ea", lambda ea: 0x1100 if ea == 0x1000 else None)
    assert list(core.iter_segments()) == [(0x1000, 0x1100), (0x1100, 0x1200)]

    monkeypatch.setattr(core, "iter_segments", lambda _a, _b, require_exec: [(1, 2)] if require_exec else [(1, 3)])
    assert core.resolve_scan_segments(1, 2) == ([(1, 2)], "", "")
    monkeypatch.setattr(core, "iter_segments", lambda _a, _b, require_exec: [] if require_exec else [(1, 3)])
    segs, note, error = core.resolve_scan_segments(1, 2)
    assert segs == [(1, 3)] and "Raw blob" in note and not error
    monkeypatch.setattr(core, "iter_segments", lambda a, b, require_exec: [(1, 2)] if require_exec and a is None else [])
    assert "No executable segment" in core.resolve_scan_segments(3, 4)[2]

    monkeypatch.setattr(core.ida_bytes, "get_flags", lambda ea: 1 if ea == 1 else 0)
    monkeypatch.setattr(core.ida_bytes, "is_code", lambda flags: flags == 1)
    monkeypatch.setattr(core.idc, "next_head", lambda ea, _end: ea + 1 if ea < 2 else core.idaapi.BADADDR)
    assert list(core.iter_code(1, 4)) == [1]
    monkeypatch.setattr(core.idc, "next_head", lambda ea, _end: ea + 1)
    assert list(core.iter_code(1, 4, force=True)) == [1, 2, 3]


def test_core_response_helpers_and_api_fallbacks(monkeypatch):
    assert core.clip_text(None) == ""
    assert core._match_size_rule(15, ">", 10, 20)
    assert core._match_size_rule(15, "<", 20, 10)
    assert core._match_size_rule(15, "==", 10, None) is False
    monkeypatch.setattr(core.idautils, "XrefsTo", lambda *_args: iter(range(3)))
    assert core.xref_count_limited(1, 2) == 2
    assert core.make_item(addr="0x1", score="not-a-number", snippet="x" * 300, extra=None)["score"] == "not-a-number"

    error = {"error": True, "code": "bad"}
    assert core.normalize_search_result(error, action="find") is error
    normalized = core.normalize_search_result(
        {"items": [{"address": 0x1000}, "bad"], "matches": "0x2000 hit"},
        action="find",
        query="needle",
    )
    assert normalized["action"] == "find"
    assert normalized["items"] == [{"address": 0x1000, "addr": "0x1000"}]
    assert normalized["matches"] == normalized["results"]
    assert core.normalize_search_result({"results": "0x2000 hit\nplain"})["items"][0]["addr"] == "0x2000"
    assert not core.looks_like_identifier("")
    assert not core.looks_like_identifier("word word")
    assert not core.looks_like_identifier("a" * 97)
    assert core.looks_like_identifier("ns::Thing")

    monkeypatch.setattr(core.ida_lines, "generate_disasm_line", lambda *_args: (_ for _ in ()).throw(RuntimeError("missing")), raising=False)
    monkeypatch.setattr(core.idc, "generate_disasm_line", lambda *_args: "fallback asm", raising=False)
    assert core.safe_generate_disasm_line(0x10) == "fallback asm"
    monkeypatch.setattr(core.idc, "get_str_type", lambda _ea: 0)
    monkeypatch.setattr(core.idc, "get_strlit_contents", lambda *_args: b"utf8")
    assert core.safe_get_strlit_contents(1) == "utf8"
    monkeypatch.setattr(core.idc, "get_str_type", lambda _ea: (_ for _ in ()).throw(RuntimeError("old")))
    monkeypatch.setattr(core.idc, "get_strlit_contents", lambda *_args: "fallback")
    assert core.safe_get_strlit_contents(1) == "fallback"


def test_target_resolution_name_demangle_blackboard_and_semantic_modes(monkeypatch):
    bad = core.idaapi.BADADDR
    monkeypatch.setattr(core, "validate_addr", lambda value: (int(value, 0), None))
    monkeypatch.setattr(core.idc, "get_name_ea_simple", lambda name: {"exact": 0x1000}.get(name, bad))
    monkeypatch.setattr(core._compat, "get_func_start", lambda ea: ea if ea in {0x1000, 0x2000, 0x3000, 0x5000} else None)
    assert core.resolve_target(None)[1] == "target is required"
    assert core.resolve_target(" ")[1] == "target is required"
    assert core.resolve_target("exact", require_function=True)[0] == 0x1000
    assert core.resolve_target("0x2000", require_function=True)[0] == 0x2000
    assert core.resolve_target("0x9999", require_function=True)[1].startswith("No function")

    monkeypatch.setattr(core.idautils, "Names", lambda: [(0x3000, "CaseName"), (0x4000, "data_label")])
    monkeypatch.setattr(core.idc, "get_name_ea_simple", lambda _name: bad)
    assert core.resolve_target("casename")[2]["match"] == "exact_name_ci"
    assert core.resolve_target("data_")[0] == 0x4000

    monkeypatch.setattr(core.idautils, "Names", lambda: [(0x5000, "_Zsemantic")])
    monkeypatch.setattr(core, "demangle_cached", lambda _name: "semantic::Thing()")
    assert core.resolve_target("semantic::Thing()", require_function=True)[2]["match"] == "demangled"

    bb = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    bb.BlackboardStore = lambda: SimpleNamespace(list=lambda **_kwargs: [{"title": "Custom loader", "addr": "0x6000"}])
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", bb)
    monkeypatch.setattr(core.idautils, "Names", list)
    monkeypatch.setattr(core._compat, "get_func_start", lambda ea: ea if ea == 0x6000 else None)
    assert core.resolve_target("custom loader", require_function=True)[2]["match"] == "blackboard_name"

    monkeypatch.setattr(core, "compile_smart_pattern", lambda *_args, **_kwargs: lambda text: text == "candidate")
    monkeypatch.setattr(core.idautils, "Names", lambda: [(0x7000, "candidate"), (0x7001, "other")])
    monkeypatch.setattr(core, "semantic_score_cheap", lambda *_args, **_kwargs: 2.0)
    monkeypatch.setattr(core, "semantic_scores", lambda _target, names, **_kwargs: [10.0] * len(names))
    semantic = core.resolve_target("needle", include_alternatives=True)
    assert semantic[2]["match"] == "semantic"
    assert core.resolve_target("needle", semantic_min_score=11)[1].startswith("Target 'needle'")

    monkeypatch.setattr(core.idautils, "Names", list)
    monkeypatch.setattr(core.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(core.ida_nalt, "get_import_module_name", lambda _idx: "libc")
    monkeypatch.setattr(core.ida_nalt, "enum_import_names", lambda _idx, cb: cb(0x8000, "candidate", 1))
    imported = core.resolve_target("needle", include_imports=True)
    assert imported[2]["semantic_kind"] == "import"
    assert imported[2]["semantic_module"] == "libc"


def test_riscv_pair_rejects_malformed_instruction_shapes():
    import ida_ua

    reg = SimpleNamespace(type=ida_ua.o_reg, reg=1)
    imm = SimpleNamespace(type=ida_ua.o_imm, value=1)
    insn = SimpleNamespace(get_canon_mnem=lambda: "lui", ops=[reg, imm], ea=0x100)
    assert core.riscv_lui_addi_pair(insn, SimpleNamespace(get_canon_mnem=lambda: "addi", ops=[])) is None
    assert core.riscv_lui_addi_pair(SimpleNamespace(get_canon_mnem=lambda: (_ for _ in ()).throw(RuntimeError())), insn) is None
    bad_imm = SimpleNamespace(type=ida_ua.o_imm, value="bad")
    addi = SimpleNamespace(get_canon_mnem=lambda: "addiw", ops=[reg, reg, bad_imm], ea=0x104)
    assert core.riscv_lui_addi_pair(insn, addi) is None
