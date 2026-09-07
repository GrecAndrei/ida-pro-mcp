"""Deep offline coverage for instruction, text, operand, and comment scans."""

from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402


class _Timer:
    def __init__(self, fail=False):
        self.fail = fail

    def check(self):
        if self.fail:
            raise TimeoutError("scan timed out")


def _module():
    return load_tool_submodule("search.code")


def _response(results, offset, limit, matches, truncated, **kwargs):
    return {
        "results": results,
        "offset": offset,
        "limit": limit,
        "matches": matches,
        "truncated": truncated,
        **kwargs,
    }


def test_instruction_scan_covers_context_offsets_badaddr_and_segment_errors(monkeypatch):
    code = _module()
    code.idaapi.BADADDR = -1
    code.build_response = _response
    code.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1003)], "", "")
    monkeypatch.setattr(code.ida_bytes, "get_flags", lambda _ea: 1, raising=False)
    monkeypatch.setattr(code.ida_bytes, "is_code", lambda _flags: True, raising=False)
    monkeypatch.setattr(
        code.idc,
        "print_insn_mnem",
        lambda ea: {0x1000: "mov", 0x1001: "ret", 0x1002: "nop"}.get(ea, ""),
        raising=False,
    )
    monkeypatch.setattr(
        code.idc,
        "next_head",
        lambda ea, end: ea + 1 if ea + 1 < end else code.idaapi.BADADDR,
        raising=False,
    )
    monkeypatch.setattr(code._compat, "get_func_start", lambda _ea: None)
    result = code.search_insns("mov,*", None, None, True, 0, 1)
    assert result["results"] == ["0x1000  [mov,ret]"]
    assert result["truncated"] is True

    skipped = code.search_insns("mov", None, None, False, 1, 10)
    assert skipped["results"] == []

    code.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", "no executable range")
    assert code.search_insns("mov", None, None, False, 0, 1)["code"] == "NOT_FOUND"

    code.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1001)], "", "")
    monkeypatch.setattr(code.idc, "next_head", lambda *_args: code.idaapi.BADADDR, raising=False)
    assert code.search_insns("mov,ret", None, None, False, 0, 1)["results"] == []

    code.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1001)], "relaxed", "")
    monkeypatch.setattr(code._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(code.ida_funcs, "get_func_name", lambda _ea: "entry", raising=False)
    next_calls = iter((0x1001, code.idaapi.BADADDR))
    monkeypatch.setattr(code.idc, "next_head", lambda *_args: next(next_calls), raising=False)
    relaxed = code.search_insns("mov", None, None, True, 0, 10)
    assert "in:entry" in relaxed["results"][0]
    assert relaxed["note"] == "relaxed"


def test_text_scan_covers_empty_lines_context_offset_truncation_and_timeout(monkeypatch):
    code = _module()
    code.idaapi.BADADDR = -1
    code.build_response = _response
    code.resolve_scan_segments = lambda *_args, **_kwargs: (
        [(0x2000, 0x2002)],
        "raw fallback",
        "",
    )
    code.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: pattern.lower() in text.lower()
    monkeypatch.setattr(
        code,
        "iter_code",
        lambda start, end, force=False: [start, start + 1],
    )

    def disasm_for_text(ea):
        return {0x2000: None, 0x2001: "MOV eax, ebx"}.get(ea)

    monkeypatch.setattr(
        code,
        "safe_generate_disasm_line",
        disasm_for_text,
    )
    monkeypatch.setattr(code.ida_lines, "tag_remove", lambda text: text, raising=False)
    monkeypatch.setattr(code._compat, "get_func_start", lambda _ea: None)
    code.SearchTimeout = lambda _timeout: _Timer()
    result = code.search_text("mov", False, None, None, True, 1, 10, 0)
    assert result["results"] == []
    assert result["note"] == "raw fallback"

    result = code.search_text("mov", False, None, None, False, 0, 1, 0)
    assert result["results"] == ["0x2001  MOV eax, ebx"]
    assert result["truncated"] is True

    context_result = code.search_text("mov", False, None, None, True, 0, 10, 0)
    assert context_result["results"] == ["0x2001  MOV eax, ebx"]

    code.resolve_scan_segments = lambda *_args, **_kwargs: (
        [(0x2000, 0x2001), (0x3000, 0x3001)],
        "",
        "",
    )
    code.SearchTimeout = lambda _timeout: _Timer(fail=True)
    timed = code.search_text("mov", False, None, None, False, 0, 10, 1)
    assert timed["timed_out"] is True
    assert "timed out" in timed["hint"]

    code.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", "bad range")
    assert code.search_text("mov", False, None, None, False, 0, 1, 0)["code"] == "NOT_FOUND"


def test_operand_scan_covers_operand_shapes_context_offsets_notes_and_timeout(monkeypatch):
    code = _module()
    code.idaapi.BADADDR = -1
    code.idaapi.o_void = 0
    code.build_response = _response
    code.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x4000, 0x4001)], "relaxed", "")
    code.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: pattern in text
    code.iter_code = lambda _start, _end, force=False: [0x4000]
    code.SearchTimeout = lambda _timeout: _Timer()
    monkeypatch.setattr(
        code.idc,
        "get_operand_type",
        lambda _ea, index: 1 if index == 0 else 0,
        raising=False,
    )
    monkeypatch.setattr(code.idc, "print_operand", lambda _ea, index: "eax" if index == 0 else "", raising=False)
    monkeypatch.setattr(code.idc, "print_insn_mnem", lambda _ea: "mov", raising=False)
    monkeypatch.setattr(code, "safe_generate_disasm_line", lambda _ea: "mov eax, eax")
    monkeypatch.setattr(code.ida_lines, "tag_remove", lambda text: text, raising=False)
    result = code.search_operand("eax", False, None, None, True, 0, 1, 0)
    assert result["results"] == ["0x4000  mov  eax  mov eax, eax"]
    assert result["note"] == "relaxed"
    assert result["truncated"] is True

    skipped = code.search_operand("eax", False, None, None, False, 1, 10, 0)
    assert skipped["results"] == []

    monkeypatch.setattr(code.idc, "get_operand_type", lambda _ea, _index: 1, raising=False)
    no_void = code.search_operand("eax", False, None, None, False, 0, 10, 0)
    assert no_void["results"]

    code.resolve_scan_segments = lambda *_args, **_kwargs: (
        [(0x4000, 0x4001), (0x5000, 0x5001)],
        "",
        "",
    )
    code.SearchTimeout = lambda _timeout: _Timer(fail=True)
    timed = code.search_operand("eax", False, None, None, False, 0, 10, 1)
    assert timed["timed_out"] is True

    code.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", "bad range")
    assert code.search_operand("eax", False, None, None, False, 0, 1, 0)["code"] == "NOT_FOUND"


def test_comment_scan_covers_regular_repeatable_offset_truncation_and_timeout(monkeypatch):
    code = _module()
    code.idaapi.BADADDR = -1
    code.build_response = _response
    code.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: pattern in text
    code.iter_segments = lambda *_args, **_kwargs: [(0x5000, 0x5003)]
    code.SearchTimeout = lambda _timeout: _Timer()
    comments = {
        (0x5000, 0): "needle regular",
        (0x5001, 0): None,
        (0x5001, 1): "needle repeatable",
    }
    monkeypatch.setattr(code.idc, "get_cmt", lambda ea, kind: comments.get((ea, kind)), raising=False)
    monkeypatch.setattr(
        code.idc,
        "next_head",
        lambda ea, end: ea + 1 if ea + 1 < end else code.idaapi.BADADDR,
        raising=False,
    )
    result = code.search_comment("needle", False, None, None, 1, 1, 0)
    assert result["results"] == ["0x5001  repeatable  needle repeatable"]
    assert result["truncated"] is True

    code.SearchTimeout = lambda _timeout: _Timer(fail=True)
    code.iter_segments = lambda *_args, **_kwargs: [(0x5000, 0x5001), (0x6000, 0x6001)]
    timed = code.search_comment("needle", False, None, None, 0, 10, 1)
    assert timed["timed_out"] is True
