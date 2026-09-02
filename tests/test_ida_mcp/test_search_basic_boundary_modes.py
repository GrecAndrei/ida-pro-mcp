"""Composed byte/string/immediate/name search coverage across IDA API modes."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import ida_ua

from ida_pro_mcp.ida_mcp.tools.search import basic


def test_bytes_compiled_api_paginates_and_keeps_context(monkeypatch):
    class Pattern:
        pass

    monkeypatch.setattr(basic.ida_bytes, "compiled_binpat_vec_t", Pattern, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "BIN_SEARCH_FORWARD", 1, raising=False)
    monkeypatch.setattr(basic.idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    monkeypatch.setattr(basic, "iter_segments", lambda *_a, **_k: [(0x1000, 0x1020), (0x2000, 0x2010)])
    parsed = []
    monkeypatch.setattr(
        basic.ida_bytes,
        "parse_binpat_str",
        lambda _pt, start, pattern, radix: parsed.append((start, pattern, radix)) or 0,
        raising=False,
    )
    hits = {0x1000: 0x1004, 0x1005: 0x1008, 0x1009: basic.idaapi.BADADDR, 0x2000: 0x2002, 0x2003: basic.idaapi.BADADDR}
    monkeypatch.setattr(
        basic.ida_bytes,
        "bin_search",
        lambda start, _end, _pt, _flags: (hits.get(start, basic.idaapi.BADADDR), 0),
        raising=False,
    )
    monkeypatch.setattr(basic.ida_bytes, "get_bytes", lambda _ea, _size: b"\x90\xcc", raising=False)
    monkeypatch.setattr(basic, "safe_generate_disasm_line", lambda _ea: "\x01mov eax, ebx")
    monkeypatch.setattr(basic.ida_lines, "tag_remove", lambda text: text.replace("\x01", ""), raising=False)

    # Return the second and third hits, proving the offset and per-segment
    # search loop work together while retaining bytes/disassembly context.
    result = basic.search_bytes("90 ?", None, None, True, 1, 2)
    assert result["ok"] is True
    assert result["count"] == 2
    assert result["total"] == 3
    assert result["truncated"] is True
    assert result["results"].splitlines() == ["0x1008  90cc  mov eax, ebx", "0x2002  90cc  mov eax, ebx"]
    assert parsed == [(0, "90 ?", 16), (0, "90 ?", 16)]


def test_bytes_compiled_parse_error_and_timeout(monkeypatch):
    class Pattern:
        pass

    monkeypatch.setattr(basic.ida_bytes, "compiled_binpat_vec_t", Pattern, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "BIN_SEARCH_FORWARD", 1, raising=False)
    monkeypatch.setattr(basic, "iter_segments", lambda *_a, **_k: [(0x1000, 0x1100)])
    monkeypatch.setattr(basic.ida_bytes, "parse_binpat_str", lambda *_a: "bad pattern", raising=False)
    invalid = basic.search_bytes("GG", None, None, False, 0, 1)
    assert invalid["code"] == "INVALID_ARGS" and invalid["error"] is True

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError("expired")

    monkeypatch.setattr(basic, "SearchTimeout", Expired)
    monkeypatch.setattr(basic.ida_bytes, "parse_binpat_str", lambda *_a: 0, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "bin_search", lambda *_a: (0x1000, 0), raising=False)
    timed = basic.search_bytes("90", None, None, False, 0, 3, timeout_ms=10)
    assert timed["ok"] is True and timed["timed_out"] is True


def test_bytes_fallback_handles_invalid_and_read_failure(monkeypatch):
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    monkeypatch.setattr(basic, "iter_segments", lambda *_a, **_k: [(0x3000, 0x3010)])
    monkeypatch.setattr(basic.ida_bytes, "get_bytes", lambda _ea, _size: b"\x90\xaf\xcc\x90", raising=False)
    no_legacy = types.ModuleType("ida_search")
    monkeypatch.setitem(sys.modules, "ida_search", no_legacy)
    found = basic.search_bytes("9? A?", None, None, False, 0, 4)
    assert found["ok"] is True and found["count"] == 1 and "0x3000" in found["results"]
    empty = basic.search_bytes("", None, None, False, 0, 4)
    assert empty["error"] is True and empty["code"] == "INVALID_ARGS"

    def broken(*_args):
        raise RuntimeError("unmapped")

    monkeypatch.setattr(basic.ida_bytes, "get_bytes", broken, raising=False)
    failed = basic.search_bytes("90", None, None, False, 0, 4)
    assert failed["error"] is True and failed["code"] == "IDA_ERROR"


def test_string_search_reads_untyped_bytes_and_filters_ranges(monkeypatch):
    monkeypatch.setattr(basic, "safe_get_strlist_items", lambda: [SimpleNamespace(ea=0x1000), SimpleNamespace(ea=0x1100)])
    monkeypatch.setattr(basic, "safe_get_strlit_contents", lambda ea: "needle" if ea == 0x1000 else None)
    monkeypatch.setattr(basic.idautils, "XrefsTo", lambda *_a: [1, 2])
    def segments(start=None, end=None, **_kwargs):
        left = 0x1000 if start is None else start
        right = 0x1200 if end is None else end
        return [(left, right)] if left < right else []

    monkeypatch.setattr(basic, "iter_segments", segments)
    blob = bytearray(0x200)
    blob[:6] = b"needle"
    blob[0x100:0x106] = b"needle"
    monkeypatch.setattr(basic.ida_bytes, "get_bytes", lambda _ea, size: bytes(blob[:size]), raising=False)
    monkeypatch.setattr(basic._compat, "get_func_start", lambda ea: 0x9000 if ea == 0x1000 else None)
    monkeypatch.setattr(basic.ida_funcs, "get_func_name", lambda _ea: "f_needles", raising=False)

    result = basic.search_string("needle", False, True, 0, 5, range_start=0x1000, range_end=0x1200)
    assert result["count"] == 2
    assert "xrefs=2" in result["results"]
    assert "in:f_needles" in result["results"]

    narrowed = basic.search_string("needle", False, False, 0, 5, range_start=0x1000, range_end=0x1100)
    assert narrowed["count"] == 1


def test_string_search_glob_and_timeout_modes(monkeypatch):
    monkeypatch.setattr(basic, "safe_get_strlist_items", lambda: [SimpleNamespace(ea=0x1000)])
    monkeypatch.setattr(basic, "safe_get_strlit_contents", lambda _ea: "needle")
    monkeypatch.setattr(basic.idautils, "XrefsTo", lambda *_a: [])
    assert basic.search_string("nee*", False, False, 0, 2)["count"] == 1

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError

    monkeypatch.setattr(basic, "SearchTimeout", Expired)
    result = basic.search_string("needle", False, False, 0, 2, timeout_ms=1)
    assert result["timed_out"] is True and result["count"] == 0


def test_immediate_resolves_names_and_skips_decode_failures(monkeypatch):
    monkeypatch.setattr(basic, "resolve_target", lambda *_a, **_k: (7, None, {"semantic": True}))
    monkeypatch.setattr(basic, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1003)], "", ""))
    instructions = {
        0x1000: SimpleNamespace(ops=[SimpleNamespace(type=ida_ua.o_reg, value=0)], size=1),
        0x1001: SimpleNamespace(ops=[SimpleNamespace(type=ida_ua.o_imm, value=7)], size=1),
    }
    def make_instruction():
        return SimpleNamespace()

    monkeypatch.setattr(ida_ua, "insn_t", make_instruction, raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda insn, ea: (insn.__dict__.update(instructions[ea].__dict__) or 1) if ea in instructions else 0, raising=False)
    monkeypatch.setattr(basic.idc, "next_head", lambda ea, _end: ea + 1, raising=False)
    result = basic.search_immediate("target_symbol", None, None, False, 0, 2)
    assert result["count"] == 1 and result["semantic"] is True

    monkeypatch.setattr(basic, "resolve_target", lambda *_a, **_k: (None, "not found", {}))
    failed = basic.search_immediate("missing", None, None, False, 0, 2)
    assert failed["code"] == "INVALID_ARGS" and failed["error"] is True


def test_name_search_classifies_kind_and_paginates(monkeypatch):
    monkeypatch.setattr(basic.idautils, "Names", lambda: [(0x1000, "alpha"), (0x2000, "alpha_data"), (0x3000, "alpha_label")])
    monkeypatch.setattr(basic._compat, "get_func_start", lambda ea: 0x1000 if ea == 0x1000 else None)
    monkeypatch.setattr(basic.ida_bytes, "get_flags", lambda ea: 1 if ea == 0x2000 else 0, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "is_data", lambda flags: flags == 1, raising=False)
    monkeypatch.setattr(basic, "xref_count_limited", lambda _ea, _limit: 3)
    result = basic.search_name("alpha", False, 1, 1)
    assert result["count"] == 1 and result["total"] == 2 and result["truncated"] is True
    assert "data" in result["results"]
