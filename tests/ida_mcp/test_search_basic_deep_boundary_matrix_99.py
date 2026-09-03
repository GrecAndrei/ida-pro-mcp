"""Deep offline coverage for the basic search implementation modes."""

from __future__ import annotations

import struct
import sys
import types
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
            raise TimeoutError("search budget exceeded")


def _module():
    return load_tool_submodule("search.basic")


def _response(results, offset, limit, matches, truncated, **kwargs):
    return {
        "results": results,
        "offset": offset,
        "limit": limit,
        "matches": matches,
        "truncated": truncated,
        **kwargs,
    }


def test_bytes_modern_and_legacy_modes_cover_context_and_limits(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.iter_segments = lambda *_args, **_kwargs: [(0x1000, 0x1004)]
    basic.ida_bytes.BIN_SEARCH_FORWARD = 1
    basic.ida_bytes.compiled_binpat_vec_t = object
    basic.ida_bytes.parse_binpat_str = lambda *_args: 0
    hits = iter([(0x1001, None), (basic.idaapi.BADADDR, None)])
    basic.ida_bytes.bin_search = lambda *_args: next(hits)
    basic.ida_bytes.get_bytes = lambda *_args: b""
    basic.safe_generate_disasm_line = lambda _ea: None
    basic.SearchTimeout = lambda _timeout: _Timer()
    result = basic.search_bytes("AA", None, None, True, 0, 10)
    assert result["results"] == ["0x1001  "]

    # The legacy IDA search API has a separate include-context and limit path.
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    legacy = types.ModuleType("ida_search")
    legacy.SEARCH_DOWN = 1
    legacy.find_binary = lambda *_args: next(iter((0x1002, -1)))
    monkeypatch.setitem(sys.modules, "ida_search", legacy)
    basic.ida_bytes.get_bytes = lambda *_args: b"\x90"
    basic.safe_generate_disasm_line = lambda _ea: "nop"
    basic.ida_lines.tag_remove = lambda text: text
    limited = basic.search_bytes("AA", None, None, True, 0, 1)
    assert limited["truncated"] is True
    assert "nop" in limited["results"][0]

    legacy_hits = iter((0x2100, basic.idaapi.BADADDR))
    legacy.find_binary = lambda *_args: next(legacy_hits)
    basic.ida_bytes.get_bytes = lambda *_args: b""
    no_context = basic.search_bytes("AA", None, None, False, 0, 10)
    assert no_context["results"] == ["0x2100"]


def test_bytes_manual_wildcards_empty_chunks_and_fallback_errors(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.iter_segments = lambda *_args, **_kwargs: [(0x2000, 0x2004)]
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    monkeypatch.setitem(sys.modules, "ida_search", types.ModuleType("ida_search"))
    basic.ida_bytes.get_bytes = lambda *_args: b"\xAA\xBB\xCC\xDD"
    basic.SearchTimeout = lambda _timeout: _Timer()
    result = basic.search_bytes("?? BB", None, None, False, 0, 10)
    assert result["matches"] == 1

    basic.ida_bytes.get_bytes = lambda *_args: b""
    empty_chunk = basic.search_bytes("AA BB", None, None, False, 0, 10)
    assert empty_chunk["results"] == []

    def fail_bytes(*_args):
        raise RuntimeError("read failed")

    basic.ida_bytes.get_bytes = fail_bytes
    failed = basic.search_bytes("AA", None, None, False, 0, 10)
    assert failed["code"] == "IDA_ERROR"


def test_bytes_legacy_and_manual_context_branches(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.iter_segments = lambda *_args, **_kwargs: [(0x2100, 0x2104)]
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    legacy = types.ModuleType("ida_search")
    legacy.SEARCH_DOWN = 1
    legacy_hits = iter((0x2100, basic.idaapi.BADADDR))
    legacy.find_binary = lambda *_args: next(legacy_hits)
    monkeypatch.setitem(sys.modules, "ida_search", legacy)
    basic.ida_bytes.get_bytes = lambda *_args: b""
    basic.safe_generate_disasm_line = lambda _ea: None
    no_context = basic.search_bytes("AA", None, None, True, 0, 10)
    assert no_context["results"] == ["0x2100  "]

    manual = types.ModuleType("ida_search")
    monkeypatch.setitem(sys.modules, "ida_search", manual)
    basic.ida_bytes.get_bytes = lambda *_args: b"\xAA\xBB\xCC"
    basic.safe_generate_disasm_line = lambda _ea: "mov eax, ebx"
    basic.ida_lines.tag_remove = lambda text: text
    with_context = basic.search_bytes("?? BB", None, None, True, 0, 1)
    assert with_context["truncated"] is True
    assert "mov eax, ebx" in with_context["results"][0]


def test_string_search_covers_packed_fallbacks_duplicates_and_timeouts(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: str(pattern) in str(text)
    basic.idautils.XrefsTo = lambda _ea: []
    basic._compat.get_func_start = lambda _ea: None
    basic.ida_bytes.get_bytes = lambda _ea, _size: b"PACKED_LITERAL"
    basic.iter_segments = lambda *_args, **_kwargs: []
    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x3004), types.SimpleNamespace(ea=0x3004)]
    basic.safe_get_strlit_contents = lambda ea: "PACKED_LITERAL" if ea == 0x3004 else None
    basic.SearchTimeout = lambda _timeout: _Timer()
    result = basic.search_string("PACKED_LITERAL", False, True, 0, 10)
    assert result["matches"] == 1

    # A mapped hit that is not in IDA's string list falls back to raw bytes;
    # the no-NUL branch and matcher-rejection branch are both intentional.
    basic.iter_segments = lambda *_args, **_kwargs: [(0x3000, 0x3020)]
    basic.safe_get_strlist_items = list
    basic.safe_get_strlit_contents = lambda _ea: (_ for _ in ()).throw(RuntimeError("not a string"))
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda _text: False
    rejected = basic.search_string("PACKED_LITERAL", False, False, 0, 10)
    assert rejected["matches"] == 0

    # If reading the packed bytes also fails, the literal query itself is the
    # safe last-resort value and can still be returned when it matches.
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda text: "PACKED_LITERAL" in str(text)
    basic._iter_mapped_byte_hits = lambda *_args, **_kwargs: iter((0x3004,))
    basic.ida_bytes.get_bytes = lambda *_args: (_ for _ in ()).throw(RuntimeError("bytes unavailable"))
    recovered = basic.search_string("PACKED_LITERAL", False, False, 0, 10)
    assert recovered["matches"] == 1

    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x3004)]
    basic.safe_get_strlit_contents = lambda _ea: "PACKED_LITERAL"
    basic.SearchTimeout = lambda _timeout: _Timer(fail=True)
    timed = basic.search_string("PACKED_LITERAL", False, False, 0, 10, timeout_ms=1)
    assert timed["timed_out"] is True


def test_string_helpers_cover_invalid_ranges_and_iterator_failures(monkeypatch):
    basic = _module()
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda _text: False
    basic.safe_get_strlist_items = list
    assert basic.search_string("abc", False, False, 0, 10)["count"] == 0
    assert list(basic._iter_mapped_byte_hits(b"needle", max_hits=0)) == []

    def broken_segments(*_args, **_kwargs):
        raise RuntimeError("segments unavailable")

    monkeypatch.setattr(basic, "iter_segments", broken_segments)
    assert list(basic._iter_mapped_byte_hits(b"needle")) == []
    assert basic._literal_ascii_needle("abc") is None
    assert basic._literal_ascii_needle("need") == b"need"
    assert basic._literal_ascii_needle("need*") is None


def test_string_search_covers_offsets_outer_breaks_and_mapped_limits(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda _text: True
    basic.idautils.XrefsTo = lambda _ea: []
    basic._compat.get_func_start = lambda _ea: None
    basic.iter_segments = lambda *_args, **_kwargs: []
    basic.safe_get_strlist_items = lambda: [
        types.SimpleNamespace(ea=0x3100),
        types.SimpleNamespace(ea=0x3104),
    ]
    basic.safe_get_strlit_contents = lambda _ea: "needle"
    basic.SearchTimeout = lambda _timeout: _Timer()
    offset = basic.search_string("needle", False, False, 1, 10)
    assert offset["matches"] == 2
    assert len(offset["results"]) == 1

    limited = basic.search_string("needle", False, False, 0, 1)
    assert limited["matches"] == 1
    assert limited["truncated"] is True

    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x3100)]
    basic.safe_get_strlit_contents = lambda _ea: (_ for _ in ()).throw(RuntimeError("decode"))
    basic.iter_segments = lambda *_args, **_kwargs: []
    assert basic.search_string("needle", False, False, 0, 10)["matches"] == 0

    basic.safe_get_strlist_items = list
    basic._iter_mapped_byte_hits = lambda *_args, **_kwargs: iter((0x3200, 0x3204))
    basic.safe_get_strlit_contents = lambda _ea: "needle"
    mapped_limited = basic.search_string("needle", False, False, 0, 1)
    assert mapped_limited["truncated"] is True

    basic.SearchTimeout = lambda _timeout: _Timer(fail=True)
    mapped_timeout = basic.search_string("needle", False, False, 0, 10, timeout_ms=1)
    assert mapped_timeout["timed_out"] is True


def test_mapped_hit_and_data_region_exception_branches(monkeypatch):
    basic = _module()
    assert list(basic._iter_mapped_byte_hits(b"")) == []
    basic.iter_segments = lambda *_args, **_kwargs: [
        (0x3300, 0x3300),
        (0x3300, 0x3304),
        (0x3400, 0x3404),
    ]
    basic.ida_bytes.get_bytes = lambda _ea, _size: b"needle"
    assert len(list(basic._iter_mapped_byte_hits(b"needle", max_hits=1))) == 1

    def broken_bytes(*_args):
        raise RuntimeError("read")

    basic.ida_bytes.get_bytes = broken_bytes
    assert list(basic._iter_mapped_byte_hits(b"needle")) == []
    basic.ida_bytes.get_bytes = lambda *_args: b""
    assert list(basic._iter_mapped_byte_hits(b"needle")) == []

    basic._compat.get_segment_ea_by_name = lambda _name: (_ for _ in ()).throw(RuntimeError("segment"))
    assert basic._resolve_data_value_region("segment", 4) is None
    assert basic._resolve_data_value_region("0xGG", 4) is None


def test_data_value_chunk_boundaries_offsets_and_invalid_targets(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic._DATA_VALUE_CHUNK = 4
    basic.iter_segments = lambda *_args, **_kwargs: [(0x7000, 0x7008), (0x8000, 0x8008)]
    target = 0x4000

    def get_bytes(ea, size):
        del size
        return struct.pack("<I", target) if ea in (0x7000, 0x8000) else b"\x00" * 8

    basic.ida_bytes.get_bytes = get_bytes
    basic._data_value_kind = lambda _ea: "unknown"
    basic.SearchTimeout = lambda _timeout: _Timer()
    limited = basic.search_data_value(target, word_size="u32", endian="le", limit=1)
    assert limited["truncated"] is True
    assert limited["items"][0]["address"] == "0x7000"
    offset = basic.search_data_value(target, word_size="u32", endian="le", offset=1)
    assert offset["matches"] == 2
    assert offset["items"] == [{
        "address": "0x8000",
        "addr": "0x8000",
        "value": "0x4000",
        "endian": "le",
        "kind": "unknown",
    }]

    invalid = basic.search_data_value("0xGG", word_size="u32", endian="le")
    assert invalid["code"] == "INVALID_ARGS"


def test_immediate_search_covers_offsets_pair_context_and_decode_errors(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x4000, 0x4008)], "raw", "")
    basic.ida_lines.tag_remove = lambda text: text
    basic._compat.get_func_start = lambda _ea: None
    basic.safe_generate_disasm_line = lambda _ea: "addi a0, a0, 1"

    class Op:
        def __init__(self, type_, value=0):
            self.type = type_
            self.value = value

    class Insn:
        def __init__(self):
            self.ops = [Op(1, 0x42), Op(0)]
            self.size = 4

    ida_ua = types.ModuleType("ida_ua")
    ida_ua.o_imm = 1
    ida_ua.insn_t = Insn
    ida_ua.decode_insn = lambda _insn, _ea: 4
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    offset = basic.search_immediate("0x42", None, None, False, 2, 10)
    assert offset["results"] == []
    context = basic.search_immediate("0x42", None, None, True, 0, 10)
    assert "addi a0" in context["results"][0]
    assert context["note"] == "raw"

    basic.SearchTimeout = lambda _timeout: _Timer(fail=True)
    basic.resolve_scan_segments = lambda *_args, **_kwargs: (
        [(0x4000, 0x4004), (0x5000, 0x5004)],
        "",
        "",
    )
    timed = basic.search_immediate("0x42", None, None, False, 0, 10, timeout_ms=1)
    assert timed["timed_out"] is True

    basic.SearchTimeout = lambda _timeout: _Timer()
    pair_calls = []

    def raise_pair(*_args):
        pair_calls.append(True)
        raise RuntimeError("pair")

    basic.riscv_lui_addi_pair = raise_pair
    basic.SearchTimeout = lambda _timeout: _Timer()
    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x4000, 0x4008)], "", "")
    pair_error = basic.search_immediate("0x99", None, None, False, 0, 10)
    assert pair_error["results"] == []
    assert pair_calls


def test_immediate_pair_context_and_data_word_validation(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.build_response = _response
    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x6000, 0x6008)], "", "")
    basic.ida_lines.tag_remove = lambda text: text
    basic._compat.get_func_start = lambda _ea: None
    basic.safe_generate_disasm_line = lambda _ea: None

    class Insn:
        def __init__(self):
            self.ops = [types.SimpleNamespace(type=0, value=0)]
            self.size = 4

    ida_ua = types.ModuleType("ida_ua")
    ida_ua.o_imm = 1
    ida_ua.insn_t = Insn
    ida_ua.decode_insn = lambda _insn, _ea: 4
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    basic.riscv_lui_addi_pair = lambda *_args: (0x99, 0x6004)
    result = basic.search_immediate("0x99", None, None, True, 0, 1)
    assert result["truncated"] is True
    assert "lui+addi" in result["results"][0]
    basic._compat.get_func_start = lambda _ea: 0x6000
    basic.ida_funcs.get_func_name = lambda _ea: "pair_target"
    with_context = basic.search_immediate("0x99", None, None, True, 0, 10)
    assert "in:pair_target" in with_context["results"][0]
    skipped = basic.search_immediate("0x99", None, None, False, 1, 10)
    assert skipped["results"] == []

    basic.iter_segments = lambda *_args, **_kwargs: [(0x7000, 0x7010)]
    basic._inf_ptr_size = lambda: 16
    basic.ida_bytes.get_bytes = lambda _ea, size: struct.pack("<I", 0x4000) + b"\x00" * (size - 4)
    basic.idc.is_code = lambda _flags: False
    basic.idc.is_data = lambda _flags: False
    basic.ida_bytes.get_flags = lambda _ea: 0
    invalid_auto = basic.search_data_value("0x4000", word_size="auto", endian="both")
    assert invalid_auto["word_size"] == "u32"
    invalid_endian = basic.search_data_value("0x4000", endian="sideways")
    assert invalid_endian["code"] == "INVALID_ARGS"
