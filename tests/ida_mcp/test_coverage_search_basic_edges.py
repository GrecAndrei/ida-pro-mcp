"""Compatibility and boundary coverage for the basic search primitives."""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.basic")


def _segments(basic, start=0x1000, end=0x1020):
    basic.iter_segments = lambda *_args, **_kwargs: [(start, end)]
    basic.idaapi.BADADDR = -1


def test_search_bytes_legacy_find_binary_and_manual_fallback(monkeypatch):
    basic = _module()
    _segments(basic)
    basic.ida_bytes.get_bytes = lambda ea, size: b"\x90\xAA\xBB"[:size]
    basic.safe_generate_disasm_line = lambda _ea: "mov eax, ebx"
    basic.ida_lines.tag_remove = lambda text: text
    basic.ida_bytes.compiled_binpat_vec_t = None
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t")
    legacy = types.ModuleType("ida_search")
    legacy.SEARCH_DOWN = 4
    hits = iter([0x1001, -1])
    legacy.find_binary = lambda *_args: next(hits)
    monkeypatch.setitem(sys.modules, "ida_search", legacy)
    result = basic.search_bytes("AA BB", 0x1000, 0x1020, True, 0, 10)
    assert result["ok"] is True
    assert "0x1001" in result["results"]
    assert "mov eax, ebx" in result["results"]

    # IDA builds without ida_search.find_binary use the bounded chunk scanner.
    manual = types.ModuleType("ida_search")
    monkeypatch.setitem(sys.modules, "ida_search", manual)
    blob = b"\x00\xA1\xB2\xC3\x00"
    basic.ida_bytes.get_bytes = lambda _ea, size: blob[:size]
    result = basic.search_bytes("A? B2 C3", 0x1000, 0x1000 + len(blob), False, 0, 10)
    assert result["ok"] is True
    assert "0x1001" in result["results"]
    bad = basic.search_bytes("GG", 0x1000, 0x1010, False, 0, 10)
    assert bad["error"] is True
    assert bad["code"] == "IDA_ERROR"


def test_search_bytes_manual_empty_and_timeout_paths(monkeypatch):
    basic = _module()
    _segments(basic, end=0x1004)
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    monkeypatch.setitem(sys.modules, "ida_search", types.ModuleType("ida_search"))
    basic.ida_bytes.get_bytes = lambda *_args: b"\x00" * 8
    empty = basic.search_bytes("", 0x1000, 0x1004, False, 0, 10)
    assert empty["error"] is True

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError("expired")

    basic.SearchTimeout = Expired
    timeout = basic.search_bytes("AA", 0x1000, 0x1004, False, 0, 10, timeout_ms=1)
    assert timeout["ok"] is True
    assert timeout["timed_out"] is True


def test_search_string_deduplicates_and_reads_packed_literal(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: str(pattern) in str(text)
    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x1004), types.SimpleNamespace(ea=0x1008)]
    basic.safe_get_strlit_contents = lambda ea: "PACKED_STRING" if ea in {0x1004, 0x1008} else None
    basic.idautils.XrefsTo = lambda _ea: []
    basic.iter_segments = lambda *_args, **_kwargs: [(0x1000, 0x1020)]
    basic._compat.get_func_start = lambda _ea: None
    blob = b"----PACKED_STRING\x00"
    basic.ida_bytes.get_bytes = lambda ea, size: blob[max(0, ea - 0x1000): max(0, ea - 0x1000) + size]
    result = basic.search_string("PACKED_STRING", False, True, 0, 10)
    assert result["ok"] is True
    assert result["count"] == 2
    assert result["results"].count("0x1004") == 1
    assert "0x1008" in result["results"]

    # A failed string decode falls back to the query text, while a range can
    # exclude the string-list hit before it reaches the matcher.
    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x1000)]
    basic.safe_get_strlit_contents = lambda _ea: (_ for _ in ()).throw(RuntimeError("not a string"))
    basic.ida_bytes.get_bytes = lambda ea, size: blob[max(0, ea - 0x1000): max(0, ea - 0x1000) + size]
    fallback = basic.search_string("PACKED_STRING", False, False, 0, 10, range_start=0x1004, range_end=0x100A)
    assert fallback["ok"] is True
    assert fallback["count"] == 1


def test_search_string_timeout_and_context_without_function(monkeypatch):
    basic = _module()
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda _text: True
    basic.safe_get_strlist_items = lambda: [types.SimpleNamespace(ea=0x1000)]
    basic.safe_get_strlit_contents = lambda _ea: "hello"
    basic.idautils.XrefsTo = lambda _ea: []
    basic._compat.get_func_start = lambda _ea: None

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError("expired")

    basic.SearchTimeout = Expired
    result = basic.search_string("hello", False, True, 0, 10, timeout_ms=1)
    assert result["timed_out"] is True
    assert result["count"] == 0


def test_search_immediate_direct_semantic_and_decode_fallback_paths(monkeypatch):
    basic = _module()
    _segments(basic, end=0x1004)
    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1004)], None, None)
    basic.safe_generate_disasm_line = lambda _ea: "mov eax, 0x42"
    basic.ida_lines.tag_remove = lambda text: text
    basic._compat.get_func_start = lambda _ea: 0x1000
    basic.ida_funcs.get_func_name = lambda _ea: "main"

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
    ida_ua.decode_insn = lambda insn, _ea: 4
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    direct = basic.search_immediate("0x42", None, None, True, 0, 10)
    assert direct["ok"] is True
    assert direct["count"] == 1
    assert "in:main" in direct["results"]

    basic.resolve_target = lambda *_args, **_kwargs: (0x42, None, {"resolved": "symbol"})
    semantic = basic.search_immediate("target_symbol", None, None, False, 0, 10)
    assert semantic["ok"] is True
    assert semantic["resolved"] == "symbol"

    basic.resolve_target = lambda *_args, **_kwargs: (None, "not found", {})
    invalid = basic.search_immediate("not-a-value", None, None, False, 0, 10)
    assert invalid["error"] is True

    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([], None, "no executable segments")
    no_segments = basic.search_immediate("1", None, None, False, 0, 10)
    assert no_segments["error"] is True
    assert no_segments["code"] == "NOT_FOUND"


def test_search_immediate_decode_failure_next_head_and_timeout(monkeypatch):
    basic = _module()
    basic.idaapi.BADADDR = -1
    basic.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1008)], None, None)

    class Insn:
        size = 4
        ops = []

    ida_ua = types.ModuleType("ida_ua")
    ida_ua.o_imm = 1
    ida_ua.insn_t = Insn
    ida_ua.decode_insn = lambda _insn, _ea: 0
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    basic.idc.next_head = lambda _ea, _end: -1
    result = basic.search_immediate("1", None, None, False, 0, 10)
    assert result["ok"] is True
    assert result["count"] == 0

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError("expired")

    basic.SearchTimeout = Expired
    timeout = basic.search_immediate("1", None, None, False, 0, 10, timeout_ms=1)
    assert timeout["timed_out"] is True


def test_search_name_and_data_value_region_helpers(monkeypatch):
    basic = _module()
    basic.compile_smart_pattern = lambda *_args, **_kwargs: lambda text: text in {"func", "data", "label"}
    basic.idautils.Names = lambda: [(0x1000, "func"), (0x1004, "data"), (0x1008, "label")]
    basic._compat.get_func_start = lambda ea: 0x1000 if ea == 0x1000 else None
    basic.ida_bytes.get_flags = lambda ea: 2 if ea == 0x1004 else 0
    basic.ida_bytes.is_data = lambda flags: flags == 2
    basic.xref_count_limited = lambda *_args: 3
    names = basic.search_name("", False, 0, 2)
    assert names["ok"] is True
    assert names["truncated"] is True
    assert "func" in names["results"]
    assert "data" in names["results"]

    segment = types.SimpleNamespace(start_ea=0x2000, end_ea=0x2100)
    basic._compat.get_segment_ea_by_name = lambda name: 0x2000 if name == ".data" else None
    basic._compat.get_segment = lambda _ea: segment
    assert basic._resolve_data_value_region("0x1000:0x1100", 8) == (0x1000, 0x1100)
    assert basic._resolve_data_value_region(".data", 8) == (0x2000, 0x2100)
    assert basic._resolve_data_value_region("0x1234", 8) == (0x1234, 0x123C)
    assert basic._resolve_data_value_region("not-a-region", 8) is None
    assert basic._resolve_data_value_region("", 8) is None

    basic.ida_bytes.get_flags = lambda _ea: 1
    basic.idc.is_code = lambda flags: flags == 1
    basic.idc.is_data = lambda _flags: False
    assert basic._data_value_kind(0x1000) == "code"
    basic.idc.is_code = lambda _flags: False
    basic.idc.is_data = lambda flags: flags == 1
    assert basic._data_value_kind(0x1000) == "data"
    basic.ida_bytes.get_flags = lambda _ea: (_ for _ in ()).throw(RuntimeError("flags"))
    assert basic._data_value_kind(0x1000) == "unknown"
