"""Boundary matrix for the memory tool's read, search, and write modes."""

from __future__ import annotations

import struct
import types

from tests.ida_mcp.test_memory_surface_modes import _full_error_envelope
from tests.ida_mcp.test_swarm_q05d_memory_misc import _load_memory


def test_memory_read_and_hexdump_failure_boundaries():
    mem = _load_memory()
    _full_error_envelope(mem)
    mem.ida_bytes.get_bytes = lambda _ea, _size: None

    assert mem._memory_impl("read", "0x1000", "bytes", 4, None, None, 2)["code"] == "ADDRESS_INVALID"
    assert mem._memory_impl("hexdump", "0x1000", "bytes", 4, None, None, 2)["code"] == "IDA_ERROR"
    assert mem._memory_impl("read", "0x1000", "bytes", -1, None, None, 2)["code"] == "ADDRESS_INVALID"

    mem.ida_bytes.get_bytes = lambda _ea, _size: None
    assert mem._memory_impl("read", "0x1000", "f32", 4, None, None, 2)["code"] == "ADDRESS_INVALID"
    assert mem._memory_impl("read", "0x1000", "f64", 8, None, None, 2)["code"] == "ADDRESS_INVALID"


def test_memory_string_compatibility_and_length_caps():
    mem = _load_memory()
    _full_error_envelope(mem)
    calls = []

    def legacy_strlit(*args):
        calls.append(args)
        if len(args) == 3:
            raise TypeError("old signature")
        return b"A" * 70000

    mem.idc.get_strlit_contents = legacy_strlit
    result = mem._memory_impl("read", "0x1000", "string", 4, None, None, 2)
    assert result["defined"] is True
    assert result["length"] == 65536
    assert [len(args) for args in calls] == [3, 1]

    mem.idc.get_strlit_contents = lambda *_args: "B" * 70000
    result = mem._memory_impl("read", "0x1000", "string", 4, None, None, 2)
    assert result["value"] == "B" * 65536

    mem.idc.get_strlit_contents = lambda *_args: None
    mem.ida_bytes.get_bytes = lambda _ea, _size: None
    assert mem._memory_impl("read", "0x1000", "string", 4, None, None, 2)["code"] == "ADDRESS_INVALID"


def test_memory_search_argument_and_region_boundaries(monkeypatch):
    mem = _load_memory(bitness=64)
    _full_error_envelope(mem)
    raw = b"needle" * 400
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]

    assert mem._memory_impl("search", "0x1000", "bytes", 4, None, None, 2)["code"] == "INVALID_ARGS"
    assert mem._memory_impl("search", None, "bytes", 4, "x", "0x1100", 2)["code"] == "INVALID_ARGS"
    mem._inf_min_ea = lambda: None
    assert mem._memory_impl("search", None, "bytes", 4, "x", None, 2)["code"] == "INVALID_ARGS"

    mem._inf_min_ea = lambda: 0x1000
    implicit_start = mem._memory_impl("search", None, "bytes", 4, "needle", None, 2)
    assert implicit_start["region"] == "0x1000-0x11000"
    capped = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "needle", "0x300000", 2
    )
    assert capped["region_capped"] is True

    many = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "needle", "0x2000", 2, regex=True
    )
    assert many["hits_capped"] is True

    mem.ida_bytes.get_bytes = lambda _ea, _size: None
    assert mem._memory_impl("search", "0x1000", "bytes", 4, "x", None, 2)["code"] == "IDA_ERROR"


def test_memory_search_integer_widening_and_overflow(monkeypatch):
    mem = _load_memory(bitness=64)
    _full_error_envelope(mem)
    value = 0x123456789
    raw = value.to_bytes(8, "little") + b"\x00" * 4
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]

    widened = mem._memory_impl(
        "search", "0x1000", "bytes", 4, hex(value), None, 2, int_width=4
    )
    assert widened["mode"] == "integer"
    assert widened["count"] == 1

    too_wide = mem._memory_impl(
        "search", "0x1000", "bytes", 4, hex(1 << 80), None, 2, int_width=4
    )
    assert too_wide["code"] == "INVALID_ARGS"

    monkeypatch.setattr(mem, "_inf_is_be", lambda: True)
    big_endian = (0x1234).to_bytes(2, "big")
    mem.ida_bytes.get_bytes = lambda _ea, size: big_endian[:size]
    assert mem._memory_impl(
        "search", "0x1000", "bytes", 4, "0x1234", None, 2, int_width=2
    )["count"] == 1


def test_memory_search_native_wildcards_and_python_fallbacks():
    mem = _load_memory()
    _full_error_envelope(mem)
    raw = bytes.fromhex("4d 5a 90 00 4d 5a ff 00")
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]
    ida_bytes = mem.ida_bytes
    ida_bytes.BIN_SEARCH_FORWARD = 1

    class Pattern:
        pass

    ida_bytes.compiled_binpat_vec_t = Pattern
    ida_bytes.parse_binpat_str = lambda _pt, _ea, _pattern, _base: 0
    hits = iter([(0x1000, 0), (0x1004, 0), (mem.idaapi.BADADDR, 0)])
    ida_bytes.bin_search = lambda *_args: next(hits)
    native = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "4d 5a ?? 00", None, 2
    )
    assert native["hits"] == ["0x1000", "0x1004"]

    ida_bytes.parse_binpat_str = lambda *_args: 1
    fallback = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "4d 5a ?? 00", None, 2
    )
    assert fallback["count"] == 2

    def broken_parse(*_args):
        raise RuntimeError("binpat unavailable")

    ida_bytes.parse_binpat_str = broken_parse
    exception_fallback = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "4d 5a ?? 00", None, 2
    )
    assert exception_fallback["count"] == 2


def test_memory_search_fallbacks_stop_at_the_hit_limit():
    mem = _load_memory()
    _full_error_envelope(mem)
    raw = b"AA" * 300
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]
    result = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "AA", None, 2,
    )
    assert result["count"] == 256
    assert result["hits_capped"] is True

    class Pattern:
        pass

    mem.ida_bytes.compiled_binpat_vec_t = Pattern
    mem.ida_bytes.parse_binpat_str = lambda *_args: 1
    result = mem._memory_impl(
        "search", "0x1000", "bytes", 4, "41 ??", None, 2,
    )
    assert result["count"] == 256


def test_memory_search_pattern_conversion_exception_uses_text_fallback(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)
    mem.ida_bytes.get_bytes = lambda _ea, size: b"needle"[:size]
    monkeypatch.setattr(mem.re, "fullmatch", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("regex parser")))
    result = mem._memory_impl("search", "0x1000", "bytes", 4, "needle", None, 2)
    assert result["mode"] == "bytes"
    assert result["count"] == 1


def test_memory_fixups_and_string_extraction_cover_fallback_shapes(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)
    mem._FIXUP_MODULE_NAMES = {}
    assert mem._fixup_type_name(0x42) == "FIXUP_REL32"

    class BrokenFixup:
        type = "unknown"

    mem.ida_fixup.fixup_data_t = BrokenFixup
    mem.ida_fixup.get_fixup = lambda *_args: True
    assert mem._fixup_info(0x1000) == {"relocation": True}

    utf16 = "wide text".encode("utf-16-le") + b"\x00\x00"
    assert mem._extract_strings(utf16, min_len=4) == [(0, "wide text", "utf-16-le")]

    monkeypatch.setattr(mem.ida_fixup, "__dir__", lambda: (_ for _ in ()).throw(RuntimeError("dir")))
    mem._FIXUP_MODULE_NAMES = None
    assert mem._fixup_name_map() == {}


def test_memory_compare_and_governance_report_missing_branches(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)
    mem.ida_bytes.get_bytes = lambda _ea, _size: b"same"
    assert mem._memory_impl("compare", None, "bytes", 4, None, None, 2)["code"] == "INVALID_ARGS"
    assert mem._memory_impl(
        "compare", None, "bytes", 4, None, None, 2, addr1="0x1000"
    )["code"] == "INVALID_ARGS"
    monkeypatch.setattr(mem, "validate_addr", lambda value: (
        (None, {"error": True, "code": "bad"}) if value == "0x2000" else (0x1000, None)
    ))
    assert mem._memory_impl(
        "compare", None, "bytes", 4, None, None, 2,
        addr1="0x1000", addr2="0x2000",
    )["code"] == "bad"

    monkeypatch.setattr(mem._compat, "get_segment_perm", lambda _ea: 0)
    monkeypatch.setattr(mem._compat, "get_segment_name", lambda _ea: ".data")
    assert mem._write_governance_metadata(0x1000) == {
        "section_type": ".data",
        "is_import_addr": False,
    }


def test_memory_struct_walk_skips_unreadable_queued_nodes_and_read_exceptions():
    mem = _load_memory()
    _full_error_envelope(mem)
    values = {0x1000: 0x2000}

    def read_pointer(ea, size):
        return struct.pack("<Q", values[ea])[:size] if ea in values else None

    mem.ida_bytes.get_bytes = read_pointer
    mem.ida_bytes.is_loaded = lambda ea: ea == 0x2000
    mem.idc.get_name = lambda _ea: ""
    walked = mem._memory_impl("struct_walk", "0x1000", "bytes", 8, None, None, 2)
    assert len(walked["nodes"]) == 1

    mem.ida_bytes.get_bytes = lambda *_args: (_ for _ in ()).throw(RuntimeError("read"))
    result = mem._memory_impl("read", "0x1000", "bytes", 4, None, None, 2)
    assert result["error"] == "read"


def test_memory_compare_reports_missing_lengths_and_large_hamming(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)

    def varying_bytes(ea, size):
        if ea == 0x1000:
            return b"abc"
        if ea == 0x2000:
            return b"ab"
        return None

    mem.ida_bytes.get_bytes = varying_bytes
    mismatch = mem._memory_impl(
        "compare", None, "bytes", 3, None, None, 2,
        addr1="0x1000", addr2="0x2000",
    )
    assert mismatch["diffs"][-1]["size_diff"] == "A=3 B=2"

    mem.ida_bytes.get_bytes = lambda _ea, _size: None
    assert mem._memory_impl(
        "compare", None, "bytes", 3, None, None, 2,
        addr1="0x1000", addr2="0x2000",
    )["code"] == "IDA_ERROR"

    large_a = b"a" * 4097
    large_b = b"b" * 4097
    mem.ida_bytes.get_bytes = lambda ea, _size: large_a if ea == 0x1000 else large_b
    large = mem._memory_impl(
        "compare", None, "bytes", 4097, None, None, 2,
        addr1="0x1000", addr2="0x2000",
    )
    assert large["hamming_distance"] == 4097


def test_memory_region_actions_handle_empty_data_and_struct_cycles():
    mem = _load_memory()
    _full_error_envelope(mem)
    mem.ida_bytes.get_bytes = lambda _ea, _size: None
    for action in ("pointers", "entropy", "strings", "histogram"):
        assert mem._memory_impl(action, "0x1000", "bytes", 4, None, None, 2)["code"] == "IDA_ERROR"

    values = {0x1000: 0x2000, 0x2000: 0x1000}

    def read_pointer(ea, size):
        return struct.pack("<Q", values[ea])[:size] if ea in values else None

    mem.ida_bytes.get_bytes = read_pointer
    mem.ida_bytes.is_loaded = lambda ea: ea in values
    mem.idc.get_name = lambda ea: f"node_{ea:x}"
    mem.ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("tinfo"))
    walked = mem._memory_impl("struct_walk", "0x1000", "bytes", 8, None, None, 4)
    assert [node["addr"] for node in walked["nodes"]] == ["0x1000", "0x2000"]


def test_memory_write_input_governance_and_exception_boundaries(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)
    mem.evaluate_operation = lambda **_kwargs: {"approved": True, "verdict": "ok", "violations": []}
    mem.ida_bytes.patch_bytes = lambda _ea, data: len(data)

    assert mem._memory_write_impl("write", "0x1000", "bytes", 4, "zz", None, 2)["code"] == "INVALID_ARGS"
    assert mem._memory_write_impl("write", "0x1000", "bytes", 4, None, None, 2)["code"] == "INVALID_ARGS"
    assert mem._memory_write_impl("other", "0x1000", "bytes", 4, "90", None, 2)["code"] == "INVALID_ARGS"

    mem._coerce_memory_params = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("coerce"))
    result = mem._memory_write_impl("write", "0x1000", "bytes", 4, "90", None, 2)
    assert result["error"] == "coerce"
