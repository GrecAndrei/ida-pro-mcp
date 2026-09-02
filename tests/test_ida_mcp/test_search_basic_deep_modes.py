"""Exercise search.basic compatibility and raw-scan boundaries."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import ida_ua

from ida_pro_mcp.ida_mcp.tools.search import basic


def test_byte_search_legacy_ida_search_and_token_fallback(monkeypatch):
    monkeypatch.delattr(basic.ida_bytes, "compiled_binpat_vec_t", raising=False)
    monkeypatch.setattr(basic, "iter_segments", lambda *_args, **_kwargs: [(0x1000, 0x1010)])
    monkeypatch.setattr(basic.idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    legacy = types.ModuleType("ida_search")
    legacy.SEARCH_DOWN = 1
    calls = []

    def find_binary(start, *_args):
        calls.append(start)
        return 0x1000 if len(calls) == 1 else basic.idaapi.BADADDR

    legacy.find_binary = find_binary
    monkeypatch.setitem(sys.modules, "ida_search", legacy)
    monkeypatch.setattr(basic.ida_bytes, "get_bytes", lambda *_args: b"\x90\xcc", raising=False)
    monkeypatch.setattr(basic, "safe_generate_disasm_line", lambda _ea: "nop")
    result = basic.search_bytes("90", None, None, True, 0, 3)
    assert result["count"] == 1
    assert "90cc" in result["results"]
    assert calls == [0x1000, 0x1001]

    monkeypatch.delattr(legacy, "find_binary")
    monkeypatch.setattr(basic.ida_bytes, "get_bytes", lambda *_args: b"\x90\xA1\xCC\x00", raising=False)
    fallback = basic.search_bytes("9? A?", None, None, False, 0, 5)
    assert fallback["ok"] is True and fallback["count"] == 1
    assert basic.search_bytes("", None, None, False, 0, 5)["code"] == "INVALID_ARGS"
    assert basic.search_bytes("GG", None, None, False, 0, 5)["code"] == "IDA_ERROR"


def test_string_and_immediate_search_cover_ranges_timeouts_and_riscv(monkeypatch):
    monkeypatch.setattr(basic, "safe_get_strlist_items", lambda: [SimpleNamespace(ea=0x1000)])
    monkeypatch.setattr(basic, "safe_get_strlit_contents", lambda _ea: "needle")
    monkeypatch.setattr(basic.idautils, "XrefsTo", lambda *_args: [])
    assert basic.search_string("needle", False, False, 0, 1, 0)["count"] == 1

    class _Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError

    monkeypatch.setattr(basic, "SearchTimeout", _Expired)
    timed = basic.search_string("needle", False, False, 0, 1, 5)
    assert timed["timed_out"] is True

    monkeypatch.setattr(basic, "SearchTimeout", lambda _timeout: SimpleNamespace(check=lambda: None))
    monkeypatch.setattr(basic, "resolve_scan_segments", lambda *_args, **_kwargs: ([(0x1000, 0x1002)], "opaque", ""))
    monkeypatch.setattr(ida_ua, "insn_t", lambda: SimpleNamespace(ops=[SimpleNamespace(type=ida_ua.o_imm, value=7)], size=1), raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, _ea: 1, raising=False)
    direct = basic.search_immediate("7", None, None, False, 0, 1)
    assert direct["count"] == 1 and direct["note"] == "opaque"

    class _Insn:
        def __init__(self, mnem, ops, ea):
            self._mnem, self.ops, self.ea, self.size = mnem, ops, ea, 1

        def get_canon_mnem(self):
            return self._mnem

    reg = SimpleNamespace(type=ida_ua.o_reg, reg=1)
    monkeypatch.setattr(
        ida_ua,
        "decode_insn",
        lambda insn, ea: (setattr(insn, "_fill", ea) or 1),
        raising=False,
    )
    # Replace the instruction factory with an adjacent lui/addi pair.
    pair = iter([
        _Insn("lui", [reg, SimpleNamespace(type=ida_ua.o_imm, value=0x123)], 0x1000),
        _Insn("addi", [reg, reg, SimpleNamespace(type=ida_ua.o_imm, value=0x456)], 0x1001),
        _Insn("ret", [], 0x1002),
    ])
    monkeypatch.setattr(ida_ua, "insn_t", lambda: next(pair), raising=False)
    riscv = basic.search_immediate("0x123456", 0x1000, 0x1002, False, 0, 2)
    assert riscv["ok"] is True

    monkeypatch.setattr(basic, "resolve_scan_segments", lambda *_args, **_kwargs: ([], "", "no exec"))
    assert basic.search_immediate("7", None, None, False, 0, 1)["code"] == "NOT_FOUND"


def test_data_value_regions_and_word_size_validation(monkeypatch):
    assert basic._literal_ascii_needle("abc") is None
    assert basic._literal_ascii_needle("hello") == b"hello"
    assert basic._literal_ascii_needle("a*bcd") is None
    assert basic._resolve_data_value_region("0x1000:0x1010", 8) == (0x1000, 0x1010)
    assert basic._resolve_data_value_region("bad region", 8) is None
    monkeypatch.setattr(basic, "iter_segments", lambda *_args, **_kwargs: [(0x1000, 0x1008)])
    monkeypatch.setattr(basic, "_inf_ptr_size", lambda: 16)
    assert basic.search_data_value(1, word_size="auto")["word_size"] == "u32"
    assert basic.search_data_value(1, endian="sideways")["code"] == "INVALID_ARGS"
    assert basic.search_data_value(1, range_start=1)["code"] == "INVALID_ARGS"
