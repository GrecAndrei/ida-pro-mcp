"""Exercise the complete memory read surface through the isolated IDA seam."""

from __future__ import annotations

import struct

from tests.ida_mcp.test_swarm_q05d_memory_misc import _load_memory


def _full_error_envelope(mem):
    mem.make_error = lambda code, message, *args, **kwargs: {
        "ok": False, "error": True, "code": code, "message": message,
        **({"hint": args[0]} if args else {}), **kwargs,
    }


def test_memory_scalar_reads_strings_and_limits():
    mem = _load_memory(bitness=64)
    _full_error_envelope(mem)
    raw = struct.pack("<Q", 0x8000) + struct.pack("<f", 1.5) + struct.pack("<d", 2.5)
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]
    mem.ida_bytes.get_wide_byte = lambda _ea: 0xFF
    mem.ida_bytes.get_wide_word = lambda _ea: 0xFFFF
    mem.ida_bytes.get_wide_dword = lambda _ea: 0xFFFFFFFF
    mem.ida_bytes.get_qword = lambda _ea: 0xFFFFFFFFFFFFFFFF
    mem.idc.get_strlit_contents = lambda *_args: b"defined text"
    assert mem.memory(action="read", address="0x1000", type="u8")["value"] == 255
    assert mem.memory(action="read", address="0x1000", type="u16")["value"] == 65535
    assert mem.memory(action="read", address="0x1000", type="u32")["value"] == 0xFFFFFFFF
    assert mem.memory(action="read", address="0x1000", type="u64")["value"] == 0xFFFFFFFFFFFFFFFF
    assert mem.memory(action="read", address="0x1000", type="s8")["value"] == -1
    assert mem.memory(action="read", address="0x1000", type="s16")["value"] == -1
    assert mem.memory(action="read", address="0x1000", type="s32")["value"] == -1
    assert mem.memory(action="read", address="0x1000", type="s64")["value"] == -1
    mem.ida_bytes.get_bytes = lambda _ea, size: struct.pack("<f", 1.5)[:size]
    assert mem.memory(action="read", address="0x1000", type="f32")["value"] == 1.5
    mem.ida_bytes.get_bytes = lambda _ea, size: struct.pack("<d", 2.5)[:size]
    assert mem.memory(action="read", address="0x1000", type="f64")["value"] == 2.5
    assert mem.memory(action="read", address="0x1000", type="ptr")["value"] == 0xFFFFFFFFFFFFFFFF
    assert mem.memory(action="read", address="0x1000", type="string")["defined"] is True
    assert mem.memory(action="read", address="0x1000", type="wat")["error"] is True
    assert mem.memory(action="read", address="0x1000", type="bytes", size=2)["size"] == 2
    assert mem.memory(action="read", address="0x1000", type="bytes", size=2_000_000)["error"] is True


def test_memory_search_modes_compare_and_region_failures(monkeypatch):
    mem = _load_memory(bitness=64)
    _full_error_envelope(mem)
    haystack = b"ABCD" + bytes.fromhex("4d 5a 90 00") + b"needle needle" + b"\x00" * 8
    mem.ida_bytes.get_bytes = lambda _ea, size: haystack[:size]
    assert mem.memory(action="hexdump", address="0x1000", size=20)["ok"] is True
    assert mem.memory(action="hexdump", address="0x1000", size=5000)["error"] is True
    assert mem.memory(action="search", address="0x1000", data="needle")["count"] == 2
    assert mem.memory(action="search", address="0x1000", data="needle", regex=True)["count"] == 2
    assert mem.memory(action="search", address="0x1000", data="[", regex=True)["error"] is True
    assert mem.memory(action="search", address="0x1000", data="4d 5a ?? 00")["mode"] == "hex_wildcard"
    assert mem.memory(action="search", address="0x1000", data="0x5a", int_width=1)["mode"] == "integer"
    assert mem.memory(action="search", address="0x1000", data="0x5a", int_width=-1)["error"] is True
    assert mem.memory(action="search", address=None, end_addr="0x1100", data="x")["error"] is True
    mem._inf_min_ea = lambda: mem.idaapi.BADADDR
    assert mem.memory(action="search", address=None, data="x")["error"] is True
    mem._inf_min_ea = lambda: 0x1000
    assert mem.memory(action="search", address="0x1000", data="x", end_addr="0x0")["ok"] is True

    mem.ida_bytes.get_bytes = lambda ea, size: (b"abc" if ea == 0x1000 else b"axc")[:size]
    compared = mem.memory(action="compare", addr1="0x1000", addr2="0x2000", size=3)
    assert compared["edit_distance"] == 1 and compared["diff_count"] == 1
    assert mem.memory(action="compare", addr1="0x1000", addr2="0x2000", size=-1)["error"] is True
    monkeypatch.setattr(mem, "validate_addr", lambda _value: (None, {"error": True, "code": "bad"}))
    assert mem.memory(action="compare", addr1="0x1000", addr2="0x2000")["error"] is True


def test_memory_pointers_entropy_strings_struct_walk_histogram_and_write():
    mem = _load_memory(bitness=64)
    _full_error_envelope(mem)
    ptr = struct.pack("<Q", 0x8000)
    mem.ida_bytes.get_bytes = lambda _ea, size: (ptr + b"AAAA\x00\x00\x00\x00")[:size]
    mem.ida_bytes.is_loaded = lambda value: value == 0x8000
    mem.idc.get_name = lambda value: "target" if value == 0x8000 else ""
    assert mem.memory(action="pointers", address="0x1000", end_addr="0x1010")["count"] >= 1
    assert mem.memory(action="pointers", address="0x1000", end_addr="0x1010", aligned=True)["mode"] == "byte_aligned"
    assert mem.memory(action="entropy", address="0x1000", end_addr="0x1010")["ok"] is True
    assert mem.memory(action="strings", address="0x1000", end_addr="0x1010")["ok"] is True
    assert mem.memory(action="histogram", address="0x1000", end_addr="0x1010")["total_bytes"] > 0
    mem.ida_nalt.get_tinfo = lambda *_args: False
    assert mem.memory(action="struct_walk", address="0x1000", depth=1)["nodes"]
    assert mem.memory(action="struct_walk", address="0x1000", depth=0)["depth"] == 0

    mem.ida_segment.SEGPERM_X = 1
    mem.ida_segment.getseg = lambda _ea: type("Seg", (), {"name": ".data", "perm": 0})()
    mem.ida_segment.get_segm_name = lambda seg, flags=0: seg.name
    mem.ida_bytes.patch_bytes = lambda _ea, data: len(data)
    assert mem.memory(action="write", address="0x1000", data="90 90", governed=False)["size"] == 2
    assert mem.memory(action="write", address="0x1000", data="odd", governed=False)["error"] is True
    assert mem.memory(action="write", address="0x1000", data="", governed=False)["error"] is True
