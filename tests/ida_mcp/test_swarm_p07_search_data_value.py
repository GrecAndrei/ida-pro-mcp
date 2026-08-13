"""Regression tests for swarm/p07 search_data_value (raw pointer-word scan).

WO-S6 closes the genuine /v gap natively on an analyzed IDB: IDA rarely
builds data xrefs for dispatch/vector tables and function-pointer arrays, so
``search(action='data_ref')`` silently misses them.  ``search_data_value``
scans the *mapped bytes* directly and unpacks LE/BE pointer-width words,
reporting every location whose raw word equals the target address regardless
of whether IDA created an xref.

Covers (all IDA-side, host-stubbed via tests._isolated_repo_loader, no live
IDA):
- finds a pointer word at both endians on a fake raw blob
- endian filtering (le / be / both)
- word_size auto/u32/u64 and RISC-V-style IVT/dispatch-table blob
- is_code_vs_data labeling via item flags
- region / start+end narrowing
- exact IDA name target resolution (get_name_ea_simple; no semantic path)
- timeout-bounded scan convention (timed_out + partial results)
- router dispatch: action="data_value" forwards value/endian/word_size/timeout
"""

import os
import struct
import sys

from tests._isolated_repo_loader import load_tool_submodule

BASE = 0x1000


def _module():
    return load_tool_submodule("search.basic")


def _config_basic(basic, blob, base=BASE, end=None):
    """Point the ida stubs at a fake raw byte blob and a single fake segment."""
    if end is None:
        end = base + len(blob)

    def _segments(a=None, b=None, require_exec=False):
        # Mirror the real iter_segments for a single segment: clamp the
        # requested range to the fake segment's bounds.
        start = base if a is None else a
        stop = end if b is None else b
        s, e = max(base, start), min(end, stop)
        return [(s, e)] if s < e else []

    sys.modules["ida_bytes"].get_bytes = (
        lambda ea, n: bytes(blob[max(0, ea - base): max(0, ea - base) + n])
    )
    sys.modules["ida_bytes"].get_flags = lambda ea: 0x0
    idc = sys.modules["idc"]
    idc.is_code = lambda f: False
    idc.is_data = lambda f: False
    basic.iter_segments = _segments


def _u64_blob():
    """32-byte blob with a u64 LE and a u64 BE pointer to 0x400000."""
    blob = bytearray(0x20)
    struct.pack_into("<Q", blob, 0x08, 0x400000)  # addr 0x1008 (little-endian)
    struct.pack_into(">Q", blob, 0x10, 0x400000)  # addr 0x1010 (big-endian)
    return blob


# ---------------------------------------------------------------------------
# Behavioral: find a pointer word at both endians on a fake raw blob
# ---------------------------------------------------------------------------

def test_data_value_finds_pointer_at_both_endians():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    assert resp["count"] == 2
    addrs = {it["address"] for it in resp["items"]}
    assert addrs == {"0x1008", "0x1010"}
    by_addr = {it["address"]: it for it in resp["items"]}
    assert by_addr["0x1008"]["endian"] == "le"
    assert by_addr["0x1010"]["endian"] == "be"
    assert by_addr["0x1008"]["value"] == "0x400000"


def test_data_value_le_only():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="le", timeout_ms=0)
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1008"]


def test_data_value_be_only():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="be", timeout_ms=0)
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1010"]


def test_data_value_int_target_accepts_plain_int():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value(0x400000, word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    assert resp["count"] == 2


# ---------------------------------------------------------------------------
# RISC-V-style IVT / dispatch table on an opaque raw blob (u32 pointers)
# ---------------------------------------------------------------------------

def _riscv_ivt_blob():
    """RISC-V-style interrupt/dispatch table: u32 entries, no EXEC segment."""
    blob = bytearray(0x40)
    targets = [0x80000000, 0x80000010, 0x80000020, 0x400000]
    for i, t in enumerate(targets):
        struct.pack_into("<I", blob, i * 4, t)
    struct.pack_into(">I", blob, 0x10, 0x400000)  # big-endian entry too
    return blob


def test_data_value_riscv_ivt_u32_on_opaque_blob():
    basic = _module()
    blob = _riscv_ivt_blob()
    _config_basic(basic, blob)
    # Opaque raw blob: bytes are undefined (not code, not data) → kind unknown.
    sys.modules["idc"].is_data = lambda f: False
    sys.modules["idc"].is_code = lambda f: False

    resp = basic.search_data_value("0x400000", word_size="u32", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    addrs = sorted(it["address"] for it in resp["items"])
    assert addrs == ["0x100c", "0x1010"]
    assert all(it["kind"] == "unknown" for it in resp["items"])


def test_data_value_auto_word_size_uses_ptr_size():
    basic = _module()
    blob = bytearray(0x20)
    struct.pack_into("<I", blob, 0x04, 0x400000)  # u32 pointer
    _config_basic(basic, blob)
    basic._inf_ptr_size = lambda: 4  # 32-bit IDB → auto = u32

    resp = basic.search_data_value("0x400000", word_size="auto", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1004"]


# ---------------------------------------------------------------------------
# is_code_vs_data labeling via item flags
# ---------------------------------------------------------------------------

def test_data_value_labels_code_and_data_locations():
    basic = _module()
    blob = _u64_blob()
    _config_basic(basic, blob)
    idc = sys.modules["idc"]

    # 0x1008 is an instruction; 0x1010 is data.
    idc.is_code = lambda f: f == 0x1
    idc.is_data = lambda f: f == 0x2
    sys.modules["ida_bytes"].get_flags = lambda ea: 0x1 if ea == 0x1008 else 0x2

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0)
    by_addr = {it["address"]: it for it in resp["items"]}
    assert by_addr["0x1008"]["kind"] == "code"
    assert by_addr["0x1010"]["kind"] == "data"


# ---------------------------------------------------------------------------
# region / start+end narrowing
# ---------------------------------------------------------------------------

def test_data_value_region_range_narrows_scan():
    basic = _module()
    _config_basic(basic, _u64_blob())

    # Region covers [0x1000, 0x1010): the LE pointer fits, the BE one (starts
    # at 0x1010) does not.
    resp = basic.search_data_value(
        "0x400000", word_size="u64", endian="both", timeout_ms=0, region="0x1000-0x1010"
    )
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1008"]
    assert resp["note"] == "Scanned 0x1000-0x1010"


def test_data_value_region_segment_name():
    basic = _module()
    blob = _u64_blob()
    _config_basic(basic, blob, base=BASE, end=BASE + len(blob))

    class _Seg:
        def __init__(self, start, end):
            self.start_ea = start
            self.end_ea = end

    sys.modules["ida_segment"].get_segm_by_name = (
        lambda name: _Seg(BASE, BASE + 0x20) if name == ".vector" else None
    )
    # get_segment_ea_by_name unwraps the pointer, then get_segment re-fetches it.
    sys.modules["ida_segment"].getseg = (
        lambda ea: _Seg(BASE, BASE + 0x20) if ea == BASE else None
    )

    resp = basic.search_data_value("0x400000", word_size="u64", endian="be", timeout_ms=0, region=".vector")
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1010"]


def test_data_value_start_end_narrows_scan():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value(
        "0x400000", word_size="u64", endian="both", timeout_ms=0,
        range_start=0x1000, range_end=0x1010,
    )
    assert resp["ok"] is True
    assert [it["address"] for it in resp["items"]] == ["0x1008"]


# ---------------------------------------------------------------------------
# symbol-name target resolution
# ---------------------------------------------------------------------------

def test_data_value_resolves_symbol_name_target():
    basic = _module()
    _config_basic(basic, _u64_blob())
    bad = getattr(basic.idaapi, "BADADDR", -1)
    basic.idc.get_name_ea_simple = lambda name: 0x400000 if name == "handler_main" else bad

    resp = basic.search_data_value("handler_main", word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    assert resp["count"] == 2


def test_data_value_invalid_symbol_target_errors():
    basic = _module()
    _config_basic(basic, _u64_blob())
    bad = getattr(basic.idaapi, "BADADDR", -1)
    basic.idc.get_name_ea_simple = lambda name: bad

    resp = basic.search_data_value("nope", word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is False
    assert resp["code"] == "INVALID_ARGS"
    assert "nope" in resp["message"]


# ---------------------------------------------------------------------------
# timeout-bounded scan convention
# ---------------------------------------------------------------------------

def test_data_value_timeout_returns_partial_results():
    basic = _module()
    _config_basic(basic, _u64_blob())

    class _ImmediateTimeout:
        def __init__(self, timeout_ms):
            pass

        def check(self):
            raise TimeoutError("Search timeout exceeded")

    basic.SearchTimeout = _ImmediateTimeout

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=500)
    assert resp["ok"] is True
    assert resp["timed_out"] is True
    assert resp["count"] == 0
    assert resp["items"] == []
    assert "timed out" in resp["hint"].lower()


def test_data_value_timeout_zero_means_no_limit():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0)
    assert resp["ok"] is True
    # basic.py convention: the timed_out key is only present when the scan
    # actually hit the budget.
    assert resp.get("timed_out") is not True
    assert resp["count"] == 2


# ---------------------------------------------------------------------------
# argument validation
# ---------------------------------------------------------------------------

def test_data_value_invalid_endian_errors():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="sideways", timeout_ms=0)
    assert resp["ok"] is False
    assert resp["code"] == "INVALID_ARGS"
    assert "endian" in resp["message"]


def test_data_value_invalid_region_errors():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0, region="!!nonsense")
    assert resp["ok"] is False
    assert resp["code"] == "INVALID_ARGS"
    assert "region" in resp["message"]


def test_data_value_start_without_end_errors():
    basic = _module()
    _config_basic(basic, _u64_blob())

    resp = basic.search_data_value("0x400000", word_size="u64", endian="both", timeout_ms=0, range_start=0x1000)
    assert resp["ok"] is False
    assert resp["code"] == "INVALID_ARGS"


# ---------------------------------------------------------------------------
# router dispatch
# ---------------------------------------------------------------------------

def _router_module():
    # The search package's semantic module reads os.environ via the _common
    # wildcard; the isolated stub only carries os when it is passed in.
    return load_tool_submodule("search", common_overrides={"os": os})


def test_router_dispatches_data_value_and_forwards_args():
    router = _router_module()
    captured = {}

    def fake_data_value(value, **kw):
        captured["value"] = value
        captured.update(kw)
        return {"ok": True}

    router.search_data_value = fake_data_value

    resp = router.search(
        action="data_value", value="0x400000",
        endian="be", word_size="u64", timeout_ms=0,
    )
    assert resp["ok"] is True
    assert captured["value"] == "0x400000"
    assert captured["endian"] == "be"
    assert captured["word_size"] == "u64"
    assert captured["timeout_ms"] == 0
    assert captured["limit"] == 100
    assert captured["offset"] == 0


def test_router_data_value_accepts_pattern_and_ranges():
    router = _router_module()
    captured = {}

    def fake_data_value(value, **kw):
        captured["value"] = value
        captured.update(kw)
        return {"ok": True}

    router.search_data_value = fake_data_value
    # The isolated stub's validate_range always returns (None, None, None);
    # mirror the real parser so start/end actually reach the handler.
    router.validate_range = lambda s, e: (int(s, 16), int(e, 16), None)

    resp = router.search(
        action="data_value", pattern="0x400000",
        start="0x1000", end="0x1020", timeout_ms=0,
    )
    assert resp["ok"] is True
    assert captured["value"] == "0x400000"
    assert captured["range_start"] == 0x1000
    assert captured["range_end"] == 0x1020


def test_router_data_value_requires_target():
    router = _router_module()

    resp = router.search(action="data_value", timeout_ms=0)
    assert resp["ok"] is False
    assert resp["code"] == "INVALID_ARGS"
    assert "target" in resp["message"]


def test_router_pointer_alias_routes_to_data_value():
    router = _router_module()
    captured = {}

    def fake_data_value(value, **kw):
        captured["value"] = value
        return {"ok": True}

    router.search_data_value = fake_data_value

    resp = router.search(action="pointer", pattern="0x400000", timeout_ms=0)
    assert resp["ok"] is True
    assert captured["value"] == "0x400000"
