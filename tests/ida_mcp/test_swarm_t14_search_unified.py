"""Regression tests for swarm/t14_search_unified findings.

Covers (all in the IDA-side search tools, host-stubbed via
tests._isolated_repo_loader):
- search_decompiled: timeout_ms is a dedicated parameter (the router binds it
  as a named arg so it was dropped from **kwargs); timeout_ms=0 now means "no
  limit" instead of silently hard-cutting at 8000ms.
- search_decompiled cache invalidation: func.flags (FUNC_*) does not change on
  rename/retype, so the cache key is now fingerprinted with the function's
  current name+prototype (_decomp_cache_mod_sig).
- search_constants: full-binary decode_insn scan now honors timeout_ms and a
  hit cap, so it no longer runs unbounded / relies solely on the host RPC
  timeout.
- _data_flags: idc.is_comm() tests the COMMON (uninitialized) storage flag, NOT
  comment presence. Comment detection now uses ida_bytes.has_cmt(ea, ...).
- search_xrefs_to_string: string value is read through safe_get_strlit_contents
  (which passes the item's own string type) instead of the plain
  idc.get_strlit_contents UTF-8 decode.
- Router forwards timeout_ms to both decompiled and constants actions.

Host-side tests: ida_* modules are stubbed; no live IDA session is required.
"""

import os
import sys

from tests._isolated_repo_loader import load_tool_submodule


class _Func:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


class _Cfunc:
    """Minimal cfunc stand-in whose str() is the decompiled pseudocode."""

    def __init__(self, ea):
        self.ea = ea

    def __str__(self):
        return f"int sub_{self.ea:x}()\n{{\n  return {self.ea};\n}}"


class _Op:
    def __init__(self, t, value=0):
        self.type = t
        self.value = value


class _Insn:
    def __init__(self):
        self.ops = []
        self.size = 4


class _Seg:
    def __init__(self, perm=0):
        self.perm = perm


def _module(relpath, **overrides):
    return load_tool_submodule(relpath, common_overrides=overrides or None)


# ---------------------------------------------------------------------------
# Finding: _data_flags mislabels COMMON symbols as "has_comment"
# ---------------------------------------------------------------------------

def _make_data_flags_idc(uni):
    idc = sys.modules["idc"]
    idc.is_byte = lambda f: False
    idc.is_word = lambda f: False
    idc.is_dword = lambda f: False
    idc.is_qword = lambda f: False
    idc.is_strlit = lambda f: False
    idc.is_struct = lambda f: False
    idc.is_align = lambda f: False
    return idc


def test_data_flags_comm_storage_flag_is_not_comment():
    uni = _module("search.unified")
    idc = _make_data_flags_idc(uni)
    idc.is_comm = lambda f: True  # COMMON/uninitialized storage — not a comment
    sys.modules["ida_bytes"].has_cmt = lambda ea, rep: False

    flags = uni._data_flags(0x1234, ea=0x1000)
    assert "has_comment" not in flags
    assert flags == ["unknown"]


def test_data_flags_real_comment_detected_via_ea():
    uni = _module("search.unified")
    idc = _make_data_flags_idc(uni)
    idc.is_byte = lambda f: True
    sys.modules["ida_bytes"].has_cmt = lambda ea, rep: rep == 0  # regular comment

    flags = uni._data_flags(0x10, ea=0x1000)
    assert "byte" in flags
    assert "has_comment" in flags


def test_data_flags_without_ea_skips_comment_check():
    uni = _module("search.unified")
    idc = _make_data_flags_idc(uni)
    idc.is_dword = lambda f: True

    flags = uni._data_flags(0x20, ea=None)
    assert "dword" in flags
    assert "has_comment" not in flags


def test_symbol_info_data_block_passes_ea_for_comment_check():
    uni = _module("search.unified")
    idc = _make_data_flags_idc(uni)
    idc.is_comm = lambda f: True
    idc.get_name_ea_simple = lambda raw: 0x1000
    idc.get_name = lambda ea: "g_data"
    idc.get_full_flags = lambda ea: 0x4
    idc.is_data = lambda flags: True
    idc.is_code = lambda flags: False
    idc.get_item_size = lambda ea: 8
    idc.get_inf_attr = lambda attr: 0
    idc.INF_SHORT_DN = 0
    idc.demangle_name = lambda name, flags: name
    idc.get_func_name = lambda ea: ""
    sys.modules["ida_bytes"].has_cmt = lambda ea, rep: rep == 1  # repeatable comment

    uni.idaapi.BADADDR = -1
    uni.idaapi.get_func = lambda ea: None
    uni.idaapi.getseg = lambda ea: _Seg()
    uni.idaapi.SEGPERM_READ = 1
    uni.idaapi.SEGPERM_WRITE = 2
    uni.idaapi.SEGPERM_EXEC = 4
    # The compat get_segment_name wrapper re-fetches the segment via ida_segment.
    uni.ida_segment.getseg = lambda ea: _Seg()
    uni.ida_segment.get_segm_name = lambda seg, flags=0: ".bss"
    uni.xref_count_limited = lambda ea, n=256: 0
    uni._count_xrefs_from_limited = lambda ea, n: 0

    resp = uni.search_symbol_info("g_data")
    assert resp["ok"] is True
    # size flag is unknown (no is_* matched) but the real comment IS reported.
    assert resp["data"]["flags"] == ["has_comment"]


# ---------------------------------------------------------------------------
# Finding: search_xrefs_to_string mis-decodes wide/UTF-16 string literals
# ---------------------------------------------------------------------------

def test_xrefs_to_string_delegates_to_safe_strlit_contents():
    uni = _module("search.unified")
    calls = []

    def fake_safe(ea):
        calls.append(ea)
        return "WIDE_HELLO"

    uni.safe_get_strlit_contents = fake_safe
    uni.get_cached_strings = lambda: [{"ea": 0x1000, "string": "hello"}]

    class _Xref:
        def __init__(self, frm, iscode):
            self.frm = frm
            self.iscode = iscode

    uni.idautils.XrefsTo = lambda ea, flow: iter([_Xref(0x1100, True)])
    uni.idaapi.get_func = lambda ea: _Func(ea, ea + 0x10)
    uni.ida_funcs.get_func_name = lambda ea: "sub_1100"

    resp = uni.search_xrefs_to_string("hello", include_context=False, timeout_ms=0)
    assert resp["ok"] is True
    assert calls == [0x1000]  # the safe wrapper was used, not raw get_strlit_contents
    assert "WIDE_HELLO" in resp["results"]
    assert resp["items"][0]["value"] == "WIDE_HELLO"
    assert resp["items"][0]["xrefs"][0]["function"] == "sub_1100"


# ---------------------------------------------------------------------------
# Finding: search_constants full-binary scan lacks timeout and hit cap
# ---------------------------------------------------------------------------

def _config_constants_ida(adv):
    sys.modules["idaapi"].BADADDR = -1
    sys.modules["ida_ua"].insn_t = _Insn
    sys.modules["ida_ua"].o_imm = 0x20
    adv.idaapi.get_func = lambda ea: _Func(ea, ea + 4)
    adv.ida_funcs.get_func_name = lambda ea: f"sub_{ea:x}"
    adv.resolve_scan_segments = lambda range_start, range_end, require_exec=True: (
        [(0x1000, 0x2000)],
        "",
        "",
    )
    adv.get_cached_constant_db = lambda: {0x1234: "MAGIC"}


def test_constants_respects_timeout():
    adv = _module("search.advanced")
    _config_constants_ida(adv)

    class _ImmediateTimeout:
        def __init__(self, timeout_ms):
            pass

        def check(self):
            raise TimeoutError("Search timeout exceeded")

    adv.SearchTimeout = _ImmediateTimeout

    resp = adv.search_constants(None, None, None, False, 0, 100, False, timeout_ms=500)
    assert resp["ok"] is True
    assert resp["timed_out"] is True
    assert resp["count"] == 0
    assert resp["truncated"] is True


def test_constants_hit_cap_bounds_results():
    adv = _module("search.advanced")
    _config_constants_ida(adv)

    def decode_imm(insn, ea):
        insn.ops = [_Op(sys.modules["ida_ua"].o_imm, 0x1234)]
        insn.size = 4
        return 1

    sys.modules["ida_ua"].decode_insn = decode_imm
    adv._CONSTANTS_HIT_CAP = 3

    resp = adv.search_constants(None, None, None, False, 0, 100, False, timeout_ms=0)
    assert resp["ok"] is True
    # Only the first 3 of the (unbounded) instruction stream were collected.
    assert resp["count"] == 3
    assert resp["total_found"] == 3
    assert resp["truncated"] is True
    assert resp["note"] == "Hit scan cap (3 constant sites) — results may be partial."


# ---------------------------------------------------------------------------
# Finding: search_decompiled cache invalidation via name+prototype fingerprint
# ---------------------------------------------------------------------------

def test_decomp_cache_sig_tracks_rename():
    adv = _module("search.advanced")
    idc = sys.modules["idc"]
    idc.get_func_name = lambda ea: "sub_401000"
    idc.get_type = lambda ea: "int sub_401000()"
    sig1 = adv._decomp_cache_mod_sig(0x401000)

    idc.get_func_name = lambda ea: "decrypt_key"
    sig2 = adv._decomp_cache_mod_sig(0x401000)
    assert sig1 != sig2


def test_decomp_cache_sig_tracks_retype():
    adv = _module("search.advanced")
    idc = sys.modules["idc"]
    idc.get_func_name = lambda ea: "sub_401000"
    idc.get_type = lambda ea: "int sub_401000()"
    sig1 = adv._decomp_cache_mod_sig(0x401000)

    idc.get_type = lambda ea: "char *sub_401000(int)"
    sig2 = adv._decomp_cache_mod_sig(0x401000)
    assert sig1 != sig2


def test_decomp_cache_sig_fallback_on_error():
    adv = _module("search.advanced")

    def boom(ea):
        raise RuntimeError("no func")

    sys.modules["idc"].get_func_name = boom
    assert adv._decomp_cache_mod_sig(0x401000) == ""


def test_seed_decompiled_parses_cache_key_with_name_fingerprint():
    adv = _module("search.advanced")
    sys.modules["idaapi"].BADADDR = -1
    adv.idaapi.get_func = lambda ea: _Func(ea, ea + 0x20)
    sys.modules["idautils"].Functions = lambda *a, **k: iter([])
    adv.get_cached_strings = list
    adv.get_cached_imports = list
    adv._get_intelligence_index = lambda: (None, None, "")

    saved = dict(adv._SEARCH_CACHE)
    adv._SEARCH_CACHE.clear()
    adv._SEARCH_CACHE["decomp:4198400:sub_401000|int sub_401000()"] = (
        "int sub_401000() { return 0x1234; }"
    )
    try:
        matcher = adv.compile_smart_pattern("0x1234", case_sensitive=False)
        ranked, meta = adv._seed_decompiled_candidates(
            "0x1234", matcher, None, None, max_functions=50, timeout_ms=2000
        )
        assert 4198400 in ranked
        assert meta["seeded_candidates"] == 1
        assert meta["seed_reasons"]["cached"] == 1
    finally:
        adv._SEARCH_CACHE.clear()
        adv._SEARCH_CACHE.update(saved)


# ---------------------------------------------------------------------------
# Finding: search_decompiled timeout_ms reachable (0 = no limit)
# ---------------------------------------------------------------------------

def _config_decompiled_ida(adv):
    sys.modules["idaapi"].BADADDR = -1
    adv.idaapi.get_func = lambda ea: _Func(ea, ea + 0x20)
    sys.modules["ida_hexrays"].init_hexrays_plugin = lambda: True
    sys.modules["ida_hexrays"].decompile = _Cfunc
    sys.modules["idc"].get_func_name = lambda ea: f"sub_{ea:x}"
    sys.modules["idc"].get_type = lambda ea: None
    sys.modules["idautils"].Functions = lambda *a, **k: iter([0x401000, 0x402000])
    adv._get_intelligence_index = lambda: (None, None, "")
    adv._SEARCH_CACHE.clear()


def test_decompiled_timeout_zero_means_no_limit():
    adv = _module("search.advanced")
    _config_decompiled_ida(adv)

    resp = adv.search_decompiled("return", False, None, None, 0, 10, False, timeout_ms=0)
    assert resp["ok"] is True
    assert resp["timed_out"] is False
    assert resp["scanned_functions"] == 2
    assert resp["decompiled_functions"] == 2


class _Clock:
    """Advancing clock: each read moves +0.5s, so a small timeout fires fast."""

    def __init__(self):
        self.now = 0.0

    def time(self):
        self.now += 0.5
        return self.now


def test_decompiled_small_timeout_stops_scan():
    adv = _module("search.advanced")
    _config_decompiled_ida(adv)
    adv._time = _Clock()

    resp = adv.search_decompiled("return", False, None, None, 0, 10, False, timeout_ms=100)
    assert resp["ok"] is True
    assert resp["timed_out"] is True
    assert resp["scanned_functions"] == 0
    assert resp["analysis_truncated"] is True


# ---------------------------------------------------------------------------
# Finding: the router drops timeout_ms for decompiled/constants
# ---------------------------------------------------------------------------

def test_router_forwards_timeout_ms_to_decompiled_and_constants():
    router = _module("search", os=os)
    captured = {}

    def fake_decompiled(pattern, case_sensitive, range_start, range_end, offset,
                        limit, include_items, timeout_ms=0, **kw):
        captured["decompiled_timeout_ms"] = timeout_ms
        return {"ok": True}

    def fake_constants(pattern, range_start, range_end, include_context, offset,
                       limit, include_items, timeout_ms=0):
        captured["constants_timeout_ms"] = timeout_ms
        return {"ok": True}

    router.search_decompiled = fake_decompiled
    router.search_constants = fake_constants

    r1 = router.search(action="decompiled", pattern="return", timeout_ms=0)
    assert r1["ok"] is True
    assert captured["decompiled_timeout_ms"] == 0

    r2 = router.search(action="constants", pattern="magic", timeout_ms=5000)
    assert r2["ok"] is True
    assert captured["constants_timeout_ms"] == 5000


def test_router_forwards_data_value_endian_word_size_timeout():
    router = _module("search", os=os)
    captured = {}

    def fake_data_value(value, **kw):
        captured["value"] = value
        captured.update(kw)
        return {"ok": True}

    router.search_data_value = fake_data_value

    r = router.search(
        action="data_value", value="0x400000",
        endian="be", word_size="u64", timeout_ms=0, region="0x1000-0x1020",
    )
    assert r["ok"] is True
    assert captured["value"] == "0x400000"
    assert captured["endian"] == "be"
    assert captured["word_size"] == "u64"
    assert captured["timeout_ms"] == 0
    assert captured["region"] == "0x1000-0x1020"
    # data_value is pattern-optional (value may arrive via the value kwarg).
    assert captured["range_start"] is None
    assert captured["range_end"] is None
