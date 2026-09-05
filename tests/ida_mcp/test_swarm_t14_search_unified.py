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
    uni.ida_funcs.get_func = uni.idaapi.get_func
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
    uni.ida_funcs.get_func = uni.idaapi.get_func
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
    adv.ida_funcs.get_func = adv.idaapi.get_func
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
    adv.ida_funcs.get_func = adv.idaapi.get_func
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
    adv.ida_funcs.get_func = adv.idaapi.get_func
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


def test_router_data_value_ascii_uses_string_scan():
    router = _module("search", os=os)
    captured = {}

    def fake_data_value(*_a, **_kw):
        captured["pointer"] = True
        return {"ok": True}

    def fake_string(pattern, *_a, **_kw):
        captured["string"] = pattern
        return {"ok": True, "results": pattern}

    router.search_data_value = fake_data_value
    router.search_string = fake_string

    r = router.search(action="data_value", value="AGENT_SURFACE_STRING_001", limit=10)
    assert r["ok"] is True
    assert captured.get("string") == "AGENT_SURFACE_STRING_001"
    assert "pointer" not in captured


def test_search_unified_edge_cases_and_symbol_info():
    uni = _module("search.unified")
    idc = sys.modules["idc"]
    idaapi = sys.modules["idaapi"]
    idautils = sys.modules["idautils"]
    compat = uni._compat

    # 1. search_xrefs_to_string empty pattern
    res = uni.search_xrefs_to_string("")
    assert res.get("error") is True or res.get("isError") is True
    assert "pattern required" in res["message"]

    # 2. search_symbol empty pattern
    res = uni.search_symbol("")
    assert res.get("error") is True or res.get("isError") is True
    assert "pattern required" in res["message"]

    # 3. _alternatives_for_name limit break
    saved_names = idautils.Names
    try:
        idautils.Names = lambda: [
            (0x401000, "my_func_1"),
            (0x401010, "my_func_2"),
            (0x401020, "my_func_3"),
        ]
        compat.get_func_start = lambda ea: ea
        alts = uni._alternatives_for_name("my_func", limit=2)
        assert len(alts) == 2
    finally:
        idautils.Names = saved_names

    # 4. search_symbol fallback score (matcher matches, but not simple substring of lower)
    orig_compile = uni.compile_smart_pattern
    saved_xrefs_to = getattr(idautils, "XrefsTo", None)
    try:
        idautils.Names = lambda: [(0x401000, "HELLO_WORLD")]
        idautils.XrefsTo = lambda ea, flags: []
        compat.get_func_start = lambda ea: ea
        idc.get_name = lambda ea: "HELLO_WORLD"
        idc.get_name_ea_simple = lambda name: idaapi.BADADDR
        uni.compile_smart_pattern = lambda pat, **k: lambda text: True
        res = uni.search_symbol("fuzzy_query", include_alternatives=False)
        assert res["ok"] is True
        assert res["total_candidates"] == 1
    finally:
        uni.compile_smart_pattern = orig_compile
        idautils.Names = saved_names
        if saved_xrefs_to:
            idautils.XrefsTo = saved_xrefs_to

    # 5. search_callees and search_callers non-function errors
    orig_resolve = uni.resolve_target
    orig_get_func = compat.get_func_start
    try:
        # resolve returns error
        uni.resolve_target = lambda *a, **k: (idaapi.BADADDR, "not found target", None)
        err_res = uni.search_callees("missing_sym", False, 0, 10, 0.5, False, False)
        assert err_res.get("error") is True
        assert "not found target" in err_res["message"]

        # resolve succeeds but get_func_start is None
        uni.resolve_target = lambda *a, **k: (0x401000, None, None)
        compat.get_func_start = lambda ea: None
        err_func = uni.search_callees("data_sym", False, 0, 10, 0.5, False, False)
        assert err_func.get("error") is True
        assert "No function at" in err_func["message"]

        err_caller = uni.search_callers("data_sym", False, 0, 10, 0.5, False, False)
        assert err_caller.get("error") is True
        assert "No function at" in err_caller["message"]
    finally:
        uni.resolve_target = orig_resolve
        compat.get_func_start = orig_get_func

    # 6. search_symbol_info with BadAddr, prototype, is_code, xrefs_to, and _count_xrefs_from_limited
    idc.get_name_ea_simple = lambda n: idaapi.BADADDR
    idc.get_name = lambda ea: ""
    # bad address literal
    res_bad = uni.search_symbol_info(hex(idaapi.BADADDR))
    assert res_bad.get("error") is True
    # unparseable literal
    res_unparsed = uni.search_symbol_info("not_a_valid_symbol_name_or_addr!!!")
    assert res_unparsed.get("error") is True

    # Function with prototype and xrefs_to
    class _FakeFunc:
        start_ea = 0x401000
        end_ea = 0x401050

    idc.INF_SHORT_DN = getattr(idc, "INF_SHORT_DN", 0)
    idc.get_inf_attr = getattr(idc, "get_inf_attr", lambda a: 0)
    idc.demangle_name = getattr(idc, "demangle_name", lambda n, inf: "")
    compat.get_func_info = lambda ea: _FakeFunc() if ea == 0x401000 else None
    compat.get_segment = lambda ea: object()
    compat.get_segment_name = lambda ea: ".text"
    compat.get_segment_perm = lambda ea: 5  # R-X
    idc.get_type = lambda ea: "int __cdecl(int, char**)"
    saved_xrefs_to = idautils.XrefsTo
    saved_xrefs_from = idautils.XrefsFrom
    try:
        class _FakeXref:
            frm = 0x402000
            iscode = True

        idautils.XrefsTo = lambda ea, flags: [_FakeXref()]
        idc.get_full_flags = lambda ea: 0x600  # code
        idc.is_code = lambda flags: True
        idc.is_data = lambda flags: False
        idc.find_func_end = lambda ea: 0x401050
        idc.next_head = lambda cur, end: 0x401050
        idautils.XrefsFrom = lambda cur, flags: [_FakeXref()]

        info = uni.search_symbol_info("0x401000", include_xrefs=True)
        assert info["ok"] is True
        assert info["function"]["prototype"] == "int __cdecl(int, char**)"
        assert len(info["xrefs_to_samples"]) == 1
        assert info["xrefs_to_samples"][0]["from"] == "0x402000"

        # Prototype exception
        idc.get_type = lambda ea: (_ for _ in ()).throw(RuntimeError("typeinfo failed"))
        info_exc = uni.search_symbol_info("0x401000", include_xrefs=False)
        assert info_exc["ok"] is True
        assert "prototype" not in info_exc["function"]

        # 64+ xrefs
        idautils.XrefsTo = lambda ea, flags: [_FakeXref() for _ in range(70)]
        info_many_xrefs = uni.search_symbol_info("0x401000", include_xrefs=True)
        assert len(info_many_xrefs["xrefs_to_samples"]) == 64

        # _count_xrefs_from_limited code flags hitting find_func_end == BADADDR, count >= max_count, and BADADDR break
        idc.is_code = lambda flags: True
        idc.find_func_end = lambda ea: idaapi.BADADDR
        next_calls = [0x401010, idaapi.BADADDR]
        idc.next_head = lambda cur, end: next_calls.pop(0) if next_calls else idaapi.BADADDR
        idautils.XrefsFrom = lambda cur, flags: [_FakeXref()]
        code_count = uni._count_xrefs_from_limited(0x401000, 50)
        assert code_count == 1
        # Code flags hitting max_count early
        idc.find_func_end = lambda ea: 0x401020
        idautils.XrefsFrom = lambda cur, flags: [_FakeXref(), _FakeXref()]
        code_count_max = uni._count_xrefs_from_limited(0x401000, 1)
        assert code_count_max == 1

        # Non-function code item
        compat.get_func_info = lambda ea: None
        idc.is_code = lambda flags: True
        idc.is_data = lambda flags: False
        idc.get_item_size = lambda ea: 4
        code_info = uni.search_symbol_info("0x401000", include_xrefs=False)
        assert code_info["ok"] is True
        assert "code" in code_info
        assert code_info["code"]["size"] == 4

        # Non-code _count_xrefs_from_limited hitting max_count (line 898)
        idc.is_code = lambda flags: False
        idautils.XrefsFrom = lambda cur, flags: [_FakeXref(), _FakeXref()]
        count = uni._count_xrefs_from_limited(0x401000, 1)
        assert count == 1
    finally:
        idautils.XrefsTo = saved_xrefs_to
        idautils.XrefsFrom = saved_xrefs_from

    # Exact name score in search_symbol hitting empty name (715) and exact score (722)
    try:
        idautils.Names = lambda: [(0x401000, ""), (0x401004, "MY_EXACT_NAME")]
        idautils.XrefsTo = lambda ea, flags: []
        compat.get_func_start = lambda ea: ea
        idc.get_name = lambda ea: "MY_EXACT_NAME"
        idc.get_name_ea_simple = lambda name: idaapi.BADADDR
        exact_res = uni.search_symbol("my_exact_name", include_alternatives=False)
        assert exact_res["ok"] is True
    finally:
        idautils.Names = saved_names


def test_search_find_heap_and_scan_edges():
    uni = _module("search.unified")
    idc = sys.modules["idc"]
    idautils = sys.modules["idautils"]
    compat = uni._compat

    saved_names = idautils.Names
    saved_cached_strings = uni.get_cached_strings
    saved_cached_imports = uni.get_cached_imports
    saved_segments = idautils.Segments
    orig_cap = uni._FIND_INSTRUCTION_CAP
    orig_mult = uni._FIND_INSTRUCTION_LIMIT_MULTIPLIER
    try:
        uni._FIND_INSTRUCTION_CAP = 5
        uni._FIND_INSTRUCTION_LIMIT_MULTIPLIER = 1

        # Names with duplicate EA and empty name (hitting line 153), plus > 5 items (hitting heapreplace lines 126-127)
        names_list = [(0x401000, "_Z4testv"), (0x401000, "_Z4testv"), (0x401008, "")]
        for i in range(10):
            names_list.append((0x401100 + i * 4, f"test_func_{i:03d}"))
        idautils.Names = lambda: names_list
        idc.demangle_name = lambda name, inf: "test()" if name == "_Z4testv" else ""
        compat.get_func_start = lambda ea: ea

        # Strings with duplicate EA
        uni.get_cached_strings = lambda: [
            {"ea": 0x401000, "string": "test string 1"},  # already in seen_eas!
            {"ea": 0x403000, "string": "test string 2"},
        ]
        # Imports with duplicate EA
        uni.get_cached_imports = lambda: [
            {"ea": 0x403000, "name": "test_imp", "module": "libtest"},  # already in seen_eas!
            {"ea": 0x404000, "name": "test_imp2", "module": "libtest"},
        ]
        # Comments exceeding comment_cap across segments
        idautils.Segments = lambda: [0x401000, 0x402000]
        idc.get_segm_end = lambda s: s + 0x100
        idautils.Heads = lambda s, e: [s + i * 4 for i in range(250)]
        idc.get_cmt = lambda ea, rep: "test comment" if rep == 0 else ""

        res = uni.search_find("test", False, None, None, False, True, False, 0, 10)
        assert res["ok"] is True
        assert res["count"] >= 10

        # Pattern starting with 0x but invalid hex
        res_bad_addr = uni.search_find("0xGHIJK", False, None, None, False, True, False, 0, 10)
        assert res_bad_addr["ok"] is True

        # Timeout in comments check
        class _FailingTimer:
            def check(self):
                raise TimeoutError("search timeout")

        orig_timeout = uni.SearchTimeout
        uni.SearchTimeout = lambda ms: _FailingTimer()
        res_timeout = uni.search_find("test", False, None, None, False, True, False, 0, 5, kind="comments")
        assert res_timeout["ok"] is True

        # Instruction scan hitting cap (line 247) and timeout across multiple segments (line 244)
        uni.SearchTimeout = orig_timeout
        uni._FIND_INSTRUCTION_CAP = 1
        uni.resolve_scan_segments = lambda start, end, require_exec: ([(0x401000, 0x402000), (0x403000, 0x404000)], "", "")
        uni.iter_code = lambda s, e, force: [s, s + 4]
        idc.print_insn_mnem = lambda ea: "mov"
        idc.print_operand = lambda ea, op: "eax" if op == 0 else "ebx"
        res_insn_cap = uni.search_find("mov", False, None, None, False, True, False, 0, 5, kind="instructions")
        assert res_insn_cap["ok"] is True

        uni.SearchTimeout = lambda ms: _FailingTimer()
        res_insn_timeout = uni.search_find("mov", False, None, None, False, True, False, 0, 5, kind="instructions")
        assert res_insn_timeout["ok"] is True
        uni.SearchTimeout = orig_timeout
    finally:
        uni._FIND_INSTRUCTION_CAP = orig_cap
        uni._FIND_INSTRUCTION_LIMIT_MULTIPLIER = orig_mult
        idautils.Names = saved_names
        uni.get_cached_strings = saved_cached_strings
        uni.get_cached_imports = saved_cached_imports
        idautils.Segments = saved_segments
