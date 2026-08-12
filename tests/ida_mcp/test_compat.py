"""Tests for ida_mcp/compat.py — the IDA 9.4 EA-API compatibility shims.

The shims feature-detect at import time, so the selection logic can be
tested without a live IDA: fake ida_* modules modeling a 9.3 surface
(legacy entry points only) and a 9.4 surface (both legacy and EA variants)
must each pick the right underlying call.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_ida_module


def _fake_hexrays(*, ea_api: bool) -> types.ModuleType:
    m = types.ModuleType("ida_hexrays")
    m.hexrays_failure_t = type("hexrays_failure_t", (), {})
    m._calls = []

    def _legacy_decompile(ea, hf, flags=0):
        m._calls.append(("decompile_func", ea, flags))
        return "cfunc-legacy"

    m.decompile_func = _legacy_decompile
    if ea_api:
        def _ea_decompile(ea, hf, flags=0):
            m._calls.append(("decompile_function", ea, flags))
            return "cfunc-ea"

        m.decompile_function = _ea_decompile
    return m


def _fake_funcs(*, ea_api: bool) -> types.ModuleType:
    """Fake ``ida_funcs``: 9.3 surface (get_func/get_prev_func/get_next_func/
    update_func) or 9.4 surface (EA variants only)."""
    funcs = types.ModuleType("ida_funcs")
    if not ea_api:
        def _get_func(ea):
            if 0x401000 <= ea < 0x402000:
                return types.SimpleNamespace(
                    start_ea=0x401000, end_ea=0x402000, flags=0x10
                )
            return None

        funcs.get_func = _get_func
        funcs.get_prev_func = lambda ea: (
            types.SimpleNamespace(start_ea=0x400000) if ea == 0x401000 else None
        )
        funcs.get_next_func = lambda ea: (
            types.SimpleNamespace(start_ea=0x402000)
            if 0x401000 <= ea < 0x402000 else None
        )
        funcs._updated = []

        def _update_func(pfn):
            funcs._updated.append(pfn.flags)
            return True

        funcs.update_func = _update_func
        return funcs
    funcs.ida_idaapi = types.ModuleType("ida_idaapi")
    funcs.ida_idaapi.BADADDR = -1
    funcs.get_func_start = lambda ea: 0x401000 if 0x401000 <= ea < 0x402000 else -1
    funcs.func_entry_info_t = types.SimpleNamespace

    def _get_func_entry_info(out, ea, flags=0):
        if 0x401000 <= ea < 0x402000:
            out.start_ea = 0x401000
            out.end_ea = 0x402000
            return True
        return False

    funcs.get_func_entry_info = _get_func_entry_info
    funcs.get_func_flags = lambda ea: 0x10
    funcs._flag_sets = []

    def _set_func_flags(ea, flags):
        funcs._flag_sets.append((ea, flags))
        return True

    funcs.set_func_flags = _set_func_flags
    funcs.get_prev_func_ea = lambda ea: 0x400000 if ea == 0x401000 else -1
    funcs.get_next_func_ea = lambda ea: (
        0x402000 if 0x401000 <= ea < 0x402000 else -1
    )
    return funcs


def _fake_segment(*, ea_api: bool) -> types.ModuleType:
    """Fake ``ida_segment`` matching a 9.3 surface (legacy pointer API only)
    or a 9.4 surface (EA-based segment_info_t API only, no ``getseg``)."""
    segment = types.ModuleType("ida_segment")
    if not ea_api:
        def _getseg(ea):
            if ea == 0x401000:
                return "seg-legacy"
            if ea == 0x500000:
                return types.SimpleNamespace(
                    start_ea=0x500000, perm=5, type=2, align=4, bitness=2
                )
            return None

        segment.getseg = _getseg
        segment.get_segm_name = lambda s, flags=0: f"name({s})"
        segment.get_segm_class = lambda s: "CODE"
        segment.set_segm_name = lambda s, name, flags=0: 1
        segment.move_segm = lambda s, to, flags=0: 0
        segment.get_segm_by_name = lambda name: (
            types.SimpleNamespace(start_ea=0x401000, end_ea=0x402000)
            if name == "seg" else None
        )
        segment.get_first_seg = lambda: types.SimpleNamespace(start_ea=0x401000)
        segment.get_next_seg = lambda ea: (
            types.SimpleNamespace(start_ea=0x402000)
            if ea == 0x401000 else None
        )
        return segment
    segment.ida_idaapi = types.ModuleType("ida_idaapi")
    segment.ida_idaapi.BADADDR = -1
    segment.segment_info_t = types.SimpleNamespace

    def _get_segment_info(out, ea, flags=0):
        if ea == 0x401000:
            out.start_ea = 0x401000
            out.end_ea = 0x402000
            return True
        if ea == 0x500000:
            out.start_ea = 0x500000
            out.get_perm = lambda: 5
            out.get_type = lambda: 2
            out.get_align = lambda: 4
            out.get_bitness = lambda: 2
            return True
        return False

    segment.get_segment_info = _get_segment_info
    segment.get_segment_name = lambda ea, flags=0: "seg-ea"
    segment.get_segment_class = lambda ea: "CODE"
    segment.set_segment_name = lambda ea, name, flags=0: 1
    segment.move_segment = lambda ea, to, flags=0: 0
    segment.get_segment_ea_by_name = lambda name: 0x401000 if name == "seg" else -1
    segment.get_first_segment_ea = lambda: 0x401000
    segment.get_next_segment_ea = lambda ea: 0x402000 if ea == 0x401000 else -1
    return segment


def _install_ida_stubs(*, ea_api: bool) -> types.ModuleType:
    hexrays = _fake_hexrays(ea_api=ea_api)
    sys.modules["ida_hexrays"] = hexrays
    sys.modules["ida_funcs"] = _fake_funcs(ea_api=ea_api)
    sys.modules["ida_segment"] = _fake_segment(ea_api=ea_api)
    return hexrays


def _load_compat():
    # Flags are computed at import time; drop any cached module so each test
    # re-detects against its own fake surface.
    sys.modules.pop("ida_pro_mcp.ida_mcp.compat", None)
    return load_ida_module("compat")


def test_prefers_ea_apis_on_94_surface():
    hexrays = _install_ida_stubs(ea_api=True)
    compat = _load_compat()

    assert compat.HAS_EA_DECOMPILE is True
    assert compat.HAS_EA_FUNCS is True
    assert compat.HAS_EA_SEGMENT is True
    assert compat.HAS_DECOMPILER is True

    out = compat.decompile_function(0x401000, None, 7)
    assert out == "cfunc-ea"
    assert hexrays._calls == [("decompile_function", 0x401000, 7)]


def test_falls_back_to_legacy_apis_on_93_surface():
    hexrays = _install_ida_stubs(ea_api=False)
    compat = _load_compat()

    assert compat.HAS_EA_DECOMPILE is False
    assert compat.HAS_EA_FUNCS is False
    assert compat.HAS_EA_SEGMENT is False
    assert compat.HAS_DECOMPILER is True

    out = compat.decompile_function(0x401000, None, 7)
    assert out == "cfunc-legacy"
    assert hexrays._calls == [("decompile_func", 0x401000, 7)]


def test_blank_hexrays_surface_reports_no_decompiler():
    sys.modules["ida_hexrays"] = types.ModuleType("ida_hexrays")
    sys.modules["ida_funcs"] = types.ModuleType("ida_funcs")
    sys.modules["ida_segment"] = types.ModuleType("ida_segment")

    compat = _load_compat()

    assert compat.HAS_DECOMPILER is False
    assert compat.HAS_EA_DECOMPILE is False


# ---------------------------------------------------------------------------
# Segment family: get_segment / get_segment_name / get_segment_class /
# set_segment_name / move_segment / get_segment_ea_by_name
# ---------------------------------------------------------------------------

def test_segment_wrappers_use_ea_api_on_94_surface():
    _install_ida_stubs(ea_api=True)
    compat = _load_compat()

    assert compat.HAS_EA_SEGMENT is True

    # get_segment fills a fresh segment_info_t via get_segment_info.
    si = compat.get_segment(0x401000)
    assert si is not None
    assert si.start_ea == 0x401000
    assert si.end_ea == 0x402000
    # None-on-miss is preserved exactly.
    assert compat.get_segment(0x9999) is None

    assert compat.get_segment_name(0x401000) == "seg-ea"
    assert compat.get_segment_class(0x401000) == "CODE"
    assert compat.set_segment_name(0x401000, "new") == 1
    assert compat.move_segment(0x401000, 0x403000) == 0

    # get_segm_by_name's sanctioned replacement is EA-returning; BADADDR -> None.
    assert compat.get_segment_ea_by_name("seg") == 0x401000
    assert compat.get_segment_ea_by_name("missing") is None


def test_segment_wrappers_fallback_to_legacy_on_93_surface():
    _install_ida_stubs(ea_api=False)
    compat = _load_compat()

    assert compat.HAS_EA_SEGMENT is False

    # get_segment returns getseg's pointer; None-on-miss is preserved.
    assert compat.get_segment(0x401000) == "seg-legacy"
    assert compat.get_segment(0x9999) is None

    # get_segment_name collapses get_segm_name(getseg(ea)).
    assert compat.get_segment_name(0x401000) == "name(seg-legacy)"
    assert compat.get_segment_class(0x401000) == "CODE"
    assert compat.set_segment_name(0x401000, "new") == 1
    assert compat.move_segment(0x401000, 0x403000) == 0

    # get_segment_ea_by_name unwraps the legacy get_segm_by_name pointer.
    assert compat.get_segment_ea_by_name("seg") == 0x401000
    assert compat.get_segment_ea_by_name("missing") is None


def test_segment_iteration_wrappers_use_ea_api_on_94_surface():
    _install_ida_stubs(ea_api=True)
    compat = _load_compat()

    assert compat.get_first_segment_ea() == 0x401000
    assert compat.get_next_segment_ea(0x401000) == 0x402000
    # BADADDR-on-miss normalizes to None.
    assert compat.get_next_segment_ea(0x402000) is None


def test_segment_iteration_wrappers_fallback_to_legacy_on_93_surface():
    _install_ida_stubs(ea_api=False)
    compat = _load_compat()

    assert compat.get_first_segment_ea() == 0x401000
    assert compat.get_next_segment_ea(0x401000) == 0x402000
    # Legacy None-on-miss propagates.
    assert compat.get_next_segment_ea(0x402000) is None


def test_segment_attr_accessors_on_both_surfaces():
    for ea_api in (True, False):
        _install_ida_stubs(ea_api=ea_api)
        compat = _load_compat()

        assert compat.get_segment_perm(0x500000) == 5
        assert compat.get_segment_type(0x500000) == 2
        assert compat.get_segment_align(0x500000) == 4
        assert compat.get_segment_bitness(0x500000) == 2
        # Unmapped EA -> None on both surfaces.
        assert compat.get_segment_perm(0x9999) is None


# ---------------------------------------------------------------------------
# Function family: get_func_start / get_func_info / get_func_flags /
# set_func_flags / get_prev_func_start / get_next_func_start
# ---------------------------------------------------------------------------

def test_func_wrappers_use_ea_api_on_94_surface():
    _install_ida_stubs(ea_api=True)
    compat = _load_compat()

    assert compat.HAS_EA_FUNCS is True

    # EA in, start EA out; BADADDR-on-miss normalizes to None.
    assert compat.get_func_start(0x401500) == 0x401000
    assert compat.get_func_start(0x9999) is None

    # func_entry_info_t exposes the same start_ea/end_ea pair as func_t.
    fi = compat.get_func_info(0x401500)
    assert (fi.start_ea, fi.end_ea) == (0x401000, 0x402000)
    assert compat.get_func_info(0x9999) is None

    assert compat.get_func_flags(0x401500) == 0x10
    assert compat.get_func_flags(0x9999) is None

    assert compat.set_func_flags(0x401500, 0x30) is True
    assert sys.modules["ida_funcs"]._flag_sets == [(0x401500, 0x30)]

    assert compat.get_prev_func_start(0x401000) == 0x400000
    assert compat.get_next_func_start(0x401500) == 0x402000
    assert compat.get_next_func_start(0x9999) is None


def test_func_wrappers_fallback_to_legacy_on_93_surface():
    _install_ida_stubs(ea_api=False)
    compat = _load_compat()

    assert compat.HAS_EA_FUNCS is False

    # get_func(ea).start_ea unwrapping; None-on-miss propagates.
    assert compat.get_func_start(0x401500) == 0x401000
    assert compat.get_func_start(0x9999) is None

    fi = compat.get_func_info(0x401500)
    assert (fi.start_ea, fi.end_ea) == (0x401000, 0x402000)
    assert compat.get_func_info(0x9999) is None

    assert compat.get_func_flags(0x401500) == 0x10
    assert compat.get_func_flags(0x9999) is None

    # Legacy set_func_flags mutates the func_t and commits via update_func.
    assert compat.set_func_flags(0x401500, 0x30) is True
    assert sys.modules["ida_funcs"]._updated == [0x30]
    assert compat.set_func_flags(0x9999, 0x30) is False

    assert compat.get_prev_func_start(0x401000) == 0x400000
    assert compat.get_next_func_start(0x401500) == 0x402000
    assert compat.get_next_func_start(0x9999) is None
