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


def _fake_segment(*, ea_api: bool) -> types.ModuleType:
    """Fake ``ida_segment`` matching a 9.3 surface (legacy pointer API only)
    or a 9.4 surface (EA-based segment_info_t API only, no ``getseg``)."""
    segment = types.ModuleType("ida_segment")
    if not ea_api:
        segment.getseg = lambda ea: "seg-legacy" if ea == 0x401000 else None
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

    funcs = types.ModuleType("ida_funcs")
    if ea_api:
        funcs.get_func_start = lambda ea: ea
    sys.modules["ida_funcs"] = funcs

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
