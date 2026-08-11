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


def _install_ida_stubs(*, ea_api: bool) -> types.ModuleType:
    hexrays = _fake_hexrays(ea_api=ea_api)
    sys.modules["ida_hexrays"] = hexrays

    funcs = types.ModuleType("ida_funcs")
    if ea_api:
        funcs.get_func_start = lambda ea: ea
    sys.modules["ida_funcs"] = funcs

    segment = types.ModuleType("ida_segment")
    if ea_api:
        segment.get_segment_info = lambda ea: None
    sys.modules["ida_segment"] = segment
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
