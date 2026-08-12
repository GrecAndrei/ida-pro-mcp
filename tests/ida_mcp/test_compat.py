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
        funcs.ida_idaapi = types.ModuleType("ida_idaapi")
        funcs.ida_idaapi.BADADDR = -1

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
                    start_ea=0x500000, perm=5, type=2, align=4, bitness=2,
                    comb=7, color=0x112233,
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
            out.get_comb = lambda: 7
            out.get_color = lambda: 0x112233
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


# ---------------------------------------------------------------------------
# flow charts / frames / thunks / prototypes


def _fake_gdl() -> types.ModuleType:
    """Fake ``ida_gdl``: FlowChart records its constructor args."""
    gdl = types.ModuleType("ida_gdl")
    gdl._charts = []

    class _FlowChart:
        def __init__(self, f=None, bounds=None, flags=0):
            gdl._charts.append((f, bounds, flags))
            self._blocks = [f"b{i}" for i in range(3)]

        def __iter__(self):
            return iter(self._blocks)

    gdl.FlowChart = _FlowChart
    return gdl


def _fake_idaapi_with_range() -> types.ModuleType:
    m = types.ModuleType("idaapi")

    class _ea_range:
        def __init__(self, start_ea=0, end_ea=0):
            self.start_ea = start_ea
            self.end_ea = end_ea

    m.ea_range_t = _ea_range
    return m


def test_get_flow_chart_builds_from_range_on_both_surfaces():
    for ea_api in (True, False):
        _install_ida_stubs(ea_api=ea_api)
        sys.modules["ida_gdl"] = _fake_gdl()
        sys.modules["idaapi"] = _fake_idaapi_with_range()
        compat = _load_compat()

        fc = compat.get_flow_chart(0x401500)
        assert list(fc) == ["b0", "b1", "b2"]
        f, bounds, _flags = sys.modules["ida_gdl"]._charts[-1]
        # The function pointer slot carries the ea_range_t, not a func_t.
        assert (f.start_ea, f.end_ea) == (0x401000, 0x402000)
        assert bounds is None

        # No function at the EA -> None (mirrors legacy `get_func` miss).
        assert compat.get_flow_chart(0x9999) is None

        sys.modules.pop("ida_gdl", None)
        sys.modules.pop("idaapi", None)


def test_calc_thunk_target_on_both_surfaces():
    _install_ida_stubs(ea_api=True)
    funcs = sys.modules["ida_funcs"]
    funcs.calc_thunk_function_target = lambda fi: 0x403000
    compat = _load_compat()
    assert compat.calc_thunk_target(0x401500) == 0x403000
    assert compat.calc_thunk_target(0x9999) == -1  # BADADDR on miss

    _install_ida_stubs(ea_api=False)
    funcs = sys.modules["ida_funcs"]
    funcs.calc_thunk_func_target = lambda pfn: 0x403000
    compat = _load_compat()
    assert compat.calc_thunk_target(0x401500) == 0x403000
    assert compat.calc_thunk_target(0x9999) == -1  # BADADDR on miss


def test_get_frame_id_on_both_surfaces():
    _install_ida_stubs(ea_api=True)
    funcs = sys.modules["ida_funcs"]

    def _fill(out, ea, flags=0):
        if 0x401000 <= ea < 0x402000:
            out.start_ea = 0x401000
            out.end_ea = 0x402000
            out.get_frame_id = lambda: 0x700000
            return True
        return False

    funcs.get_func_entry_info = _fill
    compat = _load_compat()
    assert compat.get_frame_id(0x401500) == 0x700000
    assert compat.get_frame_id(0x9999) is None

    _install_ida_stubs(ea_api=False)
    funcs = sys.modules["ida_funcs"]
    orig_get_func = funcs.get_func

    def _get_func_with_frame(ea):
        pfn = orig_get_func(ea)
        if pfn is not None:
            pfn.frame = 0x700000
        return pfn

    funcs.get_func = _get_func_with_frame
    compat = _load_compat()
    assert compat.get_frame_id(0x401500) == 0x700000
    assert compat.get_frame_id(0x9999) is None


def test_get_spd_on_both_surfaces():
    for ea_api in (True, False):
        _install_ida_stubs(ea_api=ea_api)
        frame = types.ModuleType("ida_frame")
        if ea_api:
            frame.get_func_spd = lambda func_ea, ea: (
                0x20 if func_ea == 0x401000 else 0
            )
        else:
            frame.get_spd = lambda pfn, ea: 0x20
        sys.modules["ida_frame"] = frame
        compat = _load_compat()

        assert compat.get_spd(0x401000, 0x401500) == 0x20
        assert compat.get_spd(0x9999, 0x9999) == 0  # no function -> 0

        sys.modules.pop("ida_frame", None)


def test_get_prototype_string_94_uses_ea_fallbacks():
    _install_ida_stubs(ea_api=True)
    idc = types.ModuleType("idc")
    idc.get_type = lambda ea: "int __cdecl f(int)"
    sys.modules["idc"] = idc
    compat = _load_compat()
    assert compat.get_prototype_string(0x401500) == "int __cdecl f(int)"

    # idc.get_type raises -> ida_nalt.get_tinfo fallback.
    def _raising_get_type(ea):
        raise RuntimeError("no declaration")

    idc.get_type = _raising_get_type
    nalt = types.ModuleType("ida_nalt")
    typeinf = types.ModuleType("ida_typeinf")

    class _tinfo:
        def __str__(self):
            return "int f(void)"

    typeinf.tinfo_t = _tinfo
    nalt.get_tinfo = lambda tif, ea: True
    sys.modules["ida_nalt"] = nalt
    sys.modules["ida_typeinf"] = typeinf
    assert compat.get_prototype_string(0x401500) == "int f(void)"

    sys.modules.pop("idc", None)
    sys.modules.pop("ida_nalt", None)
    sys.modules.pop("ida_typeinf", None)


def test_get_prototype_string_93_prefers_func_t_method():
    _install_ida_stubs(ea_api=False)
    funcs = sys.modules["ida_funcs"]
    orig_get_func = funcs.get_func

    class _Proto:
        def __str__(self):
            return "int __cdecl f(int)"

    def _get_func_with_proto(ea):
        pfn = orig_get_func(ea)
        if pfn is not None:
            pfn.get_prototype = _Proto
        return pfn

    funcs.get_func = _get_func_with_proto
    compat = _load_compat()
    assert compat.get_prototype_string(0x401500) == "int __cdecl f(int)"
    assert compat.get_prototype_string(0x9999) is None


# ---------------------------------------------------------------------------
# segment mutation (set_segment_attr / add_segment) + comb/color accessors


def test_segment_comb_color_accessors_on_both_surfaces():
    for ea_api in (True, False):
        _install_ida_stubs(ea_api=ea_api)
        compat = _load_compat()
        assert compat.get_segment_comb(0x500000) == 7
        assert compat.get_segment_color(0x500000) == 0x112233
        assert compat.get_segment_comb(0x9999) is None
        assert compat.get_segment_color(0x9999) is None


def test_set_segment_attr_on_94_surface():
    _install_ida_stubs(ea_api=True)
    segment = sys.modules["ida_segment"]
    committed = []

    class _SI:
        def __init__(self):
            self.perm = 1

        def set_perm(self, v):
            self.perm = v

    def _get_segment_info(out, ea, flags=0):
        if ea != 0x500000:
            return False
        out.start_ea = 0x500000
        out.set_perm = lambda v: setattr(out, "perm", v)
        return True

    segment.segment_info_t = _SI
    segment.get_segment_info = _get_segment_info

    def _set_segment_info(si, flags=0):
        committed.append(si.perm)
        return True

    segment.set_segment_info = _set_segment_info
    compat = _load_compat()

    assert compat.set_segment_attr(0x500000, "perm", 7) is True
    assert committed == [7]
    # Unknown attribute (no set_bogus on segment_info_t) -> None.
    assert compat.set_segment_attr(0x500000, "bogus", 1) is None
    # No segment at the EA -> False.
    assert compat.set_segment_attr(0x9999, "perm", 1) is False


def test_set_segment_attr_on_93_surface():
    _install_ida_stubs(ea_api=False)
    segment = sys.modules["ida_segment"]
    committed = []

    def _update_segm(seg):
        committed.append(seg.perm)
        return True

    segment.update_segm = _update_segm
    compat = _load_compat()

    assert compat.set_segment_attr(0x500000, "perm", 7) is True
    assert committed == [7]
    assert compat.set_segment_attr(0x500000, "bogus", 1) is None
    assert compat.set_segment_attr(0x9999, "perm", 1) is False


def test_add_segment_on_94_surface():
    _install_ida_stubs(ea_api=True)
    segment = sys.modules["ida_segment"]
    added = []

    class _SI:
        def __init__(self):
            self.start_ea = None
            self.end_ea = None
            self.fields = {}

        def set_name(self, v):
            self.fields["name"] = v

        def set_sclass(self, v):
            self.fields["sclass"] = v

        def set_perm(self, v):
            self.fields["perm"] = v

    segment.segment_info_t = _SI

    def _add_segment_ex(si, flags):
        added.append((si.start_ea, si.end_ea, dict(si.fields), flags))
        return True

    segment.add_segment_ex = _add_segment_ex
    compat = _load_compat()

    assert compat.add_segment(0x600000, 0x601000, "carve", "CODE", 5) is True
    assert added == [
        (0x600000, 0x601000, {"name": "carve", "sclass": "CODE", "perm": 5}, 0)
    ]


def test_add_segment_on_93_surface():
    _install_ida_stubs(ea_api=False)
    idaapi = types.ModuleType("idaapi")
    added = []

    class _SegT:
        pass

    def _add_segm_ex(seg, name, sclass, flags):
        added.append((seg.start_ea, seg.end_ea, seg.perm, name, sclass, flags))
        return 1

    idaapi.segment_t = _SegT
    idaapi.add_segm_ex = _add_segm_ex
    sys.modules["idaapi"] = idaapi
    compat = _load_compat()

    assert compat.add_segment(0x600000, 0x601000, "carve", "CODE", 5) is True
    assert added == [(0x600000, 0x601000, 5, "carve", "CODE", 0)]

    sys.modules.pop("idaapi", None)
