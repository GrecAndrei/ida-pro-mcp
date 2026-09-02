"""Boundary coverage for the IDA-version compatibility shims.

These tests model incomplete SDK surfaces rather than asserting implementation
details.  The real compatibility contract is that supported callers get the
same normalized result when an EA-based API, a legacy pointer API, or a
partially populated minimal build is active.
"""

from __future__ import annotations

import sys
import types

from tests.ida_mcp.test_compat import (
    _install_frame_stubs,
    _install_ida_stubs,
    _load_compat,
)


def test_segment_mutation_reports_setter_and_loader_failures(monkeypatch):
    _install_ida_stubs(ea_api=True)
    segment = sys.modules["ida_segment"]

    class SegmentInfo:
        def set_perm(self, _value):
            raise RuntimeError("minimal SDK rejected setter")

    segment.segment_info_t = SegmentInfo
    segment.get_segment_info = lambda _out, _ea: True
    segment.set_segment_info = lambda _out: False
    compat = _load_compat()

    assert compat.set_segment_attr(0x500000, "perm", 7) is None

    class SegmentInfoOk:
        def set_perm(self, value):
            self.perm = value

    segment.segment_info_t = SegmentInfoOk
    assert compat.set_segment_attr(0x500000, "perm", 7) is False

    _install_ida_stubs(ea_api=False)
    monkeypatch.delitem(sys.modules, "idaapi", raising=False)
    compat = _load_compat()
    assert compat.add_segment(0x600000, 0x601000, "x", "CODE", 5) is False


def test_flow_chart_uses_flags_and_idaapi_fallback(monkeypatch):
    _install_ida_stubs(ea_api=True)
    monkeypatch.setattr(
        sys.modules["ida_funcs"],
        "get_func_entry_info",
        lambda out, _ea: (setattr(out, "start_ea", 0x401000) or setattr(out, "end_ea", 0x402000) or True),
    )
    gdl = types.ModuleType("ida_gdl")
    idaapi = types.ModuleType("idaapi")
    calls = []

    class FlowChart:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))

    idaapi.FlowChart = FlowChart
    sys.modules["ida_gdl"] = gdl
    sys.modules["idaapi"] = idaapi
    compat = _load_compat()

    compat.get_flow_chart(0x401500, flags=3)
    assert len(calls) == 1
    assert calls[0][1] == {"flags": 3}
    assert calls[0][0][0].start_ea == 0x401000


def test_flow_chart_reaches_pythonized_and_legacy_constructor_forms(monkeypatch):
    _install_ida_stubs(ea_api=True)
    funcs = sys.modules["ida_funcs"]
    funcs.get_func = lambda _ea: types.SimpleNamespace(start_ea=0x401000)
    funcs.get_func_entry_info = lambda out, _ea: (
        setattr(out, "start_ea", 0x401000) or setattr(out, "end_ea", 0x402000) or True
    )
    monkeypatch.delitem(sys.modules, "idaapi", raising=False)
    gdl = types.ModuleType("ida_gdl")
    calls = []

    class PythonizedFlow:
        def __init__(self, *args):
            if len(args) == 1:
                raise TypeError("range form unavailable")
            calls.append(args)

    gdl.FlowChart = PythonizedFlow
    sys.modules["ida_gdl"] = gdl
    compat = _load_compat()
    compat.get_flow_chart(0x401500, flags=4)
    assert calls == [(None, (0x401000, 0x402000), 4)]

    calls.clear()

    class LegacyFlow:
        def __init__(self, *args):
            if len(args) != 5:
                raise TypeError("legacy form required")
            calls.append(args)

    gdl.FlowChart = LegacyFlow
    compat = _load_compat()
    compat.get_flow_chart(0x401500)
    assert calls == [("", funcs.get_func(0x401500), 0x401000, 0x402000, 0)]


def test_flow_chart_returns_none_when_all_forms_fail_or_function_lookup_raises(
    monkeypatch,
):
    _install_ida_stubs(ea_api=True)
    funcs = sys.modules["ida_funcs"]
    funcs.get_func_entry_info = lambda out, _ea: (
        setattr(out, "start_ea", 0x401000) or setattr(out, "end_ea", 0x402000) or True
    )
    funcs.get_func = lambda _ea: (_ for _ in ()).throw(TypeError("lookup failed"))
    monkeypatch.delitem(sys.modules, "idaapi", raising=False)
    gdl = types.ModuleType("ida_gdl")

    class NeverFlow:
        def __init__(self, *_args, **_kwargs):
            raise ValueError("unsupported constructor")

    gdl.FlowChart = NeverFlow
    sys.modules["ida_gdl"] = gdl
    compat = _load_compat()
    assert compat.get_flow_chart(0x401500) is None

    gdl.FlowChart = None
    assert compat.get_flow_chart(0x401500) is None


def test_legacy_frame_resolution_tries_funcs_and_struct_tiers(monkeypatch):
    _install_ida_stubs(ea_api=False)
    frame = types.ModuleType("ida_frame")
    expected = object()
    frame.get_frame = lambda _func: (_ for _ in ()).throw(RuntimeError("old tier"))
    sys.modules["ida_frame"] = frame
    funcs = sys.modules["ida_funcs"]
    funcs.get_frame = lambda _func: expected
    compat = _load_compat()
    assert compat._legacy_frame_struc(0x401500) is expected

    funcs.get_frame = lambda _func: None
    frame.get_frame = lambda _func: None
    struct = types.ModuleType("ida_struct")
    struct.get_struc = lambda sid: expected if sid == 0x222 else None
    sys.modules["ida_struct"] = struct
    idc = types.ModuleType("idc")
    idc.get_frame_id = lambda _ea: 0x222
    sys.modules["idc"] = idc
    assert compat._legacy_frame_struc(0x401500) is expected

    idc.get_frame_id = lambda _ea: None
    assert compat._legacy_frame_struc(0x401500) is None


def test_legacy_frame_members_use_duck_typed_fallbacks(monkeypatch):
    _install_ida_stubs(ea_api=False)
    frame_mod = types.ModuleType("ida_frame")
    struct_mod = types.ModuleType("ida_struct")
    idc = types.ModuleType("idc")

    class Member:
        id = 9
        soff = 0x20
        eoff = 0x28

    class Frame:
        id = 0x100
        memqty = 3
        members = []

        def get_member(self, index):
            if index == 0:
                return Member()
            if index == 1:
                raise RuntimeError("member lookup failed")
            return None

    frame = Frame()
    frame_mod.get_frame = lambda _func: frame
    frame_mod.get_member_name = lambda _member_id: (_ for _ in ()).throw(
        RuntimeError("frame name unavailable")
    )
    frame_mod.get_member_tinfo = lambda _tif, _member: (_ for _ in ()).throw(
        RuntimeError("type unavailable")
    )
    struct_mod.get_member_name = lambda _member_id: "struct_member"
    struct_mod.get_member_size = lambda _member: (_ for _ in ()).throw(
        RuntimeError("size unavailable")
    )
    struct_mod.get_struc_size = lambda _frame: 0x30
    idc.get_member_name = lambda _sid, _soff: "idc_member"
    sys.modules["ida_frame"] = frame_mod
    sys.modules["ida_struct"] = struct_mod
    sys.modules["ida_typeinf"] = types.SimpleNamespace(
        tinfo_t=type("Tinfo", (), {})
    )
    sys.modules["idc"] = idc
    compat = _load_compat()

    assert compat.frame_members(0x401500) == [
        (0, "struct_member", 0x20, 8, ""),
    ]


def test_frame_walkers_handle_partial_tinfo_and_size_apis(monkeypatch):
    _install_ida_stubs(ea_api=True)
    _install_frame_stubs(ea_api=True)
    frame = sys.modules["ida_frame"]
    typeinf = sys.modules["ida_typeinf"]

    class Udm:
        name = ""
        offset = 3
        size = 7
        type = None

        def is_gap(self):
            raise RuntimeError("gap marker absent")

    class Tif:
        def get_udt_details(self, out):
            out.append(Udm())

    typeinf.tinfo_t = Tif
    frame.get_func_frame_ea = lambda tif, _ea: True
    compat = _load_compat()
    assert compat.frame_members(0x401500) == [(0, "var_0", 0, 0, "")]


def test_frame_size_falls_back_to_member_end_offsets(monkeypatch):
    _install_ida_stubs(ea_api=False)
    frame_mod = types.ModuleType("ida_frame")
    struct_mod = types.ModuleType("ida_struct")

    class Member:
        eoff = 0x44

    class Frame:
        memqty = 2

        def get_member(self, index):
            if index == 0:
                return Member()
            raise RuntimeError("end lookup failed")

    frame = Frame()
    frame_mod.get_frame = lambda _func: frame
    frame_mod.get_struc_size = lambda _frame: (_ for _ in ()).throw(
        RuntimeError("legacy size unavailable")
    )
    struct_mod.get_struc_size = lambda _frame: (_ for _ in ()).throw(
        RuntimeError("struct size unavailable")
    )
    sys.modules["ida_frame"] = frame_mod
    sys.modules["ida_struct"] = struct_mod
    compat = _load_compat()
    assert compat.frame_size(0x401500) == 0x44


def test_prototype_fallbacks_cover_missing_and_broken_legacy_methods(monkeypatch):
    _install_ida_stubs(ea_api=False)
    funcs = sys.modules["ida_funcs"]
    pfn = types.SimpleNamespace(start_ea=0x401000, end_ea=0x402000)
    funcs.get_func = lambda _ea: pfn
    idc = types.ModuleType("idc")
    idc.get_type = lambda _ea: "int fallback(void)"
    sys.modules["idc"] = idc
    compat = _load_compat()
    assert compat.get_prototype_string(0x401500) == "int fallback(void)"

    pfn.get_prototype = lambda: (_ for _ in ()).throw(RuntimeError("broken"))
    assert compat.get_prototype_string(0x401500) is None

    _install_ida_stubs(ea_api=True)
    idc.get_type = lambda _ea: (_ for _ in ()).throw(RuntimeError("no type"))
    sys.modules["idc"] = idc
    sys.modules.pop("ida_nalt", None)
    sys.modules.pop("ida_typeinf", None)
    compat = _load_compat()
    assert compat.get_prototype_string(0x401500) is None
