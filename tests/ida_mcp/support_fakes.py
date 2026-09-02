"""Small SDK-module factory for isolated IDA-side tool tests."""

from __future__ import annotations

import types


def make_fake_ida() -> dict[str, types.ModuleType]:
    """Return independent, minimal IDA modules for loader-based tests."""
    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_inf_structure = lambda: types.SimpleNamespace(is_64bit=lambda: True)
    fake_func = types.SimpleNamespace(
        start_ea=0x401000, end_ea=0x401100, entry_ea=0x401000, flags=0, lvars=[]
    )
    idaapi.get_func = lambda _ea: fake_func

    idc = types.ModuleType("idc")
    idc.get_func_name = lambda ea: f"sub_{ea:X}"
    idc.get_name = lambda ea: f"sub_{ea:X}"
    idc.get_inf_attr = lambda _attr: 0
    idc.INF_SHORT_DN = 0
    idc.print_insn_mnem = lambda _ea: "mov"
    idc.next_head = lambda ea, _max_ea: ea + 4
    idc.get_func_cmt = lambda _ea, _repeatable: "Test function"

    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_dword = lambda _ea: 0x401000
    ida_bytes.get_qword = lambda _ea: 0x401000
    ida_bytes.get_strlit_contents = lambda _ea, _size, _stype: b".?AVMyTestClass@@"
    ida_bytes.get_flags = lambda _ea: 0x600
    ida_bytes.is_code = lambda _flags: True
    ida_bytes.is_loaded = lambda _ea: True

    def get_bytes(_ea, size):
        if size >= 16:
            return (
                b"\xf2\xff\xff\xff\x00\x00\x01\x08"
                + b"\x00" * 24
                + (0x20).to_bytes(8, "little")
                + (0x40).to_bytes(8, "little")
                + b"\x00" * max(0, size - 48)
            )[:size]
        return (0x401000).to_bytes(size, "little")

    ida_bytes.get_bytes = get_bytes

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda _ea: fake_func
    ida_funcs.get_func_name = lambda ea: f"sub_{ea:X}"
    ida_funcs.add_func = lambda _ea: True
    ida_funcs.get_func_qty = lambda: 1
    ida_funcs.get_nfn = lambda _index: fake_func

    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: True
    ida_hexrays.decompile = lambda ea: types.SimpleNamespace(
        entry_ea=ea, lvars=[], __str__=lambda self: "int sub_401000() { return 1; }"
    )

    ida_gdl = types.ModuleType("ida_gdl")
    fake_block2 = types.SimpleNamespace(start_ea=0x401050, end_ea=0x401100, succs=list)
    fake_block1 = types.SimpleNamespace(
        start_ea=0x401000, end_ea=0x401050, succs=lambda: [fake_block2]
    )
    ida_gdl.FlowChart = lambda _func: [fake_block1, fake_block2]

    ida_name = types.ModuleType("ida_name")
    ida_name.get_name = lambda ea: f"sub_{ea:X}"
    ida_name.set_name = lambda _ea, _name, _flags=0: True
    ida_name.demangle_name = lambda _name, _flags=0: "MyTestClass::Method"
    ida_name.SN_NOWARN = 0

    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_imagebase = lambda: 0x400000
    ida_nalt.STRTYPE_C = 0

    ida_segment = types.ModuleType("ida_segment")
    fake_segment = types.SimpleNamespace(start_ea=0x400000, end_ea=0x410000, perm=6)
    ida_segment.get_segm_qty = lambda: 1
    ida_segment.get_nseg = lambda _index: fake_segment
    ida_segment.getseg = lambda _ea: fake_segment
    ida_segment.add_seg = lambda *_args: True
    ida_segment.set_segm_name = lambda _segment, _name: True
    ida_segment.get_segm_name = lambda _segment: ".rdata"

    idautils = types.ModuleType("idautils")
    idautils.Chunks = lambda _ea: [0x401000]

    return {
        "idaapi": idaapi,
        "idc": idc,
        "idautils": idautils,
        "ida_bytes": ida_bytes,
        "ida_funcs": ida_funcs,
        "ida_hexrays": ida_hexrays,
        "ida_gdl": ida_gdl,
        "ida_name": ida_name,
        "ida_nalt": ida_nalt,
        "ida_segment": ida_segment,
    }
