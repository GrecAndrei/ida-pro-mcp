"""Synthetic IDB builder for benchmarking classifiers without a real IDA session.

Constructs an in-memory graph of functions, segments, named locations,
cross-references, strings, and import modules.  Calling :meth:`install`
patches the IDA stub modules (``idaapi``, ``idautils``, ``idc``, …) so that
any tool loaded via ``tests._isolated_repo_loader`` sees the synthetic state.

Usage::

    db = FakeIDB()
    db.add_segment(".text", 0x401000, 0x402000)
    db.add_func(0x401000, "recv_packet", callees=[0x401200])
    db.add_func(0x401200, "process", callees=[0x401300])
    db.add_func(0x401300, "copy_it", callees=["memcpy"])
    db.install()

    cb = load_tool_submodule("search.combinators")
    result = cb.search_vulnerable(...)
"""
from __future__ import annotations

import sys
import types
from typing import Any

MOCK_EXEC = 1
MOCK_FL_CN = 21
MOCK_FL_CF = 22
MOCK_FL_JF = 17
MOCK_FL_JN = 18
MOCK_BADADDR = 0xFFFFFFFF
MOCK_FUNC_LIB = 0x00000004
MOCK_FUNC_THUNK = 0x00000008


class MockXref:
    __slots__ = ("frm", "to", "type", "iscode")

    def __init__(self, frm: int = 0, to: int = 0, xtype: int = MOCK_FL_CN, iscode: bool = True):
        self.frm = frm
        self.to = to
        self.type = xtype
        self.iscode = iscode


class MockFunc:
    __slots__ = ("start_ea", "end_ea", "flags")

    def __init__(self, start_ea: int, end_ea: int, flags: int = 0):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.flags = flags


class MockSeg:
    __slots__ = ("start_ea", "end_ea", "perm", "name")

    def __init__(self, start_ea: int, end_ea: int, perm: int, name: str):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.perm = perm
        self.name = name


def _ensure_mod(name: str) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
    return mod


class FakeIDB:
    def __init__(self) -> None:
        self._funcs: dict[int, dict[str, Any]] = {}
        self._segments: list[dict[str, Any]] = []
        self._names: dict[int, str] = {}
        self._imports: list[str] = []
        self._callees: dict[int, set[int]] = {}
        self._callers: dict[int, set[int]] = {}
        self._strings: dict[int, list[str]] = {}
        self._next_import_ea = 0xF0000000
        self._import_ea: dict[str, int] = {}
        self._installed = False

    # ------------------------------------------------------------------
    # Builder
    # ------------------------------------------------------------------
    def add_segment(self, name: str, start: int, end: int, perm: int = MOCK_EXEC) -> "FakeIDB":
        self._segments.append({"name": name, "start": start, "end": end, "perm": perm})
        return self

    def add_func(
        self,
        ea: int,
        name: str,
        size: int = 0x100,
        segment: str = ".text",
        callees: list | None = None,
        flags: int = 0,
    ) -> "FakeIDB":
        self._funcs[ea] = {
            "ea": ea,
            "name": name,
            "start": ea,
            "end": ea + size,
            "segment": segment,
            "flags": flags,
        }
        self._names[ea] = name
        callees = callees or []
        cal_eas: set[int] = set()
        for cal in callees:
            if isinstance(cal, int):
                cal_eas.add(cal)
            else:
                if cal not in self._import_ea:
                    self._import_ea[cal] = self._next_import_ea
                    self._next_import_ea += 1
                imp_ea = self._import_ea[cal]
                cal_eas.add(imp_ea)
                self._names[imp_ea] = cal
        self._callees[ea] = cal_eas
        for ce in cal_eas:
            self._callers.setdefault(ce, set()).add(ea)
        return self

    def add_import(self, name: str) -> "FakeIDB":
        if name not in self._imports:
            self._imports.append(name)
        return self

    def add_string(self, func_ea: int, text: str) -> "FakeIDB":
        self._strings.setdefault(func_ea, []).append(text)
        return self

    # ------------------------------------------------------------------
    # Install / patch IDA stubs
    # ------------------------------------------------------------------
    def install(self) -> "FakeIDB":
        for name in (
            "idaapi", "idc", "idautils", "ida_funcs", "ida_segment",
            "ida_nalt", "ida_hexrays", "ida_lines", "ida_loader",
        ):
            _ensure_mod(name)

        self._patch_idaapi()
        self._patch_idc()
        self._patch_idautils()
        self._patch_ida_funcs()
        self._patch_ida_segment()
        self._patch_ida_nalt()
        self._patch_ida_hexrays()
        self._patch_common_helpers()
        self._installed = True
        return self

    def _patch_idaapi(self) -> None:
        m = sys.modules["idaapi"]
        m.BADADDR = MOCK_BADADDR
        m.SEGPERM_EXEC = MOCK_EXEC
        m.fl_CN = MOCK_FL_CN
        m.fl_CF = MOCK_FL_CF
        m.fl_JF = MOCK_FL_JF
        m.fl_JN = MOCK_FL_JN

        def _get_func(ea):
            f = self._funcs.get(ea)
            return MockFunc(f["start"], f["end"], f["flags"]) if f else None

        def _getseg(ea):
            for s in self._segments:
                if s["start"] <= ea < s["end"]:
                    return MockSeg(s["start"], s["end"], s["perm"], s["name"])
            return None

        segs_sorted = sorted(self._segments, key=lambda s: s["start"])

        def _get_next_seg(ea):
            for s in segs_sorted:
                if s["start"] > ea:
                    return MockSeg(s["start"], s["end"], s["perm"], s["name"])
            return None

        m.get_func = _get_func
        m.getseg = _getseg
        m.get_next_seg = _get_next_seg
        m.FUNC_LIB = MOCK_FUNC_LIB
        m.FUNC_THUNK = MOCK_FUNC_THUNK

    def _patch_idc(self) -> None:
        m = sys.modules["idc"]

        def _get_func_name(ea):
            if ea in self._names:
                return self._names[ea]
            fn = self._find_func_containing(ea)
            return fn["name"] if fn else ""

        def _get_name(ea, *a):
            return self._names.get(ea, "")

        def _get_str_type(ea):
            return None

        def _get_strlit_contents(ea, length, stype):
            return None

        def _get_name_ea_simple(name):
            for ea, n in self._names.items():
                if n == name:
                    return ea
            return 0xFFFFFFFF  # BADADDR

        m.get_func_name = _get_func_name
        m.get_name = _get_name
        m.get_str_type = _get_str_type
        m.get_strlit_contents = _get_strlit_contents
        m.get_name_ea_simple = _get_name_ea_simple

    def _patch_idautils(self) -> None:
        m = sys.modules["idautils"]

        m.Functions = lambda start=None, end=None: [
            ea for ea in self._funcs.keys()
            if start is None or (start <= ea < end)
        ]
        m.Segments = lambda: [s["start"] for s in self._segments]
        m.Names = lambda: iter(self._names.items())

        def _heads(start, end):
            cur = start
            while cur < end:
                yield cur
                cur += 2

        def _code_refs_from(ea, flags=0):
            """Yield raw callee EAs for the function that owns ``ea``.

            ``classify._get_func_callees`` calls ``idc.get_func_name(xref)``
            directly on each result, so we yield EAs (which ``get_func_name``
            resolves via ``_names``), not xref objects.
            """
            fn = self._find_func_containing(ea)
            if not fn:
                return
            for cal in self._callees.get(fn["ea"], set()):
                yield cal

        def _code_refs_to(ea, flags=0):
            """Yield source EAs (caller function start) — raw ints like real IDA."""
            for caller in self._callers.get(ea, set()):
                fn = self._funcs.get(caller)
                if fn:
                    yield fn["start"]

        def _xrefs_from(ea, flags=0):
            """Yield xref objects with .to (callee) — used by search_vulnerable."""
            fn = self._find_func_containing(ea)
            if not fn:
                return
            for cal in self._callees.get(fn["ea"], set()):
                yield MockXref(frm=ea, to=cal, xtype=MOCK_FL_CN)

        def _xrefs_to(ea, flags=0):
            """Yield xref objects with .frm (source) — used by classify initializers."""
            for caller in self._callers.get(ea, set()):
                fn = self._funcs.get(caller)
                if fn:
                    yield MockXref(frm=fn["start"], to=ea, xtype=MOCK_FL_CN)

        def _data_refs_from(ea, flags=0):
            fn = self._find_func_containing(ea)
            if not fn:
                return
            for s in self._strings.get(fn["ea"], ()):
                yield 0xD0000000 + hash(s) % 0x10000

        m.Heads = _heads
        m.CodeRefsFrom = _code_refs_from
        m.CodeRefsTo = _code_refs_to
        m.XrefsFrom = _xrefs_from
        m.XrefsTo = _xrefs_to
        m.DataRefsFrom = _data_refs_from

    def _patch_ida_funcs(self) -> None:
        m = sys.modules["ida_funcs"]
        m.FUNC_LIB = MOCK_FUNC_LIB
        m.FUNC_THUNK = MOCK_FUNC_THUNK

        def _get_func(ea):
            f = self._funcs.get(ea)
            return MockFunc(f["start"], f["end"], f["flags"]) if f else None

        def _get_func_name(ea):
            if ea in self._names:
                return self._names[ea]
            for fea, info in self._funcs.items():
                if info["start"] <= ea < info["end"]:
                    return info["name"]
            return ""

        m.get_func = _get_func
        m.get_func_name = _get_func_name

    def _patch_ida_segment(self) -> None:
        m = sys.modules["ida_segment"]

        def _getseg(ea):
            for s in self._segments:
                if s["start"] <= ea < s["end"]:
                    return MockSeg(s["start"], s["end"], s["perm"], s["name"])
            return None

        def _get_segm_name(seg):
            return getattr(seg, "name", "")

        m.getseg = _getseg
        m.get_segm_name = _get_segm_name

    def _patch_ida_nalt(self) -> None:
        m = sys.modules["ida_nalt"]
        m.get_import_module_qty = lambda: len(self._imports)
        m.get_import_module_name = lambda i: self._imports[i] if 0 <= i < len(self._imports) else None

    def _patch_ida_hexrays(self) -> None:
        m = sys.modules["ida_hexrays"]

        class _MockCfunc:
            pass

        def _decompile(ea):
            return _MockCfunc()

        m.decompile = _decompile

    def _patch_common_helpers(self) -> None:
        """Force package-level tools/_common to see our stub modules."""
        for name in (
            "idaapi", "idc", "idautils", "ida_funcs", "ida_segment",
            "ida_nalt", "ida_hexrays", "ida_lines",
        ):
            _ensure_mod(name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _find_func_containing(self, ea):
        for f in self._funcs.values():
            if f["start"] <= ea < f["end"]:
                return f
        return None
