"""IDA 9.4 compatibility shims.

IDA 9.4 deprecates ~118 pointer-based IDAPython APIs in favor of EA-based
variants that avoid returning IDA-allocated pointers (e.g. ``get_func`` ->
``get_func_start`` / ``get_func_entry_info``, ``decompile_func`` ->
``decompile_function``, ``getseg`` -> ``get_segment_info``).

The deprecated names still work on 9.4 — each emits at most one
DeprecationWarning per process via ``ida_idaapi._ida_deprecated`` — and the
EA-based replacements do not exist on IDA <= 9.3. Since the installer lets
the user pick any detected install (floor: IDA 9.2), every wrapper here
feature-detects once at import time and keeps both code paths alive. When
the supported floor rises to 9.4, this module collapses to direct calls and
can be deleted.

Feature detection (``hasattr``) is used instead of comparing kernel
versions so point releases and backports self-classify; precedent:
``hasattr(ida_search, "find_binary")`` in tools/search/basic.py.

Tracking doc with the full migration inventory:
docs/research/ida-9.4-migration.md
"""

from __future__ import annotations

import sys

import ida_funcs
import ida_hexrays
import ida_segment

# --- capability flags (computed once at import) ----------------------------

#: EA-based function APIs: get_func_start / get_func_entry_info /
#: get_prev_function_addr / get_next_function_addr / lock_func_ea ... (9.4+)
HAS_EA_FUNCS = hasattr(ida_funcs, "get_func_start")

#: EA-based decompiler entry point: decompile_function(func_ea, hf, flags)
#: replacing decompile_func. (9.4+)
HAS_EA_DECOMPILE = hasattr(ida_hexrays, "decompile_function")

#: EA-based segment APIs: get_segment_info / get_first_segment_ea / ... (9.4+)
HAS_EA_SEGMENT = hasattr(ida_segment, "get_segment_info")

#: Hex-Rays is importable and minimally usable (failure object + some
#: decompile entry point). Used as the "decompiler available" gate.
HAS_DECOMPILER = hasattr(ida_hexrays, "hexrays_failure_t") and (
    HAS_EA_DECOMPILE or hasattr(ida_hexrays, "decompile_func")
)


# --- decompiler ------------------------------------------------------------

def decompile_function(func_ea, hf, flags: int = 0):
    """Decompile ``func_ea`` across IDA <= 9.3 and 9.4+.

    Both underlying entry points take ``(ea, hexrays_failure_t, flags)`` and
    return a ``cfunc_t`` (or ``cfuncptr_t`` that dereferences to one), or
    ``None`` on failure. The 9.4 variant avoids allocating a ``func_t *``
    just to locate the function.
    """
    if HAS_EA_DECOMPILE:
        return ida_hexrays.decompile_function(func_ea, hf, flags)
    return ida_hexrays.decompile_func(func_ea, hf, flags)


# --- segments --------------------------------------------------------------

def _ida_segment():
    """Resolve the live ``ida_segment`` module at call time.

    The import-time global is correct inside a single IDA process, but the
    host test harness swaps ``sys.modules["ida_segment"]`` per test while this
    module can stay cached (e.g. when imported during test collection). Going
    through ``sys.modules`` keeps the legacy fallbacks duck-typed against
    whichever ``ida_segment`` surface is actually live.
    """
    return sys.modules.get("ida_segment") or ida_segment


def get_segment(ea):
    """Return the segment containing ``ea`` (or None when unmapped).

    On 9.4+ this fills a fresh ``segment_info_t`` through the EA-based
    ``get_segment_info`` (no IDA-allocated pointer); on <= 9.3 it returns
    ``getseg``'s ``segment_t``. Callers rely on None-on-miss — both paths
    preserve it exactly.
    """
    if HAS_EA_SEGMENT:
        seg = _ida_segment()
        si = seg.segment_info_t()
        if seg.get_segment_info(si, ea):
            return si
        return None
    return _ida_segment().getseg(ea)


def get_segment_name(ea, flags: int = 0):
    """Get the name of the segment containing ``ea``."""
    if HAS_EA_SEGMENT:
        return _ida_segment().get_segment_name(ea, flags)
    return _ida_segment().get_segm_name(_ida_segment().getseg(ea), flags)


def get_segment_class(ea):
    """Get the class of the segment containing ``ea`` (or None)."""
    if HAS_EA_SEGMENT:
        return _ida_segment().get_segment_class(ea)
    return _ida_segment().get_segm_class(_ida_segment().getseg(ea))


def set_segment_name(ea, name, flags: int = 0):
    """Rename the segment containing ``ea``; nonzero return means success."""
    if HAS_EA_SEGMENT:
        return _ida_segment().set_segment_name(ea, name, flags)
    return _ida_segment().set_segm_name(_ida_segment().getseg(ea), name, flags)


def move_segment(ea, to, flags: int = 0):
    """Move the segment containing ``ea`` so it starts at ``to``."""
    if HAS_EA_SEGMENT:
        return _ida_segment().move_segment(ea, to, flags)
    return _ida_segment().move_segm(_ida_segment().getseg(ea), to, flags)


def get_segment_ea_by_name(name):
    """Get the start EA of the segment named ``name`` (or None if absent).

    The 9.4 replacement for the deprecated ``get_segm_by_name`` is the
    EA-returning ``get_segment_ea_by_name`` (BADADDR on miss); we normalize
    that back to None to match the legacy pointer contract.
    """
    if HAS_EA_SEGMENT:
        seg = _ida_segment()
        ea = seg.get_segment_ea_by_name(name)
        badaddr = seg.ida_idaapi.BADADDR
        return None if ea == badaddr else ea
    seg = _ida_segment().get_segm_by_name(name)
    return seg.start_ea if seg else None


def get_first_segment_ea():
    """Start EA of the first segment, or None when the IDB has none.

    Normalizes the 9.4 ``get_first_segment_ea`` BADADDR-on-miss contract to
    None; on <= 9.3 falls back to ``get_first_seg``'s ``segment_t``.
    """
    seg = _ida_segment()
    if HAS_EA_SEGMENT:
        ea = seg.get_first_segment_ea()
        return None if ea == seg.ida_idaapi.BADADDR else ea
    s = seg.get_first_seg()
    return s.start_ea if s else None


def get_next_segment_ea(ea):
    """Start EA of the segment after the one containing ``ea``, or None.

    Same BADADDR→None normalization as :func:`get_first_segment_ea`.
    """
    seg = _ida_segment()
    if HAS_EA_SEGMENT:
        nxt = seg.get_next_segment_ea(ea)
        return None if nxt == seg.ida_idaapi.BADADDR else nxt
    s = seg.get_next_seg(ea)
    return s.start_ea if s else None


def _segment_attr(ea, ea_getter, legacy_attr):
    """Shared body for the segment-attribute accessors below.

    9.4's ``segment_info_t`` exposes ``perm``/``type``/``align``/``bitness``
    only via ``get_*()`` methods, while the legacy ``segment_t`` carries them
    as plain attributes. Both paths return None when ``ea`` is unmapped.
    """
    seg = _ida_segment()
    if HAS_EA_SEGMENT:
        si = seg.segment_info_t()
        if not seg.get_segment_info(si, ea):
            return None
        return getattr(si, ea_getter)()
    s = seg.getseg(ea)
    return getattr(s, legacy_attr) if s else None


def get_segment_perm(ea):
    """Permission bits of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_perm", "perm")


def get_segment_type(ea):
    """Segment type of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_type", "type")


def get_segment_align(ea):
    """Alignment code of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_align", "align")


def get_segment_bitness(ea):
    """Bitness code of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_bitness", "bitness")


def get_segment_comb(ea):
    """Combination flags of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_comb", "comb")


def get_segment_color(ea):
    """Display color of the segment containing ``ea`` (or None)."""
    return _segment_attr(ea, "get_color", "color")


def set_segment_attr(ea, attr, int_val):
    """Set a numeric segment attribute; True/False success, None if unknown.

    Replaces the deprecated ``setattr(getseg(ea), attr, v); update_segm(seg)``
    mutation pair. On 9.4 the change is staged on a ``segment_info_t`` via
    its ``set_<attr>`` method and committed with ``set_segment_info``; on
    <= 9.3 the ``segment_t`` is mutated and committed with ``update_segm``
    (which is not deprecated). Returns None when the attribute has no setter
    on the active surface (the caller reports "no such attribute").
    """
    segmod = _ida_segment()
    if HAS_EA_SEGMENT:
        si = segmod.segment_info_t()
        if not segmod.get_segment_info(si, ea):
            return False
        setter = getattr(si, f"set_{attr}", None)
        if setter is None:
            return None
        try:
            setter(int_val)
        except Exception:
            return None
        return bool(segmod.set_segment_info(si))
    seg = segmod.getseg(ea)
    if seg is None:
        return False
    if not hasattr(seg, attr):
        return None
    setattr(seg, attr, int_val)
    return bool(segmod.update_segm(seg))


def add_segment(start_ea, end_ea, name, sclass, perm):
    """Add a segment over ``[start_ea, end_ea)``; bool success.

    9.4 replacement for ``add_segm_ex(segment_t, name, sclass, flags)``:
    stages a ``segment_info_t`` (bounds as plain ``range_t`` members, the
    rest via setters) and commits via ``add_segment_ex``. Only the fields
    the tools layer sets (bounds, name, class, permissions) are staged.
    The legacy path keeps the ``idaapi`` namespace so existing fixtures and
    minimal builds resolve ``segment_t``/``add_segm_ex`` the same way the
    call sites did.
    """
    if HAS_EA_SEGMENT:
        segmod = _ida_segment()
        si = segmod.segment_info_t()
        si.start_ea = start_ea
        si.end_ea = end_ea
        si.set_name(name or "")
        si.set_sclass(sclass or "")
        si.set_perm(perm)
        return bool(segmod.add_segment_ex(si, 0))
    idaapi = _resolve_module("idaapi")
    if idaapi is None:
        return False
    seg = idaapi.segment_t()
    seg.start_ea, seg.end_ea = start_ea, end_ea
    seg.perm = perm
    return bool(idaapi.add_segm_ex(seg, name or "", sclass, 0))


# --- functions ---------------------------------------------------------------

def _ida_funcs():
    """Resolve the live ``ida_funcs`` module at call time.

    Same rationale as :func:`_ida_segment`: the host test harness swaps
    ``sys.modules["ida_funcs"]`` per test while this module can stay cached.
    """
    return sys.modules.get("ida_funcs") or ida_funcs


def get_func_start(ea):
    """Start EA of the function containing ``ea``, or None.

    Replaces the overwhelmingly common ``pfn = get_func(ea); pfn.start_ea``
    pattern. Normalizes the 9.4 ``get_func_start`` BADADDR-on-miss contract
    to the legacy ``get_func`` None-on-miss contract.
    """
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        start = funcs.get_func_start(ea)
        return None if start == funcs.ida_idaapi.BADADDR else start
    pfn = funcs.get_func(ea)
    return pfn.start_ea if pfn else None


def get_func_info(ea):
    """Function descriptor for the function containing ``ea``, or None.

    Returns a ``func_entry_info_t`` on 9.4+ (filled through the out-param
    ``get_func_entry_info``) and the legacy ``func_t`` on <= 9.3. Only
    ``.start_ea``/``.end_ea`` are guaranteed on both surfaces — use
    :func:`get_func_flags` for flags.
    """
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        fi = funcs.func_entry_info_t()
        return fi if funcs.get_func_entry_info(fi, ea) else None
    return funcs.get_func(ea)


def get_func_flags(ea):
    """Flags of the function containing ``ea``, or None when none exists."""
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        if funcs.get_func_start(ea) == funcs.ida_idaapi.BADADDR:
            return None
        return funcs.get_func_flags(ea)
    pfn = funcs.get_func(ea)
    return pfn.flags if pfn else None


def set_func_flags(ea, flags):
    """Set the flags of the function containing ``ea``; bool success.

    This is the EA-based replacement for the deprecated
    ``pfn.flags = v; update_func(pfn)`` pair: on 9.4+ it is the direct
    ``set_func_flags`` call, on <= 9.3 it mutates the ``func_t`` and commits
    with ``update_func``.
    """
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        return funcs.set_func_flags(ea, flags)
    pfn = funcs.get_func(ea)
    if not pfn:
        return False
    pfn.flags = flags
    return funcs.update_func(pfn)


def get_prev_func_start(ea):
    """Start EA of the last function starting before ``ea``, or None.

    Same BADADDR→None normalization as :func:`get_func_start`.
    """
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        start = funcs.get_prev_func_ea(ea)
        return None if start == funcs.ida_idaapi.BADADDR else start
    pfn = funcs.get_prev_func(ea)
    return pfn.start_ea if pfn else None


def get_next_func_start(ea):
    """Start EA of the first function starting after ``ea``, or None."""
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        start = funcs.get_next_func_ea(ea)
        return None if start == funcs.ida_idaapi.BADADDR else start
    pfn = funcs.get_next_func(ea)
    return pfn.start_ea if pfn else None


# --- flow charts / frames / thunks / prototypes ------------------------------

def _resolve_module(name):
    """Resolve a module at call time without growing import-time surface.

    Host-side tests fake individual ``ida_*`` modules in ``sys.modules``;
    importing them here at module top would force every fixture to provide
    every module. Falling back to a real import keeps IDA-runtime behavior
    when the module simply has not been imported yet.
    """
    mod = sys.modules.get(name)
    if mod is None:
        try:
            mod = __import__(name)
        except ImportError:
            mod = None
    return mod


class _RangeLike:
    """Duck-typed ``ea_range_t`` stand-in for minimal IDA builds / test fakes."""

    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea


def get_flow_chart(ea, flags: int = 0):
    """``ida_gdl.FlowChart`` over the function containing ``ea``, or None.

    ``FlowChart`` itself is not deprecated in 9.4, but its canonical input
    (a ``func_t *`` from ``get_func``) is unobtainable there. IDA accepts a
    range in place of the function pointer on every supported version
    (precedent: ``tools/graph.py::_build_range_chart``), so this wrapper
    resolves the function bounds and constructs the chart from a range.
    Returns None when no function contains ``ea``.
    """
    ida_gdl = _resolve_module("ida_gdl")
    idaapi = _resolve_module("idaapi")
    flow = getattr(ida_gdl, "FlowChart", None) if ida_gdl is not None else None
    if flow is None:
        # ``idaapi.FlowChart`` is the same class re-exported; some minimal
        # builds (and test fakes) only provide it there.
        flow = getattr(idaapi, "FlowChart", None) if idaapi is not None else None
    if flow is None:
        return None
    info = get_func_info(ea)
    if info is None:
        return None
    rng_cls = getattr(idaapi, "ea_range_t", None)
    rng = (
        rng_cls(info.start_ea, info.end_ea)
        if rng_cls is not None
        else _RangeLike(info.start_ea, info.end_ea)
    )
    # ``flags`` is only passed when set so narrow fakes/lambdas taking a
    # single positional argument keep working (``flags=0`` is the default
    # on every real FlowChart anyway).
    if flags:
        return flow(rng, flags=flags)
    return flow(rng)


def calc_thunk_target(ea):
    """Target EA of the thunk function containing ``ea``, or ``BADADDR``.

    Same contract as the deprecated ``calc_thunk_func_target`` (BADADDR when
    there is no function or it is not a thunk). 9.4 replaces it with
    ``calc_thunk_function_target``, which consumes the ``func_entry_info_t``
    filled by ``get_func_entry_info``.
    """
    funcs = _ida_funcs()
    ida_idaapi = _resolve_module("ida_idaapi")
    badaddr = (
        ida_idaapi.BADADDR if ida_idaapi is not None else funcs.ida_idaapi.BADADDR
    )
    if HAS_EA_FUNCS:
        fi = funcs.func_entry_info_t()
        if not funcs.get_func_entry_info(fi, ea):
            return badaddr
        return funcs.calc_thunk_function_target(fi)
    pfn = funcs.get_func(ea)
    if not pfn:
        return badaddr
    return funcs.calc_thunk_func_target(pfn)


def get_frame_id(ea):
    """Netnode id of the stack-frame structure of ``ea``'s function, or None.

    Replaces the deprecated ``ida_frame.get_frame(pfn)`` /
    ``pfn.frame`` attribute read with the 9.4
    ``func_entry_info_t.get_frame_id()``.
    """
    funcs = _ida_funcs()
    if HAS_EA_FUNCS:
        fi = funcs.func_entry_info_t()
        if not funcs.get_func_entry_info(fi, ea):
            return None
        return fi.get_frame_id()
    pfn = funcs.get_func(ea)
    return pfn.frame if pfn else None


def get_spd(func_ea, ea):
    """Stack-pointer delta at ``ea`` within the function at ``func_ea``.

    9.4 replaces the deprecated ``ida_frame.get_spd(pfn, ea)`` with the
    EA-based ``ida_frame.get_func_spd(func_ea, ea)``. Returns 0 when the
    function does not exist (the legacy ``pfn=None`` case is UB upstream).
    """
    ida_frame = _resolve_module("ida_frame")
    if ida_frame is None:
        return 0
    get_func_spd = getattr(ida_frame, "get_func_spd", None)
    if get_func_spd is not None:
        return get_func_spd(func_ea, ea)
    pfn = _ida_funcs().get_func(func_ea)
    if not pfn:
        return 0
    return ida_frame.get_spd(pfn, ea)


def _legacy_frame_struc(func_ea):
    """The ``struc_t`` stack frame of ``func_ea``'s function, or None.

    Only meaningful on <= 9.3 — 9.4 removed ``ida_frame.get_frame`` outright
    and with it the ``ida_struct`` module. Mirrors the pre-9.4 resolution
    chain used by the legacy stack-analysis helper: ``ida_frame.get_frame``
    first, then ``idc.get_frame_id`` + ``ida_struct.get_struc``.
    """
    ida_frame = _resolve_module("ida_frame")
    if ida_frame is not None:
        get_frame = getattr(ida_frame, "get_frame", None)
        if callable(get_frame):
            try:
                func = get_func_info(func_ea)
                if func is not None:
                    frame = get_frame(func)
                    if frame is not None:
                        return frame
            except Exception:
                pass
    # ``ida_funcs.get_frame`` is the same struc_t frame reachable through the
    # funcs module (legacy callers used both spellings).
    ida_funcs_mod = _resolve_module("ida_funcs")
    if ida_funcs_mod is not None:
        get_frame = getattr(ida_funcs_mod, "get_frame", None)
        if callable(get_frame):
            try:
                func = get_func_info(func_ea)
                if func is not None:
                    frame = get_frame(func)
                    if frame is not None:
                        return frame
            except Exception:
                pass
    ida_struct = _resolve_module("ida_struct")
    idc = _resolve_module("idc")
    if ida_struct is not None and idc is not None:
        try:
            get_frame_id = getattr(idc, "get_frame_id", None)
            if get_frame_id is None:
                return None
            sid = get_frame_id(func_ea)
            if sid is None:
                return None
            ida_idaapi = _resolve_module("ida_idaapi")
            badaddr = (
                getattr(ida_idaapi, "BADADDR", None)
                if ida_idaapi is not None else None
            )
            if sid not in (badaddr, -1):
                struc = ida_struct.get_struc(sid)
                if struc is not None:
                    return struc
        except Exception:
            pass
    return None


def _legacy_frame_members(func_ea):
    """struc_t-based member walk matching the pre-9.4 callers.

    Iterates ``frame.members`` (the authoritative struc_t iteration —
    ``get_member`` takes a byte offset, so index loops only reach members
    at offsets 0..N). Name resolution mirrors both legacy call sites:
    ``ida_frame.get_member_name`` first, then ``ida_struct.get_member_name``
    (code_helpers' source), then ``idc.get_member_name``; sizes come from
    ``ida_struct.get_member_size``, then ``member.size``, then
    ``eoff - soff``; types from ``ida_frame.get_member_tinfo``.
    """
    frame = _legacy_frame_struc(func_ea)
    if frame is None:
        return []
    ida_frame = _resolve_module("ida_frame")
    ida_struct = _resolve_module("ida_struct")
    ida_typeinf = _resolve_module("ida_typeinf")
    members = []
    # struc_t.members is the canonical member list; index-based
    # get_member() fallback keeps minimal fakes working.
    frame_member_list = getattr(frame, "members", None) or []
    get_member = getattr(frame, "get_member", None)
    idx = 0
    for i in range(int(getattr(frame, "memqty", 0) or 0)):
        if i < len(frame_member_list):
            member = frame_member_list[i]
        elif callable(get_member):
            try:
                member = get_member(i)
            except Exception:
                member = None
        else:
            member = None
        if not member:
            continue
        # name: ida_frame.get_member_name(member.id), then
        # ida_struct.get_member_name(member.id), then
        # idc.get_member_name(frame.id, member.soff), then var_<i>
        name = None
        for mod_name, fn_name in (
            ("ida_frame", "get_member_name"),
            ("ida_struct", "get_member_name"),
            ("idc", "get_member_name"),
        ):
            mod = _resolve_module(mod_name)
            fn = getattr(mod, fn_name, None) if mod is not None else None
            if fn is None:
                continue
            try:
                if mod_name == "idc":
                    name = fn(frame.id, member.soff)
                else:
                    name = fn(member.id)
            except Exception:
                name = None
            if name:
                break
        name = name or f"var_{i}"
        soff = int(getattr(member, "soff", 0) or 0)
        eoff = int(getattr(member, "eoff", soff) or soff)
        # size: ida_struct.get_member_size(member), then member.size,
        # then member.eoff - member.soff
        msize = None
        if ida_struct is not None and hasattr(ida_struct, "get_member_size"):
            try:
                msize = int(ida_struct.get_member_size(member) or 0)
            except Exception:
                msize = None
        if not msize:
            msize = int(getattr(member, "size", 0) or 0)
        if not msize:
            msize = max(0, eoff - soff)
        # type: ida_frame.get_member_tinfo(tif, member) -> str(tif)
        type_str = ""
        if ida_frame is not None and ida_typeinf is not None:
            get_member_tinfo = getattr(ida_frame, "get_member_tinfo", None)
            if get_member_tinfo is not None:
                try:
                    tif = ida_typeinf.tinfo_t()
                    if get_member_tinfo(tif, member):
                        type_str = str(tif)
                except Exception:
                    type_str = ""
        members.append((idx, name, soff, msize, type_str))
        idx += 1
    return members


def _udt_frame_members(udt):
    """Convert a bit-addressed ``udt_type_data_t`` to byte-normalized
    ``(index, name, offset, size, type_str)`` members; gaps are skipped."""
    members = []
    idx = 0
    for udm in udt:
        try:
            if udm.is_gap():
                continue
        except Exception:
            pass
        name = getattr(udm, "name", "") or ""
        if not name:
            name = f"var_{idx}"
        t = getattr(udm, "type", None)
        members.append((
            idx,
            name,
            int(getattr(udm, "offset", 0) or 0) // 8,
            int(getattr(udm, "size", 0) or 0) // 8,
            str(t) if t is not None else "",
        ))
        idx += 1
    return members


def frame_members(func_ea):
    """``(index, name, offset, size, type_str)`` for every real stack-frame
    member of ``func_ea``'s function (byte offsets/sizes), or ``[]`` when
    there is no frame.

    On 9.4+ the frame is a ``tinfo_t``: ``ida_frame.get_func_frame_ea``
    fills it and the ``udt_type_data_t`` walk yields members (gaps
    skipped). On <= 9.3 the legacy ``struc_t`` walk runs unchanged, so
    callers see byte-identical output to the old
    ``ida_frame.get_frame``-based iteration.
    """
    ida_frame = _resolve_module("ida_frame")
    get_func_frame_ea = (
        getattr(ida_frame, "get_func_frame_ea", None)
        if ida_frame is not None else None
    )
    if get_func_frame_ea is not None:
        ida_typeinf = _resolve_module("ida_typeinf")
        if ida_typeinf is not None:
            try:
                tif = ida_typeinf.tinfo_t()
                if get_func_frame_ea(tif, func_ea):
                    udt = ida_typeinf.udt_type_data_t()
                    tif.get_udt_details(udt)
                    return _udt_frame_members(udt)
                return []
            except Exception:
                return []
    return _legacy_frame_members(func_ea)


def frame_size(func_ea):
    """Byte size of the stack frame of ``func_ea``'s function, or 0.

    9.4+ uses the EA-based ``ida_frame.get_frame_size_ea``; <= 9.3 mirrors
    the legacy computation chain (``ida_struct.get_struc_size``, then
    ``ida_frame.get_struc_size``, then the max member end offset).
    """
    ida_frame = _resolve_module("ida_frame")
    if ida_frame is not None:
        get_size_ea = getattr(ida_frame, "get_frame_size_ea", None)
        if get_size_ea is not None:
            try:
                return int(get_size_ea(func_ea))
            except Exception:
                return 0
    frame = _legacy_frame_struc(func_ea)
    if frame is None:
        return 0
    ida_struct = _resolve_module("ida_struct")
    if ida_struct is not None and hasattr(ida_struct, "get_struc_size"):
        try:
            return int(ida_struct.get_struc_size(frame))
        except Exception:
            pass
    getter = (
        getattr(ida_frame, "get_struc_size", None)
        if ida_frame is not None else None
    )
    if callable(getter):
        try:
            return int(getter(frame))
        except Exception:
            pass
    max_eoff = 0
    for i in range(int(getattr(frame, "memqty", 0) or 0)):
        try:
            member = frame.get_member(i)
            if member and hasattr(member, "eoff"):
                max_eoff = max(max_eoff, int(member.eoff))
        except Exception:
            pass
    return max_eoff


def get_prototype_string(ea):
    """Best-effort prototype string for the function at ``ea``, or None.

    Mirrors ``ida_mcp.utils.get_prototype`` without needing a ``func_t *``:
    on <= 9.3 the primary ``func_t.get_prototype()`` path runs first
    (identical output to the legacy helper), then the EA-based
    ``idc.get_type`` fallback, then ``ida_nalt.get_tinfo`` on error. On 9.4
    the EA-based fallbacks are the only path. Kept here rather than in
    utils because utils imports this module (no circular import).
    """
    funcs = _ida_funcs()
    if not HAS_EA_FUNCS:
        pfn = funcs.get_func(ea)
        if pfn is None:
            return None
        try:
            proto = pfn.get_prototype()
            if proto is not None:
                return str(proto)
            return None
        except AttributeError:
            pass
        except Exception:
            return None
    idc_mod = _resolve_module("idc")
    if idc_mod is not None:
        try:
            return idc_mod.get_type(ea)
        except Exception:
            pass
    ida_nalt = _resolve_module("ida_nalt")
    ida_typeinf = _resolve_module("ida_typeinf")
    if ida_nalt is not None and ida_typeinf is not None:
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, ea):
                return str(tif)
        except Exception:
            pass
    return None
