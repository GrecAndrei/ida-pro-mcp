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
