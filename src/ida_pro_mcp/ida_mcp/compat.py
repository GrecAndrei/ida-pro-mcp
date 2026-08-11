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
