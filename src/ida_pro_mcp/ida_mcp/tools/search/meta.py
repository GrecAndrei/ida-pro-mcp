"""SEARCH.META - Type, export, and summary searches.

VOERA Architecture:
- Context Density Optimization: summary action returns compact counts only
- Structured Semantic Retrieval: type search uses semantic matching on type names
"""

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ..semantic_matching import semantic_score
except ImportError:
    from semantic_matching import semantic_score  # type: ignore[import-not-found]

from .core import (
    clip_text, paginate_records, build_response, resolve_target,
    iter_segments, iter_code, get_cached_imports, get_cached_strings,
    MAX_LIMIT, safe_generate_disasm_line,
)


def search_type(pattern, case_sensitive, offset, limit, include_items):
    """Search type library for matching type names and usages."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0

    # 1. Search type library names
    try:
        til = ida_typeinf.get_idati()
        if til:
            for idx in range(ida_typeinf.get_ordinal_qty(til)):
                if truncated:
                    break
                tif = ida_typeinf.tinfo_t()
                if tif.get_type_by_ordinal(til, idx):
                    name = tif.get_type_name()
                    if name and matcher(name):
                        matches_seen += 1
                        if matches_seen > offset:
                            size = tif.get_size()
                            size_str = f"size={size}" if size != idaapi.BADADDR else "size=?"
                            line = f"type_ordinal={idx}  {name}  {size_str}"
                            results.append(line)
                            if len(results) >= limit:
                                truncated = True
                                break
    except Exception:
        pass

    # 2. Search addresses with explicit type info
    for seg_start, seg_end in iter_segments(None, None, require_exec=False):
        if truncated:
            break
        ea = seg_start
        while ea < seg_end and not truncated:
            try:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, ea):
                    name = tif.get_type_name()
                    if name and matcher(name):
                        matches_seen += 1
                        if matches_seen > offset:
                            sym_name = idc.get_name(ea) or ""
                            line = f"{hex(ea)}  type_use:{name}  {sym_name}"
                            results.append(line)
                            if len(results) >= limit:
                                truncated = True
                                break
            except Exception:
                pass
            ea = idc.next_head(ea, seg_end)

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)


def search_export(pattern, case_sensitive, offset, limit, include_items):
    """Search exported symbols."""
    matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
    results = []
    truncated = False
    matches_seen = 0

    try:
        entry_count = ida_nalt.get_entry_qty()
    except Exception:
        entry_count = 0

    for idx in range(entry_count):
        if truncated:
            break
        try:
            ordinal = ida_nalt.get_entry_ordinal(idx)
            ea = ida_nalt.get_entry(ordinal)
            name = ida_nalt.get_entry_name(ordinal)
            if name and matcher(name):
                matches_seen += 1
                if matches_seen > offset:
                    line = f"{hex(ea)}  export_ordinal={ordinal}  {name}"
                    results.append(line)
                    if len(results) >= limit:
                        truncated = True
                        break
        except Exception:
            pass

    return build_response(results, offset, limit, matches_seen, truncated, pattern=pattern)


def search_summary(pattern, case_sensitive, range_start, range_end):
    """Quick summary of match counts across categories (fast, no full enumeration).
    
    If pattern is None or empty, returns total counts for all categories.
    Useful for LLM planning before running an expensive search.
    """
    if not pattern:
        try:
            total_funcs = sum(1 for _ in idautils.Functions())
            total_names = sum(1 for _ in idautils.Names())
            total_strings = sum(1 for _ in safe_get_strlist_items())
            return {
                "ok": True, "action": "summary", "pattern": None,
                "summary": {"functions": total_funcs, "names": total_names, "strings": total_strings},
                "total": total_funcs + total_names + total_strings,
                "note": "Total counts (no pattern filter). Pass pattern= to filter by keyword.",
            }
        except Exception:
            pass
    matcher = compile_smart_pattern(pattern or "", case_sensitive=case_sensitive)
    summary = {
        "names": 0, "strings": 0, "imports": 0,
        "instructions": 0, "functions": 0, "types": 0, "exports": 0,
    }

    # Names (full scan — just iteration, no decompilation)
    for ea, name in idautils.Names():
        if matcher(name):
            summary["names"] += 1

    # Strings (use cached)
    for srec in get_cached_strings():
        if matcher(srec["string"]):
            summary["strings"] += 1

    # Imports (use cached)
    for irec in get_cached_imports():
        if matcher(irec["name"]):
            summary["imports"] += 1

    # Functions (full scan)
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if matcher(name):
            summary["functions"] += 1

    # Instructions (sample bounded)
    inst_sample_limit = 5000
    inst_count = 0
    for seg_start, seg_end in iter_segments(range_start, range_end, require_exec=True):
        for ea in iter_code(seg_start, seg_end):
            if inst_count >= inst_sample_limit:
                summary["instructions_sampled"] = True
                break
            line = safe_generate_disasm_line(ea)
            if line:
                line_clean = ida_lines.tag_remove(line) if line else ""
                mnem = (idc.print_insn_mnem(ea) or "").lower()
                if matcher(line_clean) or matcher(mnem):
                    summary["instructions"] += 1
            inst_count += 1
        if inst_count >= inst_sample_limit:
            break

    # Types (lightweight check)
    try:
        til = ida_typeinf.get_idati()
        if til:
            type_sample_limit = 500
            for idx in range(min(ida_typeinf.get_ordinal_qty(til), type_sample_limit)):
                tif = ida_typeinf.tinfo_t()
                if tif.get_type_by_ordinal(til, idx):
                    name = tif.get_type_name()
                    if name and matcher(name):
                        summary["types"] += 1
            if ida_typeinf.get_ordinal_qty(til) > type_sample_limit:
                summary["types_sampled"] = True
    except Exception:
        pass

    # Exports
    try:
        for idx in range(ida_nalt.get_entry_qty()):
            ordinal = ida_nalt.get_entry_ordinal(idx)
            name = ida_nalt.get_entry_name(ordinal)
            if name and matcher(name):
                summary["exports"] += 1
    except Exception:
        pass

    total = sum(summary[k] for k in ("names", "strings", "imports", "instructions", "functions", "types", "exports"))
    return {
        "ok": True,
        "action": "summary",
        "pattern": pattern,
        "summary": summary,
        "total": total,
        "note": "Counts are approximate. Sampled categories are capped for speed.",
    }
