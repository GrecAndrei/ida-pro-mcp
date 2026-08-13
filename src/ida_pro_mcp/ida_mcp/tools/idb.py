from ._common import (
    Annotated,
    Any,
    Literal,
    MCPError,
    _filetype_name,
    _inf_bitness,
    _inf_filetype_id,
    _inf_procname,
    handle_error,
    ida_bytes,
    ida_kernwin,
    ida_nalt,
    ida_segment,
    idaapi,
    idaread,
    idautils,
    idc,
    make_error,
    tool
)

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from .. import compat as _compat

import contextlib
import glob
import json
import os
import time

import ida_entry
import ida_ida

# ida_idp is the processor register/CSR introspection surface (registers
# action). Imported defensively: outside a live IDA runtime the stub module
# cannot resolve its compiled ``_ida_idp`` extension, so the tool must keep
# loading (the registers action then reports register info unavailable).
try:
    import ida_idp
except Exception:
    ida_idp = None  # type: ignore[assignment]

try:
    from ida_pro_mcp.services import infer_binary_arch_profile
except Exception:
    infer_binary_arch_profile = None  # type: ignore

# IDA event hooks (auto-analysis-finished + function-created) + the bounded
# event ring they fill. Merely importing the events module installs the hooks
# once at tool-module init (its own module-scope install_hooks()); read_events
# is the read side of the ring.
try:
    from ..support.events import EVENT_RING_MAX, read_events
except Exception:
    EVENT_RING_MAX = 0
    def read_events(*_a, **_k):
        return []

try:
    from ..support.arch_utils import detect_riscv_gp
except Exception:
    detect_riscv_gp = None  # type: ignore

def _get_path(module, names):
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)()
    return None

def _safe_inf_get(attr_name, fallback=None):
    """Safely get ida_ida.inf_get_* or fallback to idc.get_inf_attr."""
    getter = getattr(ida_ida, f"inf_get_{attr_name}", None)
    if getter:
        try:
            return getter()
        except Exception:
            pass
    # Fallback to idc
    attr = getattr(idc, f"INF_{attr_name.upper()}", None)
    if attr is not None:
        return idc.get_inf_attr(attr)
    return fallback

@tool
def idb(
    action: Annotated[Literal["meta", "summary", "segments", "entrypoints", "bookmarks", "overview", "architecture_profile", "state", "events", "registers"],
                      "Action: meta|summary|segments|entrypoints|bookmarks|overview|architecture_profile|state|events|registers"] = "summary",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 100,
    **kwargs
) -> Any:
    """
    IDA database metadata and structural information.

    ACTIONS:

    meta - Comprehensive binary metadata
        Returns: {binary_path, idb_path, processor, bitness, compiler, image_base,
                  min_ea, max_ea, file_type, md5, sha256, crc32, timestamps}

    summary - Quick analysis summary with statistics
        Returns: {functions, named_functions, segments, strings, imports, exports,
                  comments, analysis_ok, coverage_estimate}

    overview - One-shot context for LLMs: meta + summary + segments + entrypoints combined
        Returns: {meta, summary, segments, entrypoints} - everything needed to start analysis

    architecture_profile - Current IDB architecture profile + raw-binary inference guidance
        Returns: {current, inferred_from_binary, raw_binary_mode, recommendations}

    segments - Detailed segment information with permissions and attributes
        Params: offset, count (for pagination)
        Returns: {segments: [{name, start, end, size, perms, class, align, type, flags}]}

    entrypoints - All entry points with type classification
        Returns: {entrypoints: [{name, addr, ordinal, type, is_main}]}

    bookmarks - IDA native bookmarks
        Returns: {bookmarks: [{index, addr, desc}]}

    events - Most recent analysis events from the hook event ring
        (auto_analysis_finished / function_created). Params: limit (default 50,
        capped at 500). Returns: {events: [{type, address, name, timestamp}],
        count, total, limit}.

    registers - Processor register classes + CSRs (read-only introspection)
        Params: reg_class (optional filter; e.g. gpr, segment, csr, other).
        Returns: {processor, reg_class, registers: [names], classes, count}.
    """
    try:
        if action == "meta":
            return {"ok": True, **idb_meta()}
        if action == "summary":
            return {"ok": True, **idb_summary()}
        if action == "overview":
            meta = idb_meta()
            # Keep overview responsive on large databases: use a lighter summary
            # and avoid per-segment head scans.
            summary = idb_summary(fast=True)
            segs = idb_segments_detailed(include_head_counts=False)
            entries = idb_entrypoints_detailed()
            arch_profile = idb_architecture_profile(meta=meta, summary=summary)
            inferred = arch_profile.get("inferred_from_binary") if isinstance(arch_profile, dict) else {}
            candidates = inferred.get("candidates") if isinstance(inferred, dict) and isinstance(inferred.get("candidates"), list) else []
            arch_recommendations = []
            for c in candidates[:3]:
                if not isinstance(c, dict):
                    continue
                if not c.get("processor"):
                    continue
                arch_recommendations.append(
                    {
                        "processor": c.get("processor"),
                        "bitness": c.get("bitness"),
                        "endian": c.get("endian"),
                        "confidence": c.get("confidence"),
                        "reason": c.get("reason"),
                    }
                )
            result = {
                "ok": True,
                "meta": meta,
                "summary": summary,
                "segments": segs[:20],
                "entrypoints": entries.get("entrypoints", [])[:30],
                "architecture_profile": arch_profile,
                "architecture_recommendations": arch_recommendations,
            }
            # Firmware detection hint
            is_firmware = bool(arch_profile.get("raw_binary_mode"))
            if is_firmware:
                result["firmware_detected"] = True
                result["next_actions"] = [
                    "ida_analysis_brief(limit=10)",
                    "ida_list_imports",
                    "ida_calc_resolve",
                ]
            else:
                result["next_actions"] = [
                    "ida_list_imports",
                    "ida_find(query='main')",
                    "ida_help(query='start')",
                ]
            return result
        if action == "segments":
            segs = idb_segments_detailed()
            total = len(segs)
            page = segs[offset:] if count == 0 else segs[offset:offset + count]
            return {"ok": True, "segments": page, "total": total, "offset": offset, "count": len(page)}
        if action == "entrypoints":
            return {"ok": True, **idb_entrypoints_detailed()}
        if action == "bookmarks":
            return {"ok": True, **idb_bookmarks()}
        if action == "architecture_profile":
            return {"ok": True, **idb_architecture_profile()}
        if action == "state":
            tail = int(kwargs.get("audit_tail", 5) or 0)
            return idb_state(audit_tail=tail)
        if action == "events":
            return idb_events(limit=kwargs.get("limit", 50))
        if action == "registers":
            return idb_registers(reg_class=kwargs.get("reg_class"))
        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e, "idb")

@idaread
def idb_meta():
    """Rich metadata about the binary and IDB."""
    binary_path = _get_path(ida_nalt, ["get_input_file_path"]) or _get_path(idaapi, ["get_input_file_path"]) or "unknown"
    idb_path = _get_path(idaapi, ["get_idb_path"]) or _get_path(idc, ["get_idb_path"]) or "unknown"

    # Get min/max EA
    min_ea = _safe_inf_get("min_ea", 0)
    max_ea = _safe_inf_get("max_ea", 0)

    # File hashes if available
    md5 = ida_nalt.retrieve_input_file_md5() if hasattr(ida_nalt, "retrieve_input_file_md5") else None
    sha256 = ida_nalt.retrieve_input_file_sha256() if hasattr(ida_nalt, "retrieve_input_file_sha256") else None
    crc32 = ida_nalt.retrieve_input_file_crc32() if hasattr(ida_nalt, "retrieve_input_file_crc32") else None

    # Compiler info — ida_ida.inf_get_cc_id() returns the stored INF_CC_ID
    # nibble, which follows the IDC constants (COMP_MS=1, COMP_BC=2,
    # COMP_WATCOM=3, COMP_GNU=6, COMP_VISAGE=7, COMP_BP=8). GNU C++ reports 6
    # (clang-built ELFs report 6 too); there is no stored id 4 or 9.
    comp = _safe_inf_get("cc_id", 0)
    compiler_names = {0: "unknown", 1: "visual_c", 2: "borland", 3: "watcom",
                      6: "gnu", 7: "visual_age", 8: "delphi"}

    # File type — resolve effective kind (raw vs obj discrepancy).
    file_type_id = _inf_filetype_id()
    ft_loader = _filetype_name(file_type_id)
    ft_effective = ft_loader
    ft_note = None
    try:
        inferred = infer_binary_arch_profile(binary_path) if callable(infer_binary_arch_profile) else {}
    except Exception:
        inferred = {}
    inferred_file_kind = inferred.get("file_kind") if isinstance(inferred, dict) else None
    if ft_loader == "obj" and inferred_file_kind == "raw":
        ft_effective = "raw"
        ft_note = "IDA loader reports obj for plain binaries; effective kind is raw."

    out = {
        "binary_path": binary_path,
        "idb_path": idb_path,
        "processor": _inf_procname(),
        "procname": _inf_procname(),
        "bitness": _inf_bitness(),
        "bits": _inf_bitness(),
        "file_type_id": file_type_id,
        "file_type_name": ft_loader,
        "file_type_effective": ft_effective,
        "file_type_info": {
            "loader": ft_loader,
            "loader_id": file_type_id,
            "effective": ft_effective,
            "note": ft_note,
        },
        "compiler": compiler_names.get(comp, f"compiler_{comp}"),
        "image_base": hex(_safe_inf_get("baseaddr", 0)),
        "min_ea": hex(min_ea) if min_ea is not None else None,
        "max_ea": hex(max_ea) if max_ea is not None else None,
        "image_size": hex(max_ea - min_ea) if (min_ea is not None and max_ea is not None and max_ea > min_ea) else None,
        "md5": md5.hex() if md5 else None,
        "sha256": sha256.hex() if sha256 else None,
        "crc32": hex(crc32) if crc32 else None,
        "is_dll": ida_ida.inf_is_dll() if hasattr(ida_ida, "inf_is_dll") else None,
        "is_be": ida_ida.inf_is_be() if hasattr(ida_ida, "inf_is_be") else None,
        # Carry the host-side raw-blob inference so idb_architecture_profile (and
        # the overview action) can reuse it instead of re-running the file scan.
        "inferred_arch_profile": inferred,
    }
    return out

@idaread
def idb_segments_detailed(include_head_counts=True):
    """Detailed segment information."""
    segments = []
    for ea in idautils.Segments():
        seg = _compat.get_segment(ea)
        if seg is None:
            continue
        seg_perm = _compat.get_segment_perm(ea)
        seg_type_val = _compat.get_segment_type(ea)
        seg_align = _compat.get_segment_align(ea)
        seg_bitness = _compat.get_segment_bitness(ea)

        # Permissions string
        perms = ""
        if seg_perm & idaapi.SEGPERM_READ: perms += "r"
        if seg_perm & idaapi.SEGPERM_WRITE: perms += "w"
        if seg_perm & idaapi.SEGPERM_EXEC: perms += "x"

        # Segment type - build dict safely for IDA 9 compatibility
        seg_types = {}
        for attr_name, type_name in [("SEG_CODE", "code"), ("SEG_DATA", "data"),
                                      ("SEG_BSS", "bss"), ("SEG_STACK", "stack"),
                                      ("SEG_XTRN", "extern"), ("SEG_NULL", "null"),
                                      ("SEG_NORM", "normal"), ("SEG_ABS", "absolute")]:
            if hasattr(ida_segment, attr_name):
                seg_types[getattr(ida_segment, attr_name)] = type_name
        seg_type = seg_types.get(seg_type_val, f"type_{seg_type_val}")

        code_count = None
        data_count = None
        if include_head_counts:
            code_count = 0
            data_count = 0
            head = seg.start_ea
            while head < seg.end_ea and code_count + data_count < 10000:
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_code(flags):
                    code_count += 1
                elif ida_bytes.is_data(flags):
                    data_count += 1
                head = idc.next_head(head, seg.end_ea)
                if head == idaapi.BADADDR:
                    break

        segments.append({
            "name": _compat.get_segment_name(ea),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.end_ea - seg.start_ea),
            "perms": perms or "---",
            "class": _compat.get_segment_class(ea),
            "type": seg_type,
            "align": seg_align,
            "bitness": {0: 16, 1: 32, 2: 64}.get(seg_bitness, seg_bitness * 16),
            "code_heads": code_count,
            "data_heads": data_count,
        })
    return segments

@idaread
def idb_entrypoints_detailed():
    """Entry points with classification."""
    entries = []
    main_names = {"main", "_main", "WinMain", "_WinMain@16", "wmain", "_wmain",
                  "DllMain", "_DllMain@12", "DllEntryPoint", "start", "_start"}

    for i in range(ida_entry.get_entry_qty()):
        ord_val = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord_val)
        name = ida_entry.get_entry_name(ord_val)

        # Classify entry type
        entry_type = "export"
        if i == 0:
            entry_type = "entry_point"
        elif name and name in main_names:
            entry_type = "main"
        elif name and name.startswith("Dll"):
            entry_type = "dll_entry"

        # Get function info if available
        func = _compat.get_func_info(ea)
        func_size = None
        if func is not None:
            func_size = hex(func.end_ea - func.start_ea)

        entries.append({
            "name": name,
            "addr": hex(ea),
            "ordinal": ord_val,
            "type": entry_type,
            "is_main": name in main_names if name else False,
            "func_size": func_size
        })
    return {"entrypoints": entries, "count": len(entries)}

@idaread
def idb_bookmarks():
    """Get IDA native bookmarks."""
    bookmarks = []
    try:
        for i in range(1000):
            ea = idc.get_bookmark(i)
            if ea == idaapi.BADADDR:
                break
            desc = idc.get_bookmark_desc(i)
            func_start = _compat.get_func_start(ea)
            bookmarks.append({
                "index": i,
                "addr": hex(ea),
                "desc": desc or "",
                "func": idc.get_func_name(func_start) if func_start is not None else None
            })
    except AttributeError:
        pass
    return {"bookmarks": bookmarks, "count": len(bookmarks)}

@idaread
def idb_summary(fast=False):
    """Comprehensive analysis summary."""
    # Count functions
    all_funcs = list(idautils.Functions())

    def _auto_named(name: str) -> bool:
        """IDA auto-names: empty or a reserved auto prefix (matches data annotations)."""
        return not name or name.startswith(("sub_", "j_", "loc_", "nullsub_", "unknown_libname_"))

    named_funcs = sum(1 for ea in all_funcs if not _auto_named(idc.get_func_name(ea) or ""))

    # Count strings
    string_count = idaapi.get_strlist_qty()

    # Count imports/exports
    import_count = 0
    for i in range(ida_nalt.get_import_module_qty()):
        def count_cb(ea, name, ordinal):
            nonlocal import_count
            import_count += 1
            return True
        ida_nalt.enum_import_names(i, count_cb)

    export_count = ida_entry.get_entry_qty()

    if fast:
        return {
            "functions": len(all_funcs),
            "named_functions": named_funcs,
            "auto_named_functions": len(all_funcs) - named_funcs,
            "segments": len(list(idautils.Segments())),
            "strings": string_count,
            "imports": import_count,
            "exports": export_count,
            "comments": None,
            "analysis_ok": idaapi.auto_is_ok(),
            "code_coverage_pct": None,
            "defined_code_bytes": None,
            "total_code_bytes": None,
            "approximate": True,
            "note": "Fast summary for overview; skip full comment and coverage scans on large IDBs.",
        }

    # Count comments
    comment_count = 0
    for seg_ea in idautils.Segments():
        seg = _compat.get_segment(seg_ea)
        if not seg:
            continue
        head = seg.start_ea
        limit = 0
        while head < seg.end_ea and limit < 50000:
            if idc.get_cmt(head, 0) or idc.get_cmt(head, 1):
                comment_count += 1
            head = idc.next_head(head, seg.end_ea)
            if head == idaapi.BADADDR:
                break
            limit += 1

    # Coverage estimate
    total_code_bytes = 0
    defined_code_bytes = 0
    for seg_ea in idautils.Segments():
        seg = _compat.get_segment(seg_ea)
        seg_perm = _compat.get_segment_perm(seg_ea)
        if seg is not None and seg_perm is not None and seg_perm & idaapi.SEGPERM_EXEC:
            seg_size = seg.end_ea - seg.start_ea
            total_code_bytes += seg_size
            head = seg.start_ea
            while head < seg.end_ea:
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_code(flags):
                    defined_code_bytes += idc.get_item_size(head)
                head = idc.next_head(head, seg.end_ea)
                if head == idaapi.BADADDR:
                    break

    coverage = round(defined_code_bytes / total_code_bytes * 100, 1) if total_code_bytes > 0 else 0

    return {
        "functions": len(all_funcs),
        "named_functions": named_funcs,
        "auto_named_functions": len(all_funcs) - named_funcs,
        "segments": len(list(idautils.Segments())),
        "strings": string_count,
        "imports": import_count,
        "exports": export_count,
        "comments": comment_count,
        "analysis_ok": idaapi.auto_is_ok(),
        "code_coverage_pct": coverage,
        "defined_code_bytes": defined_code_bytes,
        "total_code_bytes": total_code_bytes,
    }


@idaread
def idb_architecture_profile(meta=None, summary=None):
    if meta is None:
        meta = idb_meta()
    if summary is None:
        summary = idb_summary()

    binary_path = str(meta.get("binary_path") or "")
    inferred = {}
    # Reuse the inference already computed by idb_meta (stored in meta) instead
    # of re-scanning the file: idb_meta and the overview action already ran it.
    # Fall back to a fresh scan only when the carried profile is absent or was
    # never populated (e.g. meta built by a caller that did not use idb_meta).
    carried = meta.get("inferred_arch_profile")
    if isinstance(carried, dict) and carried.get("file_kind"):
        inferred = carried
    elif callable(infer_binary_arch_profile) and binary_path and os.path.exists(binary_path):
        try:
            inferred = infer_binary_arch_profile(binary_path) or {}
        except Exception:
            inferred = {}

    ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
    # Prefer file_type_info.effective; fall back to legacy top-level fields for backward compat.
    ft_effective = str(
        ft_info.get("effective")
        or meta.get("file_type_effective")
        or meta.get("file_type")
        or ""
    ).strip().lower()
    current = {
        "processor": meta.get("processor"),
        "bitness": meta.get("bitness"),
        "endian": "big" if meta.get("is_be") else "little",
        "file_type": ft_effective or ft_info.get("loader"),
    }
    file_type = ft_effective
    import_count = int((summary or {}).get("imports", 0) or 0)
    proc = str(meta.get("processor") or "").strip().lower()
    raw_mode = bool(
        file_type in ("raw", "unknown", "obj", "")
        or meta.get("file_type_id") in (0, 2, 17)
        or (proc in ("arm", "mips", "ppc", "msp430", "avr", "xtensa") and import_count == 0)
    )
    recs = []
    if raw_mode:
        recs.append("workflow(action='triage_fast')")
        recs.append("analysis(action='set_architecture', processor='<candidate>', bitness=<16|32|64>, endian='<little|big>')")

    # RISC-V: detect GP (x3) value for GP-relative xref resolution.  Keyed off
    # the IDB's processor name rather than is_riscv_family(), which needs the
    # IDA inf-structure and can be unreliable on opaque blobs before IDA has
    # settled on a processor module.  'riscv' is the canonical IDA module name
    # (normalized by _PROC_ALIASES), so this also covers riscv32/riscv64 aliases.
    gp_info = None
    if "riscv" in proc and callable(detect_riscv_gp):
        try:
            gp_info = detect_riscv_gp()
            if gp_info.get("found"):
                gp_val = gp_info.get("gp")
                gp_expr = hex(gp_val) if isinstance(gp_val, int) else str(gp_val)
                recs.append(
                    f"misc(action='idc', expr='idc.set_reg_value(\"gp\", {gp_expr}, idc.BADADDR)')"
                )
        except Exception:
            gp_info = None

    result = {
        "current": current,
        "inferred_from_binary": inferred,
        "raw_binary_mode": raw_mode,
        "recommendations": recs,
    }
    # Honest raw-blob surfaces: the inference caveat, any dominant load base,
    # and the empty-entry-points note (no headers / vector table on an opaque
    # blob means architecture must be set explicitly before full analysis).
    if raw_mode:
        raw_warning = inferred.get("warning") if isinstance(inferred, dict) else None
        if raw_warning:
            result["raw_binary_warning"] = raw_warning
        load_base = inferred.get("load_base") if isinstance(inferred, dict) else None
        if load_base is not None:
            result["inferred_load_base"] = load_base
        entry_count = int((summary or {}).get("exports", 0) or 0)
        if entry_count == 0:
            result["entrypoints_note"] = (
                "no entry points detected (raw blob / no vector table); "
                "set architecture explicitly before analysis"
            )
    if gp_info is not None:
        result["riscv_gp"] = gp_info
    return result


_AUTO_STATE_NAMES = {
    0: "NONE",
    1: "ANALYSING",
    2: "FINAL",
    3: "IDB",
    4: "FINAL_IDB",
    5: "USED",
    6: "TYPE",
    7: "LIBF",
}


def _safe_audit_dir() -> str | None:
    """Locate the host's audit log directory if reachable from the IDA process.

    The audit log lives on the host's filesystem (<cache_dir>/audit/YYYY-MM/).
    On single-user machines the IDA process can read it directly; in
    sandboxed or multi-user setups the path may be unreachable and the caller
    should degrade gracefully.
    """
    try:
        base = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
        if not base:
            base = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp")
        candidate = os.path.join(base, "audit")
        if os.path.isdir(candidate):
            return candidate
    except Exception:
        return None
    return None


def _read_audit_tail(audit_dir: str, max_lines: int) -> list[dict]:
    """Return the most recent <max_lines> audit records across today's files.

    Designed to be cheap: only reads the current month's directory and the
    current day file (or yesterday's if today's doesn't exist yet).
    """
    if max_lines <= 0 or not audit_dir:
        return []
    try:
        month_dirs = sorted(glob.glob(os.path.join(audit_dir, "[0-9][0-9][0-9][0-9]-[0-9][0-9]")))
        if not month_dirs:
            return []
        latest_month = month_dirs[-1]
        day_files = sorted(glob.glob(os.path.join(latest_month, "audit_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].jsonl")))
        if not day_files:
            return []
        path = day_files[-1]
        # Read tail efficiently: seek to last ~256KB and parse lines from there.
        records: list[dict] = []
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            window = min(size, 256 * 1024)
            f.seek(size - window)
            chunk = f.read().decode("utf-8", errors="replace")
        # Drop a partial first line if we didn't start at file start
        if window < size and "\n" in chunk:
            chunk = chunk.split("\n", 1)[1]
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            records.append(rec)
        return records[-max_lines:]
    except Exception:
        return []


@idaread
def idb_state(audit_tail: int = 5) -> dict:
    """Unified, cheap snapshot of what IDA is doing right now.

    Reads only IDA SDK state and filesystem metadata; never calls other tools,
    never iterates all functions. Safe to call from any LLM turn.

    Returns:
        ok, ts, analysis{state,display,is_ok,active}, database{idb_path,
        idb_age_seconds, input_file, input_size, open_seconds}, inventory{
        functions_qty, strings_qty, imports_qty, exports_qty}, ui{cursor_ea},
        debugger{active, process_state}, audit_tail[N], indicators{
        looks_empty, looks_packed, needs_packer_check, raw_blob, arch_unverified}
    """
    now = time.time()

    # Auto-analysis state
    auto_state_id = -1
    auto_state_name = "UNKNOWN"
    auto_display = ""
    auto_is_ok = True
    try:
        if hasattr(idaapi, "auto_state"):
            auto_state_id = int(idaapi.auto_state())
            auto_state_name = _AUTO_STATE_NAMES.get(auto_state_id, f"STATE_{auto_state_id}")
        if hasattr(idaapi, "get_auto_display"):
            try:
                auto_display = str(idaapi.get_auto_display() or "")
            except Exception:
                auto_display = ""
        if hasattr(idaapi, "auto_is_ok"):
            auto_is_ok = bool(idaapi.auto_is_ok())
    except Exception:
        pass

    # Database paths + liveness
    idb_path = ""
    input_path = ""
    idb_age = -1.0
    input_size = -1
    open_seconds = -1.0
    try:
        idb_path = idaapi.get_idb_path() if hasattr(idaapi, "get_idb_path") else ""
    except Exception:
        idb_path = ""
    try:
        input_path = idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else ""
    except Exception:
        input_path = ""
    if idb_path and os.path.isfile(idb_path):
        try:
            idb_age = round(max(0.0, now - os.path.getmtime(idb_path)), 3)
        except OSError:
            idb_age = -1.0
    if input_path and os.path.isfile(input_path):
        try:
            input_size = os.path.getsize(input_path)
        except OSError:
            input_size = -1
    # Heuristic: open_seconds = max(idb_age, 60) when no other signal.
    # If IDB has been touched recently (low age) IDA is active; high age is
    # either idle or stale.
    if idb_age >= 0:
        open_seconds = max(idb_age, 60.0)

    # Inventory — O(1) APIs only, no full iteration
    func_qty = -1
    str_qty = -1
    import_qty = -1
    export_qty = -1
    try:
        if hasattr(idaapi, "get_func_qty"):
            func_qty = int(idaapi.get_func_qty())
    except Exception:
        pass
    try:
        if hasattr(idaapi, "get_strlist_qty"):
            str_qty = int(idaapi.get_strlist_qty())
    except Exception:
        pass
    with contextlib.suppress(Exception):
        import_qty = int(ida_nalt.get_import_module_qty())
    with contextlib.suppress(Exception):
        export_qty = int(ida_entry.get_entry_qty())

    # Opaque-blob probe: read only the input's leading bytes (cheap, no tool
    # calls) and decide whether it carries a recognizable container magic.
    # A raw blob with no architecture confidence (few/no functions) is the
    # "arch unverified" case the LLM must act on.
    raw_blob = False
    if input_path and os.path.isfile(input_path):
        try:
            with open(input_path, "rb") as _f:
                _magic = _f.read(8)
            _known_magic = _magic.startswith(
                (b"\x7fELF", b"MZ", b"IDA2",
                 b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
            )
            raw_blob = not _known_magic
        except OSError:
            raw_blob = False
    arch_unverified = bool(raw_blob and func_qty <= 1)

    # UI cursor
    cursor_ea = ""
    try:
        if hasattr(ida_kernwin, "get_cursor_ea"):
            cea = int(ida_kernwin.get_cursor_ea())
            if cea and cea != idaapi.BADADDR:
                cursor_ea = hex(cea)
    except Exception:
        pass

    # Debugger
    dbg_active = False
    dbg_state = "NO_PROCESS"
    try:
        if hasattr(idaapi, "is_debugger_on"):
            dbg_active = bool(idaapi.is_debugger_on())
        if hasattr(idaapi, "get_process_state"):
            ps = int(idaapi.get_process_state())
            dbg_state = {
                0: "NO_PROCESS",
                1: "PROCESS_SUSPENDED",
                2: "PROCESS_RUNNING",
                3: "PROCESS_EXITED",
            }.get(ps, f"STATE_{ps}")
    except Exception:
        pass

    # Audit log tail
    audit_dir = _safe_audit_dir()
    tail_records = _read_audit_tail(audit_dir, audit_tail) if audit_dir else []
    audit_summary = []
    for rec in tail_records:
        try:
            audit_summary.append({
                "ts": rec.get("ts"),
                "tool": rec.get("tool"),
                "action": rec.get("action"),
                "latency_ms": rec.get("latency_ms"),
                "ok": not rec.get("error"),
                "guardrail_blocked": rec.get("guardrail_blocked", False),
            })
        except Exception:
            continue

    # Indicators: surface the "looks empty" / "looks packed" signal that
    # LLM agents repeatedly miss on packed game cheat binaries.
    looks_empty = (
        func_qty == 0 or
        (func_qty == 1 and str_qty == 0 and import_qty == 0)
    )
    looks_packed = looks_empty
    needs_packer_check = looks_empty
    # Heuristic: high idb_age + no auto-analysis activity + 0 functions =
    # the binary is opaque to IDA right now.
    if idb_age >= 0 and func_qty <= 1 and not auto_display:
        needs_packer_check = True

    return {
        "ok": True,
        "ts": round(now, 3),
        "analysis": {
            "state": auto_state_name,
            "state_id": auto_state_id,
            "display": auto_display,
            "is_ok": auto_is_ok,
            "active": bool(auto_display) and not auto_is_ok,
        },
        "database": {
            "idb_path": idb_path,
            "idb_age_seconds": idb_age,
            "input_file": input_path,
            "input_size": input_size,
            "open_seconds": round(open_seconds, 3) if open_seconds >= 0 else -1.0,
        },
        "inventory": {
            "functions_qty": func_qty,
            "strings_qty": str_qty,
            "imports_qty": import_qty,
            "exports_qty": export_qty,
        },
        "ui": {
            "cursor_ea": cursor_ea,
        },
        "debugger": {
            "active": dbg_active,
            "process_state": dbg_state,
        },
        "audit_tail": audit_summary,
        "indicators": {
            "looks_empty": looks_empty,
            "looks_packed": looks_packed,
            "needs_packer_check": needs_packer_check,
            "raw_blob": raw_blob,
            "arch_unverified": arch_unverified,
        },
    }


# ---------------------------------------------------------------------------
# events: read the hook event ring
# ---------------------------------------------------------------------------

@idaread
def idb_events(limit=50):
    """Return the most recent analysis events from the hook event ring.

    The ring is filled by the IDB_Hooks subclass in ``support/events.py``
    (auto_analysis_finished + function_created), which also invalidates the
    shared tool-result cache on every event so this read never goes stale.
    """
    try:
        limit = max(0, min(int(limit), EVENT_RING_MAX))
    except (TypeError, ValueError):
        limit = 50
    events, total = read_events(limit)
    return {
        "ok": True,
        "events": events,
        "count": len(events),
        "total": total,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# registers: processor register classes + CSRs (read-only introspection)
# ---------------------------------------------------------------------------

# Well-known RISC-V control/status registers (standard base set). IDA's RISC-V
# module names most registers x0-x31/ABI aliases in ph.reg_names but the CSR
# set is processor-module-dependent; exposing the documented list helps an LLM
# reason about ecall/mret/CSR handlers on opaque RISC-V firmware without
# hallucinating register names.
_RISCV_CSRS = [
    # User / floating-point CSRs
    "fflags", "frm", "fcsr",
    # User counters / timers
    "cycle", "time", "instret",
    "cycleh", "timeh", "instreth",
    "hpmcounter3", "hpmcounter4", "hpmcounter5", "hpmcounter6", "hpmcounter7",
    "hpmcounter8", "hpmcounter9", "hpmcounter10", "hpmcounter11", "hpmcounter12",
    "hpmcounter13", "hpmcounter14", "hpmcounter15", "hpmcounter16", "hpmcounter17",
    "hpmcounter18", "hpmcounter19", "hpmcounter20", "hpmcounter21", "hpmcounter22",
    "hpmcounter23", "hpmcounter24", "hpmcounter25", "hpmcounter26", "hpmcounter27",
    "hpmcounter28", "hpmcounter29", "hpmcounter30", "hpmcounter31",
    "hpmcounter3h", "hpmcounter4h", "hpmcounter5h", "hpmcounter6h", "hpmcounter7h",
    "hpmcounter8h", "hpmcounter9h", "hpmcounter10h", "hpmcounter11h", "hpmcounter12h",
    "hpmcounter13h", "hpmcounter14h", "hpmcounter15h", "hpmcounter16h", "hpmcounter17h",
    "hpmcounter18h", "hpmcounter19h", "hpmcounter20h", "hpmcounter21h", "hpmcounter22h",
    "hpmcounter23h", "hpmcounter24h", "hpmcounter25h", "hpmcounter26h", "hpmcounter27h",
    "hpmcounter28h", "hpmcounter29h", "hpmcounter30h", "hpmcounter31h",
    # Machine CSRs
    "mvendorid", "marchid", "mimpid", "mhartid",
    "mstatus", "misa", "medeleg", "mideleg", "mie", "mtvec",
    "mcounteren", "mscratch", "mepc", "mcause", "mtval", "mip",
    "mcountinhibit",
    "mhpmevent3", "mhpmevent4", "mhpmevent5", "mhpmevent6", "mhpmevent7",
    "mhpmevent8", "mhpmevent9", "mhpmevent10", "mhpmevent11", "mhpmevent12",
    "mhpmevent13", "mhpmevent14", "mhpmevent15", "mhpmevent16", "mhpmevent17",
    "mhpmevent18", "mhpmevent19", "mhpmevent20", "mhpmevent21", "mhpmevent22",
    "mhpmevent23", "mhpmevent24", "mhpmevent25", "mhpmevent26", "mhpmevent27",
    "mhpmevent28", "mhpmevent29", "mhpmevent30", "mhpmevent31",
    "mcycle", "minstret", "mcycleh", "minstreth",
    # Supervisor CSRs
    "sstatus", "sedeleg", "sideleg", "sie", "stvec",
    "scounteren", "sscratch", "sepc", "scause", "stval", "sip", "satp",
    # Physical memory protection
    "pmpcfg0", "pmpcfg1", "pmpcfg2", "pmpcfg3",
    "pmpaddr0", "pmpaddr1", "pmpaddr2", "pmpaddr3",
    "pmpaddr4", "pmpaddr5", "pmpaddr6", "pmpaddr7",
    "pmpaddr8", "pmpaddr9", "pmpaddr10", "pmpaddr11",
    "pmpaddr12", "pmpaddr13", "pmpaddr14", "pmpaddr15",
]


def _register_classes(proc):
    """Group the processor's register set into classes.

    Uses ``ida_idp.ph.reg_names`` plus the segment/ideal-register index ranges
    (``reg_first_sreg``/``reg_last_sreg``, ``reg_first_ireg``/``reg_last_ireg``).
    On IDA 9.x Python the processor table is not populated (``ph.reg_names``
    is empty/None on 9.3 and 9.4 under both idat and idalib — verified live),
    so the table is synthesized from ``ida_idp.get_reg_name`` instead.
    For RISC-V, a documented CSR name set is appended under the ``csr`` class
    (deduplicated against what the module already names). Returns a list of
    ``{reg_class, registers}`` dicts; empty when the register table is
    unavailable.
    """
    if ida_idp is None:
        return []
    ph = getattr(ida_idp, "ph", None)

    def _synthesize_reg_names():
        """Enumerate registers via get_reg_name when ph.reg_names is absent.

        Prefers the widest naming per register (rax over al/ax), iterating
        index + width until the table runs out; deduplicates aliases.
        """
        names: list[str] = []
        seen: set[str] = set()
        for reg in range(1024):
            found = None
            for width in (8, 4, 2, 1):
                try:
                    candidate = ida_idp.get_reg_name(reg, width)
                except Exception:
                    candidate = None
                if candidate:
                    found = candidate
                    break
            if found is None:
                # metapc stops around index 35; keep scanning a short tail in
                # case a processor module has sparse indices, then stop.
                if reg > 128:
                    break
                continue
            if found not in seen:
                seen.add(found)
                names.append(found)
        return names

    raw_names = [str(r) for r in (getattr(ph, "reg_names", None) or [])]
    reg_names = [r for r in raw_names if r]
    synthesized = False
    if not reg_names:
        reg_names = _synthesize_reg_names()
        synthesized = bool(reg_names)
    if not reg_names:
        return []

    def _range(attr_first, attr_last, accessor_first=None, accessor_last=None):
        if not synthesized:
            first = int(getattr(ph, attr_first, 0) or 0)
            last = int(getattr(ph, attr_last, 0) or 0)
        else:
            # ph index attributes are also unpopulated on 9.x; the dedicated
            # accessors ph_get_reg_first_sreg()/ph_get_reg_last_sreg() exist.
            first = int(getattr(ida_idp, accessor_first, lambda: 0)() or 0) if accessor_first else 0
            last = int(getattr(ida_idp, accessor_last, lambda: 0)() or 0) if accessor_last else 0
        if last < first or first < 0 or last >= len(reg_names):
            return None
        return (first, last)

    used: set[int] = set()
    classes: list[dict] = []

    ireg = _range("reg_first_ireg", "reg_last_ireg")
    if ireg is not None:
        first, last = ireg
        used.update(range(first, last + 1))
        classes.append({"reg_class": "gpr", "registers": reg_names[first:last + 1]})

    sreg = _range(
        "reg_first_sreg", "reg_last_sreg",
        accessor_first="ph_get_reg_first_sreg", accessor_last="ph_get_reg_last_sreg",
    )
    if sreg is not None:
        first, last = sreg
        used.update(range(first, last + 1))
        classes.append({"reg_class": "segment", "registers": reg_names[first:last + 1]})

    remaining = [reg_names[i] for i in range(len(reg_names)) if i not in used]
    if remaining:
        classes.append({"reg_class": "other", "registers": remaining})

    if "riscv" in (proc or "").lower():
        known = {n for c in classes for n in c["registers"]}
        csrs = [n for n in _RISCV_CSRS if n not in known]
        if csrs:
            classes.append({"reg_class": "csr", "registers": csrs})

    return classes


@idaread
def idb_registers(reg_class=None):
    """Enumerate the processor register classes + CSRs (read-only).

    ``reg_class=None`` returns a flat deduplicated union plus a per-class
    breakdown; a ``reg_class`` filter returns just that class. Read-only —
    never touches the IDB.
    """
    proc = _inf_procname()
    classes = _register_classes(proc)
    if not classes:
        return make_error(
            MCPError.IDA_ERROR,
            "Processor register info unavailable (ida_idp.ph.reg_names missing)",
        )
    if reg_class is not None:
        selected = next((c for c in classes if c["reg_class"] == reg_class), None)
        if selected is None:
            available = ", ".join(c["reg_class"] for c in classes)
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown register class: {reg_class}",
                hint=f"Available classes: {available or 'none'}",
            )
        return {
            "ok": True,
            "processor": proc,
            "reg_class": reg_class,
            "registers": selected["registers"],
            "count": len(selected["registers"]),
        }
    seen: list[str] = []
    for c in classes:
        for name in c["registers"]:
            if name not in seen:
                seen.append(name)
    return {
        "ok": True,
        "processor": proc,
        "reg_class": "all",
        "registers": seen,
        "classes": classes,
        "count": len(seen),
    }
