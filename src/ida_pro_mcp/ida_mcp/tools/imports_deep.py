
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]


# ============================================================================
# 32. IMPORTS_DEEP - Deep Import Analysis
# ============================================================================

# Memoized ea -> (module, name) import map. Rebuilt when the root filename or
# the import-module count changes; bounded so a session that re-analyzes many
# binaries does not accumulate stale entries.
_IMPORT_MAP_CACHE: dict = {}
_IMPORT_MAP_CACHE_MAX = 4

# ELF PLT / GOT segment names.
_ELF_PLT_PREFIX = ".plt"
_ELF_GOT_NAMES = (".got", ".got.plt", ".got.plt.sec")


def _import_ea_map() -> dict:
    """Return a memoized ea -> (module, name) map for every named import.

    Rebuilt lazily whenever the root filename or get_import_module_qty()
    changes, so a resolve-with-addr lookup is O(1) instead of re-enumerating
    every module's import table per address.
    """
    try:
        root = ida_nalt.get_root_filename()
    except Exception:
        root = ""
    qty = ida_nalt.get_import_module_qty()
    key = (root, qty)
    cached = _IMPORT_MAP_CACHE.get(key)
    if cached is not None:
        return cached
    mapping: dict = {}
    for i in range(qty):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name:
            continue

        def cb(ea, name, ordinal, _mod=mod_name, _mapping=mapping):
            _mapping[ea] = (_mod, name or f"ordinal_{ordinal}")
            return True

        ida_nalt.enum_import_names(i, cb)
    if len(_IMPORT_MAP_CACHE) >= _IMPORT_MAP_CACHE_MAX:
        _IMPORT_MAP_CACHE.pop(next(iter(_IMPORT_MAP_CACHE)))
    _IMPORT_MAP_CACHE[key] = mapping
    return mapping


def _iter_import_records():
    """Yield (ea, module, name) records for every import across all modules."""
    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name:
            continue
        records: list = []

        def cb(ea, name, ordinal, _mod=mod_name, _records=records):
            _records.append((ea, _mod, name or f"ordinal_{ordinal}"))
            return True

        ida_nalt.enum_import_names(i, cb)
        yield from records


def _elf_plt_thunks(query_matcher=None):
    """Resolve ELF PLT thunks: map PLT stub addresses to their symbols.

    ELF imports surface as lazy-binding stubs in .plt (and .plt.got/.plt.sec)
    that jump through a .got.plt slot. IDA records the import entry at the
    stub address, so every import whose address sits inside a PLT segment is a
    thunk; the GOT slot value recovers the resolved target.  Returns a list of
    dicts {thunk_addr, got_slot, target, name, dll}.
    """
    is_64 = _inf_bitness() == 64
    stride = 8 if is_64 else 4
    plt_ranges = []
    got_segs = []
    for seg_ea in idautils.Segments():
        seg_name = (idc.get_segm_name(seg_ea) or "").lower()
        seg = _compat.get_segment(seg_ea)
        if not seg:
            continue
        if seg_name.startswith(_ELF_PLT_PREFIX):
            plt_ranges.append((seg.start_ea, seg.end_ea))
        elif seg_name in _ELF_GOT_NAMES:
            got_segs.append(seg)
    if not plt_ranges:
        return []

    # symbol -> (got_slot_ea, target_ea). Prefer the symbol IDA attached to
    # the GOT slot; when the slot is an off_* address, fall back to the name
    # of the slot's pointee.
    got_by_name: dict = {}
    for seg in got_segs:
        ea = seg.start_ea
        while ea < seg.end_ea:
            target = idc.get_qword(ea) if is_64 else idc.get_wide_dword(ea)
            slot_name = idc.get_name(ea) or ""
            if slot_name.startswith("off_"):
                slot_name = ""
            if not slot_name and target:
                slot_name = idc.get_name(target) or ""
            if target and slot_name:
                got_by_name.setdefault(slot_name, (ea, target))
            ea += stride

    thunks = []
    for ea, module, name in _iter_import_records():
        if not any(s <= ea < e for s, e in plt_ranges):
            continue
        if query_matcher and not (query_matcher(name) or query_matcher(module or "")):
            continue
        got_slot, target = got_by_name.get(name, (None, None))
        thunks.append({
            "thunk_addr": hex(ea),
            "got_slot": hex(got_slot) if got_slot else "-",
            "target": hex(target) if target else "-",
            "name": name,
            "dll": module or "",
        })
    return thunks


@tool
@idaread
def imports_deep(
    action: Annotated[Literal["thunks", "delay", "forwarded", "ordinal", "api_sets", "resolve"],
                      "Action: thunks|delay|forwarded|ordinal|api_sets|resolve"],
    query: Annotated[Optional[str], "Import name or DLL to filter (regex/glob/substring/semantic auto-detected)"] = None,
    addr: Annotated[Optional[str], "Address for resolve action"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results"] = 100,
    **kwargs
) -> dict:
    """
    Deep import analysis with thunk resolution and delay import detection.

    ACTIONS:

    thunks - Resolve import thunks to actual API addresses
        Params: query (optional string pattern filter for DLL or function name)
        Returns: {thunks: [{thunk_addr, target, name, dll}]}

    delay - List delay-loaded imports
        Returns: {delay_imports: [{dll, functions: [...]}]}

    forwarded - Detect forwarded exports in imported DLLs
        Returns: {forwarded: [{from_dll, to_dll, name}]}

    ordinal - Resolve ordinal imports to named symbols
        Params: query (optional DLL name filter)
        Returns: {ordinal_imports: [{dll, ordinal, resolved_name}]}

    api_sets - Resolve Windows API Set redirections (api-ms-*)
        Returns: {api_sets: [{virtual_dll, actual_dll}]}

    resolve - Resolve import at specific address or list all imports
        Params: addr (optional - if omitted, lists first 100 imports)
        Returns: {addr, dll, name, type} OR {resolved: [...]}
    """
    try:
        query_matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
        # -1 = qty unavailable (not a real "zero imports"); only a genuine
        # get_import_module_qty()==0 earns the no-import-table note.
        try:
            _nimps = ida_nalt.get_import_module_qty()
        except Exception:
            _nimps = -1
        _NO_IMPORTS_NOTE = "no import table — raw/embedded binary"
        if action == "thunks":
            thunk_lines = []
            is_64 = _inf_bitness() == 64
            stride = 8 if is_64 else 4

            # PE IAT thunk sections.
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if '.idata' in seg_name.lower() or 'iat' in seg_name.lower():
                    seg = _compat.get_segment(seg_ea)
                    if not seg:
                        continue

                    ea = seg.start_ea
                    while ea < seg.end_ea:
                        target = idc.get_qword(ea) if is_64 else idc.get_wide_dword(ea)
                        name = idc.get_name(ea)

                        if name and target:
                            if query_matcher and not query_matcher(name):
                                ea += stride
                                continue

                            thunk_lines.append(f"{hex(ea)}  -> {hex(target)}  {name}")

                        ea += stride

            # ELF PLT thunks (.plt -> .got.plt). No .idata exists on ELF, so
            # without this an ELF binary's thunks would report empty.
            for t in _elf_plt_thunks(query_matcher):
                thunk_lines.append(f"{t['thunk_addr']}  -> {t['target']}  {t['name']}  [{t['dll']}]")

            total = len(thunk_lines)
            page = thunk_lines[offset:offset + count] if count != 0 else thunk_lines[offset:]
            result = {"ok": True, "thunks": "\n".join(page), "total": total, "offset": offset, "count": len(page)}
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        elif action == "delay":
            delay_imports = {}

            # Look for delay import directory
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if 'delay' in seg_name.lower() or '.didat' in seg_name.lower():
                    seg = _compat.get_segment(seg_ea)
                    if seg:
                        ea = seg.start_ea
                        _delay_items = 0
                        _DELAY_MAX = offset + count if count != 0 else 50000
                        while ea < seg.end_ea:
                            name = idc.get_name(ea)
                            if name:
                                parts = name.split('_')
                                if len(parts) >= 2:
                                    dll = parts[0]
                                    if (not query_matcher) or query_matcher(dll) or query_matcher(name):
                                        if dll not in delay_imports:
                                            delay_imports[dll] = []
                                        delay_imports[dll].append(f"{hex(ea)}  {name}")
                                        _delay_items += 1
                                        if _delay_items >= _DELAY_MAX:
                                            break
                            ea = idc.next_head(ea, seg.end_ea)
                            if ea == idaapi.BADADDR:
                                break

            result_lines = []
            for dll, funcs in delay_imports.items():
                result_lines.append(f"[{dll}]")
                for f in funcs[:20]:
                    result_lines.append(f"  {f}")
            page = result_lines[offset:offset + count] if count != 0 else result_lines[offset:]
            result = {"ok": True, "delay_imports": "\n".join(page), "total": len(result_lines), "offset": offset, "count": len(page)}
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        elif action == "forwarded":
            fwd_lines = []

            _FWD_LIMIT = offset + count if count != 0 else 50000
            def imp_cb(ea, name, ordinal):
                if len(fwd_lines) >= _FWD_LIMIT:
                    return False
                if name and '.' in name:
                    parts = name.split('.')
                    if len(parts) == 2:
                        if query_matcher and not query_matcher(name):
                            return True
                        fwd_lines.append(f"{hex(ea)}  {name}  -> {parts[1]}")
                return True

            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name:
                    ida_nalt.enum_import_names(i, imp_cb)

            page = fwd_lines[offset:offset + count] if count != 0 else fwd_lines[offset:]
            result = {"ok": True, "forwarded": "\n".join(page), "total": len(fwd_lines), "offset": offset, "count": len(page),
                      "note": "Limited detection - full analysis requires DLL parsing"}
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        elif action == "ordinal":
            ord_lines = []

            _ORD_LIMIT = offset + count if count != 0 else 50000
            def imp_cb(ea, name, ordinal):
                if len(ord_lines) >= _ORD_LIMIT:
                    return False
                if ordinal and ordinal > 0:
                    ord_lines.append(f"{hex(ea)}  ord={ordinal}  {name or f'Ordinal_{ordinal}'}")
                return True

            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if query_matcher and not query_matcher(mod_name or ""):
                    continue
                ida_nalt.enum_import_names(i, imp_cb)

            page = ord_lines[offset:offset + count] if count != 0 else ord_lines[offset:]
            result = {"ok": True, "ordinal_imports": "\n".join(page), "total": len(ord_lines), "offset": offset, "count": len(page)}
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        elif action == "api_sets":
            set_lines = []

            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                if mod_name and mod_name.lower().startswith('api-ms-'):
                    if query_matcher and not query_matcher(mod_name):
                        continue
                    # Most api-ms-* virtual DLLs redirect to kernelbase; the
                    # CRT family resolves to ucrtbase. Heuristic, not exact.
                    actual = "kernelbase.dll"
                    if 'crt' in mod_name.lower():
                        actual = "ucrtbase.dll"

                    set_lines.append(f"{mod_name}  -> {actual}")

            page = set_lines[offset:offset + count] if count != 0 else set_lines[offset:]
            result = {"ok": True, "api_sets": "\n".join(page), "total": len(set_lines), "offset": offset, "count": len(page),
                      "note": "API Set targets are a heuristic guess, not exact apisetschema resolution"}
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        elif action == "resolve":
            if not addr:
                # Perform batch resolution of all imports from the memoized map.
                resolve_lines = []
                for ea, (_mod_name, resolved_name) in _import_ea_map().items():
                    if query_matcher and not (
                        query_matcher(_mod_name or "") or query_matcher(resolved_name)
                    ):
                        continue
                    resolve_lines.append(f"{hex(ea)}  {_mod_name}  {resolved_name}")
                page = resolve_lines[offset:offset + count] if count != 0 else resolve_lines[offset:]
                result = {"ok": True, "resolved": "\n".join(page), "total": len(resolve_lines), "offset": offset, "count": len(page)}
                if _nimps == 0:
                    result["note"] = _NO_IMPORTS_NOTE
                return result

            ea, err = validate_addr(addr)
            if err: return err
            # O(1) lookup from the memoized ea -> (module, name) map instead of
            # re-enumerating every module's import table per address.
            entry = _import_ea_map().get(ea)
            module = entry[0] if entry else None
            name = entry[1] if entry else (idc.get_name(ea) or "")

            result = {
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "dll": module,
                "type": "import" if module else "unknown",
            }
            if _nimps == 0:
                result["note"] = _NO_IMPORTS_NOTE
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 33. COMMENTS_AI - AI-Optimized Comment Management
# ============================================================================
