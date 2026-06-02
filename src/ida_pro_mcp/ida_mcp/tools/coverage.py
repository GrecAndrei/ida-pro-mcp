try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 39. COVERAGE - Code Coverage Import and Analysis
# ============================================================================


@tool
@idaread
def coverage(
    action: Annotated[
        Literal["import_drcov", "import_lighthouse", "highlight", "report", "uncovered", "filter",
                "function_coverage", "gaps", "compare", "merge"],
        "Action: import_drcov|import_lighthouse|highlight|report|uncovered|filter|function_coverage|gaps|compare|merge",
    ],
    path: Annotated[Optional[str], "Path to coverage file"] = None,
    addr: Annotated[Optional[str], "Function to analyze"] = None,
    color: Annotated[Optional[str], "Highlight color (green|yellow|red)"] = "green",
    addresses: Annotated[Optional[list[str]], "List of addresses to filter (for action=filter)"] = None,
    paths: Annotated[Optional[list[str]], "List of coverage file paths (for merge/compare)"] = None,
    top_n: Annotated[int, "Number of top results to return (for function_coverage/gaps)"] = 20,
    **kwargs,
) -> dict:
    """
    Import and analyze code coverage data from various sources.

    ACTIONS:

    import_drcov - Import DynamoRIO coverage file (.log or .drcov)
        Params: path
        Returns: {imported, modules, basic_blocks}

    import_lighthouse - Import Lighthouse/coverage.py flat text format
        Params: path
        Returns: {imported, addresses}

    highlight - Apply color highlighting to executed items in the IDA viewport
        Params: path (coverage file), color (green|yellow|red)
        Returns: {highlighted, count}

    report - Detailed coverage analysis for a specific function
        Params: addr (optional - defaults to entry point), path (optional coverage data)
        Returns: {function, total_blocks, covered, percentage}

    uncovered - Identify and prioritize important functions without coverage
        Params: path
        Returns: {uncovered: [{name, importance, reason}]}

    filter - Test which of the provided addresses were actually executed
        Params: path (coverage file), addresses (list of hex strings)
        Returns: {executed: [hex_str], count}

    function_coverage - Coverage % for all functions, sorted by coverage (ascending)
        Params: path (optional coverage data), top_n
        Returns: {functions: [{name, addr, total_blocks, covered_blocks, percentage}]}

    gaps - Find largest contiguous uncovered code regions
        Params: path (optional coverage data), top_n
        Returns: {gaps: [{start, end, size, function}]}

    compare - Compare two coverage files (path vs paths[0])
        Params: path (base), paths[0] (compare)
        Returns: {newly_covered, newly_uncovered, unchanged}

    merge - Merge multiple coverage files
        Params: paths (list of coverage files)
        Returns: {merged, total_unique_addresses, sources}
    """
    try:
        import bisect
        import os
        import re
        import struct

        def _parse_num(text: str) -> Optional[int]:
            s = str(text).strip()
            if not s:
                return None
            try:
                return int(s, 0)
            except Exception:
                pass
            if s.lower().startswith("0x"):
                try:
                    return int(s, 16)
                except Exception:
                    return None
            if all(c in "0123456789abcdefABCDEF" for c in s):
                try:
                    return int(s, 16)
                except Exception:
                    return None
            return None

        def _basename_lower(p: str) -> str:
            base = os.path.basename(p or "")
            return base.lower()

        def _parse_drcov(filepath: str):
            if not os.path.exists(filepath):
                return None, "File not found"

            modules = []
            blocks = []

            with open(filepath, "rb") as f:
                first = f.readline().decode("utf-8", errors="ignore").strip()
                if not first.startswith("DRCOV"):
                    return None, "Not a drcov file"

                module_header = None
                while True:
                    raw = f.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if line.startswith("Module Table"):
                        module_header = line
                        break
                if not module_header:
                    return None, "Missing Module Table header"

                m = re.search(r"count\s+([0-9]+)", module_header, re.IGNORECASE)
                if not m:
                    m = re.search(r":\s*([0-9]+)", module_header)
                if not m:
                    return None, "Could not parse module count"
                module_count = int(m.group(1))

                # Optional columns header line
                pos = f.tell()
                maybe_columns = f.readline().decode("utf-8", errors="ignore").strip()
                if not maybe_columns.lower().startswith("columns"):
                    f.seek(pos)

                read_modules = 0
                while read_modules < module_count:
                    raw = f.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 2:
                        continue

                    mod_id = _parse_num(parts[0])
                    if mod_id is None:
                        continue

                    base = None
                    for token in parts[1:5]:
                        num = _parse_num(token)
                        if num is not None:
                            base = num
                            break
                    if base is None:
                        base = 0

                    mod_path = parts[-1] if parts else ""
                    modules.append({"id": int(mod_id), "base": int(base), "path": mod_path})
                    read_modules += 1

                bb_header = None
                while True:
                    raw = f.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if line.startswith("BB Table"):
                        bb_header = line
                        break

                if not bb_header:
                    return None, "Missing BB Table header"

                m = re.search(r"([0-9]+)\s+bbs", bb_header, re.IGNORECASE)
                bb_count = int(m.group(1)) if m else None

                # 8-byte record: start(4), size(2), mod_id(2)
                if bb_count is None:
                    blob = f.read()
                    bb_count = len(blob) // 8
                    f = None
                    for i in range(bb_count):
                        rec = blob[i * 8 : (i + 1) * 8]
                        if len(rec) < 8:
                            continue
                        start, size, mod_id = struct.unpack("<IHH", rec)
                        blocks.append({"start": int(start), "size": int(size), "module_id": int(mod_id)})
                else:
                    for _ in range(bb_count):
                        rec = f.read(8)
                        if len(rec) < 8:
                            break
                        start, size, mod_id = struct.unpack("<IHH", rec)
                        blocks.append({"start": int(start), "size": int(size), "module_id": int(mod_id)})

            return {"modules": modules, "blocks": blocks}, None

        def _module_biases(modules: list[dict]) -> dict[int, Optional[int]]:
            imagebase = int(idaapi.get_imagebase())
            idb_path = idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else ""
            idb_base = _basename_lower(idb_path)
            biases = {}

            # Prefer exact basename match to the loaded input file.
            matched_any = False
            for mod in modules:
                mod_base = int(mod.get("base", 0))
                mod_name = _basename_lower(mod.get("path", ""))
                if idb_base and mod_name and mod_name == idb_base:
                    biases[int(mod.get("id", -1))] = imagebase - mod_base
                    matched_any = True

            if not matched_any:
                if len(modules) == 1:
                    only = modules[0]
                    biases[int(only.get("id", -1))] = imagebase - int(only.get("base", 0))
                else:
                    # Fall back to nearest module base.
                    nearest = None
                    nearest_delta = None
                    for mod in modules:
                        mod_base = int(mod.get("base", 0))
                        delta = abs(mod_base - imagebase)
                        if nearest_delta is None or delta < nearest_delta:
                            nearest_delta = delta
                            nearest = mod
                    if nearest is not None:
                        biases[int(nearest.get("id", -1))] = imagebase - int(nearest.get("base", 0))

            for mod in modules:
                mid = int(mod.get("id", -1))
                biases.setdefault(mid, None)

            return biases

        def _normalize_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
            cleaned = [(int(s), int(e)) for s, e in ranges if int(e) > int(s)]
            if not cleaned:
                return []
            cleaned.sort()
            merged = [cleaned[0]]
            for s, e in cleaned[1:]:
                last_s, last_e = merged[-1]
                if s <= last_e:
                    merged[-1] = (last_s, max(last_e, e))
                else:
                    merged.append((s, e))
            return merged

        def _resolve_drcov_ranges(parsed: dict):
            modules = parsed.get("modules", [])
            blocks = parsed.get("blocks", [])
            mod_map = {int(m.get("id", -1)): m for m in modules}
            biases = _module_biases(modules)
            imagebase = int(idaapi.get_imagebase())

            ranges = []
            unresolved = 0
            mapped = 0

            for blk in blocks:
                size = max(1, int(blk.get("size", 0)))
                mod = mod_map.get(int(blk.get("module_id", -1)))
                if mod is None:
                    unresolved += 1
                    continue

                rel_start = int(blk.get("start", 0))
                mod_base = int(mod.get("base", 0))
                bias = biases.get(int(mod.get("id", -1)))

                candidates = []
                if bias is not None:
                    candidates.append(mod_base + rel_start + int(bias))
                candidates.append(mod_base + rel_start)
                candidates.append(imagebase + rel_start)

                chosen = None
                for cand in candidates:
                    try:
                        if idc.is_mapped(cand):
                            chosen = cand
                            break
                    except Exception:
                        pass
                if chosen is None:
                    chosen = candidates[0]
                    unresolved += 1
                else:
                    mapped += 1

                ranges.append((int(chosen), int(chosen) + size))

            return _normalize_ranges(ranges), {
                "modules": len(modules),
                "blocks": len(blocks),
                "mapped_blocks": mapped,
                "unresolved_blocks": unresolved,
            }

        def _load_coverage(path_value: str):
            # Try text-address coverage first (Lighthouse-like)
            addr_set = set()
            parse_errors = 0
            saw_drcov_magic = False
            with open(path_value, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f):
                    t = line.strip()
                    if not t or t.startswith("#"):
                        continue
                    if idx == 0 and t.startswith("DRCOV"):
                        saw_drcov_magic = True
                        break
                    try:
                        addr_set.add(parse_address(t))
                    except Exception:
                        parse_errors += 1
            if addr_set and not saw_drcov_magic:
                addrs_sorted = sorted(addr_set)
                return {
                    "kind": "addresses",
                    "addresses": addr_set,
                    "ranges": [(ea, ea + 1) for ea in addrs_sorted],
                    "range_starts": addrs_sorted,
                    "source": "text",
                    "parse_errors": parse_errors,
                }, None

            parsed, err = _parse_drcov(path_value)
            if err:
                return None, err
            ranges, stats = _resolve_drcov_ranges(parsed)
            starts = [s for s, _ in ranges]
            return {
                "kind": "ranges",
                "addresses": set(),
                "ranges": ranges,
                "range_starts": starts,
                "source": "drcov",
                "drcov": stats,
                "modules": parsed.get("modules", []),
            }, None

        def _range_has_coverage(start: int, end: int, cov: dict) -> bool:
            if end <= start:
                return False
            if cov.get("kind") == "addresses":
                aset = cov.get("addresses", set())
                span = end - start
                if span <= 4096:
                    for ea in range(start, end):
                        if ea in aset:
                            return True
                    return False
                for ea in idautils.Heads(start, end):
                    if ea in aset:
                        return True
                return False

            ranges = cov.get("ranges", [])
            starts = cov.get("range_starts", [])
            if not ranges:
                return False
            i = bisect.bisect_right(starts, start) - 1
            if i >= 0:
                rs, re_ = ranges[i]
                if re_ > start and rs < end:
                    return True
            j = i + 1
            while 0 <= j < len(ranges):
                rs, re_ = ranges[j]
                if rs >= end:
                    break
                if re_ > start:
                    return True
                j += 1
            return False

        def _addr_covered(ea: int, cov: dict) -> bool:
            return _range_has_coverage(int(ea), int(ea) + 1, cov)

        if action == "filter":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path (coverage file) required")
            if not addresses:
                return make_error(MCPError.INVALID_ARGS, "addresses list required")
            path, err = validate_path_safe(path)
            if err:
                return err
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")

            cov, load_err = _load_coverage(path)
            if load_err:
                return make_error(MCPError.FILE_NOT_FOUND, load_err)

            executed = []
            from ida_pro_mcp.host.intelligence_helpers import coerce_int
            for addr_str in addresses:
                try:
                    ea = coerce_int(addr_str)
                except Exception:
                    continue
                if _addr_covered(ea, cov):
                    executed.append(addr_str)
                    continue
                fn = ida_funcs.get_func(ea)
                if fn and _range_has_coverage(fn.start_ea, fn.end_ea, cov):
                    executed.append(addr_str)

            return {
                "ok": True,
                "path": path,
                "executed": executed,
                "count": len(executed),
                "coverage_source": cov.get("source"),
            }

        if action == "import_drcov":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err:
                return err

            parsed, parse_err = _parse_drcov(path)
            if parse_err:
                return make_error(MCPError.FILE_NOT_FOUND, parse_err)
            ranges, stats = _resolve_drcov_ranges(parsed)

            return {
                "ok": True,
                "imported": True,
                "path": path,
                "modules": stats["modules"],
                "basic_blocks": stats["blocks"],
                "mapped_blocks": stats["mapped_blocks"],
                "unresolved_blocks": stats["unresolved_blocks"],
                "range_count": len(ranges),
                "module_names": [m.get("path", "") for m in parsed.get("modules", [])[:10]],
            }

        elif action == "import_lighthouse":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err:
                return err
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")

            addresses_list = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        try:
                            addresses_list.append(parse_address(t))
                        except Exception:
                            continue

            return {
                "ok": True,
                "imported": True,
                "path": path,
                "addresses": len(addresses_list),
                "unique": len(set(addresses_list)),
            }

        elif action == "highlight":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err:
                return err
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")

            cov, load_err = _load_coverage(path)
            if load_err:
                return make_error(MCPError.FILE_NOT_FOUND, load_err)

            color_map = {"green": 0x90EE90, "yellow": 0x00FFFF, "red": 0x0000FF}
            bgr = color_map.get((color or "green").lower(), 0x90EE90)
            max_paints = max(1, min(int(kwargs.get("max_paints", 200000)), 1_000_000))

            painted = 0
            truncated = False

            if cov.get("kind") == "addresses":
                for ea in sorted(cov.get("addresses", set())):
                    if painted >= max_paints:
                        truncated = True
                        break
                    if idc.is_mapped(ea):
                        idc.set_color(ea, idc.CIC_ITEM, bgr)
                        painted += 1
            else:
                for start, end in cov.get("ranges", []):
                    if painted >= max_paints:
                        truncated = True
                        break
                    any_head = False
                    for ea in idautils.Heads(start, end):
                        any_head = True
                        if painted >= max_paints:
                            truncated = True
                            break
                        if idc.is_mapped(ea):
                            idc.set_color(ea, idc.CIC_ITEM, bgr)
                            painted += 1
                    if not any_head and idc.is_mapped(start):
                        if painted >= max_paints:
                            truncated = True
                            break
                        idc.set_color(start, idc.CIC_ITEM, bgr)
                        painted += 1

            return {
                "ok": True,
                "highlighted": True,
                "count": painted,
                "color": color,
                "truncated": truncated,
                "max_paints": max_paints,
                "coverage_source": cov.get("source"),
            }

        elif action == "report":
            try:
                start_ea = _inf_start_ea()
            except AttributeError:
                import ida_ida

                start_ea = ida_ida.inf_get_start_ea()

            target = addr or hex(start_ea)
            ea = parse_address(target)
            func = ida_funcs.get_func(ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function found at {target}")

            cov = {"kind": "addresses", "addresses": set(), "ranges": [], "range_starts": [], "source": "none"}
            if path:
                path, err = validate_path_safe(path)
                if err:
                    return err
                if not os.path.exists(path):
                    return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")
                loaded, load_err = _load_coverage(path)
                if load_err:
                    return make_error(MCPError.FILE_NOT_FOUND, load_err)
                cov = loaded

            try:
                fc = idaapi.FlowChart(func)
                total = 0
                covered = 0
                blocks = []

                for block in fc:
                    total += 1
                    is_cov = _range_has_coverage(block.start_ea, block.end_ea, cov)
                    if is_cov:
                        covered += 1
                    if len(blocks) < 40:
                        blocks.append({"start": hex(block.start_ea), "end": hex(block.end_ea), "covered": is_cov})

                return {
                    "ok": True,
                    "function": idc.get_func_name(func.start_ea) or hex(func.start_ea),
                    "total_blocks": total,
                    "covered_blocks": covered,
                    "percentage": round((covered / total) * 100, 2) if total else 0.0,
                    "blocks": blocks,
                    "coverage_source": cov.get("source"),
                    "note": "No coverage data loaded" if cov.get("source") == "none" else "",
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Could not analyze function: {e}")

        elif action == "uncovered":
            covered_funcs = set()
            cov = None
            if path:
                safe_path, path_err = validate_path_safe(path)
                if not path_err and os.path.exists(safe_path):
                    loaded, load_err = _load_coverage(safe_path)
                    if not load_err:
                        cov = loaded

            if cov is not None:
                for f_idx, func_ea in enumerate(idautils.Functions()):
                    if f_idx >= 50000:
                        break
                    fn = ida_funcs.get_func(func_ea)
                    if fn and _range_has_coverage(fn.start_ea, fn.end_ea, cov):
                        covered_funcs.add(fn.start_ea)

            uncovered = []
            importance_keywords = ["main", "init", "parse", "process", "handle", "check", "verify"]
            for f_idx, func_ea in enumerate(idautils.Functions()):
                if f_idx >= 50000:
                    break
                if func_ea in covered_funcs:
                    continue
                name = idc.get_func_name(func_ea)
                if not name or name.startswith("sub_"):
                    continue
                importance = "normal"
                reason = ""
                low = name.lower()
                for kw in importance_keywords:
                    if kw in low:
                        importance = "high"
                        reason = f"Contains '{kw}'"
                        break
                uncovered.append({"addr": hex(func_ea), "name": name, "importance": importance, "reason": reason})

            uncovered.sort(key=lambda x: (0 if x["importance"] == "high" else 1, x["name"]))
            return {"ok": True, "uncovered": uncovered[:50], "coverage_loaded": cov is not None}

        elif action == "function_coverage":
            cov = {"kind": "addresses", "addresses": set(), "ranges": [], "range_starts": [], "source": "none"}
            if path:
                path, err = validate_path_safe(path)
                if err:
                    return err
                if not os.path.exists(path):
                    return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")
                loaded, load_err = _load_coverage(path)
                if load_err:
                    return make_error(MCPError.FILE_NOT_FOUND, load_err)
                cov = loaded

            results = []
            for f_idx, func_ea in enumerate(idautils.Functions()):
                if f_idx >= 50000:
                    break
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue
                try:
                    fc = idaapi.FlowChart(fn)
                except Exception:
                    continue
                total = 0
                covered = 0
                for block in fc:
                    total += 1
                    if _range_has_coverage(block.start_ea, block.end_ea, cov):
                        covered += 1
                if total > 0:
                    pct = round((covered / total) * 100, 2)
                    results.append({
                        "name": idc.get_func_name(func_ea) or hex(func_ea),
                        "addr": hex(func_ea),
                        "total_blocks": total,
                        "covered_blocks": covered,
                        "percentage": pct,
                    })

            # Sort by coverage ascending (most uncovered first), then by name
            results.sort(key=lambda x: (x["percentage"], x["name"]))
            return {
                "ok": True,
                "functions": results[:top_n],
                "total_functions": len(results),
                "fully_covered": sum(1 for r in results if r["percentage"] == 100.0),
                "zero_covered": sum(1 for r in results if r["percentage"] == 0.0),
                "coverage_loaded": cov.get("source") != "none",
            }

        elif action == "gaps":
            cov = {"kind": "addresses", "addresses": set(), "ranges": [], "range_starts": [], "source": "none"}
            if path:
                path, err = validate_path_safe(path)
                if err:
                    return err
                if not os.path.exists(path):
                    return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")
                loaded, load_err = _load_coverage(path)
                if load_err:
                    return make_error(MCPError.FILE_NOT_FOUND, load_err)
                cov = loaded

            gaps = []
            for f_idx, func_ea in enumerate(idautils.Functions()):
                if f_idx >= 50000:
                    break
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue
                try:
                    fc = idaapi.FlowChart(fn)
                except Exception:
                    continue
                prev_end = fn.start_ea
                for block in fc:
                    if not _range_has_coverage(block.start_ea, block.end_ea, cov):
                        # This block is uncovered; measure gap from prev_end to block.end_ea
                        # but only if contiguous with previous uncovered blocks
                        gap_start = block.start_ea
                        gap_end = block.end_ea
                        if prev_end > gap_start:
                            gap_start = prev_end
                        if gap_end > gap_start:
                            gaps.append({
                                "start": hex(gap_start),
                                "end": hex(gap_end),
                                "size": int(gap_end - gap_start),
                                "function": idc.get_func_name(func_ea) or hex(func_ea),
                                "func_addr": hex(func_ea),
                            })
                    prev_end = block.end_ea

            gaps.sort(key=lambda x: -x["size"])
            return {
                "ok": True,
                "gaps": gaps[:top_n],
                "total_gap_bytes": sum(g["size"] for g in gaps),
                "coverage_loaded": cov.get("source") != "none",
            }

        elif action == "compare":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path (base coverage file) required")
            if not paths or len(paths) < 1:
                return make_error(MCPError.INVALID_ARGS, "paths[0] (compare coverage file) required")
            base_path, err = validate_path_safe(path)
            if err:
                return err
            cmp_path, err = validate_path_safe(paths[0])
            if err:
                return err
            if not os.path.exists(base_path):
                return make_error(MCPError.FILE_NOT_FOUND, f"Base file not found: {base_path}")
            if not os.path.exists(cmp_path):
                return make_error(MCPError.FILE_NOT_FOUND, f"Compare file not found: {cmp_path}")

            base_cov, base_err = _load_coverage(base_path)
            if base_err:
                return make_error(MCPError.FILE_NOT_FOUND, base_err)
            cmp_cov, cmp_err = _load_coverage(cmp_path)
            if cmp_err:
                return make_error(MCPError.FILE_NOT_FOUND, cmp_err)

            # Build address sets for quick comparison
            def _to_addr_set(cov):
                addrs = set()
                if cov.get("kind") == "addresses":
                    addrs.update(cov.get("addresses", set()))
                else:
                    for start, end in cov.get("ranges", []):
                        # Sample every 16 bytes to keep sets manageable
                        for ea in range(start, end, 16):
                            addrs.add(ea)
                return addrs

            base_addrs = _to_addr_set(base_cov)
            cmp_addrs = _to_addr_set(cmp_cov)

            newly_covered = sorted(cmp_addrs - base_addrs)
            newly_uncovered = sorted(base_addrs - cmp_addrs)
            unchanged = sorted(base_addrs & cmp_addrs)

            return {
                "ok": True,
                "base_path": base_path,
                "compare_path": cmp_path,
                "newly_covered_count": len(newly_covered),
                "newly_uncovered_count": len(newly_uncovered),
                "unchanged_count": len(unchanged),
                "newly_covered": [hex(a) for a in newly_covered[:50]],
                "newly_uncovered": [hex(a) for a in newly_uncovered[:50]],
                "unchanged": [hex(a) for a in unchanged[:50]],
            }

        elif action == "merge":
            if not paths:
                return make_error(MCPError.INVALID_ARGS, "paths (list of coverage files) required")
            merged_addrs = set()
            merged_ranges = []
            sources = []
            for p in paths:
                safe_p, err = validate_path_safe(p)
                if err:
                    continue
                if not os.path.exists(safe_p):
                    continue
                cov, load_err = _load_coverage(safe_p)
                if load_err:
                    continue
                sources.append(safe_p)
                if cov.get("kind") == "addresses":
                    merged_addrs.update(cov.get("addresses", set()))
                else:
                    merged_ranges.extend(cov.get("ranges", []))

            # Merge ranges and deduplicate with address set
            if merged_ranges:
                merged_ranges = _normalize_ranges(merged_ranges)
                for start, end in merged_ranges:
                    for ea in range(start, end, 16):
                        merged_addrs.add(ea)

            return {
                "ok": True,
                "merged": True,
                "sources": sources,
                "total_unique_addresses": len(merged_addrs),
                "total_sources": len(sources),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# END OF DYNAMIC ANALYSIS TOOLS (36-39)
# Total tools: 39
# ============================================================================
