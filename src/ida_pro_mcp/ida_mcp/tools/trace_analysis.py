import contextlib

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

_TRACE_CACHE: list[int] = []
_TRACE_RUNS: dict[str, list[int]] = {}
_TRACE_STATE_SNAPSHOTS: dict[str, dict] = {}
_TRACE_RUNS_MAX = 32
_TRACE_SNAPSHOTS_MAX = 64

# Emulator architecture width. 32-bit x86/ARM/MIPS targets need 32-bit masks.
EMU_ARCH_WIDTH = 64
EMU_ARCH_MASK = (1 << EMU_ARCH_WIDTH) - 1

# Hardcoded address windows used by the emulator. Extracted from the
# TinyEmulator implementation so the collision risk is visible at module level.
EMU_DUMMY_ARG_BASE = 0x10000000
EMU_DUMMY_ARG_STRIDE = 0x10000000
EMU_DUMMY_ARG_TOP = 0x70000000
EMU_STACK_BASE = 0x7f000000
EMU_STACK_TOP = 0x80000000
EMU_STACK_INIT_RSP = 0x7ffffff0

# x86 move-like mnemonics that anti-analysis PEB/TEB checks rely on.
# The shared MOV_MNEMONICS set from arch_utils.py only lists 'mov' and
# 'movabs' for x86, but PEB access patterns also use zero/sign-extend
# moves (movzx, movsx, movsxd), byte-swapped moves (movbe) and the
# aligned/unaligned SIMD/FP moves. Local set used by anti_analysis_detect.
PEB_RELEVANT_MOV_MNEMONICS = {
    "MOV", "MOVABS",
    "MOVZX", "MOVSX", "MOVSXD", "MOVBE",
    "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD",
    "MOVDQA", "MOVDQU", "MOVNTI", "MOVNTPS",
    "XCHG", "CMOVZ", "CMOVE", "CMOVNZ", "CMOVNE",
}


def safe_get_byte(ea: int):
    """Read one byte from the IDB, returning None for unmapped addresses.

    ida_bytes.get_byte() returns 0xff for unmapped addresses which the
    emulator previously consumed as data. Returning None lets the read
    path distinguish "no data" from "byte happens to be 0xff".
    """
    try:
        import ida_bytes
    except Exception:
        return None
    try:
        if not ida_bytes.is_loaded(ea):
            return None
    except Exception:
        return None
    try:
        return ida_bytes.get_byte(ea)
    except Exception:
        return None


# ============================================================================
# 36. TRACE_ANALYSIS - Post-mortem execution trace analysis
# ============================================================================

@tool
@idaread
def trace_analysis(
    action: Annotated[
        Literal[
            "import_trace",
            "analyze_coverage",
            "find_loops",
            "extract_api_calls",
            "basic_blocks_hit",
            "execution_timeline_graph",
            "cross_run_diff",
            "coverage_debug_plan",
            "anti_analysis_detect",
            "trace_entropy",
            "api_sequence",
            "loop_analysis",
            "get",
            "clear",
            "set_options",
            "static_trace",
            "decrypt_strings",
            "eval_expr",
            "deobfuscate_emulate",
            "prefetch_context",
        ],
        "Action: import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit|execution_timeline_graph|cross_run_diff|coverage_debug_plan|anti_analysis_detect|trace_entropy|api_sequence|loop_analysis|get|clear|set_options|static_trace|decrypt_strings|eval_expr|deobfuscate_emulate|prefetch_context",
    ],
    path: Annotated[Optional[str], "Path to trace file"] = None,
    addr: Annotated[Optional[str], "Function or address to analyze"] = None,
    trace_data: Annotated[Optional[list], "List of executed addresses"] = None,
    count: Annotated[int, "Max trace entries to return (action=get)"] = 1000,
    enable_insn: Annotated[Optional[bool], "Enable instruction tracing (action=set_options)"] = None,
    enable_func: Annotated[Optional[bool], "Enable function tracing (action=set_options)"] = None,
    enable_bblk: Annotated[Optional[bool], "Enable basic block tracing (action=set_options)"] = None,
    max_steps: Annotated[int, "Max instructions in static_trace"] = 1000,
    follow_calls: Annotated[bool, "Follow call edges in static_trace"] = False,
    max_depth: Annotated[int, "Max call depth in static_trace"] = 1,
    include_blocks: Annotated[bool, "Include basic block CFG info in static_trace"] = True,
    expr: Annotated[Optional[str], "Expression for eval_expr"] = None,
    **kwargs
) -> dict:
    """
    Post-mortem execution trace analysis and runtime/static trace utilities.

    Actions:
    - import_trace: Load a list of addresses from a file or 'trace_data' parameter.
    - analyze_coverage: Calculate global basic block coverage based on the current trace.
    - find_loops: Identify the most frequently executed code regions (hot spots).
    - extract_api_calls: Find and count imported API calls matching the trace.
    - basic_blocks_hit: Per-function block-level coverage analysis.
        Params: addr (optional - defaults to entry point)
    - execution_timeline_graph: Merge trace flow + APIs + coverage + breakpoints + memory events into a timeline graph.
    - cross_run_diff: Compare two traces (run IDs or explicit lists) and report divergences with semantic comparison.
    - coverage_debug_plan: Recommend next breakpoints/watchpoints to maximize novel coverage.
    - anti_analysis_detect: Detect anti-debug/anti-VM/timing/environment checks, debug register accesses, and VM instructions in traces.
    - trace_entropy: Find high-entropy execution regions (crypto/packing) using address and instruction entropy.
    - api_sequence: Extract ordered API call sequences from trace for behavioral analysis.
    - loop_analysis: Detailed loop iteration counts, back-edge detection, hot spot identification, and nesting analysis.
    - get: Read current execution trace entries (IDA debugger runtime trace).
    - clear: Clear the runtime execution trace.
    - set_options: Configure runtime trace options (enable_insn/enable_func/enable_bblk).
    - static_trace: Statically walk control flow from addr (no register changes), with optional call following.
    - decrypt_strings: Heuristic search for string-decryption calls reaching addr.
    - eval_expr: Evaluate an IDC expression, or dump memory at addr.
    """
    try:
        import bisect
        import math
        from collections import Counter, defaultdict

        def _parse_addrs(values):
            parsed = []
            for a in values:
                try:
                    parsed.append(int(str(a), 0))
                except (ValueError, TypeError):
                    continue
            return parsed

        def _trace_from_runtime(limit: int = 200000) -> list[int]:
            try:
                import ida_dbg
            except Exception:
                return []
            has_tev = all(
                hasattr(ida_dbg, attr)
                for attr in ("tev_t", "get_tev_qty", "get_tev_info")
            )
            if not has_tev:
                return []
            out = []
            try:
                qty = min(int(ida_dbg.get_tev_qty()), int(limit))
                tev = ida_dbg.tev_t()
                for i in range(qty):
                    if ida_dbg.get_tev_info(i, tev):
                        out.append(int(tev.ea))
            except Exception:
                return []
            return out

        def _resolve_run_trace(run_name: Optional[str], fallback: Optional[list[int]] = None) -> list[int]:
            if run_name:
                return list(_TRACE_RUNS.get(str(run_name), []))
            return list(fallback) if fallback else []

        def _cache_run_trace(run_name: Optional[str], values: list[int]) -> None:
            if not run_name:
                return
            key = str(run_name)
            if key in _TRACE_RUNS:
                _TRACE_RUNS.pop(key, None)
            _TRACE_RUNS[key] = list(values)
            while len(_TRACE_RUNS) > _TRACE_RUNS_MAX:
                oldest = next(iter(_TRACE_RUNS))
                _TRACE_RUNS.pop(oldest, None)

        def _cache_snapshot(snapshot_id: str, payload: dict) -> None:
            if snapshot_id in _TRACE_STATE_SNAPSHOTS:
                _TRACE_STATE_SNAPSHOTS.pop(snapshot_id, None)
            _TRACE_STATE_SNAPSHOTS[snapshot_id] = payload
            while len(_TRACE_STATE_SNAPSHOTS) > _TRACE_SNAPSHOTS_MAX:
                oldest = next(iter(_TRACE_STATE_SNAPSHOTS))
                _TRACE_STATE_SNAPSHOTS.pop(oldest, None)

        def _compress_trace(trace_list: list[int]) -> list[dict]:
            """Run-length encode consecutive duplicate addresses for compact storage."""
            if not trace_list:
                return []
            compressed = []
            current = int(trace_list[0])
            count = 1
            for ea in trace_list[1:]:
                ea = int(ea)
                if ea == current:
                    count += 1
                else:
                    compressed.append({"addr": current, "count": count})
                    current = ea
                    count = 1
            compressed.append({"addr": current, "count": count})
            return compressed

        def _decompress_trace(compressed: list[dict]) -> list[int]:
            out = []
            for row in compressed:
                out.extend([int(row["addr"])] * int(row.get("count", 1)))
            return out

        def load_trace(run_id: Optional[str] = None, compress: bool = False):
            nonlocal trace_data
            global _TRACE_CACHE
            if trace_data and isinstance(trace_data, list):
                parsed = _parse_addrs(trace_data)
                if compress:
                    parsed = _decompress_trace(parsed) if parsed and isinstance(parsed[0], dict) else parsed
                _TRACE_CACHE = parsed
                _cache_run_trace(run_id, _TRACE_CACHE)
                return list(_TRACE_CACHE)
            if path:
                p, err = validate_path_safe(path)
                if err:
                    return []
                addrs = []
                with open(p) as f:
                    for line in f:
                        try:
                            val = line.strip()
                            if val.startswith('{'):
                                import json
                                row = json.loads(val)
                                addrs.extend([int(row["addr"])] * int(row.get("count", 1)))
                            else:
                                addrs.append(int(val, 0))
                        except Exception:
                            pass
                if compress:
                    addrs = _decompress_trace(addrs) if addrs and isinstance(addrs[0], dict) else addrs
                _TRACE_CACHE = addrs
                _cache_run_trace(run_id, _TRACE_CACHE)
                return list(addrs)
            if _TRACE_CACHE:
                _cache_run_trace(run_id, _TRACE_CACHE)
                return list(_TRACE_CACHE)
            runtime_trace = _trace_from_runtime()
            if runtime_trace:
                _TRACE_CACHE = runtime_trace
                _cache_run_trace(run_id, _TRACE_CACHE)
                return list(runtime_trace)
            return []

        def _has_hit(sorted_hits, start_ea: int, end_ea: int) -> bool:
            idx = bisect.bisect_left(sorted_hits, start_ea)
            return idx < len(sorted_hits) and sorted_hits[idx] < end_ea

        def _trace_pairs(trace_list: list[int]) -> set[tuple[int, int]]:
            if len(trace_list) < 2:
                return set()
            return {(int(trace_list[i]), int(trace_list[i + 1])) for i in range(len(trace_list) - 1)}

        def _ea_name(ea: int) -> str:
            try:
                return idc.get_name(ea) or idc.get_func_name(ea) or ""
            except Exception:
                return ""

        def _ea_func_name(ea: int) -> str:
            try:
                f = ida_funcs.get_func(ea)
                return idc.get_func_name(f.start_ea) if f else ""
            except Exception:
                return ""

        def _safe_debug_state():
            try:
                import ida_dbg
            except Exception:
                return {"available": False, "reason": "ida_dbg unavailable"}
            if not bool(getattr(ida_dbg, "is_debugger_on", lambda: False)()):
                return {"available": False, "reason": "debugger not active"}
            ip = None
            try:
                ip = int(ida_dbg.get_ip_val())
            except Exception:
                ip = None
            regs = {}
            for reg_name in ("RIP", "EIP", "PC", "RSP", "ESP", "SP", "RBP", "EBP", "FP"):
                try:
                    rv = ida_dbg.get_reg_val(reg_name)
                    if isinstance(rv, int):
                        regs[reg_name] = int(rv)
                except Exception:
                    continue
            return {"available": True, "ip": ip, "regs": regs}

        def _get_insn_mnemonic(ea: int) -> str:
            try:
                return idc.print_insn_mnem(ea) or ""
            except Exception:
                return ""

        def _get_insn_bytes(ea: int, size: int = 16) -> bytes:
            try:
                return ida_bytes.get_bytes(ea, size) or b""
            except Exception:
                return b""

        def _shannon_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            freq = Counter(data)
            length = len(data)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy

        def _windowed_entropy(values: list[int], window: int = 64) -> list[dict]:
            if len(values) < window:
                return []
            regions = []
            # Detect target endianness to avoid data corruption on big-endian archs
            try:
                _endian = "big" if _inf_is_be() else "little"
            except Exception:
                _endian = "little"
            for i in range(0, len(values) - window + 1, window // 2):
                chunk = values[i:i + window]
                # Address transition entropy
                diffs = [abs(int(chunk[j + 1]) - int(chunk[j])) for j in range(len(chunk) - 1)]
                diff_bytes = b"".join(d.to_bytes(8, _endian, signed=True) for d in diffs)
                addr_entropy = _shannon_entropy(diff_bytes)
                # Instruction byte entropy
                insn_bytes = b""
                for ea in chunk:
                    insn_bytes += _get_insn_bytes(int(ea), 16)
                insn_entropy = _shannon_entropy(insn_bytes)
                regions.append({
                    "start_idx": i,
                    "end_idx": i + window,
                    "addr_entropy": round(addr_entropy, 3),
                    "insn_entropy": round(insn_entropy, 3),
                    "avg_addr": hex(sum(int(x) for x in chunk) // len(chunk)),
                })
            return regions

        def _get_api_calls_ordered(trace_list: list[int], max_xrefs: int = 5000) -> list[dict]:
            apis = []
            xref_count = 0
            for idx, ea in enumerate(trace_list):
                try:
                    for xref in idautils.XrefsFrom(ea):
                        if xref_count >= max_xrefs:
                            break
                        xref_count += 1
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                category = API_TO_CATEGORY.get(callee, "unknown")
                                apis.append({
                                    "idx": idx,
                                    "addr": hex(ea),
                                    "api": callee,
                                    "category": category,
                                    "to": hex(xref.to),
                                })
                    if xref_count >= max_xrefs:
                        break
                except Exception:
                    pass
            return apis

        def _detect_back_edges(trace_list: list[int]) -> list[dict]:
            """Detect loop back-edges by finding transitions to previously seen addresses within a function."""
            loops = []
            func_history = defaultdict(list)  # func_start -> list of (idx, ea)
            for idx, ea in enumerate(trace_list):
                try:
                    f = ida_funcs.get_func(ea)
                    fstart = int(f.start_ea) if f else None
                except Exception:
                    fstart = None
                if fstart is None:
                    continue
                history = func_history[fstart]
                # Find if we've been near this address before in the same function
                for prev_idx, prev_ea in reversed(history[-20:]):
                    if int(ea) == int(prev_ea) and idx - prev_idx > 1:
                        loops.append({
                            "func": _ea_name(fstart),
                            "func_addr": hex(fstart),
                            "back_edge_to": hex(ea),
                            "back_edge_from": hex(trace_list[idx - 1]) if idx > 0 else None,
                            "iteration_start_idx": prev_idx,
                            "iteration_end_idx": idx,
                            "iteration_length": idx - prev_idx,
                        })
                        break
                history.append((idx, ea))
            return loops

        def _extract_dangerous_apis_in_trace(trace_list: list[int], max_xrefs: int = 5000) -> list[dict]:
            dangerous = []
            xref_count = 0
            for idx, ea in enumerate(trace_list):
                try:
                    for xref in idautils.XrefsFrom(ea):
                        if xref_count >= max_xrefs:
                            break
                        xref_count += 1
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and callee in DANGEROUS_APIS:
                                dangerous.append({
                                    "idx": idx,
                                    "addr": hex(ea),
                                    "api": callee,
                                    "severity": DANGEROUS_APIS.get(callee, "medium"),
                                })
                    if xref_count >= max_xrefs:
                        break
                except Exception:
                    pass
            return dangerous

        if action == "import_trace":
            run_id = kwargs.get("run_id")
            compress = bool(kwargs.get("compress", False))
            if not path and trace_data is None and not _TRACE_CACHE:
                return make_error(MCPError.INVALID_ARGS, "path or trace_data required")
            addrs = load_trace(run_id=str(run_id) if run_id is not None else None, compress=compress)
            result = {
                "ok": True,
                "path": path,
                "count": len(addrs),
                "unique": len(set(addrs)),
                "source": "runtime" if (not path and not trace_data and addrs) else ("cache" if (not path and not trace_data) else "input"),
            }
            if run_id is not None:
                result["run_id"] = str(run_id)
            if compress:
                compressed = _compress_trace(addrs)
                result["compressed_count"] = len(compressed)
                result["compression_ratio"] = round(len(addrs) / max(len(compressed), 1), 2)
            return result

        elif action == "analyze_coverage":
            trace_list = load_trace()
            if not trace_list:
                return {
                    "ok": True,
                    "total": 0,
                    "hit": 0,
                    "pct": 0.0,
                    "note": "No trace data loaded. Use import_trace(path=...) or pass trace_data.",
                }
            trace_set = set(trace_list)
            trace_sorted = sorted(trace_set)

            total_blocks, hit_blocks = 0, 0
            _max_funcs = int(kwargs.get("max_functions", 50000))
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _max_funcs:
                    break
                func = idaapi.get_func(ea)
                if not func: continue
                for block in idaapi.FlowChart(func):
                    total_blocks += 1
                    if _has_hit(trace_sorted, block.start_ea, block.end_ea):
                        hit_blocks += 1

            return {"ok": True, "total": total_blocks, "hit": hit_blocks, "pct": round(hit_blocks/total_blocks*100, 2) if total_blocks else 0}

        elif action == "find_loops":
            # Requires full list for frequency
            t_list = list(load_trace())
            if not t_list:
                return {"ok": True, "hot_spots": [], "count": 0, "note": "No trace data loaded."}
            loops = []
            for ea, count in Counter(t_list).most_common(20):
                if count > 5:
                    f = ida_funcs.get_func(ea)
                    loops.append({"addr": hex(ea), "hits": count, "func": idc.get_func_name(f.start_ea) if f else None})
            return {"ok": True, "hot_spots": loops, "count": len(loops)}

        elif action == "extract_api_calls":
            trace_set = set(load_trace())
            if not trace_set:
                return {"ok": True, "api_calls": [], "count": 0, "note": "No trace data loaded."}
            calls = []
            xref_count = 0
            max_xrefs = int(kwargs.get("max_xrefs", 100000))
            for ea in trace_set:
                for xref in idautils.XrefsFrom(ea):
                    if xref_count >= max_xrefs:
                        break
                    xref_count += 1
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        name = idc.get_name(xref.to)
                        if name and not name.startswith("sub_"):
                            calls.append(name)
                if xref_count >= max_xrefs:
                    break
            api_calls = Counter(calls).most_common(50)
            return {"ok": True, "api_calls": api_calls, "count": len(api_calls)}

        elif action == "basic_blocks_hit":
            trace_set = set(load_trace())
            trace_sorted = sorted(trace_set)

            # Entry point resolution compatible with IDA 7.x-9.x
            try:
                start_ea = _inf_start_ea()
            except AttributeError:
                import ida_ida
                start_ea = ida_ida.inf_get_start_ea()

            target = addr or hex(start_ea)
            ea, err = validate_addr(target, require_func=True)
            if err: return err

            blocks = []
            for block in idaapi.FlowChart(ida_funcs.get_func(ea)):
                hit = _has_hit(trace_sorted, block.start_ea, block.end_ea)
                blocks.append({"start": hex(block.start_ea), "end": hex(block.end_ea), "hit": hit})
            result = {"ok": True, "function": idc.get_func_name(ea), "blocks": blocks}
            if not trace_set:
                result["note"] = "No trace data loaded. All blocks are marked as not hit."
            return result

        elif action == "execution_timeline_graph":
            run_id = kwargs.get("run_id")
            timeline_limit = max(1, int(kwargs.get("timeline_limit", 2000)))
            compress = bool(kwargs.get("compress", False))
            trace_list = _resolve_run_trace(str(run_id), load_trace(run_id=str(run_id) if run_id is not None else None))
            if not trace_list:
                return {"ok": True, "timeline": [], "nodes": [], "edges": [], "count": 0, "note": "No trace data loaded."}

            # Apply compression for long traces
            if compress and len(trace_list) > timeline_limit:
                compressed = _compress_trace(trace_list)
                # Expand back to unique timeline events but preserve counts
                trace_trimmed = []
                for row in compressed[:timeline_limit]:
                    trace_trimmed.append(row["addr"])
            else:
                trace_trimmed = trace_list[:timeline_limit]

            events = []
            nodes = []
            edges = []
            seen_nodes = set()
            hits = set(trace_trimmed)
            api_hits = []
            _tl_xref_limit = int(kwargs.get("timeline_xref_limit", 20000))
            _tl_xref_count = 0
            for idx, ea in enumerate(trace_trimmed):
                event = {"idx": idx, "t": idx, "type": "trace", "addr": hex(ea)}
                name = _ea_name(ea)
                if name:
                    event["name"] = name
                try:
                    for xref in idautils.XrefsFrom(ea):
                        if _tl_xref_count >= _tl_xref_limit:
                            break
                        _tl_xref_count += 1
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                api_event = {"idx": idx, "t": idx, "type": "api_call", "from": hex(ea), "to": hex(xref.to), "name": callee}
                                api_hits.append(api_event)
                    if _tl_xref_count >= _tl_xref_limit:
                        break
                except Exception:
                    pass
                events.append(event)
                if ea not in seen_nodes:
                    nodes.append({"id": hex(ea), "kind": "trace_addr", "covered": True})
                    seen_nodes.add(ea)
                if idx > 0:
                    prev = trace_trimmed[idx - 1]
                    edges.append({"source": hex(prev), "target": hex(ea), "kind": "flow"})

            events.extend(api_hits)
            bp_rows = []
            try:
                import ida_dbg
                for i in range(int(ida_dbg.get_bpt_qty())):
                    bpt = ida_dbg.bpt_t()
                    if ida_dbg.getn_bpt(i, bpt):
                        bp_rows.append({"type": "breakpoint", "addr": hex(int(bpt.ea)), "enabled": bool(bpt.is_enabled())})
            except Exception:
                pass
            events.extend(bp_rows)

            mem_writes = kwargs.get("memory_writes") or []
            for row in mem_writes:
                try:
                    wa = int(str(row.get("addr")), 0)
                except Exception:
                    continue
                events.append({"type": "mem_write", "addr": hex(wa), "size": int(row.get("size", 1)), "idx": row.get("idx")})
                if wa not in seen_nodes:
                    nodes.append({"id": hex(wa), "kind": "memory_write", "covered": wa in hits})
                    seen_nodes.add(wa)

            events.sort(key=lambda x: (int(x.get("t", x.get("idx", 0) or 0)), str(x.get("type", ""))))
            return {
                "ok": True,
                "run_id": str(run_id) if run_id is not None else None,
                "timeline": events,
                "nodes": nodes,
                "edges": edges,
                "count": len(events),
                "trace_points": len(trace_trimmed),
                "api_calls": len(api_hits),
                "compressed": compress,
            }

        elif action == "cross_run_diff":
            run_a = kwargs.get("run_a")
            run_b = kwargs.get("run_b")
            raw_trace_a = kwargs.get("trace_a")
            raw_trace_b = kwargs.get("trace_b")
            compare_with = kwargs.get("compare_with")
            semantic = bool(kwargs.get("semantic", True))
            has_trace_a = raw_trace_a is not None or run_a is not None
            has_trace_b = raw_trace_b is not None or run_b is not None or compare_with is not None
            if not has_trace_a or not has_trace_b:
                return make_error(MCPError.INVALID_ARGS, "cross_run_diff requires two traces (run IDs or trace_a/trace_b)")
            trace_a = _parse_addrs(raw_trace_a) if isinstance(raw_trace_a, list) else _resolve_run_trace(str(run_a) if run_a is not None else None)
            trace_b = _parse_addrs(raw_trace_b) if isinstance(raw_trace_b, list) else _resolve_run_trace(str(run_b) if run_b is not None else None)
            if not trace_a:
                trace_a = load_trace(run_id=str(run_a) if run_a is not None else None)
            if not trace_b:
                trace_b = _resolve_run_trace(str(compare_with) if compare_with is not None else None)

            set_a, set_b = set(trace_a), set(trace_b)
            pairs_a, pairs_b = _trace_pairs(trace_a), _trace_pairs(trace_b)
            only_a = sorted(set_a - set_b)
            only_b = sorted(set_b - set_a)
            transitions_only_a = sorted(pairs_a - pairs_b)
            transitions_only_b = sorted(pairs_b - pairs_a)
            overlap = len(set_a & set_b)
            denom = max(len(set_a | set_b), 1)
            similarity = round(overlap / denom, 4)

            result = {
                "ok": True,
                "run_a": str(run_a) if run_a is not None else "trace_a",
                "run_b": str(run_b) if run_b is not None else "trace_b",
                "a_only_addrs": [hex(x) for x in only_a[:500]],
                "b_only_addrs": [hex(x) for x in only_b[:500]],
                "a_only_transitions": [{"from": hex(x), "to": hex(y)} for (x, y) in transitions_only_a[:500]],
                "b_only_transitions": [{"from": hex(x), "to": hex(y)} for (x, y) in transitions_only_b[:500]],
                "summary": {
                    "a_unique": len(set_a),
                    "b_unique": len(set_b),
                    "overlap": overlap,
                    "similarity": similarity,
                },
            }

            if semantic:
                # Function-level semantic diff
                funcs_a = Counter()
                funcs_b = Counter()
                apis_a = []
                apis_b = []
                for ea in trace_a:
                    fn = _ea_func_name(ea)
                    if fn:
                        funcs_a[fn] += 1
                for ea in trace_b:
                    fn = _ea_func_name(ea)
                    if fn:
                        funcs_b[fn] += 1
                _diff_xref_limit = int(kwargs.get("diff_xref_limit", 50000))
                _diff_xref_count = 0
                for _idx, ea in enumerate(trace_a):
                    if _diff_xref_count >= _diff_xref_limit:
                        break
                    for xref in idautils.XrefsFrom(ea):
                        if _diff_xref_count >= _diff_xref_limit:
                            break
                        _diff_xref_count += 1
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                apis_a.append(callee)
                for _idx, ea in enumerate(trace_b):
                    if _diff_xref_count >= _diff_xref_limit:
                        break
                    for xref in idautils.XrefsFrom(ea):
                        if _diff_xref_count >= _diff_xref_limit:
                            break
                        _diff_xref_count += 1
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                apis_b.append(callee)

                func_set_a = set(funcs_a.keys())
                func_set_b = set(funcs_b.keys())
                api_set_a = set(apis_a)
                api_set_b = set(apis_b)

                # Find first divergence point
                divergence_idx = None
                divergence_addr = None
                for i in range(min(len(trace_a), len(trace_b))):
                    if int(trace_a[i]) != int(trace_b[i]):
                        divergence_idx = i
                        divergence_addr = hex(trace_a[i])
                        break

                result["semantic"] = {
                    "functions_only_a": sorted(func_set_a - func_set_b)[:100],
                    "functions_only_b": sorted(func_set_b - func_set_a)[:100],
                    "functions_common": sorted(func_set_a & func_set_b)[:100],
                    "apis_only_a": sorted(api_set_a - api_set_b)[:100],
                    "apis_only_b": sorted(api_set_b - api_set_a)[:100],
                    "apis_common": sorted(api_set_a & api_set_b)[:100],
                    "function_call_counts_a": dict(funcs_a.most_common(50)),
                    "function_call_counts_b": dict(funcs_b.most_common(50)),
                    "divergence_idx": divergence_idx,
                    "divergence_addr": divergence_addr,
                    "trace_a_length": len(trace_a),
                    "trace_b_length": len(trace_b),
                }
            return result




        elif action == "coverage_debug_plan":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            trace_set = set(trace_list)
            ranked = []
            _max_funcs = int(kwargs.get("max_functions", 50000))
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _max_funcs:
                    break
                try:
                    f = ida_funcs.get_func(ea)
                    if not f:
                        continue
                    blocks = list(idaapi.FlowChart(f))
                    if not blocks:
                        continue
                    total = len(blocks)
                    hit = sum(1 for b in blocks if any((x >= b.start_ea and x < b.end_ea) for x in trace_set))
                    pct = (hit / total) if total else 0.0
                    if pct >= 1.0:
                        continue
                    ranked.append({
                        "addr": int(ea),
                        "name": idc.get_func_name(ea),
                        "coverage": round(pct * 100.0, 2),
                        "novelty": round((1.0 - pct) * total, 2),
                        "blocks_total": total,
                        "blocks_hit": hit,
                    })
                except Exception:
                    continue
            ranked.sort(key=lambda x: (x["novelty"], x["blocks_total"]), reverse=True)
            top = ranked[: int(kwargs.get("limit", 25))]
            breakpoints = [{"action": "add_bp", "addr": hex(x["addr"]), "reason": f"coverage={x['coverage']}%"} for x in top]
            return {"ok": True, "targets": [{**x, "addr": hex(x["addr"])} for x in top], "breakpoint_plan": breakpoints}


        elif action == "anti_analysis_detect":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            trace_set = set(trace_list)
            suspicious_apis = {
                "debugger": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "DebugActiveProcess"),
                "timing": ("QueryPerformanceCounter", "GetTickCount", "GetTickCount64", "timeGetTime", "NtQueryPerformanceCounter"),
                "environment": ("GetModuleHandle", "GetProcAddress", "GetAdaptersInfo", "GetSystemInfo", "GlobalMemoryStatusEx"),
                "vm": ("VBox", "vmware", "qemu", "wine", "virtualbox", "xen"),
                "process": ("CreateToolhelp32Snapshot", "Process32First", "Process32Next", "NtQuerySystemInformation"),
            }
            findings = []
            names = []
            for ea in trace_set:
                nm = _ea_name(ea)
                if nm:
                    names.append(nm)
            names_blob = " ".join(names).lower()
            for family, patterns in suspicious_apis.items():
                hits = [p for p in patterns if p.lower() in names_blob]
                if hits:
                    findings.append({"family": family, "hits": hits, "count": len(hits), "type": "api"})

            # Instruction-level detection
            timing_insns = []
            debug_reg_insns = []
            vm_insns = []
            peb_checks = []
            hw_bp_checks = []
            for ea in trace_set:
                try:
                    mnem = _get_insn_mnemonic(ea).upper()
                    # Timing checks
                    if mnem in ("RDTSC", "RDTSCP"):
                        timing_insns.append({"addr": hex(ea), "mnem": mnem, "type": "timing_insn"})
                    # Debug register accesses
                    ops = [idc.print_operand(ea, i) for i in range(2)]
                    for op in ops:
                        if op and any(dr in op.upper() for dr in ("DR0", "DR1", "DR2", "DR3", "DR6", "DR7")):
                            debug_reg_insns.append({"addr": hex(ea), "mnem": mnem, "operand": op, "type": "debug_reg_access"})
                            break
                    # CPUID (VM detection leafs)
                    if mnem == "CPUID":
                        vm_insns.append({"addr": hex(ea), "mnem": mnem, "type": "cpuid", "note": "check for hypervisor leaf 0x40000000"})
                    # PEB checks (common anti-debug: mov eax, fs:[30h]; cmp byte ptr [eax+2], 0)
                    if mnem in PEB_RELEVANT_MOV_MNEMONICS:
                        disasm = idc.generate_disasm_line(ea, 0) or ""
                        if "fs:[0x30]" in disasm or "gs:[0x60]" in disasm or "PEB" in disasm.upper():
                            peb_checks.append({"addr": hex(ea), "mnem": mnem, "disasm": disasm, "type": "peb_access"})
                    # Hardware breakpoint checks via CONTEXT.DebugRegisters
                    disasm = idc.generate_disasm_line(ea, 0) or ""
                    if any(x in disasm.lower() for x in ("debugreg", "context", "exception", "vectored")):
                        hw_bp_checks.append({"addr": hex(ea), "mnem": mnem, "disasm": disasm, "type": "hw_bp_check"})
                    # VM detection via IN/OUT instructions (e.g., VMWare backdoor)
                    if mnem in ("IN", "OUT"):
                        vm_insns.append({"addr": hex(ea), "mnem": mnem, "type": "io_port", "note": "potential VM backdoor"})
                except Exception:
                    pass

            all_insn_findings = timing_insns + debug_reg_insns + vm_insns + peb_checks + hw_bp_checks
            for f in all_insn_findings:
                findings.append(f)

            # Timing loop detection: tight RDTSC loops
            if timing_insns:
                for t in timing_insns:
                    t_addr = int(t["addr"], 0)
                    # Check if RDTSC is followed by another RDTSC or in a loop
                    if t_addr in trace_list:
                        idx = trace_list.index(t_addr)
                        if idx > 0 and idx < len(trace_list) - 1:
                            prev_dist = abs(int(trace_list[idx]) - int(trace_list[idx - 1]))
                            next_dist = abs(int(trace_list[idx + 1]) - int(trace_list[idx]))
                            if prev_dist < 32 or next_dist < 32:
                                t["timing_loop"] = True

            api_families = len([f for f in findings if f.get("type") == "api"])
            insn_families = len([f for f in findings if f.get("type") != "api"])
            total_indicators = api_families + insn_families
            # Adaptive confidence from observed indicator balance/intensity.
            api_ratio = (api_families / total_indicators) if total_indicators > 0 else 0.0
            insn_ratio = (insn_families / total_indicators) if total_indicators > 0 else 0.0
            confidence_signal = (
                min(1.0, total_indicators / max(1.0, total_indicators + 4.0))
                + api_ratio
                + insn_ratio
            ) / 3.0
            if confidence_signal >= 0.67:
                confidence = "high"
            elif confidence_signal >= 0.34:
                confidence = "medium"
            else:
                confidence = "low"

            return {
                "ok": True,
                "confidence": confidence,
                "findings": findings[:200],
                "observed_symbol_count": len(names),
                "timing_instructions": timing_insns[:50],
                "debug_register_accesses": debug_reg_insns[:50],
                "vm_instructions": vm_insns[:50],
                "peb_checks": peb_checks[:50],
                "hw_bp_checks": hw_bp_checks[:50],
                "summary": {
                    "api_families": api_families,
                    "instruction_indicators": insn_families,
                    "total_findings": len(findings),
                },
            }



        elif action == "trace_entropy":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "regions": [], "note": "No trace data loaded."}
            window = max(16, int(kwargs.get("window", 64)))
            regions = _windowed_entropy(trace_list, window=window)
            insn_vals = sorted(float(r.get("insn_entropy", 0.0) or 0.0) for r in regions)
            addr_vals = sorted(float(r.get("addr_entropy", 0.0) or 0.0) for r in regions)
            if regions:
                iq = int(round((len(regions) - 1) * 0.75))
                mq = len(regions) // 2
                insn_q50 = insn_vals[mq]
                insn_q75 = insn_vals[min(len(insn_vals) - 1, iq)]
                addr_q50 = addr_vals[mq]
                addr_q75 = addr_vals[min(len(addr_vals) - 1, iq)]
                default_gate = max(insn_q50 + max(0.0, insn_q75 - insn_q50), addr_q50 + max(0.0, addr_q75 - addr_q50))
            else:
                default_gate = 0.0
            threshold = float(kwargs.get("threshold", default_gate))
            high_entropy = [
                r for r in regions
                if float(r.get("insn_entropy", 0) or 0.0) >= threshold
                or float(r.get("addr_entropy", 0) or 0.0) >= threshold
            ]
            # Sort by combined entropy
            high_entropy.sort(key=lambda x: x.get("insn_entropy", 0) + x.get("addr_entropy", 0), reverse=True)
            return {
                "ok": True,
                "window": window,
                "threshold": threshold,
                "adaptive_threshold": round(default_gate, 3),
                "regions": regions[:500],
                "high_entropy_regions": high_entropy[:100],
                "high_entropy_count": len(high_entropy),
                "avg_insn_entropy": round(sum(r.get("insn_entropy", 0) for r in regions) / max(len(regions), 1), 3),
                "avg_addr_entropy": round(sum(r.get("addr_entropy", 0) for r in regions) / max(len(regions), 1), 3),
                "note": "High entropy regions may indicate packed, encrypted, or obfuscated code. Low entropy with high addr entropy may indicate crypto loops.",
            }

        elif action == "api_sequence":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "sequences": [], "note": "No trace data loaded."}
            max_gap = max(1, int(kwargs.get("max_gap", 10)))
            min_length = max(2, int(kwargs.get("min_length", 2)))
            apis = _get_api_calls_ordered(trace_list)
            if not apis:
                return {"ok": True, "sequences": [], "note": "No API calls found in trace."}

            # Build contiguous sequences with gap tolerance
            sequences = []
            current_seq = [apis[0]]
            for i in range(1, len(apis)):
                gap = apis[i]["idx"] - apis[i - 1]["idx"]
                if gap <= max_gap:
                    current_seq.append(apis[i])
                else:
                    if len(current_seq) >= min_length:
                        sequences.append(current_seq)
                    current_seq = [apis[i]]
            if len(current_seq) >= min_length:
                sequences.append(current_seq)

            # Summarize sequences into behavioral signatures
            signatures = []
            for seq in sequences:
                sig = " -> ".join([s["api"] for s in seq])
                categories = [s["category"] for s in seq]
                signatures.append({
                    "signature": sig,
                    "length": len(seq),
                    "start_idx": seq[0]["idx"],
                    "end_idx": seq[-1]["idx"],
                    "apis": [s["api"] for s in seq],
                    "categories": categories,
                    "dangerous_apis": [s["api"] for s in seq if s["api"] in DANGEROUS_APIS],
                })

            # Also extract n-grams for behavioral clustering
            n = min(5, max(2, int(kwargs.get("ngram", 3))))
            ngrams = Counter()
            for seq in sequences:
                api_names = [s["api"] for s in seq]
                for i in range(len(api_names) - n + 1):
                    ngrams[tuple(api_names[i:i + n])] += 1

            return {
                "ok": True,
                "api_call_count": len(apis),
                "sequences": signatures[:100],
                "sequence_count": len(signatures),
                "top_ngrams": [{"ngram": " -> ".join(ng), "count": c} for ng, c in ngrams.most_common(50)],
                "dangerous_api_count": sum(1 for a in apis if a["api"] in DANGEROUS_APIS),
                "behavioral_summary": {
                    "categories_present": sorted({a["category"] for a in apis}),
                    "unique_apis": len({a["api"] for a in apis}),
                },
            }

        elif action == "loop_analysis":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "loops": [], "note": "No trace data loaded."}
            back_edges = _detect_back_edges(trace_list)
            # Count iterations per loop by detecting consecutive back-edges
            loop_stats = defaultdict(lambda: {"iterations": 0, "total_hits": 0, "max_depth": 0, "back_edges": []})
            func_loop_chains = defaultdict(list)
            for be in back_edges:
                key = (be["func_addr"], be["back_edge_to"])
                loop_stats[key]["back_edges"].append(be)
                loop_stats[key]["iterations"] += 1
                func_loop_chains[be["func_addr"]].append(be)

            # Identify hot loops by total hits
            addr_counter = Counter(trace_list)
            hot_loops = []
            for (func_addr, loop_addr), stats in loop_stats.items():
                loop_ea = int(loop_addr, 0)
                total_hits = addr_counter.get(loop_ea, 0)
                # Estimate nesting: count how many different back-edge targets in same function
                same_func_loops = [k for k in loop_stats if k[0] == func_addr]
                nesting = len(same_func_loops)
                hot_loops.append({
                    "func": stats["back_edges"][0]["func"] if stats["back_edges"] else _ea_func_name(int(func_addr, 0)),
                    "func_addr": func_addr,
                    "loop_addr": loop_addr,
                    "iterations": stats["iterations"],
                    "total_hits": total_hits,
                    "estimated_nesting": nesting,
                    "avg_iteration_length": round(sum(be["iteration_length"] for be in stats["back_edges"]) / max(len(stats["back_edges"]), 1), 1),
                })

            hot_loops.sort(key=lambda x: x["total_hits"], reverse=True)

            # Hot spots at function level
            func_hits = Counter(_ea_func_name(ea) for ea in trace_list if _ea_func_name(ea))
            top_funcs = [{"func": f, "hits": c} for f, c in func_hits.most_common(20)]

            return {
                "ok": True,
                "loops": hot_loops[:100],
                "loop_count": len(hot_loops),
                "back_edge_count": len(back_edges),
                "top_functions": top_funcs,
                "trace_length": len(trace_list),
                "unique_addresses": len(set(trace_list)),
            }

        elif action in ("get", "clear", "set_options", "static_trace", "decrypt_strings", "eval_expr", "deobfuscate_emulate", "prefetch_context"):
            full_args = dict(kwargs)
            if addr is not None:
                full_args["addr"] = addr
            if path is not None:
                full_args["path"] = path
            if count is not None:
                full_args["count"] = count
            if enable_insn is not None:
                full_args["enable_insn"] = enable_insn
            if enable_func is not None:
                full_args["enable_func"] = enable_func
            if enable_bblk is not None:
                full_args["enable_bblk"] = enable_bblk
            if max_steps is not None:
                full_args["max_steps"] = max_steps
            if follow_calls is not None:
                full_args["follow_calls"] = follow_calls
            if max_depth is not None:
                full_args["max_depth"] = max_depth
            if include_blocks is not None:
                full_args["include_blocks"] = include_blocks
            if expr is not None:
                full_args["expr"] = expr
            return _trace_analysis_merged_dispatch(action, full_args)

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ---- Runtime trace (was: src/ida_pro_mcp/ida_mcp/tools/trace.py) ----

_TRACE_SOFT_OPTIONS = {
    "enable_insn": None,
    "enable_func": None,
    "enable_bblk": None,
}


def _runtime_trace_get(addr: Optional[str], count: int) -> dict:
    try:
        import ida_dbg
    except Exception:
        return {
            "ok": True,
            "traces": [],
            "count": 0,
            "trace_api": "unavailable",
            "note": "ida_dbg unavailable in this runtime.",
        }
    has_tev = all(hasattr(ida_dbg, a) for a in ("tev_t", "get_tev_qty", "get_tev_info"))
    if not has_tev:
        return {
            "ok": True,
            "traces": [],
            "count": 0,
            "trace_api": "unavailable",
            "note": "Trace event API is unavailable in this IDA runtime; import external trace data for analysis.",
        }
    traces = []
    tev = ida_dbg.tev_t()
    for i in range(min(ida_dbg.get_tev_qty(), count)):
        if ida_dbg.get_tev_info(i, tev):
            entry = {"idx": i, "addr": hex(tev.ea), "type": tev.type}
            if addr and hex(tev.ea) != addr:
                continue
            traces.append(entry)
    payload = {"ok": True, "traces": traces, "count": len(traces), "trace_api": "tev"}
    soft = {k: v for k, v in _TRACE_SOFT_OPTIONS.items() if v is not None}
    if soft:
        payload["requested_options"] = soft
    return payload


def _runtime_trace_clear() -> dict:
    try:
        import ida_dbg
    except Exception:
        return {"ok": True, "cleared": False, "note": "ida_dbg unavailable in this runtime."}
    clear_fn = getattr(ida_dbg, "clear_trace", None)
    if callable(clear_fn):
        clear_fn()
        return {"ok": True, "cleared": True}
    return {"ok": True, "cleared": False, "note": "Trace clear API is unavailable in this IDA runtime."}


def _runtime_trace_set_options(enable_insn, enable_func, enable_bblk) -> dict:
    import ida_dbg
    err = check_debugger(require_active=True)
    if err:
        return err
    changed: dict = {}
    unsupported: list = []

    def _try_set_via_func(fn_names, value):
        for n in fn_names:
            fn = getattr(ida_dbg, n, None)
            if callable(fn):
                fn(value)
                return True
        return False

    def _try_set_via_flags(flag_names, value):
        get_opts = getattr(ida_dbg, "get_step_trace_options", None)
        set_opts = getattr(ida_dbg, "set_step_trace_options", None)
        if not callable(get_opts) or not callable(set_opts):
            return False
        opts = get_opts()
        for n in flag_names:
            f = getattr(ida_dbg, n, None)
            if isinstance(f, int):
                if value:
                    opts |= f
                else:
                    opts &= ~f
                set_opts(opts)
                return True
        return False

    if enable_insn is not None:
        applied = _try_set_via_func(["enable_insn_trace", "enable_step_trace"], bool(enable_insn))
        if not applied:
            applied = _try_set_via_flags(
                ["ST_TRACE_INSN", "ST_TRACE_INSTRUCTIONS", "ST_INSN_TRACE", "ST_OVER_LIB_FUNC"],
                bool(enable_insn),
            )
        if applied:
            changed["enable_insn"] = bool(enable_insn)
        else:
            unsupported.append("enable_insn")

    if enable_func is not None:
        applied = _try_set_via_func(["enable_func_trace", "enable_function_trace"], bool(enable_func))
        if not applied:
            applied = _try_set_via_flags(
                ["ST_TRACE_FUNC", "ST_TRACE_FUNCTIONS", "ST_FUNC_TRACE"],
                bool(enable_func),
            )
        if applied:
            changed["enable_func"] = bool(enable_func)
        else:
            unsupported.append("enable_func")

    if enable_bblk is not None:
        applied = _try_set_via_func(["enable_bblk_trace", "enable_basic_block_trace"], bool(enable_bblk))
        if not applied:
            applied = _try_set_via_flags(
                ["ST_TRACE_BBLK", "ST_TRACE_BASIC_BLOCKS", "ST_BBLK_TRACE"],
                bool(enable_bblk),
            )
        if applied:
            changed["enable_bblk"] = bool(enable_bblk)
        else:
            unsupported.append("enable_bblk")

    if not changed and unsupported:
        requested = {}
        if enable_insn is not None:
            _TRACE_SOFT_OPTIONS["enable_insn"] = bool(enable_insn)
            requested["enable_insn"] = bool(enable_insn)
        if enable_func is not None:
            _TRACE_SOFT_OPTIONS["enable_func"] = bool(enable_func)
            requested["enable_func"] = bool(enable_func)
        if enable_bblk is not None:
            _TRACE_SOFT_OPTIONS["enable_bblk"] = bool(enable_bblk)
            requested["enable_bblk"] = bool(enable_bblk)
        return {
            "ok": True,
            "changed": {},
            "applied": False,
            "requested": requested,
            "soft_state": {k: v for k, v in _TRACE_SOFT_OPTIONS.items() if v is not None},
            "warning": "Trace option APIs are unavailable in this IDA build; options were recorded only (not enforced by debugger runtime).",
            "unsupported": unsupported,
        }
    result = {"ok": True, "changed": changed, "applied": True}
    if unsupported:
        result["warning"] = f"Unsupported options: {', '.join(unsupported)}"
    get_opts = getattr(ida_dbg, "get_step_trace_options", None)
    if callable(get_opts):
        result["options"] = get_opts()
    soft = {k: v for k, v in _TRACE_SOFT_OPTIONS.items() if v is not None}
    if soft:
        result["soft_options"] = soft
    return result


# ---- Static trace (was: src/ida_pro_mcp/ida_mcp/tools/static_trace.py) ----

def _static_trace_walk(ea: int, max_steps: int, follow_calls: bool, max_depth: int, include_blocks: bool) -> dict:
    func = ida_funcs.get_func(ea)
    trace: list = []
    visited: set = set()
    queue: list = [(ea, 0)]
    edges: list = []
    while queue and len(trace) < max_steps:
        curr, depth = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, curr) <= 0:
            continue
        disasm = idc.generate_disasm_line(curr, 0)
        trace.append({"addr": hex(curr), "disasm": ida_lines.tag_remove(disasm) if disasm else ""})
        is_ret_fn = getattr(idaapi, "is_ret_insn", None) or getattr(__import__("ida_idp"), "is_ret_insn", None)
        if is_ret_fn and is_ret_fn(insn):
            continue
        next_heads: list = []
        for xref in idautils.XrefsFrom(curr, 0):
            if not xref.iscode:
                continue
            if not follow_calls and xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                continue
            next_heads.append(xref.to)
            edges.append({"from": hex(curr), "to": hex(xref.to)})
        if not next_heads:
            fall = idc.next_head(curr)
            if fall != idaapi.BADADDR:
                next_heads.append(fall)
                edges.append({"from": hex(curr), "to": hex(fall)})
        for n in next_heads:
            if n != idaapi.BADADDR:
                if func and not (func.start_ea <= n < func.end_ea):
                    if follow_calls and depth < max_depth:
                        queue.append((n, depth + 1))
                    continue
                queue.append((n, depth))
    blocks: list = []
    if include_blocks and func:
        try:
            fc = idaapi.FlowChart(func)
            for b in fc:
                blocks.append({
                    "start": hex(b.start_ea),
                    "end": hex(b.end_ea),
                    "succs": [hex(s.start_ea) for s in b.succs()],
                    "preds": [hex(p.start_ea) for p in b.preds()],
                })
        except Exception:
            blocks = []
    return {
        "ok": True,
        "start": hex(ea),
        "trace": trace,
        "edges": edges,
        "count": len(trace),
        "blocks": blocks,
    }


def _static_trace_decrypt_strings(ea: int) -> dict:
    calls: list = []
    for xref in idautils.XrefsTo(ea):
        if xref.iscode:
            prev = xref.frm
            for _ in range(12):
                prev = idc.prev_head(prev)
                if prev == idaapi.BADADDR:
                    break
                for op_n in range(2):
                    val = idc.get_operand_value(prev, op_n)
                    if not val:
                        continue
                    s = idc.get_strlit_contents(val)
                    if s:
                        if isinstance(s, bytes):
                            s = s.decode("utf-8", errors="replace")
                        calls.append({
                            "call_site": hex(xref.frm),
                            "string_addr": hex(val),
                            "string": s,
                            "xref": hex(prev),
                        })
                        if len(calls) >= 50:
                            break
                if len(calls) >= 50:
                    break
        if len(calls) >= 50:
            break
    return {"ok": True, "decrypt_function": hex(ea), "potential_calls": calls, "count": len(calls)}


def _static_trace_eval_expr(addr: Optional[str], expr: Optional[str]) -> dict:
    if not addr and not expr:
        return make_error(MCPError.INVALID_ARGS, "addr or expr required")
    if expr:
        try:
            val = idc.eval_idc(expr)
            return {"ok": True, "expr": expr, "value": val, "language": "idc"}
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"Expression eval failed: {e}")
    ea, err = validate_addr(addr)
    if err:
        return err
    return {
        "ok": True,
        "addr": hex(ea),
        "u8": ida_bytes.get_byte(ea),
        "u16": ida_bytes.get_word(ea),
        "u32": ida_bytes.get_dword(ea),
        "u64": ida_bytes.get_qword(ea),
        "name": idc.get_name(ea),
    }


def _prefetch_function_context(ea):
    import re

    import ida_bytes
    import ida_funcs
    import ida_typeinf
    import idaapi
    import idautils
    import idc

    func = ida_funcs.get_func(ea)
    if not func:
        return make_error(
            MCPError.FUNCTION_NOT_FOUND,
            f"No function at address {ea:#x}",
        )

    func_start = func.start_ea
    func_end = func.end_ea

    # Demangling helper for better readability
    def _get_demangled_name(address):
        name = idc.get_func_name(address) or idc.get_name(address)
        if not name:
            return ""
        demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        return demangled or name

    # VTable Layout Dumper helper
    def _dump_vtable_layout(class_name):
        names_to_try = [
            f"vtable for {class_name}",
            f"{class_name}::vftable",
            f"??_7{class_name}@@6B@",
        ]
        names_to_try.append(f"_ZTV{len(class_name)}{class_name}")

        vtable_ea = None
        vtable_name = None
        for name in names_to_try:
            val_ea = idc.get_name_ea(idc.BADADDR, name)
            if val_ea != idc.BADADDR:
                vtable_ea = val_ea
                vtable_name = name
                break

        if vtable_ea is None:
            for val_ea, name in idautils.Names():
                if class_name in name and ("vftable" in name.lower() or "vtable" in name.lower() or name.startswith(("_ZTV", "??_7"))):
                    vtable_ea = val_ea
                    vtable_name = name
                    break

        if vtable_ea is None or vtable_ea == idc.BADADDR:
            return None

        methods = []
        curr_ptr = vtable_ea
        for i in range(64):
            ptr = ida_bytes.get_qword(curr_ptr)
            if ptr in (idc.BADADDR, 0):
                ptr = ida_bytes.get_dword(curr_ptr)
                if ptr in (idc.BADADDR, 0):
                    break

            func_name = idc.get_func_name(ptr)
            if not func_name:
                func_name = idc.get_name(ptr) or ""

            if not func_name and i > 0:
                break

            demangled_fn = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN)) if func_name else ""
            methods.append({
                "offset": i * 8,
                "offset_hex": hex(i * 8),
                "address": hex(ptr),
                "name": func_name or "unknown_method",
                "demangled_name": demangled_fn or func_name or "unknown_method"
            })
            curr_ptr += 8

        return {
            "class_name": class_name,
            "vtable_symbol": vtable_name,
            "vtable_address": hex(vtable_ea),
            "methods": methods
        }

    # Structure Definition Dumper helper
    def _get_struct_definition(struct_name):
        from unittest.mock import MagicMock
        try:
            import ida_struct
            import ida_typeinf
        except ImportError:
            return None

        clean_name = struct_name
        if not isinstance(clean_name, str):
            return None
        if clean_name.startswith("struct "):
            clean_name = clean_name[7:]
        elif clean_name.startswith("class "):
            clean_name = clean_name[6:]
        if not clean_name:
            return None

        try:
            # Try local struct definitions first
            struct_id = ida_struct.get_struc_id(clean_name)
            if struct_id != idc.BADADDR and isinstance(struct_id, int):
                s = ida_struct.get_struc(struct_id)
                if s and not isinstance(s, MagicMock):
                    members = []
                    offset = 0
                    total_size = ida_struct.get_struc_size(s)
                    if isinstance(total_size, int):
                        while offset < total_size:
                            member = ida_struct.get_member(s, offset)
                            if member and not isinstance(member, MagicMock):
                                m_name = ida_struct.get_member_name(member.id) or ""
                                m_size = ida_struct.get_member_size(member)
                                m_offset = member.soff
                                if isinstance(m_offset, int) and isinstance(m_size, int):
                                    tinfo = ida_typeinf.tinfo_t()
                                    m_type = ""
                                    if ida_struct.get_member_tinfo(tinfo, member):
                                        m_type = str(tinfo)
                                    members.append({
                                        "name": str(m_name),
                                        "offset": m_offset,
                                        "offset_hex": hex(m_offset),
                                        "size": m_size,
                                        "type": str(m_type) or "unknown"
                                    })
                                    offset += m_size
                                else:
                                    offset += 1
                            else:
                                offset += 1
                        return {
                            "name": clean_name,
                            "size": total_size,
                            "members": members
                        }
        except Exception:
            pass

        try:
            # Try type info library (TIL)
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(idaapi.get_idati(), clean_name) and tif.is_udt():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for m in udt:
                        if not isinstance(m, MagicMock):
                            members.append({
                                "name": str(m.name),
                                "offset": m.offset // 8,
                                "offset_hex": hex(m.offset // 8),
                                "size": m.size // 8,
                                "type": str(m.type)
                            })
                    return {
                        "name": clean_name,
                        "size": tif.get_size(),
                        "members": members
                    }
        except Exception:
            pass
        return None

    # 1. Callee Prototypes & Signatures
    callee_prototypes = {}
    curr = func_start
    while curr < func_end:
        for xref in idautils.XrefsFrom(curr):
            if xref.iscode and xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                callee_ea = xref.to
                name = idc.get_func_name(callee_ea)
                if name:
                    demangled_name = _get_demangled_name(callee_ea)
                    tinfo = ida_typeinf.tinfo_t()
                    proto = ""
                    proto = str(tinfo) if ida_typeinf.get_tinfo(tinfo, callee_ea) else idc.get_type(callee_ea) or ""
                    callee_prototypes[hex(callee_ea)] = {
                        "name": name,
                        "demangled_name": demangled_name,
                        "prototype": proto or "void unknown()"
                    }
        curr = idc.next_head(curr, func_end)

    # 2. Scanned Globals & Strings
    resolved_globals = {}
    curr = func_start
    import ida_ua
    while curr < func_end:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, curr) > 0:
            for op in insn.ops:
                if op.type == ida_ua.o_mem:
                    mem_ea = op.addr
                    name = idc.get_name(mem_ea)
                    if name and mem_ea != idaapi.BADADDR:
                        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN)) or name
                        val = 0
                        val_str = ""
                        s = idc.get_strlit_contents(mem_ea)
                        if s:
                            val_str = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                        else:
                            val = ida_bytes.get_qword(mem_ea)
                            if val in (idaapi.BADADDR, 0):
                                val = ida_bytes.get_dword(mem_ea)

                        resolved_globals[hex(mem_ea)] = {
                            "name": name,
                            "demangled_name": demangled_name,
                            "type": idc.get_type(mem_ea) or "",
                            "value_hex": hex(val) if not val_str else None,
                            "string_value": val_str or None,
                        }
        curr = idc.next_head(curr, func_end)

    # 3. Virtual calls & structure offsets (Ast-based if decompiler is available)
    vtables_and_structs = []
    try:
        from unittest.mock import MagicMock

        import ida_hexrays
        import ida_lines

        cfunc = ida_hexrays.decompile(func_start)
        if cfunc and not isinstance(cfunc, MagicMock):
            class StructVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.accesses = []

                def visit_expr(self, e):
                    if e.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                        ea = int(getattr(e, 'ea', 0) or 0)
                        offset = getattr(e, 'm', None)
                        if offset is not None and isinstance(offset, int):
                            struct_type = ""
                            member_name = ""
                            try:
                                tif = e.x.type
                                if e.op == ida_hexrays.cot_memptr and tif.is_ptr():
                                    tif = tif.get_pointed_object()
                                struct_type = tif.get_type_name() or ""

                                # Resolve member name using type info details if possible
                                if tif.is_udt():
                                    udt = ida_typeinf.udt_type_data_t()
                                    if tif.get_udt_details(udt):
                                        for m in udt:
                                            if m.offset // 8 == offset:
                                                member_name = m.name
                                                break

                                # Fallback to local struct database
                                if not member_name and struct_type:
                                    struct_id = ida_struct.get_struc_id(struct_type)
                                    if struct_id != idc.BADADDR:
                                        s = ida_struct.get_struc(struct_id)
                                        if s:
                                            m = ida_struct.get_member(s, offset)
                                            if m:
                                                member_name = ida_struct.get_member_name(m.id) or ""
                            except Exception:
                                pass

                            expr_str = ""
                            with contextlib.suppress(Exception):
                                expr_str = ida_lines.tag_remove(e.print1(None)) or ""

                            # Fallback to string heuristic if APIs didn't resolve it
                            if not member_name and expr_str:
                                if "->" in expr_str:
                                    member_name = expr_str.split("->")[-1].strip()
                                elif "." in expr_str:
                                    member_name = expr_str.split(".")[-1].strip()

                            self.accesses.append({
                                "ea": hex(ea) if ea else None,
                                "struct_type": struct_type,
                                "member_name": member_name,
                                "offset": offset,
                                "offset_hex": hex(offset),
                                "expression": expr_str
                            })
                    return 0

            visitor = StructVisitor()
            visitor.apply_to(cfunc.body, None)
            vtables_and_structs = visitor.accesses
    except Exception:
        pass

    if not vtables_and_structs:
        # Refined disassembly fallback
        curr = func_start
        while curr < func_end:
            dis = idc.generate_disasm_line(curr, 0)
            if dis and ("[" in dis and "]" in dis):
                match_struct = re.search(r'\[([a-z0-9]+)\s*\+\s*([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\]', dis, re.IGNORECASE)
                if match_struct:
                    reg, struct_name, member_name = match_struct.groups()
                    if reg.lower() not in ("rsp", "esp", "rbp", "ebp"):
                        vtables_and_structs.append({
                            "ea": hex(curr),
                            "instruction": dis,
                            "struct_type": struct_name,
                            "member_name": member_name,
                            "offset": None,
                            "offset_hex": None,
                        })
                else:
                    match_offset = re.search(r'\[([a-z0-9]+)\s*\+\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+h|[0-9]+)\]', dis, re.IGNORECASE)
                    if match_offset:
                        reg, offset_str = match_offset.groups()
                        if reg.lower() not in ("rsp", "esp", "rbp", "ebp"):
                            try:
                                offset = int(offset_str.replace('h', ''), 16) if 'h' in offset_str else int(offset_str, 0)
                                vtables_and_structs.append({
                                    "ea": hex(curr),
                                    "instruction": dis,
                                    "struct_type": "",
                                    "member_name": "",
                                    "offset": offset,
                                    "offset_hex": hex(offset)
                                })
                            except Exception:
                                pass
            curr = idc.next_head(curr, func_end)

    # Dump VTable Layouts and Struct Definitions for accessed structures/classes
    vtable_layouts = []
    struct_definitions = {}
    seen_structs = set()
    for item in vtables_and_structs:
        s_type = item.get("struct_type")
        if s_type:
            if s_type.startswith("struct "):
                s_type = s_type[7:]
            elif s_type.startswith("class "):
                s_type = s_type[6:]
            if s_type and s_type not in seen_structs:
                seen_structs.add(s_type)
                layout = _dump_vtable_layout(s_type)
                if layout:
                    vtable_layouts.append(layout)
                s_def = _get_struct_definition(s_type)
                if s_def:
                    struct_definitions[s_type] = s_def

    # 4. Speculative Emulation
    emulation_insights = {}
    resolved_pointers = {}
    virtual_calls = []
    argument_dereferences = {}
    try:
        emu = TinyEmulator(func_start)
        emu.setup_argument_pointers()
        res = emu.speculative_explore(max_depth=50, max_paths=8)
        emulation_insights = {
            "opaque_predicates": res.get("opaque_predicates", {}),
            "stack_strings": res.get("stack_strings", []),
            "extracted_strings": res.get("extracted_strings", []),
            "reachable_instructions": len(res.get("reachable_eas", [])),
            "taint_log": res.get("taint_log", []),
        }
        virtual_calls = res.get("virtual_calls", [])
        argument_dereferences = res.get("argument_dereferences", {})

        # Resolve dynamic pointer dereferences from emulation
        for entry in res.get("dereferenced_pointers", []):
            if isinstance(entry, dict):
                ip_val = int(entry.get("ip", "0"), 0)
                ptr_ea = int(entry.get("addr", "0"), 0)
                access_type = entry.get("access", "")
            else:
                ip_val, ptr_ea, access_type = entry
            if ptr_ea != idaapi.BADADDR:
                name = idc.get_name(ptr_ea)
                demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN)) if name else ""
                val = 0
                val_str = ""
                s = idc.get_strlit_contents(ptr_ea)
                if s:
                    val_str = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                else:
                    val = ida_bytes.get_qword(ptr_ea)
                    if val in (idaapi.BADADDR, 0):
                        val = ida_bytes.get_dword(ptr_ea)

                resolved_pointers[hex(ptr_ea)] = {
                    "dereferenced_at": hex(ip_val),
                    "access": access_type,
                    "name": name or "",
                    "demangled_name": demangled_name or name or "",
                    "type": idc.get_type(ptr_ea) or "",
                    "value_hex": hex(val) if not val_str else None,
                    "string_value": val_str or None,
                }
    except Exception as e:
        emulation_insights = handle_error(e, context="emulation_insights")

    # 5. Call Graph Neighborhood
    callers = []
    callees = []
    for xref in idautils.XrefsTo(func_start):
        if xref.iscode:
            caller_name = _get_demangled_name(xref.frm)
            callers.append({"ea": hex(xref.frm), "name": caller_name or "unknown"})
    for xref in idautils.XrefsFrom(func_start):
        if xref.iscode:
            callee_name = _get_demangled_name(xref.to)
            callees.append({"ea": hex(xref.to), "name": callee_name or "unknown"})

    # Inline decompiled or disassembled pseudocode of small callees to prevent roundtrips
    small_callees = {}
    try:
        from unittest.mock import MagicMock

        import ida_hexrays
        for callee_hex, callee_info in callee_prototypes.items():
            callee_ea = int(callee_hex, 16)
            c_func = ida_funcs.get_func(callee_ea)
            if c_func and not isinstance(c_func, MagicMock):
                c_size = c_func.end_ea - c_func.start_ea
                if isinstance(c_size, int) and c_size <= 256:
                    decompiled = False
                    try:
                        cfunc = ida_hexrays.decompile(callee_ea)
                        if cfunc and not isinstance(cfunc, MagicMock):
                            lines = []
                            for line in cfunc.get_pseudocode():
                                lines.append(ida_lines.tag_remove(line.line))
                            if len(lines) < 25:
                                small_callees[callee_hex] = {
                                    "name": callee_info.get("name") or "",
                                    "demangled_name": callee_info.get("demangled_name") or "",
                                    "type": "decompiled",
                                    "code": "\n".join(lines)
                                }
                                decompiled = True
                    except Exception:
                        pass

                    if not decompiled:
                        try:
                            inst_count = 0
                            curr_inst = c_func.start_ea
                            while curr_inst < c_func.end_ea:
                                inst_count += 1
                                curr_inst = idc.next_head(curr_inst, c_func.end_ea)
                            if isinstance(inst_count, int) and inst_count < 15:
                                disasm_lines = []
                                curr_inst = c_func.start_ea
                                while curr_inst < c_func.end_ea:
                                    disasm_lines.append(f"{hex(curr_inst)}: {idc.generate_disasm_line(curr_inst, 0)}")
                                    curr_inst = idc.next_head(curr_inst, c_func.end_ea)
                                small_callees[callee_hex] = {
                                    "name": callee_info.get("name") or "",
                                    "demangled_name": callee_info.get("demangled_name") or "",
                                    "type": "disassembly",
                                    "code": "\n".join(disasm_lines)
                                }
                        except Exception:
                            pass
    except Exception:
        pass

    return {
        "ok": True,
        "function_address": hex(func_start),
        "name": _get_demangled_name(func_start),
        "callee_prototypes": callee_prototypes,
        "small_callees": small_callees,
        "resolved_globals": resolved_globals,
        "resolved_pointers": resolved_pointers,
        "virtual_calls": virtual_calls,
        "vtables_and_structs": vtables_and_structs[:10],
        "vtable_layouts": vtable_layouts,
        "struct_definitions": struct_definitions,
        "argument_dereferences": argument_dereferences,
        "emulation_insights": emulation_insights,
        "cfg_neighborhood": {
            "callers": callers[:5],
            "callees": callees[:5]
        }
    }




def format_sym_expr(expr):
    if not isinstance(expr, tuple):
        if isinstance(expr, int):
            return hex(expr) if expr > 9 else str(expr)
        return str(expr)

    if len(expr) == 0:
        return ""

    op = expr[0]
    if op == "val":
        val = expr[1]
        return hex(val) if isinstance(val, int) and val > 9 else str(val)
    elif op == "reg":
        return str(expr[1])
    elif op == "mem":
        addr = format_sym_expr(expr[1])
        return f"[{addr}]"
    elif op in ("add", "sub", "mul", "xor", "and", "or", "shl", "shr", "sar", "rol", "ror"):
        op_signs = {
            "add": "+", "sub": "-", "mul": "*", "xor": "^",
            "and": "&", "or": "|", "shl": "<<", "shr": ">>", "sar": ">>a",
            "rol": "rol", "ror": "ror"
        }
        sign = op_signs.get(op, op)
        left = format_sym_expr(expr[1])
        right = format_sym_expr(expr[2])
        return f"({left} {sign} {right})"
    elif op in ("neg", "not"):
        sign = "-" if op == "neg" else "~"
        val = format_sym_expr(expr[1])
        return f"{sign}{val}"
    elif op == "call":
        func = expr[1]
        args = ", ".join(format_sym_expr(a) for a in expr[2])
        return f"{func}({args})"
    elif op == "cmov":
        cond = expr[1]
        val1 = format_sym_expr(expr[2])
        val0 = format_sym_expr(expr[3])
        return f"({val1} if {cond} else {val0})"
    elif op == "set":
        cond = expr[1]
        flags = format_sym_expr(expr[2])
        return f"(1 if {cond}({flags}) else 0)"

    return str(expr)


def format_constraint(constraint):
    if not isinstance(constraint, tuple) or len(constraint) < 2:
        return str(constraint)

    op = constraint[0]
    if op in ("eq", "ne", "lt", "gt", "le", "ge"):
        op_signs = {"eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">="}
        sign = op_signs[op]
        left = format_sym_expr(constraint[1])
        right = format_sym_expr(constraint[2])
        return f"{left} {sign} {right}"
    elif op in ("zero", "nonzero"):
        val = format_sym_expr(constraint[1])
        return f"{val} == 0" if op == "zero" else f"{val} != 0"
    elif op in ("taken", "fallthrough"):
        flags = format_sym_expr(constraint[1])
        return f"{op}({flags})"

    return str(constraint)


def solve_constraints(constraints):
    solutions = {}

    def solve_expr(expr, target_val):
        if not isinstance(expr, tuple):
            return

        op = expr[0]
        if op == "reg":
            solutions[expr[1]] = target_val
        elif op == "mem":
            addr_str = format_sym_expr(expr[1])
            solutions[f"[{addr_str}]"] = target_val
        elif op == "add":
            left, right = expr[1], expr[2]
            if isinstance(right, tuple) and right[0] == "val":
                solve_expr(left, target_val - right[1])
            elif isinstance(left, tuple) and left[0] == "val":
                solve_expr(right, target_val - left[1])
        elif op == "sub":
            left, right = expr[1], expr[2]
            if isinstance(right, tuple) and right[0] == "val":
                solve_expr(left, target_val + right[1])
            elif isinstance(left, tuple) and left[0] == "val":
                solve_expr(right, left[1] - target_val)
        elif op == "xor":
            left, right = expr[1], expr[2]
            if isinstance(right, tuple) and right[0] == "val":
                solve_expr(left, target_val ^ right[1])
            elif isinstance(left, tuple) and left[0] == "val":
                solve_expr(right, target_val ^ left[1])

    for constraint in constraints:
        if not isinstance(constraint, tuple):
            continue
        op = constraint[0]
        if op == "eq":
            left, right = constraint[1], constraint[2]
            if isinstance(right, tuple) and right[0] == "val":
                solve_expr(left, right[1])
            elif isinstance(left, tuple) and left[0] == "val":
                solve_expr(right, left[1])
        elif op == "zero":
            expr = constraint[1]
            solve_expr(expr, 0)

    return solutions


def get_branch_constraints(mnem, flags_sym):
    if not flags_sym:
        return None, None

    if not isinstance(flags_sym, tuple) or len(flags_sym) < 2:
        flags_sym = ("test", flags_sym, flags_sym)

    op = flags_sym[0]
    if op == "cmp":
        left, right = flags_sym[1], flags_sym[2]
        if mnem in ("je", "jz"):
            return ("eq", left, right), ("ne", left, right)
        elif mnem in ("jne", "jnz"):
            return ("ne", left, right), ("eq", left, right)
        elif mnem in ("jb", "jl", "js"):
            return ("lt", left, right), ("ge", left, right)
        elif mnem in ("jae", "jge", "jns"):
            return ("ge", left, right), ("lt", left, right)
        elif mnem == "jg":
            return ("gt", left, right), ("le", left, right)
        elif mnem == "jle":
            return ("le", left, right), ("gt", left, right)
    elif op == "test":
        left, right = flags_sym[1], flags_sym[2]
        test_expr = ("and", left, right)
        if mnem in ("je", "jz"):
            return ("eq", test_expr, ("val", 0)), ("ne", test_expr, ("val", 0))
        elif mnem in ("jne", "jnz"):
            return ("ne", test_expr, ("val", 0)), ("eq", test_expr, ("val", 0))

    return ("taken", flags_sym), ("fallthrough", flags_sym)


class TinyEmulator:
    def __init__(self, start_ea, arch_width: int = 64):
        import ida_funcs
        self.arch_width = arch_width
        self.arch_mask = (1 << arch_width) - 1
        self.regs = {
            'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0,
            'rsi': 0, 'rdi': 0, 'rbp': 0, 'rsp': EMU_STACK_INIT_RSP,
            'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0,
            'zf': 0, 'sf': 0, 'cf': 0, 'of': 0, 'pf': 0
        }
        self.mem = {}  # address -> byte
        self.written_addrs = set()
        self.ip = start_ea
        self.func = ida_funcs.get_func(start_ea)
        self.func_start = self.func.start_ea if self.func else start_ea
        self.func_end = self.func.end_ea if self.func else start_ea + 0x1000

        # Extended capabilities
        self.tainted_regs = set()
        self.tainted_mem = set()
        self.taint_log = []
        self.flags_tainted = False
        self.stack_writes = {}
        self.opaque_predicates = {}
        self.dereferenced_pointers = set()
        self.virtual_calls = []
        self.arg_derefs = {}
        self.sym_regs = {}
        self.sym_mem = {}
        self.flags_sym = None
        self.path_constraints = []

    def setup_argument_pointers(self):
        # We assign dummy pointers in the range EMU_DUMMY_ARG_BASE..EMU_DUMMY_ARG_TOP
        # for standard x64 argument registers
        self.regs['rdi'] = EMU_DUMMY_ARG_BASE + 0 * EMU_DUMMY_ARG_STRIDE
        self.regs['rsi'] = EMU_DUMMY_ARG_BASE + 1 * EMU_DUMMY_ARG_STRIDE
        self.regs['rdx'] = EMU_DUMMY_ARG_BASE + 2 * EMU_DUMMY_ARG_STRIDE
        self.regs['rcx'] = EMU_DUMMY_ARG_BASE + 3 * EMU_DUMMY_ARG_STRIDE
        self.regs['r8']  = EMU_DUMMY_ARG_BASE + 4 * EMU_DUMMY_ARG_STRIDE
        self.regs['r9']  = EMU_DUMMY_ARG_BASE + 5 * EMU_DUMMY_ARG_STRIDE

    def clone(self):
        other = TinyEmulator(self.ip)
        other.regs = dict(self.regs)
        other.mem = dict(self.mem)
        other.written_addrs = set(self.written_addrs)
        other.func = self.func
        other.func_start = self.func_start
        other.func_end = self.func_end
        other.tainted_regs = set(self.tainted_regs)
        other.tainted_mem = set(self.tainted_mem)
        other.taint_log = list(self.taint_log)
        other.flags_tainted = self.flags_tainted
        other.stack_writes = {k: list(v) if isinstance(v, list) else v for k, v in self.stack_writes.items()}
        other.opaque_predicates = dict(self.opaque_predicates)
        other.dereferenced_pointers = set(self.dereferenced_pointers)
        other.virtual_calls = list(self.virtual_calls)
        other.arg_derefs = {k: list(v) for k, v in self.arg_derefs.items()}
        other.sym_regs = dict(self.sym_regs)
        other.sym_mem = dict(self.sym_mem)
        other.flags_sym = self.flags_sym
        other.path_constraints = list(self.path_constraints)
        return other

    def _normalize_reg_name(self, name):
        name = name.lower().strip()
        mapping32 = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11', 'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'
        }
        mapping16 = {
            'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
            'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp'
        }
        mapping8 = {
            'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
            'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11', 'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15'
        }
        if name in mapping32:
            return mapping32[name]
        if name in mapping16:
            return mapping16[name]
        if name in mapping8:
            return mapping8[name]
        return name

    def is_reg_tainted(self, name):
        return self._normalize_reg_name(name) in self.tainted_regs

    def set_reg_taint(self, name, state=True):
        norm = self._normalize_reg_name(name)
        if state:
            self.tainted_regs.add(norm)
            if norm not in self.sym_regs:
                self.sym_regs[norm] = ("reg", norm)
        else:
            self.tainted_regs.discard(norm)
            self.sym_regs.pop(norm, None)

    def is_mem_tainted(self, addr, size=1):
        return any(addr + i in self.tainted_mem for i in range(size))

    def set_mem_taint(self, addr, size=1, state=True):
        for i in range(size):
            if state:
                self.tainted_mem.add(addr + i)
                if (addr + i) not in self.sym_mem:
                    self.sym_mem[addr + i] = ("mem", ("val", addr + i), 1)
            else:
                self.tainted_mem.discard(addr + i)
                self.sym_mem.pop(addr + i, None)

    def get_reg(self, name):
        name = name.lower()
        if name in self.regs:
            return self.regs[name]
        mapping32 = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11', 'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'
        }
        if name in mapping32:
            return self.regs[mapping32[name]] & 0xffffffff

        mapping16 = {
            'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
            'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp'
        }
        if name in mapping16:
            return self.regs[mapping16[name]] & 0xffff

        mapping8 = {
            'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
            'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11', 'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15'
        }
        if name in mapping8:
            return self.regs[mapping8[name]] & 0xff
        return 0

    def set_reg(self, name, val):
        name = name.lower()
        val = val & self.arch_mask
        if name in self.regs:
            self.regs[name] = val
            return
        mapping32 = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11', 'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'
        }
        if name in mapping32:
            parent = mapping32[name]
            self.regs[parent] = (val & 0xffffffff)
            return
        mapping16 = {
            'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
            'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp'
        }
        if name in mapping16:
            parent = mapping16[name]
            self.regs[parent] = (self.regs[parent] & 0xffffffffffff0000) | (val & 0xffff)
            return
        mapping8 = {
            'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
            'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11', 'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15'
        }
        if name in mapping8:
            parent = mapping8[name]
            self.regs[parent] = (self.regs[parent] & 0xffffffffffffff00) | (val & 0xff)
            return

    def read_mem(self, addr, size=1):
        import idc
        out = 0
        all_unmapped = True
        any_unmapped = False

        # Check if this is a read from one of our dummy argument pointers
        if EMU_DUMMY_ARG_BASE <= addr < EMU_DUMMY_ARG_TOP:
            reg_idx = (addr - EMU_DUMMY_ARG_BASE) // EMU_DUMMY_ARG_STRIDE + 1
            reg_names = {1: "rdi", 2: "rsi", 3: "rdx", 4: "rcx", 5: "r8", 6: "r9"}
            reg_name = reg_names.get(reg_idx, "unknown")
            offset = addr - EMU_DUMMY_ARG_BASE
            self.arg_derefs.setdefault(reg_name, []).append({
                "offset": offset,
                "offset_hex": hex(offset),
                "size": size,
                "access": "read"
            })
            return 0

        for i in range(size):
            if (addr + i) in self.mem:
                b = self.mem[addr + i]
                all_unmapped = False
            else:
                b = safe_get_byte(addr + i)
                if b is None:
                    any_unmapped = True
                    b = 0
                else:
                    all_unmapped = False
            out |= (b << (i * 8))

        # Skip deref-pointer tracking for unmapped reads; don't synthesize
        # deref entries that are actually just placeholder 0xff/0 returns.
        if all_unmapped or any_unmapped:
            return out

        # Track dereferenced pointers (non-stack, non-zero)
        if not (EMU_STACK_BASE <= addr <= EMU_STACK_TOP) and addr != 0:
            self.dereferenced_pointers.add((self.ip, addr, "read"))

        # Track C++ virtual calls (if reading a pointer from a vtable)
        if size == 8 and not (EMU_STACK_BASE <= addr <= EMU_STACK_TOP) and addr != 0:
            vtable_base = None
            vtable_name = None
            for offset_check in range(0, 512, 8):
                check_ea = addr - offset_check
                name = idc.get_name(check_ea)
                if name and ("vftable" in name.lower() or "vtable" in name.lower() or name.startswith(("_ZTV", "??_7"))):
                    vtable_base = check_ea
                    vtable_name = name
                    break
            if vtable_base is not None:
                vtable_offset = addr - vtable_base
                target_name = idc.get_name(out) or ""
                demangled = idc.demangle_name(target_name, idc.get_inf_attr(idc.INF_SHORT_DN)) if target_name else ""
                self.virtual_calls.append({
                    "vtable_name": vtable_name,
                    "vtable_offset": vtable_offset,
                    "vtable_offset_hex": hex(vtable_offset),
                    "target_address": hex(out),
                    "target_name": target_name,
                    "demangled_target_name": demangled or target_name,
                    "target_type": idc.get_type(out) or ""
                })
        return out

    def write_mem(self, addr, val, size=1):
        # Check if this is a write to one of our dummy argument pointers
        if EMU_DUMMY_ARG_BASE <= addr < EMU_DUMMY_ARG_TOP:
            reg_idx = (addr - EMU_DUMMY_ARG_BASE) // EMU_DUMMY_ARG_STRIDE + 1
            reg_names = {1: "rdi", 2: "rsi", 3: "rdx", 4: "rcx", 5: "r8", 6: "r9"}
            reg_name = reg_names.get(reg_idx, "unknown")
            offset = addr - EMU_DUMMY_ARG_BASE
            self.arg_derefs.setdefault(reg_name, []).append({
                "offset": offset,
                "offset_hex": hex(offset),
                "size": size,
                "access": "write"
            })
            return

        for i in range(size):
            b = (val >> (i * 8)) & 0xff
            self.mem[addr + i] = b
            self.written_addrs.add(addr + i)
            # Track stack writes
            if EMU_STACK_BASE <= addr <= EMU_STACK_TOP:
                offset = addr - EMU_STACK_INIT_RSP
                self.stack_writes[offset + i] = (self.ip, b)

        # Track dereferenced pointers (non-stack, non-zero)
        if not (EMU_STACK_BASE <= addr <= EMU_STACK_TOP) and addr != 0:
            self.dereferenced_pointers.add((self.ip, addr, "write"))

    def parse_op(self, insn, op_idx):
        import ida_ua
        import idc
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_reg:
            return self.get_reg(idc.print_operand(insn.ea, op_idx))
        elif op.type == ida_ua.o_imm:
            return op.value
        elif op.type in (ida_ua.o_phrase, ida_ua.o_displ):
            op_str = idc.print_operand(insn.ea, op_idx)
            addr = self.parse_address_expr(op_str)
            return addr
        elif op.type in (ida_ua.o_near, ida_ua.o_mem):
            return op.addr
        return 0

    def parse_op_taint(self, insn, op_idx):
        import ida_ua
        import idc
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_reg:
            reg_name = idc.print_operand(insn.ea, op_idx)
            return self.is_reg_tainted(reg_name)
        elif op.type == ida_ua.o_imm:
            return False
        elif op.type in (ida_ua.o_phrase, ida_ua.o_displ):
            op_str = idc.print_operand(insn.ea, op_idx)
            addr = self.parse_address_expr(op_str)
            addr_tainted = False
            for r in self.regs:
                if r in op_str.lower() and self.is_reg_tainted(r):
                    addr_tainted = True
                    break
            size = self.dtype_size(op.dtype)
            return addr_tainted or self.is_mem_tainted(addr, size)
        elif op.type == ida_ua.o_mem:
            size = self.dtype_size(op.dtype)
            return self.is_mem_tainted(op.addr, size)
        return False

    def parse_address_expr(self, expr_str, radix: int = 16):
        expr_str = expr_str.lower()
        if '[' in expr_str:
            expr_str = expr_str.split('[')[1].split(']')[0]
        else:
            return 0

        import re
        digit_re = re.compile(r'^[0-9a-f]+$') if radix == 16 else re.compile(r'^[0-9]+$')
        tokens = re.split(r'(\+|\-)', expr_str)
        val = 0
        current_op = '+'
        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok in ('+', '-'):
                current_op = tok
                continue

            tok_val = 0
            if '*' in tok:
                parts = tok.split('*')
                reg_name = parts[0].strip()
                try:
                    scale = int(parts[1].strip(), 0)
                except ValueError:
                    scale = 1
                tok_val = self.get_reg(reg_name) * scale
            elif tok.endswith('h') and radix == 16:
                try:
                    tok_val = int(tok[:-1], 16)
                except ValueError:
                    tok_val = 0
            elif digit_re.match(tok):
                try:
                    tok_val = int(tok, radix)
                except ValueError:
                    tok_val = 0
            elif tok in self.regs or tok in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'al', 'bl', 'cl', 'dl'):
                tok_val = self.get_reg(tok)
            else:
                try:
                    tok_val = int(tok, 0)
                except ValueError:
                    tok_val = 0

            if current_op == '+':
                val += tok_val
            else:
                val -= tok_val
        return val & self.arch_mask

    def get_op_width(self, insn, op_idx):
        import ida_ua
        import idc
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_reg:
            reg_name = idc.print_operand(insn.ea, op_idx).lower().strip()
            if reg_name in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
                return 64
            if reg_name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'):
                return 32
            if reg_name in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
                return 16
            if reg_name in ('al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'):
                return 8
        size = self.dtype_size(op.dtype)
        return size * 8

    def get_address_sym(self, expr_str, radix: int = 16):
        expr_str = expr_str.lower()
        if '[' in expr_str:
            expr_str = expr_str.split('[')[1].split(']')[0]
        else:
            return ("val", 0)

        import re
        digit_re = re.compile(r'^[0-9a-f]+$') if radix == 16 else re.compile(r'^[0-9]+$')
        tokens = re.split(r'(\+|\-)', expr_str)
        sym_expr = ("val", 0)
        current_op = '+'
        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok in ('+', '-'):
                current_op = tok
                continue

            tok_sym = None
            if '*' in tok:
                parts = tok.split('*')
                reg_name = parts[0].strip()
                try:
                    scale = int(parts[1].strip(), 0)
                except ValueError:
                    scale = 1
                norm_reg = self._normalize_reg_name(reg_name)
                if self.is_reg_tainted(reg_name):
                    reg_sym = self.sym_regs.get(norm_reg, ("reg", norm_reg))
                    tok_sym = ("mul", reg_sym, ("val", scale))
                else:
                    tok_sym = ("val", self.get_reg(reg_name) * scale)
            elif tok.endswith('h') and radix == 16:
                try:
                    tok_val = int(tok[:-1], 16)
                except ValueError:
                    tok_val = 0
                tok_sym = ("val", tok_val)
            elif digit_re.match(tok):
                try:
                    tok_val = int(tok, radix)
                except ValueError:
                    tok_val = 0
                tok_sym = ("val", tok_val)
            elif self._normalize_reg_name(tok) in self.regs or tok in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'al', 'bl', 'cl', 'dl'):
                norm_reg = self._normalize_reg_name(tok)
                if self.is_reg_tainted(tok):
                    tok_sym = self.sym_regs.get(norm_reg, ("reg", norm_reg))
                else:
                    tok_sym = ("val", self.get_reg(tok))
            else:
                try:
                    tok_val = int(tok, 0)
                except ValueError:
                    tok_val = 0
                tok_sym = ("val", tok_val)

            if current_op == '+':
                sym_expr = tok_sym if sym_expr == ("val", 0) else ("add", sym_expr, tok_sym)
            else:
                sym_expr = ("sub", sym_expr, tok_sym)
        return sym_expr

    def get_op_sym(self, insn, op_idx):
        import ida_ua
        import idc
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_reg:
            reg_name = idc.print_operand(insn.ea, op_idx)
            norm = self._normalize_reg_name(reg_name)
            if self.is_reg_tainted(reg_name):
                return self.sym_regs.get(norm, ("reg", norm))
            else:
                return ("val", self.get_reg(reg_name))
        elif op.type == ida_ua.o_imm:
            return ("val", op.value)
        elif op.type in (ida_ua.o_phrase, ida_ua.o_displ):
            op_str = idc.print_operand(insn.ea, op_idx)
            concrete_addr = self.parse_address_expr(op_str)
            size = self.dtype_size(op.dtype)

            addr_is_symbolic = False
            for r in self.regs:
                if r in op_str.lower() and self.is_reg_tainted(r):
                    addr_is_symbolic = True
                    break

            addr_sym = self.get_address_sym(op_str)
            mem_tainted = self.is_mem_tainted(concrete_addr, size)

            if mem_tainted:
                for offset in range(size):
                    if (concrete_addr + offset) in self.sym_mem:
                        return self.sym_mem[concrete_addr + offset]
                return ("mem", addr_sym, size)
            elif addr_is_symbolic:
                return ("mem", addr_sym, size)
            else:
                return ("val", self.read_mem(concrete_addr, size))
        elif op.type == ida_ua.o_mem:
            size = self.dtype_size(op.dtype)
            if self.is_mem_tainted(op.addr, size):
                for offset in range(size):
                    if (op.addr + offset) in self.sym_mem:
                        return self.sym_mem[op.addr + offset]
                return ("mem", ("val", op.addr), size)
            else:
                return ("val", self.read_mem(op.addr, size))
        return ("val", 0)

    def set_op_sym(self, insn, op_idx, sym_expr, tainted):
        import ida_ua
        import idc
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_reg:
            reg_name = idc.print_operand(insn.ea, op_idx)
            norm = self._normalize_reg_name(reg_name)
            if tainted:
                self.sym_regs[norm] = sym_expr
            else:
                self.sym_regs.pop(norm, None)
        elif op.type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
            if op.type == ida_ua.o_mem:
                addr = op.addr
            else:
                op_str = idc.print_operand(insn.ea, op_idx)
                addr = self.parse_address_expr(op_str)
            size = self.dtype_size(op.dtype)
            for i in range(size):
                if tainted:
                    self.sym_mem[addr + i] = sym_expr
                else:
                    self.sym_mem.pop(addr + i, None)

    def step(self):
        import ida_ua
        import idc
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, self.ip) <= 0:
            return False

        mnem = idc.print_insn_mnem(self.ip).lower()
        next_ip = self.ip + insn.size

        if mnem in ("mov", "movzx", "movsx"):
            op0_str = idc.print_operand(self.ip, 0)
            val1 = self.parse_op(insn, 1)
            t1 = self.parse_op_taint(insn, 1)
            sym1 = self.get_op_sym(insn, 1)
            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, val1, size)
                self.set_mem_taint(addr, size, t1)
                self.set_op_sym(insn, 0, sym1, t1)
                if t1:
                    self.taint_log.append((self.ip, f"Taint stored to mem address {hex(addr)}"))
            else:
                self.set_reg(op0_str, val1)
                self.set_reg_taint(op0_str, t1)
                self.set_op_sym(insn, 0, sym1, t1)
                if t1:
                    self.taint_log.append((self.ip, f"Taint moved to register {op0_str}"))

        elif mnem == "lea":
            op0_str = idc.print_operand(self.ip, 0)
            addr = self.parse_op(insn, 1)
            t1 = False
            op1_str = idc.print_operand(self.ip, 1)
            for r in self.regs:
                if r in op1_str.lower() and self.is_reg_tainted(r):
                    t1 = True
                    break
            sym1 = self.get_address_sym(op1_str)
            self.set_reg(op0_str, addr)
            self.set_reg_taint(op0_str, t1)
            self.set_op_sym(insn, 0, sym1, t1)
            if t1:
                self.taint_log.append((self.ip, f"Taint loaded to register {op0_str} via LEA"))

        elif mnem == "xor":
            op0_str = idc.print_operand(self.ip, 0)
            op1_str = idc.print_operand(self.ip, 1)
            val0 = self.parse_op(insn, 0)
            val1 = self.parse_op(insn, 1)
            res = val0 ^ val1

            t0 = self.parse_op_taint(insn, 0)
            t1 = self.parse_op_taint(insn, 1)
            t_res = (t0 or t1) if op0_str != op1_str else False

            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            sym_res = ("xor", sym0, sym1) if op0_str != op1_str else ("val", 0)

            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & 0xffffffff) == 0 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem in ("add", "sub"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            val1 = self.parse_op(insn, 1)
            res = (val0 + val1) if mnem == "add" else (val0 - val1)

            t0 = self.parse_op_taint(insn, 0)
            t1 = self.parse_op_taint(insn, 1)
            t_res = t0 or t1

            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            sym_res = (mnem, sym0, sym1)

            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & self.arch_mask) == 0 else 0
            if mnem == "add":
                self.regs['cf'] = 1 if (val0 + val1) > self.arch_mask else 0
            else:
                self.regs['cf'] = 1 if val0 < val1 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem in ("inc", "dec"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            res = (val0 + 1) if mnem == "inc" else (val0 - 1)

            t_res = self.parse_op_taint(insn, 0)
            sym0 = self.get_op_sym(insn, 0)
            sym_res = ("add" if mnem == "inc" else "sub", sym0, ("val", 1))

            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & 0xffffffff) == 0 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem == "cmp":
            val0 = self.parse_op(insn, 0)
            val1 = self.parse_op(insn, 1)
            diff = val0 - val1
            self.regs['zf'] = 1 if diff == 0 else 0
            self.regs['sf'] = 1 if diff < 0 else 0
            self.regs['cf'] = 1 if val0 < val1 else 0
            self.flags_tainted = self.parse_op_taint(insn, 0) or self.parse_op_taint(insn, 1)
            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            self.flags_sym = ("cmp", sym0, sym1) if self.flags_tainted else None

        elif mnem == "test":
            val0 = self.parse_op(insn, 0)
            val1 = self.parse_op(insn, 1)
            res = val0 & val1
            self.regs['zf'] = 1 if res == 0 else 0
            self.regs['cf'] = 0
            self.flags_tainted = self.parse_op_taint(insn, 0) or self.parse_op_taint(insn, 1)
            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            self.flags_sym = ("test", sym0, sym1) if self.flags_tainted else None

        elif mnem == "push":
            val = self.parse_op(insn, 0)
            t = self.parse_op_taint(insn, 0)
            sym = self.get_op_sym(insn, 0)
            rsp = self.get_reg("rsp") - 8
            self.set_reg("rsp", rsp)
            self.write_mem(rsp, val, 8)
            self.set_mem_taint(rsp, 8, t)
            for i in range(8):
                if t:
                    self.sym_mem[rsp + i] = sym
                else:
                    self.sym_mem.pop(rsp + i, None)
            if t:
                self.taint_log.append((self.ip, f"Taint pushed to stack [rsp]: {hex(rsp)}"))

        elif mnem == "pop":
            op0_str = idc.print_operand(self.ip, 0)
            rsp = self.get_reg("rsp")
            val = self.read_mem(rsp, 8)
            t = self.is_mem_tainted(rsp, 8)
            sym = None
            if t:
                for i in range(8):
                    if (rsp + i) in self.sym_mem:
                        sym = self.sym_mem[rsp + i]
                        break
                if sym is None:
                    sym = ("mem", ("val", rsp), 8)
            self.set_reg("rsp", rsp + 8)
            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, val, size)
                self.set_mem_taint(addr, size, t)
                self.set_op_sym(insn, 0, sym, t)
            else:
                self.set_reg(op0_str, val)
                self.set_reg_taint(op0_str, t)
                self.set_op_sym(insn, 0, sym, t)
            if t:
                self.taint_log.append((self.ip, f"Taint popped from stack [rsp] ({hex(rsp)}) to {op0_str}"))

        elif mnem == "call":
            arg_regs = ["rcx", "rdx", "r8", "r9", "rdi", "rsi"]
            any_tainted = any(self.is_reg_tainted(r) for r in arg_regs)
            self.set_reg("rax", 0)
            self.set_reg_taint("rax", any_tainted)
            rsp = self.get_reg("rsp") - 8
            self.set_reg("rsp", rsp)
            if any_tainted:
                func_op = idc.print_operand(self.ip, 0)
                args_sym = []
                for r in arg_regs:
                    if self.is_reg_tainted(r):
                        args_sym.append(self.sym_regs.get(r, ("reg", r)))
                    else:
                        args_sym.append(("val", self.get_reg(r)))
                func_sym = ("call", func_op, args_sym)
                self.sym_regs["rax"] = func_sym
                self.taint_log.append((self.ip, "Taint propagated to RAX via CALL return value"))
            else:
                self.sym_regs.pop("rax", None)

        elif mnem in ("and", "or"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            val1 = self.parse_op(insn, 1)
            res = (val0 & val1) if mnem == "and" else (val0 | val1)
            t0 = self.parse_op_taint(insn, 0)
            t1 = self.parse_op_taint(insn, 1)
            t_res = t0 or t1
            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            sym_res = (mnem, sym0, sym1)
            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & 0xffffffff) == 0 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem in ("shl", "shr", "sar"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            op_width = self.get_op_width(insn, 0)
            op_mask = (1 << op_width) - 1
            shift_count_mask = 0x3f if op_width == 64 else 0x1f
            val1 = self.parse_op(insn, 1) & shift_count_mask
            if mnem == "shl":
                res = (val0 << val1) & op_mask
            elif mnem == "shr":
                res = (val0 & op_mask) >> val1
            elif val0 & (1 << (op_width - 1)):
                res = ((val0 & op_mask) >> val1) | (~((op_mask) >> val1) & op_mask)
            else:
                res = (val0 & op_mask) >> val1
            t0 = self.parse_op_taint(insn, 0)
            t1 = self.parse_op_taint(insn, 1)
            t_res = t0 or t1
            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            sym_res = (mnem, sym0, sym1)
            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = self.dtype_size(insn.ops[0].dtype)
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & op_mask) == 0 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem in ("rol", "ror"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            if len(insn.ops) < 2 or insn.ops[1].type == 0:
                val1 = 1
                t1 = False
            else:
                val1 = self.parse_op(insn, 1)
                t1 = self.parse_op_taint(insn, 1)
            width = self.get_op_width(insn, 0)
            mask = (1 << width) - 1
            val0 = val0 & mask

            shift = val1 % width
            if shift == 0:
                res = val0
            elif mnem == "rol":
                res = ((val0 << shift) | (val0 >> (width - shift))) & mask
            else:
                res = ((val0 >> shift) | (val0 << (width - shift))) & mask

            t0 = self.parse_op_taint(insn, 0)
            t_res = t0 or t1
            sym0 = self.get_op_sym(insn, 0)
            sym1 = self.get_op_sym(insn, 1)
            sym_res = (mnem, sym0, sym1)

            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = width // 8
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)

        elif mnem in ("not", "neg"):
            op0_str = idc.print_operand(self.ip, 0)
            val0 = self.parse_op(insn, 0)
            width = self.get_op_width(insn, 0)
            mask = (1 << width) - 1
            val0 = val0 & mask

            t_res = self.parse_op_taint(insn, 0)
            sym0 = self.get_op_sym(insn, 0)
            sym_res = (mnem, sym0)

            if mnem == "not":
                res = (~val0) & mask
            else:  # neg
                res = (-val0) & mask
                self.regs['zf'] = 1 if res == 0 else 0
                self.regs['sf'] = 1 if (res & (1 << (width - 1))) != 0 else 0
                self.flags_tainted = t_res
                self.flags_sym = sym_res if t_res else None

            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                size = width // 8
                self.write_mem(addr, res, size)
                self.set_mem_taint(addr, size, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)

        elif mnem in ("cmovz", "cmove", "cmovnz", "cmovne"):
            cond = False
            if mnem in ("cmovz", "cmove"):
                cond = (self.regs['zf'] == 1)
            elif mnem in ("cmovnz", "cmovne"):
                cond = (self.regs['zf'] == 0)

            if cond:
                op0_str = idc.print_operand(self.ip, 0)
                val1 = self.parse_op(insn, 1)
                t1 = self.parse_op_taint(insn, 1)
                t_res = t1 or self.flags_tainted

                sym1 = self.get_op_sym(insn, 1)
                if self.flags_tainted:
                    sym0 = self.get_op_sym(insn, 0)
                    sym_res = ("cmov", mnem, sym1, sym0)
                else:
                    sym_res = sym1

                if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                    addr = self.parse_op(insn, 0)
                    width = self.get_op_width(insn, 0)
                    size = width // 8
                    self.write_mem(addr, val1, size)
                    self.set_mem_taint(addr, size, t_res)
                    self.set_op_sym(insn, 0, sym_res, t_res)
                else:
                    self.set_reg(op0_str, val1)
                    self.set_reg_taint(op0_str, t_res)
                    self.set_op_sym(insn, 0, sym_res, t_res)
                    if t_res:
                        self.taint_log.append((self.ip, f"Taint conditionally moved to register {op0_str}"))

        elif mnem in ("setz", "sete", "setnz", "setne"):
            cond = False
            if mnem in ("setz", "sete"):
                cond = (self.regs['zf'] == 1)
            elif mnem in ("setnz", "setne"):
                cond = (self.regs['zf'] == 0)

            res = 1 if cond else 0
            t_res = self.flags_tainted
            sym_res = ("set", mnem, self.flags_sym) if t_res else ("val", res)

            op0_str = idc.print_operand(self.ip, 0)
            if insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
                addr = self.parse_op(insn, 0)
                self.write_mem(addr, res, 1)
                self.set_mem_taint(addr, 1, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            else:
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)

        elif mnem in ("imul", "mul"):
            op0_str = idc.print_operand(self.ip, 0)
            num_ops = 0
            for op in insn.ops:
                if op.type != 0:
                    num_ops += 1
            t_res = False
            res = 0
            sym_res = None
            if num_ops == 1:
                val0 = self.get_reg("rax")
                val1 = self.parse_op(insn, 0)
                res = val0 * val1
                t_res = self.is_reg_tainted("rax") or self.parse_op_taint(insn, 0)
                sym0 = self.sym_regs.get("rax", ("reg", "rax")) if self.is_reg_tainted("rax") else ("val", val0)
                sym1 = self.get_op_sym(insn, 0)
                sym_res = ("mul", sym0, sym1)
                self.set_reg("rax", res)
                self.set_reg_taint("rax", t_res)
                if t_res:
                    self.sym_regs["rax"] = sym_res
                else:
                    self.sym_regs.pop("rax", None)
            elif num_ops == 2:
                val0 = self.parse_op(insn, 0)
                val1 = self.parse_op(insn, 1)
                res = val0 * val1
                t_res = self.parse_op_taint(insn, 0) or self.parse_op_taint(insn, 1)
                sym0 = self.get_op_sym(insn, 0)
                sym1 = self.get_op_sym(insn, 1)
                sym_res = ("mul", sym0, sym1)
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            elif num_ops == 3:
                val1 = self.parse_op(insn, 1)
                val2 = self.parse_op(insn, 2)
                res = val1 * val2
                t_res = self.parse_op_taint(insn, 1) or self.parse_op_taint(insn, 2)
                sym1 = self.get_op_sym(insn, 1)
                sym2 = self.get_op_sym(insn, 2)
                sym_res = ("mul", sym1, sym2)
                self.set_reg(op0_str, res)
                self.set_reg_taint(op0_str, t_res)
                self.set_op_sym(insn, 0, sym_res, t_res)
            self.regs['zf'] = 1 if (res & 0xffffffff) == 0 else 0
            self.flags_tainted = t_res
            self.flags_sym = sym_res if t_res else None

        elif mnem in (
            "jmp", "je", "jne", "jz", "jnz", "jb", "jae",
            "ja", "jbe", "jg", "jl", "jge", "jle",
            "jo", "jno", "js", "jns", "jp", "jnp", "jcxz",
        ):
            target = self.parse_op(insn, 0)
            jump = False
            zf = self.regs['zf']
            sf = self.regs['sf']
            cf = self.regs['cf']
            of = self.regs['of']
            pf = self.regs['pf']
            if mnem == "jmp":
                jump = True
            elif mnem in ("je", "jz"):
                jump = (zf == 1)
            elif mnem in ("jne", "jnz"):
                jump = (zf == 0)
            elif mnem == "jb":
                jump = (cf != 0)
            elif mnem in ("jae", "jnb", "jnc"):
                jump = (cf == 0)
            elif mnem == "ja":
                jump = (cf == 0 and zf == 0)
            elif mnem == "jbe":
                jump = (cf != 0 or zf == 1)
            elif mnem == "js":
                jump = (sf != 0)
            elif mnem == "jns":
                jump = (sf == 0)
            elif mnem == "jo":
                jump = (of != 0)
            elif mnem == "jno":
                jump = (of == 0)
            elif mnem == "jp":
                jump = (pf != 0)
            elif mnem == "jnp":
                jump = (pf == 0)
            elif mnem == "jl":
                jump = (sf != of)
            elif mnem == "jge":
                jump = (sf == of)
            elif mnem == "jg":
                jump = (zf == 0 and sf == of)
            elif mnem == "jle":
                jump = (zf != 0 or sf != of)
            elif mnem == "jcxz":
                jump = (self.regs['rcx'] == 0)

            if self.flags_tainted:
                taken_c, fallthrough_c = get_branch_constraints(mnem, self.flags_sym)
                if jump:
                    if taken_c:
                        self.path_constraints.append((self.ip, taken_c))
                elif fallthrough_c:
                    self.path_constraints.append((self.ip, fallthrough_c))

            if jump and self.func_start <= target < self.func_end:
                next_ip = target

        elif mnem in ("ret", "retn"):
            rsp = self.get_reg("rsp") + 8
            self.set_reg("rsp", rsp)
            return False

        self.ip = next_ip
        return True

    def dtype_size(self, dtype):
        if dtype == 0: return 1
        elif dtype == 1: return 2
        elif dtype == 2: return 4
        elif dtype == 7: return 8
        return 1

    def run_emulation(self, limit=2000):
        step_count = 0
        while step_count < limit:
            if not self.step():
                break
            step_count += 1
        return self.get_memory_strings()

    def get_memory_strings(self):
        extracted_strings = []
        current_str = []
        mem_keys = sorted(self.mem.keys())
        for k in mem_keys:
            val = self.mem[k]
            if 32 <= val <= 126 or val in (9, 10, 13):
                current_str.append(chr(val))
            else:
                if len(current_str) >= 4:
                    extracted_strings.append("".join(current_str))
                current_str = []
        if len(current_str) >= 4:
            extracted_strings.append("".join(current_str))
        return sorted(set(extracted_strings))

    def get_stack_strings(self):
        extracted_strings = []
        current_str = []
        offsets = sorted(self.stack_writes.keys())
        for off in offsets:
            _, val = self.stack_writes[off]
            if 32 <= val <= 126 or val in (9, 10, 13):
                current_str.append(chr(val))
            else:
                if len(current_str) >= 4:
                    extracted_strings.append("".join(current_str))
                current_str = []
        if len(current_str) >= 4:
            extracted_strings.append("".join(current_str))
        return sorted(set(extracted_strings))

    def speculative_explore(self, max_depth=100, max_paths=32):
        import ida_ua
        import idc

        paths = [self]
        completed_paths = []
        reachable_eas = set()
        truncated = False
        _STEP_CAP = 5000

        step_count = 0
        while paths and len(completed_paths) + len(paths) <= max_paths:
            current_emu = paths.pop(0)

            for _ in range(max_depth):
                ea = current_emu.ip
                reachable_eas.add(ea)

                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea) <= 0:
                    completed_paths.append(current_emu)
                    break

                mnem = idc.print_insn_mnem(ea).lower()

                if mnem in (
                    "je", "jne", "jz", "jnz", "jb", "jae",
                    "ja", "jbe", "jg", "jl", "jge", "jle",
                    "jo", "jno", "js", "jns", "jp", "jnp", "jcxz",
                ):
                    target = current_emu.parse_op(insn, 0)
                    next_ip = ea + insn.size

                    if current_emu.flags_tainted:
                        taken_constraint, fallthrough_constraint = get_branch_constraints(mnem, current_emu.flags_sym)

                        if current_emu.func_start <= target < current_emu.func_end:
                            emu_taken = current_emu.clone()
                            emu_taken.ip = target
                            emu_taken.flags_tainted = False
                            if taken_constraint:
                                emu_taken.path_constraints.append((ea, taken_constraint))
                            paths.append(emu_taken)

                        emu_fallthrough = current_emu.clone()
                        emu_fallthrough.ip = next_ip
                        emu_fallthrough.flags_tainted = False
                        if fallthrough_constraint:
                            emu_fallthrough.path_constraints.append((ea, fallthrough_constraint))
                        paths.append(emu_fallthrough)

                        current_emu.opaque_predicates[ea] = "symbolic_branch"
                        break
                    zf = current_emu.regs['zf']
                    sf = current_emu.regs['sf']
                    cf = current_emu.regs['cf']
                    of = current_emu.regs['of']
                    pf = current_emu.regs['pf']
                    if mnem in ("je", "jz"):
                        jump = (zf == 1)
                    elif mnem in ("jne", "jnz"):
                        jump = (zf == 0)
                    elif mnem == "jb":
                        jump = (cf != 0)
                    elif mnem in ("jae", "jnb", "jnc"):
                        jump = (cf == 0)
                    elif mnem == "ja":
                        jump = (cf == 0 and zf == 0)
                    elif mnem == "jbe":
                        jump = (cf != 0 or zf == 1)
                    elif mnem == "js":
                        jump = (sf != 0)
                    elif mnem == "jns":
                        jump = (sf == 0)
                    elif mnem == "jo":
                        jump = (of != 0)
                    elif mnem == "jno":
                        jump = (of == 0)
                    elif mnem == "jp":
                        jump = (pf != 0)
                    elif mnem == "jnp":
                        jump = (pf == 0)
                    elif mnem == "jl":
                        jump = (sf != of)
                    elif mnem == "jge":
                        jump = (sf == of)
                    elif mnem == "jg":
                        jump = (zf == 0 and sf == of)
                    elif mnem == "jle":
                        jump = (zf != 0 or sf != of)
                    elif mnem == "jcxz":
                        jump = (current_emu.regs['rcx'] == 0)
                    else:
                        jump = (zf == 1)

                    current_emu.opaque_predicates[ea] = "always_taken" if jump else "always_fallthrough"

                    if jump and current_emu.func_start <= target < current_emu.func_end:
                        current_emu.ip = target
                    else:
                        current_emu.ip = next_ip
                elif mnem in ("ret", "retn") or not current_emu.step():
                    completed_paths.append(current_emu)
                    break

                step_count += 1
                if step_count > _STEP_CAP:
                    truncated = True
                    completed_paths.append(current_emu)
                    break
            else:
                completed_paths.append(current_emu)

        all_strings = set()
        all_stack_strings = set()
        all_taint_logs = []
        merged_opaque_predicates = {}
        opaque_predicate_conflicts = []
        merged_dereferenced_pointers = set()
        merged_virtual_calls = []
        seen_calls = set()
        merged_arg_derefs = {}

        for emu in completed_paths + paths:
            all_strings.update(emu.get_memory_strings())
            all_stack_strings.update(emu.get_stack_strings())
            for ea, desc in emu.taint_log:
                all_taint_logs.append({"addr": hex(ea), "description": desc})
            for ea, verdict in emu.opaque_predicates.items():
                if ea in merged_opaque_predicates and merged_opaque_predicates[ea] != verdict:
                    opaque_predicate_conflicts.append({
                        "ea": hex(ea),
                        "previous": merged_opaque_predicates[ea],
                        "new": verdict,
                    })
                merged_opaque_predicates[ea] = verdict
            for ip_val, ptr_ea, access in emu.dereferenced_pointers:
                merged_dereferenced_pointers.add((ip_val, ptr_ea, access))
            for vc in emu.virtual_calls:
                call_key = (vc["vtable_name"], vc["vtable_offset"])
                if call_key not in seen_calls:
                    seen_calls.add(call_key)
                    merged_virtual_calls.append(vc)
            for reg, derefs in emu.arg_derefs.items():
                seen_d = { (d["offset"], d["size"], d["access"]) for d in merged_arg_derefs.get(reg, []) }
                for d in derefs:
                    key = (d["offset"], d["size"], d["access"])
                    if key not in seen_d:
                        seen_d.add(key)
                        merged_arg_derefs.setdefault(reg, []).append(d)

        path_details = []
        for idx, emu in enumerate(completed_paths + paths):
            c_strs = [format_constraint(c[1]) for c in emu.path_constraints]
            solutions = solve_constraints([c[1] for c in emu.path_constraints])
            path_details.append({
                "path_id": idx,
                "last_address": hex(emu.ip),
                "constraints": c_strs,
                "solved_inputs": {k: hex(v) if isinstance(v, int) else v for k, v in solutions.items()}
            })

        deref_records = [
            {"ip": hex(ip_val), "addr": hex(ptr_ea), "access": access}
            for ip_val, ptr_ea, access in sorted(merged_dereferenced_pointers)
        ]

        return {
            "reachable_eas": sorted([hex(x) for x in reachable_eas]),
            "opaque_predicates": {hex(k): v for k, v in merged_opaque_predicates.items()},
            "opaque_predicate_conflicts": opaque_predicate_conflicts,
            "extracted_strings": sorted(all_strings),
            "stack_strings": sorted(all_stack_strings),
            "taint_log": all_taint_logs,
            "dereferenced_pointers": deref_records,
            "virtual_calls": merged_virtual_calls,
            "argument_dereferences": merged_arg_derefs,
            "paths": path_details,
            "truncated": truncated,
        }


# ---- Dispatcher hook for the merged actions ----
# The original trace() and static_trace() tools were @tool @idaread entry
# points; we now route their action names into the same dispatcher. The
# callers (CLI, server, RPC) should call trace_analysis with the same
# action name. We use a thin wrapper to keep behaviour identical.

def _trace_analysis_merged_dispatch(action, kwargs) -> dict:
    """Dispatch the actions merged from trace.py and static_trace.py.

    The wrapper preserves the exact return shape of the original tools.
    """
    if action == "get":
        return _runtime_trace_get(kwargs.get("addr"), int(kwargs.get("count", 1000)))
    if action == "clear":
        return _runtime_trace_clear()
    if action == "set_options":
        return _runtime_trace_set_options(
            kwargs.get("enable_insn"),
            kwargs.get("enable_func"),
            kwargs.get("enable_bblk"),
        )
    if action == "static_trace":
        addr = kwargs.get("addr")
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err
        return _static_trace_walk(
            ea,
            int(kwargs.get("max_steps", 1000)),
            bool(kwargs.get("follow_calls", False)),
            int(kwargs.get("max_depth", 1)),
            bool(kwargs.get("include_blocks", True)),
        )
    if action == "decrypt_strings":
        addr = kwargs.get("addr")
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err
        return _static_trace_decrypt_strings(ea)
    if action == "eval_expr":
        return _static_trace_eval_expr(kwargs.get("addr"), kwargs.get("expr"))
    if action == "prefetch_context":
        addr = kwargs.get("addr")
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err
        return _prefetch_function_context(ea)
    if action == "deobfuscate_emulate":
        addr = kwargs.get("addr")
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err
        steps = int(kwargs.get("max_steps", 2000))
        emu = TinyEmulator(ea)

        # Parse taint inputs
        taint_regs = kwargs.get("taint_regs") or []
        if isinstance(taint_regs, str):
            taint_regs = [x.strip() for x in taint_regs.split(",") if x.strip()]
        for r in taint_regs:
            emu.set_reg_taint(r, True)

        taint_mem = kwargs.get("taint_mem") or []
        if isinstance(taint_mem, str):
            taint_mem = [x.strip() for x in taint_mem.split(",") if x.strip()]
        for m in taint_mem:
            try:
                m_ea = int(m, 0)
                emu.set_mem_taint(m_ea, 8, True)
            except (ValueError, TypeError):
                pass

        if kwargs.get("speculative") or kwargs.get("speculate"):
            # Multi-path speculative explore
            max_depth = int(kwargs.get("max_depth", 100))
            max_paths = int(kwargs.get("max_paths", 32))
            res = emu.speculative_explore(max_depth=max_depth, max_paths=max_paths)
            return {
                "ok": True,
                "emulated_address": hex(ea),
                "steps_executed": steps,
                "mode": "speculative",
                "extracted_strings": res["extracted_strings"],
                "stack_strings": res["stack_strings"],
                "reachable_eas": res["reachable_eas"],
                "opaque_predicates": res["opaque_predicates"],
                "taint_log": res["taint_log"],
                "paths": res["paths"],
            }
        else:
            # Single-path run
            strings = emu.run_emulation(steps)
            c_strs = [format_constraint(c[1]) for c in emu.path_constraints]
            solutions = solve_constraints([c[1] for c in emu.path_constraints])
            return {
                "ok": True,
                "emulated_address": hex(ea),
                "steps_executed": steps,
                "mode": "single_path",
                "extracted_strings": strings,
                "stack_strings": emu.get_stack_strings(),
                "written_memory_bytes": len(emu.mem),
                "taint_log": [{"addr": hex(ea_log), "description": desc} for ea_log, desc in emu.taint_log],
                "constraints": c_strs,
                "solved_inputs": {k: hex(v) if isinstance(v, int) else v for k, v in solutions.items()}
            }
    return make_error(MCPError.INVALID_ARGS, f"Unknown merged action: {action}")


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================
