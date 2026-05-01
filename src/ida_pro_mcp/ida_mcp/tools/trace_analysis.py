
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

_TRACE_CACHE: list[int] = []
_TRACE_RUNS: dict[str, list[int]] = {}
_TRACE_STATE_SNAPSHOTS: dict[str, dict] = {}
_TRACE_RUNS_MAX = 32
_TRACE_SNAPSHOTS_MAX = 64


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
            "runtime_taint_overlay",
            "state_replay",
            "path_unlock",
            "coverage_debug_plan",
            "exploitability_score",
            "anti_analysis_detect",
            "lifetime_map",
            "hybrid_callgraph_confidence",
            "trace_entropy",
            "api_sequence",
            "loop_analysis",
        ],
        "Action: import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit|execution_timeline_graph|cross_run_diff|runtime_taint_overlay|state_replay|path_unlock|coverage_debug_plan|exploitability_score|anti_analysis_detect|lifetime_map|hybrid_callgraph_confidence|trace_entropy|api_sequence|loop_analysis",
    ],
    path: Annotated[Optional[str], "Path to trace file"] = None,
    addr: Annotated[Optional[str], "Function or address to analyze"] = None,
    trace_data: Annotated[Optional[list], "List of executed addresses"] = None,
    **kwargs
) -> dict:
    """
    Post-mortem execution trace analysis.
    
    Actions:
    - import_trace: Load a list of addresses from a file or 'trace_data' parameter.
    - analyze_coverage: Calculate global basic block coverage based on the current trace.
    - find_loops: Identify the most frequently executed code regions (hot spots).
    - extract_api_calls: Find and count imported API calls matching the trace.
    - basic_blocks_hit: Per-function block-level coverage analysis.
        Params: addr (optional - defaults to entry point)
    - execution_timeline_graph: Merge trace flow + APIs + coverage + breakpoints + memory events into a timeline graph.
    - cross_run_diff: Compare two traces (run IDs or explicit lists) and report divergences with semantic comparison.
    - runtime_taint_overlay: Taint propagation through trace with source/sink labeling, register tracking, and distance metrics.
    - state_replay: Snapshot debugger state or compare current state to a stored snapshot.
    - path_unlock: Suggest concrete inputs and breakpoints to unlock uncovered/runtime-blocked paths.
    - coverage_debug_plan: Recommend next breakpoints/watchpoints to maximize novel coverage.
    - exploitability_score: Rank suspicious runtime behavior using execution evidence, crash proximity, and dangerous APIs.
    - anti_analysis_detect: Detect anti-debug/anti-VM/timing/environment checks, debug register accesses, and VM instructions in traces.
    - lifetime_map: Build temporal alloc/free/use map and flag UAF/double-free candidates.
    - hybrid_callgraph_confidence: Reconcile static and dynamic edges with confidence tags.
    - trace_entropy: Find high-entropy execution regions (crypto/packing) using address and instruction entropy.
    - api_sequence: Extract ordered API call sequences from trace for behavioral analysis.
    - loop_analysis: Detailed loop iteration counts, back-edge detection, hot spot identification, and nesting analysis.
    """
    try:
        import bisect
        import time
        import math
        import hashlib
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
            global _TRACE_RUNS
            if run_name:
                return list(_TRACE_RUNS.get(str(run_name), []))
            return list(fallback) if fallback else []

        def _cache_run_trace(run_name: Optional[str], values: list[int]) -> None:
            global _TRACE_RUNS
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
            global _TRACE_STATE_SNAPSHOTS
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
            global _TRACE_CACHE, _TRACE_RUNS
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
                with open(p, 'r') as f:
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
            for i in range(0, len(values) - window + 1, window // 2):
                chunk = values[i:i + window]
                # Address transition entropy
                diffs = [abs(int(chunk[j + 1]) - int(chunk[j])) for j in range(len(chunk) - 1)]
                diff_bytes = b"".join(d.to_bytes(8, "little", signed=True) for d in diffs)
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

        def _get_api_calls_ordered(trace_list: list[int]) -> list[dict]:
            apis = []
            for idx, ea in enumerate(trace_list):
                try:
                    for xref in idautils.XrefsFrom(ea):
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

        def _extract_dangerous_apis_in_trace(trace_list: list[int]) -> list[dict]:
            dangerous = []
            for idx, ea in enumerate(trace_list):
                try:
                    for xref in idautils.XrefsFrom(ea):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and callee in DANGEROUS_APIS:
                                dangerous.append({
                                    "idx": idx,
                                    "addr": hex(ea),
                                    "api": callee,
                                    "severity": DANGEROUS_APIS.get(callee, "medium"),
                                })
                except Exception:
                    pass
            return dangerous

        if action == "import_trace":
            run_id = kwargs.get("run_id")
            compress = bool(kwargs.get("compress", False))
            if not path and not trace_data and not _TRACE_CACHE:
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
            for ea in idautils.Functions():
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
            for ea in trace_set:
                for xref in idautils.XrefsFrom(ea):
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        name = idc.get_name(xref.to)
                        if name and not name.startswith("sub_"):
                            calls.append(name)
            api_calls = Counter(calls).most_common(50)
            return {"ok": True, "api_calls": api_calls, "count": len(api_calls)}

        elif action == "basic_blocks_hit":
            trace_set = set(load_trace())
            trace_sorted = sorted(trace_set)
            
            # Entry point resolution compatible with IDA 7.x-9.x
            try:
                start_ea = idaapi.get_inf_structure().start_ea
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
            for idx, ea in enumerate(trace_trimmed):
                event = {"idx": idx, "t": idx, "type": "trace", "addr": hex(ea)}
                name = _ea_name(ea)
                if name:
                    event["name"] = name
                try:
                    for xref in idautils.XrefsFrom(ea):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                api_event = {"idx": idx, "t": idx, "type": "api_call", "from": hex(ea), "to": hex(xref.to), "name": callee}
                                api_hits.append(api_event)
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
            semantic = bool(kwargs.get("semantic", True))
            trace_a = _parse_addrs(raw_trace_a) if isinstance(raw_trace_a, list) else _resolve_run_trace(str(run_a) if run_a is not None else None)
            trace_b = _parse_addrs(raw_trace_b) if isinstance(raw_trace_b, list) else _resolve_run_trace(str(run_b) if run_b is not None else None)
            if not trace_a:
                trace_a = load_trace(run_id=str(run_a) if run_a is not None else None)
            if not trace_b:
                compare_with = kwargs.get("compare_with")
                trace_b = _resolve_run_trace(str(compare_with) if compare_with is not None else None)
            if not trace_a or not trace_b:
                return make_error(MCPError.INVALID_ARGS, "cross_run_diff requires two traces (run IDs or trace_a/trace_b)")

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
                for idx, ea in enumerate(trace_a):
                    for xref in idautils.XrefsFrom(ea):
                        if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                            callee = idc.get_name(xref.to)
                            if callee and not callee.startswith("sub_"):
                                apis_a.append(callee)
                for idx, ea in enumerate(trace_b):
                    for xref in idautils.XrefsFrom(ea):
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

        elif action == "runtime_taint_overlay":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "tainted": [], "propagation": [], "note": "No trace data loaded."}
            sources = _parse_addrs(kwargs.get("taint_sources") or kwargs.get("sources") or [])
            sinks = set(_parse_addrs(kwargs.get("sink_addrs") or kwargs.get("sinks") or []))
            source_labels = kwargs.get("source_labels") or {}
            sink_labels = kwargs.get("sink_labels") or {}
            if not sources:
                sources = [trace_list[0]]
            window = max(1, int(kwargs.get("propagation_window", 3)))
            track_registers = bool(kwargs.get("track_registers", False))

            tainted_addrs = set(sources)
            tainted_regs = defaultdict(set)  # reg_name -> set of source ids
            propagation = []
            source_map = {}  # tainted addr -> source addr
            for s in sources:
                source_map[s] = s

            for i, ea in enumerate(trace_list):
                if ea in tainted_addrs:
                    current_source = source_map.get(ea, ea)
                    # Forward propagation within window
                    for off in range(1, window + 1):
                        j = i + off
                        if j >= len(trace_list):
                            break
                        nxt = int(trace_list[j])
                        if nxt not in tainted_addrs:
                            tainted_addrs.add(nxt)
                            source_map[nxt] = current_source
                            propagation.append({
                                "from": hex(ea),
                                "to": hex(nxt),
                                "distance": off,
                                "source": hex(current_source),
                            })
                    # Register-level tracking
                    if track_registers:
                        try:
                            mnem = _get_insn_mnemonic(ea).upper()
                            if any(m in mnem for m in MOV_MNEMONICS):
                                # Simple heuristic: if instruction is a mov, propagate taint to destination register
                                op0 = idc.print_operand(ea, 0)
                                op1 = idc.print_operand(ea, 1)
                                if op0 and op1:
                                    tainted_regs[op0] = tainted_regs.get(op0, set()) | tainted_regs.get(op1, {ea})
                        except Exception:
                            pass

            overlays = []
            sink_chains = []
            for ea in sorted(tainted_addrs):
                overlay = {
                    "addr": hex(ea),
                    "name": _ea_name(ea),
                    "source": hex(source_map.get(ea, sources[0])),
                    "sink_reached": ea in sinks,
                }
                if ea in sinks:
                    label = sink_labels.get(hex(ea), sink_labels.get(str(ea), ""))
                    overlay["sink_label"] = label
                    # Build chain from source to this sink
                    chain = []
                    current = ea
                    visited = set()
                    while current in source_map and current not in visited:
                        visited.add(current)
                        chain.append(hex(current))
                        if current == source_map[current]:
                            break
                        current = source_map[current]
                    chain.reverse()
                    sink_chains.append({
                        "sink": hex(ea),
                        "sink_label": label,
                        "chain": chain,
                        "chain_length": len(chain),
                    })
                # Add source labels
                if ea in sources:
                    overlay["source_label"] = source_labels.get(hex(ea), source_labels.get(str(ea), "source"))
                overlays.append(overlay)

            sink_hits = [x for x in overlays if x["sink_reached"]]
            return {
                "ok": True,
                "sources": [hex(x) for x in sources],
                "source_labels": source_labels,
                "tainted": overlays[:2000],
                "propagation": propagation[:4000],
                "sink_hits": sink_hits[:200],
                "sink_chains": sink_chains[:200],
                "register_taint": {k: list(v)[:50] for k, v in tainted_regs.items()} if track_registers else {},
                "counts": {
                    "tainted": len(overlays),
                    "sink_hits": len(sink_hits),
                    "propagation_edges": len(propagation),
                },
            }

        elif action == "state_replay":
            global _TRACE_STATE_SNAPSHOTS
            mode = str(kwargs.get("mode", "snapshot")).strip().lower()
            snapshot_id = str(kwargs.get("snapshot_id", f"snap_{time.time_ns()}"))
            if mode not in {"snapshot", "replay"}:
                return make_error(MCPError.INVALID_ARGS, "state_replay mode must be snapshot|replay")

            if mode == "snapshot":
                trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
                dbg_state = _safe_debug_state()
                snap = {
                    "snapshot_id": snapshot_id,
                    "created_at": int(time.time()),
                    "debug_state": dbg_state,
                    "trace_head": [hex(x) for x in trace_list[:1000]],
                    "trace_count": len(trace_list),
                    "meta": kwargs.get("meta") if isinstance(kwargs.get("meta"), dict) else {},
                }
                _cache_snapshot(snapshot_id, snap)
                return {"ok": True, "mode": "snapshot", "snapshot": snap}

            snap = _TRACE_STATE_SNAPSHOTS.get(snapshot_id)
            if not snap:
                return make_error(MCPError.NOT_FOUND, f"snapshot not found: {snapshot_id}")
            current = _safe_debug_state()
            expected = (snap.get("debug_state") or {}).get("regs", {})
            now_regs = current.get("regs", {}) if isinstance(current, dict) else {}
            reg_diff = []
            for k in sorted(set(expected.keys()) | set(now_regs.keys())):
                a, b = expected.get(k), now_regs.get(k)
                if a != b:
                    reg_diff.append({"reg": k, "expected": hex(a) if isinstance(a, int) else a, "current": hex(b) if isinstance(b, int) else b})
            replay_plan = [{"action": "set_reg", "reg": d["reg"], "value": d["expected"]} for d in reg_diff if d.get("expected") is not None]
            return {
                "ok": True,
                "mode": "replay",
                "snapshot_id": snapshot_id,
                "ip_expected": (snap.get("debug_state") or {}).get("ip"),
                "ip_current": current.get("ip") if isinstance(current, dict) else None,
                "reg_diff": reg_diff[:256],
                "replay_plan": replay_plan[:256],
                "determinism": "high" if not reg_diff else ("medium" if len(reg_diff) < 8 else "low"),
            }

        elif action == "path_unlock":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            blockers = _parse_addrs(kwargs.get("blockers") or [])
            if not blockers and trace_list:
                freq = Counter(trace_list)
                blockers = [ea for ea, c in freq.most_common(10) if c > 1]
            candidates = []
            for ea in blockers[:50]:
                candidates.append({"addr": hex(ea), "kind": "cmp_eq", "input_mutation": "set byte == 0"})
                candidates.append({"addr": hex(ea), "kind": "cmp_ne", "input_mutation": "set byte != 0"})
                candidates.append({"addr": hex(ea), "kind": "cmp_range", "input_mutation": "try [0x20,0x7e] ASCII span"})
            plan = [{"action": "add_bp", "addr": row["addr"]} for row in candidates[:64]]
            return {
                "ok": True,
                "blocking_predicates": [hex(x) for x in blockers[:100]],
                "input_mutations": candidates[:200],
                "debug_plan": plan,
                "note": "Heuristic path unlocking suggestions; validate with runtime trace deltas.",
            }

        elif action == "coverage_debug_plan":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            trace_set = set(trace_list)
            ranked = []
            for ea in idautils.Functions():
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

        elif action == "exploitability_score":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            sinks = _parse_addrs(kwargs.get("sinks") or kwargs.get("sink_addrs") or [])
            writes = kwargs.get("memory_writes") or []
            crash_addr = kwargs.get("crash_addr")
            loops = Counter(trace_list).most_common(20)
            hot = sum(1 for _, c in loops if c > 5)
            sink_hits = sum(1 for ea in trace_list if ea in set(sinks))
            transition_count = len(_trace_pairs(trace_list))

            # Dangerous APIs in trace
            dangerous_apis = _extract_dangerous_apis_in_trace(trace_list)
            dangerous_count = len(dangerous_apis)
            critical_apis = [d for d in dangerous_apis if d.get("severity") == "critical"]
            high_apis = [d for d in dangerous_apis if d.get("severity") == "high"]

            # Crash proximity (closer to end = higher score)
            crash_proximity = 0.0
            if crash_addr:
                try:
                    crash_ea = int(str(crash_addr), 0)
                    if crash_ea in trace_list:
                        idx = trace_list.index(crash_ea)
                        crash_proximity = (len(trace_list) - idx) / max(len(trace_list), 1) * 20.0
                    else:
                        crash_proximity = 5.0  # Crash not in trace but reported
                except Exception:
                    crash_proximity = 5.0

            # Memory write pattern analysis
            large_writes = sum(1 for w in writes if int(w.get("size", 1)) >= 256)
            stack_writes = sum(1 for w in writes if any(seg for seg in [ida_segment.getseg(int(str(w.get("addr")), 0))] if seg and (seg.perm & ida_segment.SEGPERM_EXEC)))

            score = 0.0
            score += min(20.0, hot * 2.0)
            score += min(15.0, sink_hits * 3.0)
            score += min(15.0, len(writes) * 1.5)
            score += min(10.0, transition_count / 100.0)
            score += min(15.0, dangerous_count * 3.0)
            score += min(10.0, len(critical_apis) * 5.0 + len(high_apis) * 2.5)
            score += crash_proximity
            score += min(10.0, large_writes * 2.0)
            score += min(5.0, stack_writes * 1.0)

            sev = "low"
            if score >= 70:
                sev = "high"
            elif score >= 40:
                sev = "medium"

            return {
                "ok": True,
                "score": round(min(100.0, score), 2),
                "severity": sev,
                "evidence": {
                    "trace_points": len(trace_list),
                    "hot_regions": hot,
                    "sink_hits": sink_hits,
                    "memory_writes": len(writes),
                    "large_writes": large_writes,
                    "transitions": transition_count,
                    "dangerous_apis": dangerous_count,
                    "critical_apis": len(critical_apis),
                    "high_apis": len(high_apis),
                    "crash_proximity": round(crash_proximity, 2),
                    "top_dangerous_apis": dangerous_apis[:20],
                },
            }

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
                    if mnem in MOV_MNEMONICS:
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

            confidence = "low"
            api_families = len([f for f in findings if f.get("type") == "api"])
            insn_families = len([f for f in findings if f.get("type") != "api"])
            if api_families >= 3 or insn_families >= 5:
                confidence = "high"
            elif api_families >= 1 or insn_families >= 2:
                confidence = "medium"

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

        elif action == "lifetime_map":
            alloc_events = kwargs.get("alloc_events") or []
            free_events = kwargs.get("free_events") or []
            use_events = kwargs.get("use_events") or []
            allocations = {}
            lifetimes = defaultdict(lambda: {"alloc": None, "free": [], "uses": []})
            for ev in alloc_events:
                oid = str(ev.get("id") or ev.get("ptr") or ev.get("addr"))
                if not oid:
                    continue
                allocations[oid] = ev
                lifetimes[oid]["alloc"] = ev
            for ev in free_events:
                oid = str(ev.get("id") or ev.get("ptr") or ev.get("addr"))
                if not oid:
                    continue
                lifetimes[oid]["free"].append(ev)
            for ev in use_events:
                oid = str(ev.get("id") or ev.get("ptr") or ev.get("addr"))
                if not oid:
                    continue
                lifetimes[oid]["uses"].append(ev)
            issues = []
            for oid, row in lifetimes.items():
                frees = row["free"]
                uses = row["uses"]
                if len(frees) > 1:
                    issues.append({"id": oid, "type": "double_free", "free_count": len(frees)})
                if frees and uses:
                    try:
                        free_times = []
                        for x in frees:
                            t = x.get("t", None)
                            if t is None:
                                continue
                            tv = float(t)
                            if tv > 0:
                                free_times.append(tv)
                        if not free_times:
                            late_uses = []
                        else:
                            first_free_t = min(free_times)
                            late_uses = []
                            for u in uses:
                                ut = u.get("t", None)
                                if ut is None:
                                    continue
                                uv = float(ut)
                                if uv > first_free_t:
                                    late_uses.append(u)
                    except Exception:
                        late_uses = uses
                    if late_uses:
                        issues.append({"id": oid, "type": "use_after_free", "use_count": len(late_uses)})
            return {
                "ok": True,
                "objects": [{"id": oid, **row} for oid, row in list(lifetimes.items())[:2000]],
                "issues": issues[:500],
                "counts": {"objects": len(lifetimes), "issues": len(issues)},
            }

        elif action == "hybrid_callgraph_confidence":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            dynamic_edges = set()
            last_func = None
            for ea in trace_list:
                try:
                    f = ida_funcs.get_func(ea)
                    fstart = int(f.start_ea) if f else None
                except Exception:
                    fstart = None
                if fstart is None:
                    continue
                if last_func is not None and last_func != fstart:
                    dynamic_edges.add((last_func, fstart))
                last_func = fstart

            static_edges = set()
            for (src, dst) in kwargs.get("static_edges") or []:
                try:
                    static_edges.add((int(str(src), 0), int(str(dst), 0)))
                except Exception:
                    continue
            if not static_edges:
                sampled = set()
                for ea in set(trace_list[:5000]):
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        sampled.add(int(fn.start_ea))
                for src in sampled:
                    try:
                        for x in idautils.XrefsFrom(src):
                            if x.type in [idaapi.fl_CN, idaapi.fl_CF]:
                                static_edges.add((int(src), int(x.to)))
                    except Exception:
                        continue

            observed = static_edges & dynamic_edges
            static_only = static_edges - dynamic_edges
            dynamic_only = dynamic_edges - static_edges
            confidence_rows = []
            for src, dst in list(observed)[:1500]:
                confidence_rows.append({"from": hex(src), "to": hex(dst), "confidence": "high", "evidence": "static+dynamic"})
            for src, dst in list(static_only)[:1500]:
                confidence_rows.append({"from": hex(src), "to": hex(dst), "confidence": "low", "evidence": "static_only"})
            for src, dst in list(dynamic_only)[:1500]:
                confidence_rows.append({"from": hex(src), "to": hex(dst), "confidence": "medium", "evidence": "dynamic_only"})
            return {
                "ok": True,
                "edges": confidence_rows,
                "summary": {
                    "observed": len(observed),
                    "static_only": len(static_only),
                    "dynamic_only": len(dynamic_only),
                },
                "hypotheses": [
                    "dynamic_only edges may indicate indirect calls, vtables, thunk folding, or obfuscation",
                    "static_only edges may indicate dead code, gated paths, or unmet runtime conditions",
                ],
            }

        elif action == "trace_entropy":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "regions": [], "note": "No trace data loaded."}
            window = max(16, int(kwargs.get("window", 64)))
            threshold = float(kwargs.get("threshold", 6.5))
            regions = _windowed_entropy(trace_list, window=window)
            high_entropy = [r for r in regions if r.get("insn_entropy", 0) >= threshold or r.get("addr_entropy", 0) >= threshold]
            # Sort by combined entropy
            high_entropy.sort(key=lambda x: x.get("insn_entropy", 0) + x.get("addr_entropy", 0), reverse=True)
            return {
                "ok": True,
                "window": window,
                "threshold": threshold,
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
                    "categories_present": sorted(set(a["category"] for a in apis)),
                    "unique_apis": len(set(a["api"] for a in apis)),
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================
