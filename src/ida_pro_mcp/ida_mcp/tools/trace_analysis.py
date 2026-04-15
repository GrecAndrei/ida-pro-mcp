
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
        ],
        "Action: import_trace|analyze_coverage|find_loops|extract_api_calls|basic_blocks_hit|execution_timeline_graph|cross_run_diff|runtime_taint_overlay|state_replay|path_unlock|coverage_debug_plan|exploitability_score|anti_analysis_detect|lifetime_map|hybrid_callgraph_confidence",
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
    - cross_run_diff: Compare two traces (run IDs or explicit lists) and report divergences.
    - runtime_taint_overlay: Lightweight taint overlay from source addresses to potential sinks.
    - state_replay: Snapshot debugger state or compare current state to a stored snapshot.
    - path_unlock: Suggest concrete inputs and breakpoints to unlock uncovered/runtime-blocked paths.
    - coverage_debug_plan: Recommend next breakpoints/watchpoints to maximize novel coverage.
    - exploitability_score: Rank suspicious runtime behavior using execution evidence.
    - anti_analysis_detect: Detect anti-debug/anti-VM/timing/environment checks in observed execution.
    - lifetime_map: Build temporal alloc/free/use map and flag UAF/double-free candidates.
    - hybrid_callgraph_confidence: Reconcile static and dynamic edges with confidence tags.
    """
    try:
        import bisect
        import time
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

        def load_trace(run_id: Optional[str] = None):
            nonlocal trace_data
            global _TRACE_CACHE, _TRACE_RUNS
            if trace_data and isinstance(trace_data, list):
                _TRACE_CACHE = _parse_addrs(trace_data)
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
                            addrs.append(int(line.strip(), 0))
                        except Exception:
                            pass
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

        if action == "import_trace":
            run_id = kwargs.get("run_id")
            if not path and not trace_data and not _TRACE_CACHE:
                return make_error(MCPError.INVALID_ARGS, "path or trace_data required")
            addrs = load_trace(run_id=str(run_id) if run_id is not None else None)
            result = {
                "ok": True,
                "path": path,
                "count": len(addrs),
                "unique": len(set(addrs)),
                "source": "runtime" if (not path and not trace_data and addrs) else ("cache" if (not path and not trace_data) else "input"),
            }
            if run_id is not None:
                result["run_id"] = str(run_id)
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
            trace_list = _resolve_run_trace(str(run_id), load_trace(run_id=str(run_id) if run_id is not None else None))
            if not trace_list:
                return {"ok": True, "timeline": [], "nodes": [], "edges": [], "count": 0, "note": "No trace data loaded."}

            events = []
            nodes = []
            edges = []
            seen_nodes = set()
            trace_trimmed = trace_list[:timeline_limit]
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
            }

        elif action == "cross_run_diff":
            run_a = kwargs.get("run_a")
            run_b = kwargs.get("run_b")
            raw_trace_a = kwargs.get("trace_a")
            raw_trace_b = kwargs.get("trace_b")
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
            return {
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

        elif action == "runtime_taint_overlay":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            if not trace_list:
                return {"ok": True, "tainted": [], "propagation": [], "note": "No trace data loaded."}
            sources = _parse_addrs(kwargs.get("taint_sources") or kwargs.get("sources") or [])
            sinks = set(_parse_addrs(kwargs.get("sink_addrs") or kwargs.get("sinks") or []))
            if not sources:
                sources = [trace_list[0]]
            window = max(1, int(kwargs.get("propagation_window", 3)))

            tainted = set(sources)
            propagation = []
            for i, ea in enumerate(trace_list):
                if ea in tainted:
                    for off in range(1, window + 1):
                        j = i + off
                        if j >= len(trace_list):
                            break
                        nxt = int(trace_list[j])
                        if nxt not in tainted:
                            tainted.add(nxt)
                            propagation.append({"from": hex(ea), "to": hex(nxt), "distance": off})

            overlays = []
            for ea in sorted(tainted):
                overlays.append({
                    "addr": hex(ea),
                    "name": _ea_name(ea),
                    "sink_reached": ea in sinks,
                })
            sink_hits = [x for x in overlays if x["sink_reached"]]
            return {
                "ok": True,
                "sources": [hex(x) for x in sources],
                "tainted": overlays[:2000],
                "propagation": propagation[:4000],
                "sink_hits": sink_hits[:200],
                "counts": {"tainted": len(overlays), "sink_hits": len(sink_hits)},
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
            loops = Counter(trace_list).most_common(20)
            hot = sum(1 for _, c in loops if c > 5)
            sink_hits = sum(1 for ea in trace_list if ea in set(sinks))
            transition_count = len(_trace_pairs(trace_list))
            score = 0.0
            score += min(30.0, hot * 3.0)
            score += min(25.0, sink_hits * 5.0)
            score += min(25.0, len(writes) * 2.0)
            score += min(20.0, transition_count / 50.0)
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
                    "transitions": transition_count,
                },
            }

        elif action == "anti_analysis_detect":
            trace_list = load_trace(run_id=str(kwargs.get("run_id")) if kwargs.get("run_id") is not None else None)
            suspicious_apis = {
                "debugger": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"),
                "timing": ("QueryPerformanceCounter", "GetTickCount", "RDTSC"),
                "environment": ("GetModuleHandle", "GetProcAddress", "GetAdaptersInfo"),
                "vm": ("VBox", "vmware", "qemu", "wine"),
            }
            findings = []
            names = []
            for ea in set(trace_list):
                nm = _ea_name(ea)
                if nm:
                    names.append(nm)
            names_blob = " ".join(names).lower()
            for family, patterns in suspicious_apis.items():
                hits = [p for p in patterns if p.lower() in names_blob]
                if hits:
                    findings.append({"family": family, "hits": hits, "count": len(hits)})
            confidence = "low"
            if len(findings) >= 3:
                confidence = "high"
            elif len(findings) >= 1:
                confidence = "medium"
            return {
                "ok": True,
                "confidence": confidence,
                "findings": findings,
                "observed_symbol_count": len(names),
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================
