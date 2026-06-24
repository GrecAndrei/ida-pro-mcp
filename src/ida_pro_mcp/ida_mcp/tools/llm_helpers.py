
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import json
import re


def _adaptive_score_gate(vals):
    """Adaptive gate = Q50 + IQR for score/confidence arrays."""
    try:
        arr = sorted(float(v) for v in vals if v is not None)
    except Exception:
        arr = []
    if not arr:
        return 0.0
    q50 = arr[len(arr) // 2]
    q75 = arr[min(len(arr) - 1, int(round((len(arr) - 1) * 0.75)))]
    return float(q50 + max(0.0, q75 - q50))


# ============================================================================
# LLM_HELPERS - LLM-Specific Helper Actions for Optimized Interaction
# ============================================================================

try:
    from ..support._api_categories import API_CATEGORIES as _API_CATEGORIES
except ImportError:
    from support._api_categories import API_CATEGORIES as _API_CATEGORIES  # type: ignore[import-not-found]

try:
    from ...host.context_density import ContextDensityOptimizer
except ImportError:
    try:
        from ida_pro_mcp.services import ContextDensityOptimizer
    except ImportError:
        ContextDensityOptimizer = None  # type: ignore[misc,assignment]


def _count_functions(max_count: int = 200000):
    """Count total functions (capped for safety on huge binaries)."""
    idx = -1
    for idx, _ in enumerate(idautils.Functions()):
        if idx >= max_count - 1:
            return max_count
    return idx + 1


def _get_imports_summary():
    """Get a compact import summary."""
    imports = {}
    def imp_cb(ea, name, ordinal):
        if name:
            imports[name] = ea
        return True
    nimps = ida_nalt.get_import_module_qty()
    modules = []
    for i in range(nimps):
        mod = ida_nalt.get_import_module_name(i)
        if mod:
            modules.append(mod)
        ida_nalt.enum_import_names(i, imp_cb)
    return modules, imports


def _categorize_imports(imports):
    """Categorize imports into functional groups."""
    cats = {}
    for name in imports:
        for cat, apis in _API_CATEGORIES.items():
            for api in apis:
                if api.lower() in name.lower():
                    cats.setdefault(cat, []).append(name)
                    break
    return cats


def _estimate_tokens(text):
    """Estimate token count (~4 chars per token)."""
    try:
        from ida_pro_mcp.services import estimate_tokens
    except ImportError:
        return len(text) // 4 if text else 0
    return estimate_tokens(text)


# ============================================================================
# Context Density Optimizer for RE-specific compaction
# ============================================================================

_RE_COMPACTION_RULES = [
    # Strip IDA color/font tags
    (re.compile(r'<[^>]+>'), ''),
    # Collapse xref dumps: "xref: addr1\nxref: addr2\n..." -> "xrefs: addr1, addr2, ... (N total)"
    (re.compile(r'(xref[s]?\s*[:\-]?\s*)\n+', re.IGNORECASE), r'\1'),
    # Compress hex dumps: keep first 3 and last 1 line, collapse middle
    (re.compile(r'((?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){3})(?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){3,}((?:[0-9a-fA-F]{8,16}\s+[0-9a-fA-F ]{16,48}\s+.*\n){1})'), r'\1... (hex truncated)\n\2'),
    # Compress long decompiler output: keep first 5 lines
    (re.compile(r'(//.*?\n|\n){6,}'), lambda m: '... (code truncated)\n'),
]


def _clean_re_content(raw_message: str, max_lines: int = 30, max_line_len: int = 200) -> str:
    """Aggressively prune RE-specific verbose content to maximize context density.
    
    Implements Contextual Information Density Maximization principles:
    - Strip IDA markup tags
    - Compress hex dumps to previews
    - Truncate long xref lists to histograms
    - Collapse redundant whitespace
    """
    if not raw_message:
        return ""
    cleaned = raw_message
    
    # Apply regex-based compaction rules
    for pattern, replacement in _RE_COMPACTION_RULES:
        cleaned = pattern.sub(replacement, cleaned)
    
    # Line-level compaction
    lines = cleaned.splitlines()
    if len(lines) > max_lines:
        # Keep first N/2 and last N/2 lines, indicate truncation
        half = max_lines // 2
        lines = lines[:half] + [f"... ({len(lines) - max_lines} lines truncated) ..."] + lines[-half:]
    
    # Truncate individual long lines
    result_lines = []
    for line in lines:
        line = line.strip()
        if len(line) > max_line_len:
            line = line[:max_line_len - 3] + "..."
        result_lines.append(line)
    
    cleaned = "\n".join(result_lines)
    
    # Collapse redundant whitespace
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    cleaned = re.sub(r'[ \t]+', ' ', cleaned)
    
    return cleaned.strip()


def _compress_xref_list(xrefs: list[str], max_show: int = 10) -> str:
    """Compress a list of xrefs into a compact histogram + preview."""
    if not xrefs:
        return "none"
    total = len(xrefs)
    if total <= max_show:
        return ", ".join(xrefs)
    # Show top N and indicate remainder
    preview = ", ".join(xrefs[:max_show])
    return f"{preview} ... ({total - max_show} more)"


def _histogram_by_segment(addresses: list[int]) -> dict[str, int]:
    """Count addresses by segment name for compact representation."""
    counts: dict[str, int] = {}
    for ea in addresses:
        seg = idaapi.getseg(ea)
        name = ida_segment.get_segm_name(seg) if seg else "unknown"
        counts[name] = counts.get(name, 0) + 1
    return counts


def _llm_summarize_output(data: dict) -> str:
    """Generate a one-line LLM-friendly summary of any tool output."""
    if not isinstance(data, dict):
        return "Non-dict output received"
    if data.get("error") is True or "error" in data:
        return f"Error: {data.get('message', data.get('error', 'unknown'))}"
    if "functions" in data:
        total = data.get("total_matches", len(data.get("functions", [])))
        return f"Found {total} function(s) matching constraints"
    if "candidates" in data:
        return f"Bridge search found {len(data.get('candidates', []))} candidate(s) via {data.get('bridges', {})}"
    if "results" in data and "compression_ratio" in data:
        return f"TurboQuant: {data.get('ingested', 0)} vectors, {data.get('compression_ratio', 0)}x compression"
    if "ranked" in data:
        return f"Preference store ranked {len(data.get('ranked', []))} candidate(s) by Q-value"
    if "ingested" in data:
        return f"Ingested {data.get('ingested', 0)} function(s)"
    if "stats" in data:
        return f"Stats: {data['stats']}"
    if "macros" in data:
        return f"{data.get('count', 0)} macro(s)"
    if "sessions" in data:
        return f"{data.get('count', len(data.get('sessions', [])))} session(s)"
    if "cheatsheet" in data:
        return "Cheatsheet generated"
    if "compacted" in data:
        return f"Compacted {data.get('original_tokens', 0)} -> {data.get('compacted_tokens', 0)} tokens"
    return "Tool completed successfully"


@tool
@idaread
def llm_helpers(
    action: Annotated[Literal[
        "bootstrap",
        "context_window", "function_digest", "binary_digest", "explain_address",
        "suggest_next", "progress_report", "focus_area", "question_answer",
        "guided_analysis", "cheatsheet", "compact", "enrich",
        "intent_tool_compiler", "adaptive_query_planner", "question_type_router",
        "behavioral_signature_search", "cross_artifact_correlation_search",
        "function_role_classifier", "dangerous_pattern_explainer",
        "api_contract_extractor", "global_state_influence_mapper",
        "interprocedural_data_lineage_graph", "semantic_diff_explainer",
        "decompile_disasm_consistency_search", "argument_semantics_search",
        "path_constrained_search",
    ],
                       "LLM helper action"],
    addr: Annotated[Optional[str], "Address for context"] = None,
    query: Annotated[Optional[str], "Question or topic"] = None,
    max_tokens: Annotated[int, "Target token budget"] = 2000,
    limit: Annotated[int, "Max results to return"] = 10,
    history: Annotated[Optional[str], "Comma-separated previously analyzed addresses"] = None,
    **kwargs,
) -> dict:
    """
    LLM-specific helper actions to optimize binary analysis interaction.

    Actions:
    - bootstrap: Opinionated first-turn playbook for LLMs new to this MCP (what to call first and why)
    - context_window: Build optimized context window fitting token budget
    - function_digest: Ultra-compact function summary (name, args, purpose, key APIs)
    - binary_digest: Ultra-compact binary overview (~200 tokens)
    - explain_address: Natural-language-ready explanation of what's at an address
    - suggest_next: Suggest next areas to investigate based on history
    - progress_report: Analysis progress report (% functions analyzed)
    - focus_area: Identify most interesting/important area to analyze next
    - question_answer: Answer a question about the binary using available data
    - guided_analysis: Step-by-step guided analysis workflow
    - cheatsheet: Dynamic cheatsheet of relevant tool calls for this binary
    - compact: RE-specific context density optimizer (strip IDA tags, compress hex/xrefs, truncate long output)
        Params: query (content to compact), max_lines, max_line_len
        Returns: {compacted, original_tokens, compacted_tokens, note}
    - enrich: Post-process any tool output with LLM-friendly metadata.
        Params: query (JSON tool output to enrich)
        Returns: {enriched, confidence, coverage, estimated_tokens, budget_pct, suggested_next_actions, summary, original}
    """
    try:
        # Compatibility shim: older guided paths referenced `info` directly.
        info = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None

        if action == "bootstrap":
            return {
                "ok": True,
                "action": "bootstrap",
                "first_calls": [
                    "session(action='info')",
                    "blackboard(action='frontier', limit=10)",
                    "predictor(action='recommend_bundle')",
                ],
            }

        elif action == "context_window":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for context_window")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(ea) or hex(ea)
            budget = max_tokens * 4  # chars budget

            parts = []

            # Function header
            proto = get_prototype(ea)
            parts.append(f"== {func_name} ==")
            if proto:
                parts.append(f"Prototype: {proto}")
            parts.append(f"Address: {hex(ea)}  Size: {hex_size(func.end_ea - func.start_ea)}")

            # Disassembly (prioritize first)
            disasm_lines = []
            for item in idautils.FuncItems(ea):
                line = f"{hex(item)}  {ida_lines.tag_remove(idc.generate_disasm_line(item, 0))}"
                disasm_lines.append(line)

            # Xrefs to this function
            callers = []
            _ctx_xref_limit = 5000
            _ctx_xref_count = 0
            for xref in idautils.XrefsTo(ea):
                if _ctx_xref_count >= _ctx_xref_limit:
                    break
                _ctx_xref_count += 1
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.append(idc.get_func_name(caller_func.start_ea) or hex(caller_func.start_ea))
            callers = list(set(callers))[:10]

            # Xrefs from this function
            callees = []
            _ctx_cr_count = 0
            _ctx_cr_limit = 5000
            for item in idautils.FuncItems(ea):
                if _ctx_cr_count >= _ctx_cr_limit:
                    break
                for xref in idautils.CodeRefsFrom(item, 0):
                    if _ctx_cr_count >= _ctx_cr_limit:
                        break
                    _ctx_cr_count += 1
                    target = ida_funcs.get_func(xref)
                    if target and target.start_ea != ea:
                        callees.append(idc.get_func_name(target.start_ea) or hex(target.start_ea))
            callees = list(set(callees))[:10]

            if callers:
                parts.append(f"Called by: {', '.join(callers)}")
            if callees:
                parts.append(f"Calls: {', '.join(callees)}")

            # String references
            str_refs = []
            _ctx_dref_limit = 5000
            _ctx_dref_count = 0
            for item in idautils.FuncItems(ea):
                if _ctx_dref_count >= _ctx_dref_limit:
                    break
                for dref in idautils.DataRefsFrom(item):
                    if _ctx_dref_count >= _ctx_dref_limit:
                        break
                    _ctx_dref_count += 1
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                                str_refs.append(decoded[:80])
                            except Exception:
                                pass
            if str_refs:
                parts.append(f"Strings: {'; '.join(str_refs[:10])}")

            # Add disassembly up to budget
            current_size = sum(len(p) for p in parts)
            remaining = budget - current_size - 50
            disasm_text = "\n".join(disasm_lines)
            if remaining <= 0:
                disasm_text = "... (truncated)"
            elif len(disasm_text) > remaining:
                disasm_text = disasm_text[:remaining] + "\n... (truncated)"
            parts.append(f"Disassembly:\n{disasm_text}")

            context = "\n".join(parts)
            return {
                "ok": True,
                "context": context,
                "estimated_tokens": _estimate_tokens(context),
                "budget": max_tokens,
            }

        elif action == "function_digest":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(ea) or f"sub_{ea:x}"
            proto = get_prototype(ea) or ""
            size = func.end_ea - func.start_ea

            # Key API calls
            apis = []
            _dig_xref_limit = 5000
            _dig_xref_count = 0
            for item in idautils.FuncItems(ea):
                if _dig_xref_count >= _dig_xref_limit:
                    break
                for xref in idautils.CodeRefsFrom(item, 0):
                    if _dig_xref_count >= _dig_xref_limit:
                        break
                    _dig_xref_count += 1
                    target_name = idc.get_func_name(xref)
                    if target_name and not target_name.startswith("sub_"):
                        apis.append(target_name)
            apis = list(dict.fromkeys(apis))[:8]

            # Strings referenced
            strs = []
            _dig_dref_limit = 5000
            _dig_dref_count = 0
            for item in idautils.FuncItems(ea):
                if _dig_dref_count >= _dig_dref_limit:
                    break
                for dref in idautils.DataRefsFrom(item):
                    if _dig_dref_count >= _dig_dref_limit:
                        break
                    _dig_dref_count += 1
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                                strs.append(decoded[:40])
                            except Exception:
                                pass
            strs = strs[:5]

            digest = f"{func_name} @ {hex(ea)} | size={size} | apis=[{', '.join(apis)}]"
            if strs:
                digest += f" | strs=[{', '.join(strs)}]"
            if proto:
                digest += f" | proto={proto}"

            return {"ok": True, "digest": digest}

        elif action == "binary_digest":
            func_count = _count_functions()
            modules, imports = _get_imports_summary()
            cats = _categorize_imports(imports)

            # Top strings
            top_strings = []
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if raw and len(raw) > 5:
                    try:
                        decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                        top_strings.append(decoded[:60])
                    except Exception:
                        pass
                    if len(top_strings) >= 20:
                        break

            file_type_id = _inf_filetype_id() if info else 0
            file_type_name = _filetype_name(file_type_id).upper() if info else "UNKNOWN"

            image_size = (_inf_max_ea() - _inf_min_ea()) if info else 0
            seg_count = sum(1 for _ in idautils.Segments())

            proc_name = _inf_procname() if info else ""
            bits = _inf_bitness() if info else 0
            min_ea = _inf_min_ea() if info else 0
            max_ea = _inf_max_ea() if info else 0
            lines = [
                f"Format: {file_type_name} | Arch: {proc_name} | Bits: {bits}",
                f"Image: {hex(min_ea)}-{hex(max_ea)} ({hex_size(image_size)})",
                f"Functions: {func_count} | Segments: {seg_count} | Imports: {len(imports)} | Modules: {len(modules)}",
            ]
            if cats:
                cat_summary = ", ".join(f"{k}:{len(v)}" for k, v in sorted(cats.items(), key=lambda x: -len(x[1])))
                lines.append(f"API categories: {cat_summary}")
            if modules:
                lines.append(f"Import modules: {', '.join(modules[:10])}")
            if top_strings:
                lines.append(f"Notable strings: {'; '.join(top_strings[:10])}")
            if file_type_name in ("UNKNOWN", "RAW", "OBJ"):
                lines.append(
                    "Raw/unknown format: start with firmware_view(action='scan_region') and firmware_view(action='pointer_sweep') after confirming the load architecture."
                )

            digest = "\n".join(lines)
            return {"ok": True, "digest": digest, "estimated_tokens": _estimate_tokens(digest)}

        elif action == "explain_address":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea = parse_address(addr)

            explanation = []
            name = idc.get_name(ea) or ""
            func = ida_funcs.get_func(ea)

            if func:
                func_name = idc.get_func_name(func.start_ea) or hex(func.start_ea)
                if ea == func.start_ea:
                    explanation.append(f"Function entry point: {func_name}")
                    proto = get_prototype(ea)
                    if proto:
                        explanation.append(f"Prototype: {proto}")
                else:
                    offset = ea - func.start_ea
                    explanation.append(f"Inside function {func_name} at offset +{hex(offset)}")

                disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                explanation.append(f"Instruction: {disasm}")
            else:
                # Data or unknown
                flags = ida_bytes.get_flags(ea)
                if ida_bytes.is_data(flags):
                    explanation.append(f"Data at {hex(ea)}")
                    st = idc.get_str_type(ea)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(ea, -1, st)
                        if raw:
                            decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                            explanation.append(f"String: {decoded[:100]}")
                    else:
                        val = ida_bytes.get_dword(ea)
                        explanation.append(f"Value: {hex(val)}")
                elif ida_bytes.is_code(flags):
                    explanation.append(f"Code (not in a function): {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}")
                else:
                    explanation.append(f"Unknown/unexplored at {hex(ea)}")

            if name and not name.startswith("sub_"):
                explanation.insert(0, f"Named: {name}")

            # Segment context
            seg = idaapi.getseg(ea)
            if seg:
                seg_name = ida_segment.get_segm_name(seg)
                explanation.append(f"Segment: {seg_name}")

            return {"ok": True, "explanation": "\n".join(explanation)}

        elif action == "suggest_next":
            analyzed = set()
            if history:
                for h in history.split(","):
                    h = h.strip()
                    if h:
                        try:
                            analyzed.add(parse_address(h))
                        except Exception:
                            pass

            suggestions = []

            if not analyzed:
                # No history - suggest entry points and interesting functions
                import ida_entry
                for i in range(min(ida_entry.get_entry_qty(), 3)):
                    ordinal = ida_entry.get_entry_ordinal(i)
                    ea = ida_entry.get_entry(ordinal)
                    name = ida_entry.get_entry_name(ordinal) or hex(ea)
                    suggestions.append(f"Entry point: {name} @ {hex(ea)}")

                # Find functions with interesting names
                _sug_func_limit = 50000
                for sug_idx, ea in enumerate(idautils.Functions()):
                    if sug_idx >= _sug_func_limit:
                        break
                    fname = idc.get_func_name(ea) or ""
                    if any(kw in fname.lower() for kw in ("main", "init", "start", "entry", "setup")):
                        suggestions.append(f"Key function: {fname} @ {hex(ea)}")
                    if len(suggestions) >= 10:
                        break
            else:
                # Find connected functions not yet analyzed
                _sug_xref_limit = 5000
                _sug_xref_count = 0
                for analyzed_ea in analyzed:
                    if len(suggestions) >= 15:
                        break
                    func = ida_funcs.get_func(analyzed_ea)
                    if not func:
                        continue
                    for item in idautils.FuncItems(func.start_ea):
                        if _sug_xref_count >= _sug_xref_limit:
                            break
                        for xref in idautils.CodeRefsFrom(item, 0):
                            if _sug_xref_count >= _sug_xref_limit:
                                break
                            _sug_xref_count += 1
                            target = ida_funcs.get_func(xref)
                            if target and target.start_ea not in analyzed:
                                tname = idc.get_func_name(target.start_ea) or hex(target.start_ea)
                                suggestion = f"Called by analyzed: {tname} @ {hex(target.start_ea)}"
                                if suggestion not in suggestions:
                                    suggestions.append(suggestion)
                    # Also check callers
                    for xref in idautils.XrefsTo(func.start_ea):
                        if _sug_xref_count >= _sug_xref_limit:
                            break
                        _sug_xref_count += 1
                        caller = ida_funcs.get_func(xref.frm)
                        if caller and caller.start_ea not in analyzed:
                            cname = idc.get_func_name(caller.start_ea) or hex(caller.start_ea)
                            suggestion = f"Calls analyzed: {cname} @ {hex(caller.start_ea)}"
                            if suggestion not in suggestions:
                                suggestions.append(suggestion)

            return {"ok": True, "suggestions": "\n".join(suggestions[:limit]), "count": len(suggestions)}

        elif action == "progress_report":
            analyzed = set()
            if history:
                for h in history.split(","):
                    h = h.strip()
                    if h:
                        try:
                            analyzed.add(parse_address(h))
                        except Exception:
                            pass

            total = _count_functions()
            analyzed_count = len(analyzed)
            pct = (analyzed_count / total * 100) if total else 0

            # Categorize remaining functions
            named_remaining = 0
            unnamed_remaining = 0
            _prog_func_limit = 100000
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _prog_func_limit:
                    break
                if ea not in analyzed:
                    name = idc.get_func_name(ea) or ""
                    if name.startswith("sub_"):
                        unnamed_remaining += 1
                    else:
                        named_remaining += 1

            return {
                "ok": True,
                "total_functions": total,
                "analyzed": analyzed_count,
                "progress_pct": round(pct, 1),
                "named_remaining": named_remaining,
                "unnamed_remaining": unnamed_remaining,
            }

        elif action == "focus_area":
            # Identify most interesting function to analyze next
            candidates = []
            _focus_func_limit = int(kwargs.get("max_functions", 50000))
            _focus_xref_limit = 5000
            for func_idx, ea in enumerate(idautils.Functions()):
                if func_idx >= _focus_func_limit:
                    break
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                name = idc.get_func_name(ea) or ""
                size = func.end_ea - func.start_ea
                _xr_count = 0
                for _ in idautils.XrefsTo(ea):
                    _xr_count += 1
                    if _xr_count >= _focus_xref_limit:
                        break
                xref_count = _xr_count

                # Score based on multiple factors
                score = 0
                if not name.startswith("sub_"):
                    score += 5
                score += min(xref_count, 20)
                score += min(size // 100, 10)

                # Check for interesting API calls
                _focus_cr_count = 0
                for item in idautils.FuncItems(ea):
                    if _focus_cr_count >= _focus_xref_limit:
                        break
                    for xref in idautils.CodeRefsFrom(item, 0):
                        if _focus_cr_count >= _focus_xref_limit:
                            break
                        _focus_cr_count += 1
                        target_name = idc.get_func_name(xref) or ""
                        for cat in _API_CATEGORIES:
                            if any(api.lower() in target_name.lower() for api in _API_CATEGORIES[cat]):
                                score += 3
                                break
                    if score > 30:
                        break

                candidates.append((ea, name or f"sub_{ea:x}", score, size, xref_count))

            candidates.sort(key=lambda x: -x[2])
            lines = []
            for ea, name, score, size, xrefs in candidates[:limit]:
                lines.append(f"{name} @ {hex(ea)}  score={score}  size={size}  xrefs={xrefs}")

            return {"ok": True, "focus_areas": "\n".join(lines), "count": len(lines)}

        elif action == "question_answer":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for question_answer")

            q = query.lower()
            answer_parts = []

            # Route to appropriate data based on question keywords
            if any(kw in q for kw in ("import", "api", "library", "dll", "module")):
                modules, imports = _get_imports_summary()
                cats = _categorize_imports(imports)
                answer_parts.append(f"Import modules ({len(modules)}): {', '.join(modules[:15])}")
                answer_parts.append(f"Total imports: {len(imports)}")
                if cats:
                    for cat, apis in sorted(cats.items(), key=lambda x: -len(x[1])):
                        answer_parts.append(f"  {cat}: {', '.join(apis[:10])}")

            elif any(kw in q for kw in ("string", "text", "message")):
                strs = []
                for s in idautils.Strings():
                    raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                    if raw and len(raw) > 4:
                        try:
                            decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                            strs.append(f"{hex(s.ea)}  {decoded[:80]}")
                        except Exception:
                            pass
                        if len(strs) >= 30:
                            break
                answer_parts.append(f"Strings found ({len(strs)}):")
                answer_parts.extend(strs[:20])

            elif any(kw in q for kw in ("function", "func", "routine", "subroutine")):
                func_count = _count_functions()
                named = 0
                _qa_func_limit = 200000
                for qa_idx, ea in enumerate(idautils.Functions()):
                    if qa_idx >= _qa_func_limit:
                        break
                    if not (idc.get_func_name(ea) or "").startswith("sub_"):
                        named += 1
                answer_parts.append(f"Total functions: {func_count}")
                answer_parts.append(f"Named functions: {named}")
                answer_parts.append(f"Unnamed (sub_): {func_count - named}")

            elif any(kw in q for kw in ("size", "segment", "section")):
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if seg:
                        name = ida_segment.get_segm_name(seg)
                        answer_parts.append(f"{name}: {hex(seg.start_ea)}-{hex(seg.end_ea)} ({hex_size(seg.size())})")

            else:
                # General overview
                answer_parts.append(f"Binary: {_inf_procname() if info else ''} {_inf_bitness()}-bit")
                answer_parts.append(f"Functions: {_count_functions()}")
                modules, imports = _get_imports_summary()
                answer_parts.append(f"Imports: {len(imports)} from {len(modules)} modules")
                answer_parts.append(f"Query '{query}' - use more specific keywords (import, string, function, segment) for detailed answers")

            return {"ok": True, "answer": "\n".join(answer_parts)}

        elif action == "guided_analysis":
            file_type = _inf_filetype_id() if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            if is_firmware := not (is_pe or is_elf):
                steps = [
                    "firmware_view(action='triage_snapshot')",
                    "firmware_view(action='detect_load_address')",
                    "firmware_view(action='detect_vector_table')",
                    "firmware_view(action='detect_mmio')",
                    "firmware_view(action='campaign')",
                    "taint(action='report')",
                ]
            elif is_pe:
                steps = [
                    "imports_deep(action='summary')",
                    "crypto_id(action='scan')",
                    "llm_helpers(action='function_digest', addr='entry')",
                    "llm_helpers(action='focus_area')",
                ]
            else:
                steps = [
                    "imports_deep(action='summary')",
                    "llm_helpers(action='function_digest', addr='main')",
                    "llm_helpers(action='focus_area')",
                ]

            return {"ok": True, "guided_steps": steps}

        elif action == "compact":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query (content to compact) required for compact action")
            max_lines = int(kwargs.get("max_lines", 30))
            max_line_len = int(kwargs.get("max_line_len", 200))

            if ContextDensityOptimizer is not None:
                optimizer = ContextDensityOptimizer(
                    max_code_preview=max_lines if max_lines < 10 else 5,
                    max_hex_preview=3,
                    max_line_length=max_line_len,
                )
                compacted = optimizer.optimize(query, context_label="llm_helpers_compact")
                return {
                    "ok": True,
                    "original_lines": len(query.splitlines()) if query else 0,
                    "compacted_lines": len(compacted["compacted"].splitlines()),
                    "original_tokens": compacted["original_tokens"],
                    "compacted_tokens": compacted["compacted_tokens"],
                    "compacted": compacted["compacted"],
                    "compression_ratio": compacted["compression_ratio"],
                    "info_density_before": compacted.get("info_density_before"),
                    "info_density_after": compacted.get("info_density_after"),
                    "note": "ContextDensityOptimizer applied: IDA tags stripped, hex dumps truncated, xrefs compressed, whitespace collapsed.",
                }
            else:
                # Backward-compatible fallback
                compacted = _clean_re_content(query, max_lines=max_lines, max_line_len=max_line_len)
                return {
                    "ok": True,
                    "original_lines": len(query.splitlines()) if query else 0,
                    "compacted_lines": len(compacted.splitlines()),
                    "original_tokens": _estimate_tokens(query),
                    "compacted_tokens": _estimate_tokens(compacted),
                    "compacted": compacted,
                    "note": "RE-specific compaction applied: IDA tags stripped, hex dumps truncated, xrefs compressed, redundant whitespace collapsed."
                }

        elif action == "enrich":
            """
            Post-process any tool output with LLM-friendly metadata.
            Adds confidence, coverage, suggested next actions, and context budget tracking.
            """
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query (JSON tool output) required for enrich action")
            try:
                data = json.loads(query) if isinstance(query, str) else query
            except json.JSONDecodeError:
                data = {"raw_text": query}

            # Heuristic confidence scoring based on data completeness
            confidence = 0.5
            coverage = "partial"
            suggestions = []

            if isinstance(data, dict):
                if data.get("ok") is True:
                    confidence = 0.8
                    coverage = "complete"

                # Schemaboot query results
                if "functions" in data and "total_matches" in data:
                    matched = data.get("total_matches", 0)
                    limit = len(data.get("functions", []))
                    confidence = min(0.95, 0.7 + (limit / max(matched, 1)) * 0.25)
                    if matched > limit:
                        coverage = f"top {limit} of {matched} matches"
                        suggestions.append(f"schemaboot(action='query', constraints=..., limit={min(matched, 50)}, offset={limit})")
                    else:
                        coverage = "all matches returned"
                    if matched == 0:
                        confidence = 0.1
                        suggestions.append("Broaden constraints or use schemaboot(action='stats') to see index coverage")

                # Bridge search results
                if "candidates" in data and "bridges" in data:
                    nc = len(data.get("candidates", []))
                    nb = sum(len(v) for v in data.get("bridges", {}).values())
                    confidence = min(0.9, 0.6 + nc * 0.02 + nb * 0.03)
                    if nc == 0:
                        confidence = 0.1
                        suggestions.append("Try different query_constraints or bridge_types=['strings']")

                # TurboQuant results
                if "results" in data and "compression_ratio" in data:
                    confidence = 0.85
                    suggestions.append("Use turboquant(action='query', query_key=..., top_k=10) for similarity search")

                # Generic: if error present, suggest remediation
                if data.get("error") is True or "error" in data:
                    confidence = 0.0
                    code = data.get("code", "")
                    if "SESSION_REQUIRED" in code or "session" in str(data.get("hint", "")).lower():
                        suggestions.append("session(action='create', binary_path='...')")
                    if "FILE_NOT_FOUND" in code:
                        suggestions.append("Verify the path exists using misc(action='health')")
                    if "ACTION_NOT_FOUND" in code:
                        suggestions.append("Call tools/list to see available actions")
                    if "DB_ERROR" in code or "index" in str(data.get("hint", "")).lower():
                        suggestions.append("schemaboot(action='ingest') to rebuild the index")

            # Context budget estimation
            payload_json = json.dumps(data, separators=(",", ":"))
            estimated_tokens = len(payload_json) // 4
            budget_pct = min(100, round(estimated_tokens / max(max_tokens, 1) * 100, 1))

            return {
                "ok": True,
                "enriched": True,
                "confidence": round(confidence, 2),
                "coverage": coverage,
                "estimated_tokens": estimated_tokens,
                "budget_pct": budget_pct,
                "suggested_next_actions": suggestions[:5],
                "summary": _llm_summarize_output(data),
                "original": data,
            }

        elif action == "cheatsheet":
            file_type = _inf_filetype_id() if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)
            fmt = "PE" if is_pe else "ELF" if is_elf else "firmware/raw"
            return {
                "ok": True,
                "format": fmt,
                "hint": "Invoke /ida-start skill for orientation, /ida-analysis for tool reference.",
            }

            cheat = ["=== Quick Reference for This Binary ==="]
            cheat.append(f"Arch: {_inf_procname() if info else ''} | {_inf_bitness()}-bit")
            cheat.append("")
            cheat.append("== START HERE ==")
            cheat.append("ida://state                                    # READ FIRST — full picture + next actions")
            cheat.append("ida://blackboard/frontier                      # Ranked unvisited functions")
            cheat.append("ida://blackboard/coverage                      # How much have you analyzed?")
            cheat.append("")
            cheat.append("== ORIENT ==")
            cheat.append("idb(action='summary')                          # Binary metadata")
            cheat.append("data(action='imports')                         # What APIs does it use?")
            cheat.append("llm_helpers(action='binary_digest')            # Compact overview")
            cheat.append("summarize(action='report')                     # Full report: security + taint + blackboard")
            cheat.append("")
            cheat.append("== ANALYZE A FUNCTION ==")
            cheat.append("code(action='smart_decompile', addrs='0xADDR') # Best single call — everything at once")
            cheat.append("code(action='explain', addrs='0xADDR')         # Plain-English summary (no pseudocode)")
            cheat.append("llm_helpers(action='function_role_classifier', addr='0xADDR')  # entry_point/callback/dispatcher?")
            cheat.append("llm_helpers(action='dangerous_pattern_explainer', addr='0xADDR')  # Why is it dangerous?")
            cheat.append("llm_helpers(action='api_contract_extractor', addr='0xADDR')   # What does it expect/return?")
            cheat.append("")
            cheat.append("== FIND THINGS ==")
            cheat.append("search(action='nl', query='function that parses HTTP headers')  # Semantic search (embeddings)")
            cheat.append("search(action='behavior', pattern='crypto_symmetric')           # Find by behavior tag")
            cheat.append("search(action='find', pattern='recv')                           # Smart unified search")
            cheat.append("search(action='func_by_sig', pattern='leaf')                    # Leaf functions")
            cheat.append("search(action='func_by_sig', pattern='no_callers')              # Entry points / callbacks")
            cheat.append("llm_helpers(action='behavioral_signature_search', query='network_http')  # BehaviorClassifier search")
            cheat.append("")
            cheat.append("== SECURITY / VULNS ==")
            cheat.append("taint(action='report')                         # All source→sink paths")
            cheat.append("taint(action='trace', addr='0xADDR', source='recv')  # Trace from specific source")
            cheat.append("ida://taint                                    # READ: full taint report as resource")
            cheat.append("search(action='vulnerable')                    # Dangerous API call sites")
            cheat.append("summarize(action='security_posture')           # Risk level + mitigations")
            cheat.append("")
            cheat.append("== COVERAGE / FRONTIER ==")
            cheat.append("blackboard(action='coverage')                  # How much analyzed? Per-cluster breakdown")
            cheat.append("blackboard(action='frontier', limit=10)        # Top 10 unvisited functions to analyze next")
            cheat.append("blackboard(action='propagate_labels')          # Spread labels to similar functions")
            cheat.append("")
            cheat.append("== BLACKBOARD ==")
            cheat.append("blackboard(action='write', addr='0xADDR', category='hypothesis', title='...', confidence=0.8)")
            cheat.append("blackboard(action='next_target')               # Priority queue of what to analyze")
            cheat.append("blackboard(action='list', category='vuln')     # All confirmed vulnerabilities")
            cheat.append("blackboard(action='frontier')                  # Unvisited functions ranked by proximity to findings")
            cheat.append("")
            cheat.append("== CROSS-FUNCTION ==")
            cheat.append("llm_helpers(action='interprocedural_data_lineage_graph', addr='0xADDR', query='recv')")
            cheat.append("llm_helpers(action='global_state_influence_mapper', addr='0xADDR')  # What globals does it touch?")
            cheat.append("llm_helpers(action='semantic_diff_explainer', addr='0xADDR', query='0xADDR2')  # Diff two functions")
            cheat.append("llm_helpers(action='path_constrained_search', addr='0xADDR', query='crypto')   # Reachable crypto funcs")
            cheat.append("")
            cheat.append("== STRINGS ==")
            cheat.append("string_ops(action='indicators')            # C2 / malware behavior patterns")
            cheat.append("string_ops(action='ioc_extract')               # C2 URLs, IPs, registry keys")
            cheat.append("string_ops(action='score_c2')                  # Malware family guess + risk score")
            cheat.append("string_ops(action='find_urls')                 # URLs")
            cheat.append("string_ops(action='find_commands')             # Shell commands")
            cheat.append("")
            cheat.append("== RESOURCES (read without tool calls) ==")
            cheat.append("ida://state                 # Full analysis state — read at start of every turn")
            cheat.append("ida://proposals             # Pending engine proposals (renames, vulns, contradictions)")
            cheat.append("ida://blackboard/frontier   # Ranked unvisited functions")
            cheat.append("ida://blackboard/coverage   # Coverage map")
            cheat.append("ida://taint                 # Taint report")
            cheat.append("ida://knowledge/gaps        # Expected but not found subsystems")

            # Firmware-specific section (always shown — many binaries are firmware)
            cheat.append("")
            cheat.append("== RAW FIRMWARE (flat binary / ROM / flash image) ==")
            cheat.append("firmware_view(action='triage_snapshot')       # One-shot load/vector/MMIO orientation snapshot")
            cheat.append("")
            cheat.append("-- Step 0: Solve the three hard problems (no datasheet needed) --")
            cheat.append("firmware_view(action='detect_load_address')    # Where is this binary mapped? (Cortex-M/MIPS/generic)")
            cheat.append("firmware_view(action='detect_vector_table')    # Where are the entry points? (IVT extraction)")
            cheat.append("firmware_view(action='detect_mmio')            # What are those register addresses? (peripheral detection)")
            cheat.append("")
            cheat.append("-- Step 1: Identify what you have --")
            cheat.append("binary_info(action='headers')                  # File type, arch, base address")
            cheat.append("binary_info(action='sections')                 # Sections with entropy")
            cheat.append("binary_info(action='compiler')                 # Compiler/toolchain hints")
            cheat.append("firmware_view(action='scan_region')            # Classify all regions (code/data/strings/pointers)")
            cheat.append("firmware_view(action='region_profile')         # Entropy + type distribution per region")
            cheat.append("")
            cheat.append("-- Step 2: Find structure --")
            cheat.append("firmware_view(action='pointer_sweep')          # Find pointer tables and vtables")
            cheat.append("firmware_view(action='pointer_clusters')       # Group pointers by target region")
            cheat.append("firmware_view(action='table_candidates')       # Jump tables, dispatch tables")
            cheat.append("firmware_view(action='carve_plan')             # Recommended retyping plan")
            cheat.append("")
            cheat.append("-- Step 3: Apply structure --")
            cheat.append("firmware_view(action='smart_carve', apply=false)  # Dry-run: see what would be created")
            cheat.append("firmware_view(action='smart_carve', apply=true)   # Apply: create functions/structs/strings")
            cheat.append("firmware_view(action='auto_retype')            # Auto-retype data regions")
            cheat.append("")
            cheat.append("-- Step 4: Campaign (full automated workflow) --")
            cheat.append("firmware_view(action='campaign')               # Run full firmware analysis campaign")
            cheat.append("firmware_view(action='multi_region_campaign')  # Plan ranked multi-region campaign")
            cheat.append("")
            cheat.append("-- Step 5: Understand what's there --")
            cheat.append("blackboard(action='list', category='firmware_view')  # All firmware findings")
            cheat.append("ida://knowledge/gaps                           # Expected subsystems not yet found")
            cheat.append("ida://knowledge/peripherals                    # MMIO peripheral map")
            cheat.append("ida://knowledge/state_machines                 # Detected state machines")
            cheat.append("taint(action='report')                         # MMIO/DMA/UART input → dangerous sinks")
            cheat.append("")
            cheat.append("-- Firmware-specific search --")
            cheat.append("search(action='behavior', pattern='crypto_symmetric')  # Crypto primitives")
            cheat.append("search(action='func_by_sig', pattern='no_callers')     # Interrupt handlers / entry points")
            cheat.append("search(action='func_by_sig', pattern='leaf size:>200') # Large leaf functions (crypto/codec)")
            cheat.append("string_ops(action='find_paths')                # Unix paths (Linux firmware)")
            cheat.append("string_ops(action='find_commands')             # Shell commands")



            return {"ok": True, "cheatsheet": "\n".join(cheat)}

        elif action == "behavioral_signature_search":
            # Find functions matching a behavioral signature using BehaviorClassifier.
            # More precise than search(action='behavior') — uses full pseudocode + embedding.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required: behavioral signature to search for")
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
            except Exception:
                return make_error(MCPError.IDA_ERROR, "BehaviorClassifier unavailable")
            tag = query.strip().lower().replace(" ", "_")
            matches = []
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 300 or len(matches) >= limit:
                    break
                checked += 1
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    hits = classifier.classify(str(cfunc)[:2000], threshold=0.0, top_k=6, block=False)
                    gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                    hits = [h for h in hits if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate]
                    for h in hits:
                        if tag in h.get("behavior", "").lower() or tag in h.get("behavior", ""):
                            matches.append({
                                "addr": hex(func_ea),
                                "name": idc.get_func_name(func_ea),
                                "behavior": h["behavior"],
                                "score": round(float(h.get("score", 0)), 3),
                            })
                            break
                except Exception:
                    pass
            matches.sort(key=lambda x: -x["score"])
            return {
                "ok": True,
                "query": tag,
                "matches": "\n".join(f"{m['addr']}  {m['name']}  {m['behavior']}  score={m['score']}" for m in matches),
                "items": matches,
                "count": len(matches),
                "checked": checked,
            }

        elif action == "function_role_classifier":
            # Classify a function's architectural role: entry_point, callback, handler,
            # parser, serializer, crypto_primitive, allocator, dispatcher, etc.
            # Uses BehaviorClassifier + structural signals (callers, callees, size).
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)
            n_callers = sum(1 for x in idautils.XrefsTo(ea, 0) if x.iscode)
            callees = set()
            for item in idautils.FuncItems(ea):
                for xr in idautils.XrefsFrom(item, 0):
                    if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                        callees.add(idc.get_name(xr.to) or hex(xr.to))
            size = func.end_ea - func.start_ea if func else 0

            # Structural role signals
            roles = []
            if n_callers == 0:
                roles.append({"role": "entry_point_or_callback", "confidence": 0.75,
                               "reason": "no callers — likely entry point, export, or callback"})
            if size < 32 and len(callees) == 1:
                roles.append({"role": "wrapper", "confidence": 0.80,
                               "reason": f"tiny function ({size}b) with single callee"})
            if len(callees) > 15:
                roles.append({"role": "dispatcher", "confidence": 0.70,
                               "reason": f"calls {len(callees)} functions — likely dispatcher/router"})

            # BehaviorClassifier role
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    hits = classifier.classify(str(cfunc)[:2000], threshold=0.0, top_k=6, block=False)
                    gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                    hits = [h for h in hits if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate]
                    for h in hits:
                        roles.append({"role": h["behavior"], "confidence": round(float(h.get("score", 0)), 3),
                                      "reason": "BehaviorClassifier"})
            except Exception:
                pass

            roles.sort(key=lambda x: -x["confidence"])
            primary = roles[0] if roles else {"role": "unknown", "confidence": 0.0, "reason": "no signals"}
            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "primary_role": primary["role"],
                "confidence": primary["confidence"],
                "all_roles": roles[:6],
                "callers": n_callers, "callees": len(callees), "size": size,
            }

        elif action == "dangerous_pattern_explainer":
            # Explain why a dangerous pattern is dangerous and what exploitation looks like.
            # Uses BehaviorClassifier to identify the pattern, then generates a structured explanation.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            pseudo = ""
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    pseudo = str(cfunc)[:3000]
            except Exception:
                pass
            if not pseudo:
                return make_error(MCPError.DECOMPILER_UNAVAILABLE, "decompilation required")

            # Identify dangerous patterns
            _DANGEROUS = {
                "memcpy": ("buffer_overflow", "destination buffer may be smaller than source length"),
                "strcpy": ("buffer_overflow", "no length check — classic stack/heap overflow"),
                "sprintf": ("buffer_overflow", "format string written to fixed buffer"),
                "gets": ("buffer_overflow", "reads unlimited input — always exploitable"),
                "system": ("command_injection", "shell command built from user input"),
                "execve": ("command_injection", "executes arbitrary command"),
                "printf": ("format_string", "first arg may be user-controlled format string"),
                "scanf": ("buffer_overflow", "reads into fixed buffer without length"),
            }
            found = [(api, *_DANGEROUS[api]) for api in _DANGEROUS if api in pseudo]

            # BehaviorClassifier for additional context
            classifier_tags = []
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                hits = classifier.classify(pseudo, threshold=0.0, top_k=6, block=False)
                gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                hits = [h for h in hits if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate]
                classifier_tags = [{"behavior": h["behavior"], "score": round(float(h.get("score", 0)), 3)} for h in hits]
            except Exception:
                pass

            explanations = []
            for api, vuln_type, reason in found:
                explanations.append({
                    "api": api,
                    "vuln_type": vuln_type,
                    "why_dangerous": reason,
                    "exploitation": {
                        "buffer_overflow": "Attacker controls source/length → overwrite return address or adjacent heap chunk",
                        "command_injection": "Attacker controls string argument → arbitrary OS command execution",
                        "format_string": "Attacker controls format string → arbitrary read/write via %n/%s",
                    }.get(vuln_type, "Attacker-controlled input reaches dangerous operation"),
                    "mitigation": {
                        "buffer_overflow": "Use strncpy/snprintf with explicit length; validate input size before copy",
                        "command_injection": "Use execve with argument array; never pass user input to system()",
                        "format_string": "Always use printf(\"%s\", user_input) — never printf(user_input)",
                    }.get(vuln_type, "Validate and sanitize all inputs before use"),
                })

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "dangerous_patterns": explanations,
                "behavior_tags": classifier_tags,
                "summary": (
                    f"{fname} contains {len(found)} dangerous pattern(s): "
                    + ", ".join(f"{e['api']} ({e['vuln_type']})" for e in explanations)
                ) if found else f"{fname}: no known dangerous patterns detected in pseudocode",
            }

        elif action == "api_contract_extractor":
            # Infer what a function expects (preconditions) and returns (postconditions)
            # by analyzing all call sites. Uses embedding similarity to group call patterns.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)

            # Collect call sites and their context
            call_sites = []
            for xref in idautils.XrefsTo(ea, 0):
                if not xref.iscode:
                    continue
                caller_func = idaapi.get_func(xref.frm)
                if not caller_func:
                    continue
                try:
                    cfunc = ida_hexrays.decompile(caller_func.start_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    # Find the call line
                    call_ea_hex = hex(xref.frm)
                    for line in pseudo.splitlines():
                        if fname in line or call_ea_hex in line:
                            call_sites.append({
                                "caller": idc.get_func_name(caller_func.start_ea),
                                "call_line": line.strip()[:120],
                                "caller_addr": hex(caller_func.start_ea),
                            })
                            break
                except Exception:
                    pass
                if len(call_sites) >= 20:
                    break

            # Analyze the function itself for return value usage
            return_patterns = []
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    pseudo = str(cfunc)
                    # Look for return statements
                    for line in pseudo.splitlines():
                        if "return" in line.lower():
                            return_patterns.append(line.strip()[:80])
            except Exception:
                pass

            # Use BehaviorClassifier to infer contract semantics
            contract_tags = []
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                call_context = "\n".join(cs["call_line"] for cs in call_sites[:10])
                if call_context:
                    hits = classifier.classify(call_context, threshold=0.0, top_k=5, block=False)
                    gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                    hits = [h for h in hits if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate]
                    contract_tags = [h["behavior"] for h in hits]
            except Exception:
                pass

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "call_sites_analyzed": len(call_sites),
                "call_patterns": call_sites[:10],
                "return_patterns": return_patterns[:5],
                "inferred_contract": {
                    "behavior_tags": contract_tags,
                    "note": (
                        f"Analyzed {len(call_sites)} call sites. "
                        "Call patterns show how callers use this function. "
                        "Return patterns show what values are returned."
                    ),
                },
            }

        elif action == "global_state_influence_mapper":
            # Map which global variables a function reads and writes.
            # Returns a structured influence map: {global_addr: {read, write, name}}.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)
            fname = idc.get_func_name(ea)
            reads, writes = {}, {}
            for item_ea in idautils.FuncItems(ea):
                for xref in idautils.DataRefsFrom(item_ea):
                    seg = idaapi.getseg(xref)
                    if not seg:
                        continue
                    # Skip code segments (function pointers etc)
                    if seg.perm & idaapi.SEGPERM_EXEC:
                        continue
                    gname = idc.get_name(xref) or hex(xref)
                    gsize = idc.get_item_size(xref)
                    entry = {"addr": hex(xref), "name": gname, "size": gsize}
                    # Determine read vs write from instruction
                    flags = ida_bytes.get_flags(item_ea)
                    if ida_bytes.is_code(flags):
                        mnem = (idc.print_insn_mnem(item_ea) or "").lower()
                        if any(m in mnem for m in ("mov", "str", "st", "push", "write")):
                            writes[hex(xref)] = entry
                        else:
                            reads[hex(xref)] = entry
                    else:
                        reads[hex(xref)] = entry

            return {
                "ok": True, "addr": hex(ea), "name": fname,
                "reads": list(reads.values())[:30],
                "writes": list(writes.values())[:30],
                "read_count": len(reads),
                "write_count": len(writes),
                "summary": (
                    f"{fname} reads {len(reads)} global(s), writes {len(writes)} global(s). "
                    + ("Pure function (no global writes)." if not writes else
                       f"Modifies: {', '.join(e['name'] for e in list(writes.values())[:5])}")
                ),
            }

        elif action == "interprocedural_data_lineage_graph":
            # Trace how a value flows from a source address through function calls.
            # Uses taint tool internally for the actual tracing.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (source function or address)")
            source = query or "recv"
            try:
                try: from .taint import taint as _taint
                except ImportError: from taint import taint as _taint  # type: ignore[import-not-found]
                result = _taint(action="paths", source=source, max_depth=5, max_paths=15)
                paths = result.get("paths", [])
                return {
                    "ok": True,
                    "source": source,
                    "addr": addr,
                    "paths": paths,
                    "path_count": len(paths),
                    "note": (
                        f"Data lineage from '{source}' traced through {len(paths)} path(s). "
                        "Each path shows the call chain from source to sink."
                    ),
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"taint tracing failed: {e}")

        elif action == "semantic_diff_explainer":
            # Explain behavioral differences between two functions using embedding distance
            # and BehaviorClassifier. addr = function A, query = address of function B.
            if not addr or not query:
                return make_error(MCPError.INVALID_ARGS, "addr (function A) and query (function B address) required")
            ea_a, err = validate_addr(addr, require_func=True)
            if err:
                return err
            ea_b, err2 = validate_addr(query, require_func=True)
            if err2:
                return err2

            pseudo_a = pseudo_b = ""
            try:
                cfunc = ida_hexrays.decompile(ea_a)
                if cfunc:
                    pseudo_a = str(cfunc)[:3000]
                cfunc = ida_hexrays.decompile(ea_b)
                if cfunc:
                    pseudo_b = str(cfunc)[:3000]
            except Exception:
                pass

            # Embedding similarity
            emb_sim = 0.0
            tags_a, tags_b = [], []
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                classifier = BehaviorClassifier.instance(embedder)
                if pseudo_a and pseudo_b:
                    vec_a = embedder.embed(pseudo_a)
                    vec_b = embedder.embed(pseudo_b)
                    dot = sum(x * y for x, y in zip(vec_a, vec_b))
                    import math
                    na = math.sqrt(sum(x*x for x in vec_a))
                    nb = math.sqrt(sum(x*x for x in vec_b))
                    emb_sim = dot / (na * nb) if na > 0 and nb > 0 else 0.0
                if pseudo_a:
                    hits_a = classifier.classify(pseudo_a, threshold=0.0, top_k=6, block=False)
                    gate_a = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits_a])
                    tags_a = [h["behavior"] for h in hits_a if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate_a]
                if pseudo_b:
                    hits_b = classifier.classify(pseudo_b, threshold=0.0, top_k=6, block=False)
                    gate_b = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits_b])
                    tags_b = [h["behavior"] for h in hits_b if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate_b]
            except Exception:
                pass

            only_a = [t for t in tags_a if t not in tags_b]
            only_b = [t for t in tags_b if t not in tags_a]
            shared = [t for t in tags_a if t in tags_b]

            return {
                "ok": True,
                "addr_a": hex(ea_a), "name_a": idc.get_func_name(ea_a),
                "addr_b": hex(ea_b), "name_b": idc.get_func_name(ea_b),
                "embedding_similarity": round(emb_sim, 3),
                "shared_behaviors": shared,
                "only_in_a": only_a,
                "only_in_b": only_b,
                "summary": (
                    f"Similarity: {emb_sim:.3f}. "
                    + (f"Shared: {', '.join(shared)}. " if shared else "No shared behaviors. ")
                    + (f"A only: {', '.join(only_a)}. " if only_a else "")
                    + (f"B only: {', '.join(only_b)}." if only_b else "")
                ),
            }

        elif action == "decompile_disasm_consistency_search":
            # Find functions where decompiler output and disassembly disagree.
            # Signals: decompiler shows no loops but disasm has back-edges,
            # decompiler shows no calls but disasm has call instructions, etc.
            results = []
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 200 or len(results) >= limit:
                    break
                checked += 1
                try:
                    # Count calls in disasm
                    disasm_calls = sum(
                        1 for item in idautils.FuncItems(func_ea)
                        if (idc.print_insn_mnem(item) or "").lower().startswith("call")
                    )
                    # Count calls in decompiler
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    pseudo_calls = pseudo.count("(") - pseudo.count("if (") - pseudo.count("while (") - pseudo.count("for (")
                    # Significant mismatch
                    if disasm_calls > 0 and pseudo_calls == 0:
                        results.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "issue": "disasm_has_calls_pseudo_doesnt",
                            "disasm_calls": disasm_calls,
                            "note": "Decompiler may have inlined or missed calls",
                        })
                    elif disasm_calls == 0 and pseudo_calls > 3:
                        results.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "issue": "pseudo_has_calls_disasm_doesnt",
                            "pseudo_calls": pseudo_calls,
                            "note": "Decompiler may have synthesized calls from indirect branches",
                        })
                except Exception:
                    pass
            return {
                "ok": True,
                "inconsistencies": results,
                "count": len(results),
                "checked": checked,
                "note": "Functions where decompiler and disassembly disagree on call structure.",
            }

        elif action == "argument_semantics_search":
            # Find functions where argument N has a specific semantic role.
            # Example: query="buffer pointer", addr="1" (arg index)
            # Uses BehaviorClassifier on call sites to infer argument semantics.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required: semantic description of argument role")
            arg_idx = 0
            try:
                arg_idx = int(addr) if addr else 0
            except Exception:
                pass
            matches = []
            try:
                from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
            except Exception:
                return make_error(MCPError.IDA_ERROR, "BehaviorClassifier unavailable")
            checked = 0
            for func_ea in idautils.Functions():
                if checked >= 200 or len(matches) >= limit:
                    break
                checked += 1
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue
                    pseudo = str(cfunc)
                    # Find lines with function signature (first few lines)
                    sig_lines = pseudo.splitlines()[:5]
                    sig_text = " ".join(sig_lines)
                    hits = classifier.classify(sig_text + " " + query, threshold=0.0, top_k=4, block=False)
                    gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                    if hits and float(hits[0].get("score", 0)) >= gate:
                        matches.append({
                            "addr": hex(func_ea),
                            "name": idc.get_func_name(func_ea),
                            "score": round(float(hits[0].get("score", 0)), 3),
                            "behavior": hits[0].get("behavior", ""),
                        })
                except Exception:
                    pass
            matches.sort(key=lambda x: -x["score"])
            return {
                "ok": True, "query": query, "arg_index": arg_idx,
                "matches": matches[:limit],
                "count": len(matches),
            }

        elif action == "path_constrained_search":
            # Find functions reachable from addr only under specific conditions.
            # Uses xref_analysis call_chain + BehaviorClassifier to filter by behavior.
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (start function)")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            behavior_filter = (query or "").strip().lower()
            # BFS from addr, collect reachable functions
            from collections import deque
            visited = set()
            queue = deque([ea])
            reachable = []
            while queue and len(reachable) < 200:
                cur = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                func = idaapi.get_func(cur)
                if not func:
                    continue
                reachable.append(cur)
                for item in idautils.FuncItems(cur):
                    for xr in idautils.XrefsFrom(item, 0):
                        if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                            tgt = idaapi.get_func(xr.to)
                            if tgt and tgt.start_ea not in visited:
                                queue.append(tgt.start_ea)

            # Filter by behavior if requested
            if behavior_filter:
                try:
                    from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
                    classifier = BehaviorClassifier.instance(BgeCodeEmbedder())
                    filtered = []
                    for func_ea in reachable[:100]:
                        try:
                            cfunc = ida_hexrays.decompile(func_ea)
                            if not cfunc:
                                continue
                            hits = classifier.classify(str(cfunc)[:1500], threshold=0.0, top_k=4, block=False)
                            gate = _adaptive_score_gate([h.get("score", h.get("confidence", 0.0)) for h in hits])
                            hits = [h for h in hits if float(h.get("score", h.get("confidence", 0.0)) or 0.0) >= gate]
                            if any(behavior_filter in h.get("behavior", "").lower() for h in hits):
                                filtered.append({"addr": hex(func_ea), "name": idc.get_func_name(func_ea),
                                                 "behavior": hits[0]["behavior"] if hits else ""})
                        except Exception:
                            pass
                    reachable_result = filtered
                except Exception:
                    reachable_result = [{"addr": hex(f), "name": idc.get_func_name(f)} for f in reachable[:limit]]
            else:
                reachable_result = [{"addr": hex(f), "name": idc.get_func_name(f)} for f in reachable[:limit]]

            return {
                "ok": True, "start": hex(ea),
                "behavior_filter": behavior_filter or None,
                "reachable": reachable_result,
                "count": len(reachable_result),
                "total_reachable": len(reachable),
            }

        elif action == "cross_artifact_correlation_search":
            # Correlate findings across strings, imports, xrefs, and blackboard.
            # Returns a unified ranked list of addresses with evidence from multiple sources.
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            try: from .search import search as _search
            except ImportError: from ida_mcp.tools.search import search as _search
            try: from .blackboard import BlackboardStore
            except ImportError: from blackboard import BlackboardStore  # type: ignore[import-not-found]
            results = {}

            def _add(ea_str, source, score, text):
                if ea_str not in results:
                    results[ea_str] = {"addr": ea_str, "sources": [], "score": 0.0}
                results[ea_str]["sources"].append({"source": source, "text": text[:80], "score": score})
                results[ea_str]["score"] += score

            # String matches
            sr = _search(action="string", pattern=query, limit=20)
            for line in (sr.get("matches") or "").splitlines():
                parts = line.split()
                if parts:
                    _add(parts[0], "string", 0.6, line)

            # Name matches
            nr = _search(action="name", pattern=query, limit=20)
            for line in (nr.get("matches") or "").splitlines():
                parts = line.split()
                if parts:
                    _add(parts[0], "name", 0.8, line)

            # Blackboard matches
            try:
                store = BlackboardStore()
                bb = store.list(limit=50)
                for e in bb:
                    if query.lower() in (e.get("title") or "").lower():
                        _add(e.get("addr") or "bb", "blackboard", 0.9, e.get("title", ""))
            except Exception:
                pass

            ranked = sorted(results.values(), key=lambda x: -x["score"])
            return {
                "ok": True, "query": query,
                "results": ranked[:limit],
                "count": len(ranked),
                "note": "Score = sum of evidence weights across strings/names/imports/blackboard.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
