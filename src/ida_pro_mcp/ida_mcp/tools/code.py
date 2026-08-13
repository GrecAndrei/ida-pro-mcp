import contextlib

from ._common import (
    Annotated,
    ERROR_HINTS,
    Literal,
    MCPError,
    Optional,
    TAINT_SOURCES,
    compile_smart_pattern,
    handle_error,
    hex_ea,
    ida_funcs,
    ida_lines,
    ida_nalt,
    ida_name,
    ida_typeinf,
    idaapi,
    idaread,
    idautils,
    idc,
    is_riscv_family,
    make_error,
    normalize_list_input,
    public_arg,
    run_action,
    tool,
    validate_addr
)

# ida_ua is intentionally not exported by _common.__all__ — import it directly.
try:
    import ida_ua  # type: ignore[import-not-found]
except Exception:
    ida_ua = None  # type: ignore[assignment]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from .. import compat as _compat

try:
    from ..support.arch_utils import detect_riscv_gp as _detect_riscv_gp
except ImportError:
    _detect_riscv_gp = None  # type: ignore

from .code_helpers import *
# ``import *`` intentionally omits private helper names. This dispatcher
# uses them directly, so import the implementation helpers explicitly.
from .code_helpers import (
    _build_decompile_enrichment,
    _build_decompiler_dataflow,
    _build_function_structure_summary,
    _collect_compact_callees,
    _collect_compact_callers,
    _collect_function_string_entries,
    _collect_function_strings,
    _compute_cfg_semantics,
    _decompile_with_diagnostics,
    _detect_firmware_signals,
    _disasm_range,
    _disasm_range_structured,
    _disasm_window,
    _get_next_func,
    _get_prev_func,
    _run_custom_detector,
    _semantic_pseudocode_summary,
    _trace_argument_origin,
)

def _decompile_error_entry(addr, dec_err):
    """Normalize a per-address decompile failure into the host error envelope.

    The ida-side ``_decompile_with_diagnostics`` returns error dicts built by
    ``make_error`` (which sets ``error: True`` but never ``category``). Every
    per-address failure must carry ``error: True`` so host plumbing
    (server_dispatch / server_multi_session / postprocess) recognizes it as a
    failure rather than a success entry, plus a non-null ``category`` for
    consistency with sibling actions.
    """
    if isinstance(dec_err, dict):
        entry: dict = {
            "error": True,
            "addr": addr,
            "code": dec_err.get("code") or MCPError.DECOMPILER_FAILED,
            "category": dec_err.get("category") or "runtime",
            "message": dec_err.get("message", "Decompilation failed"),
        }
        if dec_err.get("hint"):
            entry["hint"] = dec_err["hint"]
        if dec_err.get("details"):
            entry["details"] = dec_err["details"]
        return entry
    return {
        "error": True,
        "addr": addr,
        "code": MCPError.DECOMPILER_FAILED,
        "category": "runtime",
        "message": "Decompilation failed",
        "hint": ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
    }


def _invalidate_tool_read_cache() -> None:
    """Drop the ``@idaread`` result cache after a RISC-V GP application.

    Applying the GP value and queueing reanalysis changes what later reads
    resolve (GP-relative xrefs, strings), so cached results from before the
    application must not be served for their TTL. Imported lazily because sync
    is not part of the tool module graph in every install layout.
    """
    try:
        from ida_pro_mcp.ida_mcp.sync import _tool_cache as _tc
    except Exception:
        try:
            from ida_mcp.sync import _tool_cache as _tc  # type: ignore[import-not-found]
        except Exception:
            return
    try:
        cache = _tc()
        if cache is not None:
            cache.invalidate_all()
    except Exception:
        pass


@tool
@idaread
def code(
    action: Annotated[Literal[
        "decompile", "disasm", "xrefs_to", "xrefs_from", "xrefs_to_field",
        "callees", "callers", "blocks", "callgraph", "export",
        "find_paths", "strings_in_func", "diff_functions", "semantic_decompile",
        "decomp_dataflow", "decompile_chain", "smart_decompile", "explain",
        "trace_argument_origin", "decompile_all", "detect"
    ], "Action"],
    addrs: Annotated[Optional[list[str] | str], "Address(es) - hex string or name"] = None,
    addr: Annotated[Optional[str], "Single address (alias for addrs)"] = None,
    max_items: Annotated[int, "Max items to return"] = 1000,
    max_depth: Annotated[int, "Max depth for callgraph/find_paths"] = 5,
    format: Annotated[Literal["json", "c_header", "prototypes"], "Export format"] = "json",
    disasm_style: Annotated[Literal["csmini", "classic", "annotated"], "Disassembly line style"] = "csmini",
    include_bytes: Annotated[bool, "Include instruction bytes in disassembly output"] = False,
    include_comments: Annotated[bool, "Include IDA comments inline in disassembly"] = False,
    annotate_branches: Annotated[bool, "Annotate branch/call targets with resolved names"] = False,
    structured: Annotated[bool, "Return structured per-instruction JSON instead of text"] = False,
    end: Annotated[Optional[str], "Optional end address for disasm range"] = None,
    limit: Annotated[Optional[int], "Alias for max_items (especially useful with disasm)"] = None,
    window: Annotated[Optional[int], "Disasm: number of instructions BEFORE and AFTER the start address (centered view). Overrides function-bounded default."] = None,
    field_name: Annotated[Optional[str], "Struct field name (for xrefs_to_field)"] = None,
    target: Annotated[Optional[str], "Target address (for find_paths)"] = None,
    details: Annotated[bool, "Include verbose enrichment fields in decompile output: var_rename_hints, annotated_code, complexity, callers/callees/strings lists, dataflow graph. Default False — omit to keep response compact."] = False,
    offset: Annotated[Optional[int], "decompile_all: number of matched functions to skip before returning the page (pagination)."] = None,
    mode: Annotated[Optional[Literal["full", "listing"]], "decompile_all: 'full' decompiles each function (default); 'listing' returns a fast disasm-only table (addr/name/size/prototype) without Hex-Rays."] = None,
    **kwargs
) -> list[dict] | dict:
    """
    Perform code analysis, decompilation, and graph traversal.

    ACTIONS:

    decompile - Decompile function to Pseudo-C (requires Hex-Rays)
        Params: addrs (REQUIRED), details (bool, default false)
        Returns: [{addr, code, prototype, structure, api_calls, dangerous_patterns}]
        Pass details=true to also get: var_rename_hints, annotated_code, complexity,
          dataflow top_hubs/edge_counts, blackboard_context
        Example: code(action="decompile", addrs="0x401000")
        Example: code(action="decompile", addrs="0x401000", details=true)

    disasm - Get assembly listing (LLM-compact text, one line per instruction)
        Params: addrs (REQUIRED), optional end, window (±N instructions around addrs),
                disasm_style (csmini|classic|annotated), include_bytes, include_comments,
                annotate_branches, structured (returns per-instruction JSON), limit
        Returns: [{addr, name, disasm, count, style, range}] or [{addr, name, instructions: [{addr, mnem, operands, ...}]}] if structured
        Example: code(action="disasm", addrs="0x401000")
        Example: code(action="disasm", addrs="0x125b0", end="0x12640", limit=160)
        Example: code(action="disasm", addrs="0x401000", include_comments=true, annotate_branches=true)
        Example: code(action="disasm", addrs="0x401000", structured=true)
        Example: code(action="disasm", addrs="0x4010a0", window=20)   # ±20 instructions around 0x4010a0

    xrefs_to - Get cross-references TO an address (compact text, includes function names)
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: "addr  type  func_name\\n...", count}]
        Example: code(action="xrefs_to", addrs="0x401000")

    xrefs_from - Get cross-references FROM an address (compact text, includes names)
        Params: addrs (REQUIRED)
        Returns: [{addr, xrefs: "addr  type  name\\n...", count}]
        Example: code(action="xrefs_from", addrs="0x401000")

    callees - List functions called BY this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callees: "addr  name\\n...", count}]
        Example: code(action="callees", addrs="main")

    callers - List functions that CALL this function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, callers: "addr  name\\n...", count}]
        Example: code(action="callers", addrs="printf")

    blocks - Get basic blocks (compact text with successors/predecessors)
        Params: addrs (REQUIRED)
        Returns: [{addr, blocks: "start-end  succs=[...]  preds=[...]\\n...", count}]
        Example: code(action="blocks", addrs="0x401000")

    smart_decompile - Best single call for understanding a function
        Params: addrs (REQUIRED)
        Returns: [{addr, pseudocode, behavior_tags, api_calls, crypto_hints,
                   dangerous_patterns, var_rename_hints, callers, callees,
                   strings, blackboard_context, complexity,
                   suggested_next_actions}]
        Example: code(action="smart_decompile", addrs="main")
        Best for: Getting full context about a function in one call

    explain - Plain-English structured summary of what a function does
        Params: addrs (REQUIRED)
        Returns: [{addr, name, summary, purpose, api_calls, dangerous_calls,
                   strings, complexity, callers, callees}]
        Example: code(action="explain", addrs="main")

    callgraph - Generate call graph from starting function (compact text)
        Params: addrs (REQUIRED), max_depth (default 5)
        Returns: [{addr, nodes: "addr  depth=N  name\\n...", edges: "addr -> addr\\n..."}]
        Example: code(action="callgraph", addrs="main", max_depth=3)

    find_paths - Find call-graph paths from one function to another (BFS over call graph)
        Note: this traverses the call graph (function-to-function), not intra-function CFG.
        For intra-function basic block paths, use cfg_analysis(action="paths").
        Params: addrs (REQUIRED - start function), target (REQUIRED - target function)
        Returns: {from, to, paths: [[addr1, addr2, ...], ...]}
        Example: code(action="find_paths", addrs="0x401000", target="0x402000")

    strings_in_func - List strings referenced in function (compact text)
        Params: addrs (REQUIRED)
        Returns: [{addr, strings: "addr  string_value\\n...", count}]
        Example: code(action="strings_in_func", addrs="main")

    diff_functions - Compare two functions' decompilation side by side
        Params: addrs (REQUIRED - exactly 2 addresses)
        Returns: {func_a, func_b, diff: "unified diff text", similarity: float}
        Example: code(action="diff_functions", addrs=["0x401000", "0x402000"])

    semantic_decompile - High-complexity semantic decompilation profile
        Params: addrs (REQUIRED)
        Returns: [{addr, pseudocode, semantic_summary, cfg_semantics, decomp_dataflow}]
        Includes complexity metrics, control-flow semantics, and variable dependency hubs.

    decomp_dataflow - Build decompiler-derived variable dependency graph
        Params: addrs (REQUIRED)
        Returns: [{addr, function, dataflow: {nodes, edges, top_hubs, ...}}]

    decompile_chain - Decompile function with caller/callee context
        Params: addrs (REQUIRED), max_depth (default 2 for callers/callees count)
        Returns: [{addr, function, pseudocode, callers_context: [{addr, name, pseudocode}], callees_context: [{addr, name, pseudocode}]}]
        Best for: Understanding a function within its call graph neighborhood.

    trace_argument_origin - Trace a function argument backward through callers.
        Params: addrs (REQUIRED - target function), arg_index (REQUIRED - 0-based argument index),
                max_depth (default 4), max_callers_per_level (default 10)
        Returns: {target, argument_name, prototype, trace_tree: [...]}
        Each trace entry: {depth, caller_addr, caller_name, call_site, call_line, arg_source, arg_type}
        Example: code(action="trace_argument_origin", addrs="0x401000", arg_index=2)
        Best for: Finding where a specific value (e.g., a key, buffer size, or flag) originates.

    export - Export function info
        Params: addrs (REQUIRED), format (json|c_header|prototypes)
        Returns: [{addr, name, prototype, start, end}] or {header}/{prototype}
        Example: code(action="export", addrs="main", format="c_header")

    xrefs_to_field - Find code that accesses a struct field by offset
        Params: addrs (REQUIRED), field_name (REQUIRED, e.g. "struct_name.field" or bare field name)
        Returns: [{field, struct, offset, xrefs: [{ea, func, func_name, disasm}], count}]
        Example: code(action="xrefs_to_field", addrs="main", field_name="pkt_hdr.len")

    decompile_all - Decompile many functions (optionally filtered by a name pattern)
        Params: max_items/limit (bound the number of functions returned),
                query (name substring filter), offset (pagination — skip N matched),
                mode ('full' decompiles each function; 'listing' returns a fast
                disasm-only table with no Hex-Rays, ideal for cheap triage of
                large opaque firmware)
        Returns: {results: [{addr, name, code, prototype}], count, total_functions,
                  total_matched, offset, returned, truncated, mode}
        total_functions = number actually returned this call; total_matched = full
        match count across the binary (honest, so callers can page).
        Example: code(action="decompile_all", limit=50)
        Example: code(action="decompile_all", query="_irq", mode="listing", max_items=200)

    detect - Custom per-session vulnerability/pattern detector (LLM-defined rules)
        rule_type: api_chain | string_ref | type_match | xor_threshold | caller_of | callee_of
        For api_chain: apis=['recv','memcpy'], strict_order=true — finds functions calling APIs in sequence
        For string_ref: pattern='password' — finds functions referencing matching strings
        For type_match: type_pattern='SOCKET' — finds functions with matching parameter types
        For xor_threshold: threshold=4 — finds functions with N+ XOR ops (crypto indicator)
        For caller_of/callee_of: target='recv' — finds callers/callees of a function
        Register persistent: register=true, name='my_rule', rule={...}
        List/delete: rule_type='list' or rule_type='delete', name='my_rule'
        Example: code(action="detect", rule_type="api_chain", apis=["recv","memcpy"], strict_order=true)
    """
    try:
        # Public MCP names stay on the wire; accept them beside legacy aliases.
        addrs = public_arg(kwargs, 'address', addrs)
        addr = public_arg(kwargs, 'address', addr)
        if addr and not addrs:
            addrs = addr
        disasm_style = public_arg(kwargs, 'style', disasm_style)
        limit = public_arg(kwargs, 'limit', limit)
        # decompile_all doesn't need addrs — it uses a name filter.
        # Named params offset/mode are forwarded by the host schema when present;
        # also tolerate them arriving via kwargs (direct/RPC calls).
        if action == "decompile_all":
            if offset is None:
                offset = kwargs.get("offset")
            if mode is None:
                mode = kwargs.get("mode")
            try:
                offset = max(int(offset or 0), 0)
            except (TypeError, ValueError):
                offset = 0
            listing = (mode or "").lower() == "listing"
            query = kwargs.get("query")
            # Bound the decompile set with max_items/limit (the host schema
            # strips `query`, so without this the action would decompile every
            # function unbounded and return an unbounded payload).
            budget = limit if isinstance(limit, int) else max_items
            if not isinstance(budget, int):
                try:
                    budget = int(budget)
                except (TypeError, ValueError):
                    budget = 1000
            budget = max(budget, 1)
            matcher = compile_smart_pattern(query, case_sensitive=False) if query else None
            # Two-pass collection: count every match (total_matched) but only
            # retain the requested page (budget after `offset`). Honest pagination
            # metadata so callers can page through large firmware cheaply.
            total_matched = 0
            all_funcs = []
            for func_ea in idautils.Functions():
                name = ida_funcs.get_func_name(func_ea) or ""
                if matcher and not matcher(name):
                    continue
                total_matched += 1
                # Count every match; only retain the requested page. No early
                # break: total_matched must reflect ALL matching functions, not
                # just those before the budget cut (the len(all_funcs) guard
                # keeps the collection bounded).
                if total_matched <= offset or len(all_funcs) >= budget:
                    continue
                all_funcs.append(func_ea)
            if not all_funcs:
                return {"ok": True, "results": [], "count": 0,
                        "query": query or "", "total_functions": 0,
                        "total_matched": total_matched, "offset": offset,
                        "returned": 0, "truncated": False, "mode": mode or "full"}
            all_results = []
            for func_ea in all_funcs:
                try:
                    if listing:
                        # Fast disasm-only listing mode: no Hex-Rays decompile.
                        # Gives a cheap triage table over a whole opaque blob.
                        size = 0
                        fobj = _compat.get_func_info(func_ea)
                        if fobj is not None:
                            size = int(getattr(fobj, "end_ea", func_ea)) - int(func_ea)
                        all_results.append({
                            "ok": True,
                            "addr": hex_ea(func_ea),
                            "name": ida_funcs.get_func_name(func_ea) or "",
                            "size": max(size, 0),
                            "prototype": _compat.get_prototype_string(func_ea),
                            "mode": "listing",
                        })
                        continue
                    cfunc, dec_err = _decompile_with_diagnostics(func_ea)
                    if cfunc:
                        all_results.append({
                            "ok": True,
                            "addr": hex_ea(func_ea),
                            "name": ida_funcs.get_func_name(func_ea) or "",
                            "code": str(cfunc),
                            "prototype": _compat.get_prototype_string(func_ea),
                        })
                    else:
                        entry = _decompile_error_entry(hex_ea(func_ea), dec_err)
                        entry["name"] = ida_funcs.get_func_name(func_ea) or ""
                        all_results.append(entry)
                except Exception as e:
                    entry = _decompile_error_entry(hex_ea(func_ea), {
                        "code": MCPError.DECOMPILER_FAILED,
                        "category": "runtime",
                        "message": f"Decompilation exception: {e}",
                        "hint": ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                    })
                    entry["name"] = ida_funcs.get_func_name(func_ea) or ""
                    all_results.append(entry)
            return {
                "ok": True,
                "results": all_results,
                "count": len(all_results),
                "query": query or "",
                "total_functions": len(all_funcs),
                "total_matched": total_matched,
                "offset": offset,
                "returned": len(all_results),
                "truncated": bool(total_matched > len(all_funcs) + offset),
                "mode": mode or "full",
            }

        # detect is address-less — it scans the whole binary, so it runs
        # before the per-address loop (which would otherwise reject it with
        # "Address is required" via validate_addr(None)).
        if action == "detect":
            # `target` is a named parameter of code() (used by find_paths), so
            # it never lands in **kwargs — fold it back in for caller_of and
            # callee_of detectors.
            return _run_custom_detector({**kwargs, "target": target}, max_items)

        # Support both addr (singular) and addrs (plural) for compatibility.
        # detect is address-less (it scans the whole binary), so it must not
        # be blocked by the addrs pre-check.
        if not addrs and addr:
            addrs = addr
        if not addrs:
            return make_error(MCPError.INVALID_ARGS, "addrs or addr parameter required")
        if action == "disasm":
            disasm_max = limit if isinstance(limit, int) else max_items
            if not isinstance(disasm_max, int):
                try:
                    disasm_max = int(disasm_max)
                except (TypeError, ValueError):
                    disasm_max = DISASM_MAX_LINES
            # Clamp disasm rows even when caller uses max_items directly.
            max_items = min(max(disasm_max, 1), DISASM_MAX_LINES)
        addrs = normalize_list_input(addrs)

        # For RISC-V disasm: probe GP (x3) once per call so every result entry
        # carries a note if GP-relative xrefs may be unresolved.
        _riscv_gp_info = None
        if action == "disasm" and is_riscv_family() and callable(_detect_riscv_gp):
            try:
                _riscv_gp_info = _detect_riscv_gp()
            except Exception:
                pass

        results = []

        for addr in addrs:
            ea, error = validate_addr(addr)
            if error:
                results.append({"addr": addr, **error})
                continue

            if action == "decompile":
                func = _compat.get_func_info(ea)
                if not func:
                    # Find nearest function for better error
                    prev_ea = _get_prev_func(ea)
                    next_ea = _get_next_func(ea)
                    suggestion = ""
                    if prev_ea is not None:
                        suggestion = f" Try {hex_ea(prev_ea)} ({ida_funcs.get_func_name(prev_ea) or 'unnamed'})"
                    elif next_ea is not None:
                        suggestion = f" Try {hex_ea(next_ea)} ({ida_funcs.get_func_name(next_ea) or 'unnamed'})"

                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}.{suggestion}", details={"addr": addr}))
                    continue

                # Thunk auto-resolution: if this is a thunk, follow to the real implementation
                thunk_target = None
                flags = _compat.get_func_flags(ea) or 0
                if flags & ida_funcs.FUNC_THUNK:
                    try:
                        target_ea = _compat.calc_thunk_target(ea)
                        if target_ea and target_ea != idaapi.BADADDR:
                            thunk_target = target_ea
                    except Exception:
                        pass

                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    if cfunc:
                        pseudo = str(cfunc)
                        # If thunk, append the real implementation info
                        if thunk_target:
                            target_name = idc.get_name(thunk_target) or ""
                            try:
                                import ida_nalt
                                demangled = ida_nalt.demangle_name(target_name, ida_nalt.get_short_name_synonym()) or target_name
                                if "(" in demangled:
                                    demangled = demangled[:demangled.index("(")].strip()
                            except Exception:
                                demangled = target_name
                            pseudo = f"// THUNK -> {hex(thunk_target)} ({demangled})\n{pseudo}"
                        result_entry = {
                            "ok": True,
                            "addr": hex_ea(func.start_ea),
                            "code": pseudo,
                            "prototype": _compat.get_prototype_string(func.start_ea),
                            "structure": _build_function_structure_summary(func, cfunc, details=details),
                        }
                        # Inline enrichment — heavy fields gated behind details=True
                        try:
                            enrichment = _build_decompile_enrichment(
                                func.start_ea,
                                cfunc,
                                pseudo,
                                detailed_dangerous=False,
                                include_switch_cases=False,
                                api_limit=12,
                            )
                            # Opt-in via details=True: verbose/duplicate fields.
                            # Always-on keys (api_calls, dangerous_patterns,
                            # crypto_hints) are the implicit default — keys not
                            # listed here pass through regardless of details.
                            _DETAILS_FIELDS = {
                                "var_rename_hints", "complexity", "blackboard_context",
                            }
                            for key, value in enrichment.items():
                                if not value:
                                    continue
                                if key in _DETAILS_FIELDS and not details:
                                    continue
                                result_entry[key] = value
                            # annotated_code is opt-in: only when it adds something
                            # AND the caller asked for details
                            if details:
                                try:
                                    annotated = annotate_pseudocode(
                                        pseudo, func.start_ea,
                                        enrichment.get("blackboard_context", []),
                                        enrichment.get("dangerous_patterns", []),
                                        cfunc=cfunc,
                                    )
                                    if annotated != pseudo:
                                        result_entry["annotated_code"] = annotated
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        results.append(result_entry)
                    else:
                        # Aggregate errors per-address carry the host
                        # error-envelope fields so per-batch decomp failures
                        # are recognized as errors by host plumbing.
                        results.append(_decompile_error_entry(addr, dec_err))
                except Exception as e:
                    results.append(_decompile_error_entry(addr, {
                        "code": MCPError.DECOMPILER_FAILED,
                        "category": "runtime",
                        "message": f"Decompilation exception: {e}",
                        "hint": ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                    }))

            elif action == "decompile_chain":
                func = _compat.get_func_info(ea)
                if not func:
                    prev_ea = _get_prev_func(ea)
                    next_ea = _get_next_func(ea)
                    suggestion = ""
                    if prev_ea is not None:
                        suggestion = f" Try {hex_ea(prev_ea)} ({ida_funcs.get_func_name(prev_ea) or 'unnamed'})"
                    elif next_ea is not None:
                        suggestion = f" Try {hex_ea(next_ea)} ({ida_funcs.get_func_name(next_ea) or 'unnamed'})"
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}.{suggestion}", details={"addr": addr}))
                    continue
                chain_depth = max(1, min(max_depth, 3))  # hard cap at 3
                try:
                    cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                    if not cfunc:
                        # Same contract as the other decompile actions: a
                        # decompiler refusal must surface as an error entry,
                        # not a success with an empty pseudocode body.
                        results.append(_decompile_error_entry(addr, dec_err))
                        continue
                    main_pseudo = str(cfunc)
                    main_proto = _compat.get_prototype_string(func.start_ea)
                    # Collect callers (compact: name + first 8 lines of pseudocode).
                    # caller_count reflects every unique caller found; only the
                    # first chain_depth get their pseudocode decompiled into
                    # callers_context.
                    callers_ctx = []
                    decompiled_callers = set()
                    all_caller_addrs = set()
                    for xref in idautils.CodeRefsTo(func.start_ea, 0):
                        caller_fn = _compat.get_func_start(xref)
                        if caller_fn is None:
                            continue
                        all_caller_addrs.add(caller_fn)
                        if len(callers_ctx) >= chain_depth:
                            continue
                        if caller_fn in decompiled_callers:
                            continue
                        decompiled_callers.add(caller_fn)
                        ccfunc, _ = _decompile_with_diagnostics(caller_fn)
                        if ccfunc:
                            pseudo_lines = str(ccfunc).splitlines()
                            callers_ctx.append({
                                "addr": hex_ea(caller_fn),
                                "name": ida_funcs.get_func_name(caller_fn),
                                # First 8 lines only — enough for call context
                                "pseudocode_head": "\n".join(pseudo_lines[:8]),
                                "total_lines": len(pseudo_lines),
                            })
                    # Collect callees (compact)
                    callees_ctx = []
                    decompiled_callees = set()
                    all_callee_addrs = set()
                    for item in idautils.FuncItems(func.start_ea):
                        for ref in idautils.CodeRefsFrom(item, 0):
                            callee_fn = _compat.get_func_start(ref)
                            if callee_fn is None:
                                continue
                            all_callee_addrs.add(callee_fn)
                            if len(callees_ctx) >= chain_depth:
                                continue
                            if callee_fn in decompiled_callees:
                                continue
                            decompiled_callees.add(callee_fn)
                            ccfunc, _ = _decompile_with_diagnostics(callee_fn)
                            if ccfunc:
                                pseudo_lines = str(ccfunc).splitlines()
                                callees_ctx.append({
                                    "addr": hex_ea(callee_fn),
                                    "name": ida_funcs.get_func_name(callee_fn),
                                    "pseudocode_head": "\n".join(pseudo_lines[:8]),
                                    "total_lines": len(pseudo_lines),
                                })
                    results.append({
                        "ok": True,
                        "addr": hex_ea(func.start_ea),
                        "name": ida_funcs.get_func_name(func.start_ea),
                        "prototype": main_proto,
                        "pseudocode": main_pseudo,
                        "callers_context": callers_ctx,
                        "callees_context": callees_ctx,
                        "caller_count": len(all_caller_addrs),
                        "callee_count": len(all_callee_addrs),
                        "note": "callers/callees show first 8 lines only. Use code(action='decompile') for full pseudocode.",
                    })
                except Exception as e:
                    results.append(
                        make_error(
                            MCPError.IDA_ERROR,
                            f"decompile_chain collection failed at {addr}: {type(e).__name__}: {e}",
                            details={"addr": addr, "exception_type": type(e).__name__},
                        )
                    )

            elif action == "disasm":
                func = _compat.get_func_info(ea)
                end_ea = None
                if end:
                    end_ea, end_err = validate_addr(end)
                    if end_err:
                        results.append({"addr": addr, **end_err})
                        continue
                    if end_ea <= ea:
                        results.append({"addr": addr, **make_error(MCPError.INVALID_ARGS, "end must be greater than start address")})
                        continue
                # window=N: capture ±N instructions around the start address,
                # centered on `ea`. Wins over function-bounded extraction so
                # that a caller with a known hot address gets exactly the slice
                # they asked for without paging through the rest of the body.
                # `structured` only applies to range-based disasm; reject the
                # combination instead of silently returning text.
                if window is not None and structured:
                    results.append(make_error(
                        MCPError.INVALID_ARGS,
                        "window and structured cannot be combined",
                        hint="Use structured=true without window, or window=N for a text slice.",
                        details={"window": window, "structured": structured},
                    ))
                    continue
                if window is not None:
                    try:
                        radius = int(window)
                    except (TypeError, ValueError):
                        results.append(make_error(
                            MCPError.INVALID_ARGS,
                            "window must be a non-negative integer",
                            details={"got": str(window), "type": type(window).__name__},
                        ))
                        continue
                    if radius < 0:
                        results.append(make_error(
                            MCPError.INVALID_ARGS,
                            "window must be non-negative",
                            details={"got": radius},
                        ))
                        continue
                    lines = _disasm_window(
                        ea,
                        radius=radius,
                        max_items=max_items,
                        style=disasm_style,
                        include_bytes=include_bytes,
                        include_comments=include_comments,
                        annotate_branches=annotate_branches,
                    )
                    fname = ida_funcs.get_func_name(func.start_ea) if func else ""
                    # Extract first/last addresses from formatted lines
                    # Lines are "*addr:instr" (csmini), "*addr: instr" (annotated), or "addr  instr" (classic)
                    def _extract_addr(line: str, fallback_ea: int) -> str:
                        clean = line.lstrip("*").split(":", 1)[0].split("  ", 1)[0].strip()
                        return clean if clean.startswith("0x") else hex_ea(fallback_ea)
                    first_addr = _extract_addr(lines[0], ea) if lines else hex_ea(ea)
                    last_addr = _extract_addr(lines[-1], ea) if lines else hex_ea(ea)
                    entry = {
                        "ok": True,
                        "addr": hex_ea(ea),
                        "name": fname,
                        "disasm": "\n".join(lines),
                        "count": len(lines),
                        "style": disasm_style,
                        "range": f"{first_addr}-{last_addr}",
                        "window": radius,
                    }
                    if func:
                        entry["structure"] = _build_function_structure_summary(func)
                    if not func:
                        entry["warning"] = "Address is not within a defined function. Showing raw disassembly."
                    results.append(entry)
                    continue
                if not func:
                    # Disassemble raw bytes even without function
                    raw_end = end_ea if end_ea is not None else (ea + 0x1000)
                    if structured:
                        items = _disasm_range_structured(ea, raw_end, max_items)
                        results.append({"ok": True, "addr": hex_ea(ea), "instructions": items, "count": len(items)})
                        continue
                    lines = _disasm_range(
                        ea,
                        raw_end,
                        max_items=max_items,
                        style=disasm_style,
                        include_bytes=include_bytes,
                        include_comments=include_comments,
                        annotate_branches=annotate_branches,
                    )
                    results.append({
                        "ok": True,
                        "addr": hex_ea(ea),
                        "warning": "Address is not within a defined function. Showing raw disassembly.",
                        "disasm": "\n".join(lines),
                        "count": len(lines),
                        "style": disasm_style,
                        "range": f"{hex_ea(ea)}-{hex_ea(raw_end)}",
                    })
                    continue
                disasm_start = ea
                disasm_end = end_ea if end_ea is not None else func.end_ea
                if structured:
                    items = _disasm_range_structured(disasm_start, disasm_end, max_items)
                    fname = ida_funcs.get_func_name(func.start_ea)
                    results.append({"ok": True, "addr": hex_ea(func.start_ea), "name": fname,
                                    "instructions": items, "count": len(items),
                                    "structure": _build_function_structure_summary(func)})
                    continue
                lines = _disasm_range(
                    disasm_start,
                    disasm_end,
                    max_items=max_items,
                    style=disasm_style,
                    include_bytes=include_bytes,
                    include_comments=include_comments,
                    annotate_branches=annotate_branches,
                )
                fname = ida_funcs.get_func_name(func.start_ea)
                entry = {
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "disasm": "\n".join(lines),
                    "count": len(lines),
                    "style": disasm_style,
                    "range": f"{hex_ea(disasm_start)}-{hex_ea(disasm_end)}",
                    "structure": _build_function_structure_summary(func),
                }
                try:
                    ctx = gather_function_context(func.start_ea, max_refs=6)
                    if ctx:
                        entry["context"] = ctx
                except Exception:
                    pass
                results.append(entry)

            elif action == "xrefs_to":
                xref_lines = []
                for x in idautils.XrefsTo(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    fn = _compat.get_func_start(x.frm)
                    fn_name = ida_funcs.get_func_name(fn) if fn is not None else ""
                    xref_lines.append(f"{hex_ea(x.frm)}  {kind}  {fn_name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})

            elif action == "xrefs_from":
                xref_lines = []
                for x in idautils.XrefsFrom(ea, 0):
                    if len(xref_lines) >= max_items:
                        break
                    kind = "code" if x.iscode else "data"
                    name = ida_name.get_name(x.to) or ""
                    xref_lines.append(f"{hex_ea(x.to)}  {kind}  {name}")
                results.append({"ok": True, "addr": addr, "xrefs": "\n".join(xref_lines), "count": len(xref_lines)})

            elif action == "callees":
                func = _compat.get_func_start(ea)
                if func is None:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}", "Use 'funcs.create' to define a function here first"))
                    continue
                callees = set()
                for item in idautils.FuncItems(func):
                    for xref in idautils.XrefsFrom(item, 0):
                        if xref.iscode:
                            target_func = _compat.get_func_start(xref.to)
                            if target_func is not None and target_func != func:
                                callees.add((hex_ea(target_func),
                                            ida_funcs.get_func_name(target_func)))
                callee_lines = [f"{a}  {n}" for a, n in sorted(callees)]
                results.append({"ok": True, "addr": addr, "callees": "\n".join(callee_lines), "count": len(callee_lines)})

            elif action == "callers":
                func = _compat.get_func_start(ea)
                start = func if func is not None else ea
                callers = set()
                for xref in idautils.XrefsTo(start, 0):
                    if xref.iscode:
                        caller_func = _compat.get_func_start(xref.frm)
                        if caller_func is not None:
                            callers.add((hex_ea(caller_func),
                                        ida_funcs.get_func_name(caller_func)))
                caller_lines = [f"{a}  {n}" for a, n in sorted(callers)]
                results.append({"ok": True, "addr": addr, "callers": "\n".join(caller_lines), "count": len(caller_lines)})

            elif action == "blocks":
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                fc = _compat.get_flow_chart(ea)
                block_lines = []
                block_count = 0
                for block in fc:
                    succs = ",".join(hex_ea(s.start_ea) for s in block.succs())
                    preds = ",".join(hex_ea(p.start_ea) for p in block.preds())
                    block_lines.append(f"{hex_ea(block.start_ea)}-{hex_ea(block.end_ea)}  succs=[{succs}]  preds=[{preds}]")
                    block_count += 1
                    if block_count >= max_items:
                        break
                results.append({"ok": True, "addr": addr, "blocks": "\n".join(block_lines), "count": block_count})

            elif action == "callgraph":
                # BFS for call graph
                func = _compat.get_func_start(ea)
                if func is None:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                visited = {func: 0}
                queue = [(func, 0)]
                edge_set = set()

                while queue and len(edge_set) < max_items:
                    curr_ea, dist = queue.pop(0)
                    if dist >= max_depth:
                        continue

                    for item_ea in idautils.FuncItems(curr_ea):
                        for xref in idautils.XrefsFrom(item_ea, 0):
                            if xref.iscode:
                                tf = _compat.get_func_start(xref.to)
                                if tf is not None and tf != curr_ea:
                                    target_ea = tf
                                    edge_set.add((curr_ea, target_ea))
                                    if target_ea not in visited:
                                        visited[target_ea] = dist + 1
                                        queue.append((target_ea, dist + 1))

                # Compact: nodes with depth, then edges
                node_lines = [f"{hex_ea(k)}  depth={v}  {ida_funcs.get_func_name(k)}" for k, v in sorted(visited.items(), key=lambda x: x[1])]
                edge_lines = [f"{hex_ea(c)} -> {hex_ea(t)}" for c, t in sorted(edge_set)]
                results.append({"ok": True, "addr": hex_ea(func), "nodes": "\n".join(node_lines), "edges": "\n".join(edge_lines)})

            elif action == "export":
                # Export function info
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                name = ida_funcs.get_func_name(func.start_ea)
                proto = _compat.get_prototype_string(func.start_ea)

                if format == "c_header":
                    results.append({"addr": addr, "header": f"{proto};"})
                elif format == "prototypes":
                    results.append({"addr": addr, "prototype": proto})
                else:
                    results.append({"addr": addr, "name": name, "prototype": proto,
                                   "start": hex_ea(func.start_ea), "end": hex_ea(func.end_ea)})

            elif action == "xrefs_to_field":
                # Find code that accesses a specific struct field by offset.
                # Operand-based (ida_ua displacement match) so it works on
                # RISC-V/MIPS/AArch64 where the old substring scan of the
                # disasm text missed alternate renderings.
                if not field_name:
                    results.append(make_error(MCPError.INVALID_ARGS, "field_name required"))
                    continue

                struct_name = None
                actual_field = field_name
                if "." in field_name:
                    struct_name, actual_field = field_name.rsplit(".", 1)

                # Bound the scan so a large opaque firmware image can't stall.
                MAX_FIELD_SCAN_FUNCS = 5000
                MAX_FIELD_SCAN_INSNS = 200000

                try:
                    til = ida_typeinf.get_idati()
                    qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)

                    # Step 1: Find the field offset in the struct
                    field_offset = None
                    field_type_str = None
                    found_struct = None
                    if struct_name:
                        tinfo = ida_typeinf.tinfo_t()
                        if tinfo.get_named_type(til, struct_name):
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            field_offset = member.offset // 8
                                            field_type_str = str(member.type)
                                            found_struct = struct_name
                                            break
                    else:
                        for ordinal in range(1, qty_func(til) + 1):
                            tinfo = ida_typeinf.tinfo_t()
                            if not tinfo.get_numbered_type(til, ordinal):
                                continue
                            type_name = tinfo.get_type_name()
                            if tinfo.is_struct() or tinfo.is_union():
                                udt = ida_typeinf.udt_type_data_t()
                                if tinfo.get_udt_details(udt):
                                    for member in udt:
                                        if member.name == actual_field:
                                            field_offset = member.offset // 8
                                            field_type_str = str(member.type)
                                            found_struct = type_name
                                            break
                            if field_offset is not None:
                                break

                    if field_offset is None:
                        results.append({"addr": addr, "field": field_name, "xrefs": [],
                                        "note": f"Field '{actual_field}' not found in any struct"})
                        continue

                    # Step 2: Find code that accesses this offset — match the
                    # decoded operand displacement (o_displ/o_phrase) exactly.
                    def _insn_field_matches(item_ea: int, f_off: int) -> bool:
                        if ida_ua is None:
                            return False
                        try:
                            insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(insn, item_ea) <= 0:
                                return False
                            o_displ = getattr(ida_ua, "o_displ", 4)
                            o_phrase = getattr(ida_ua, "o_phrase", 5)
                            for i, op in enumerate(insn.ops):
                                if op.type in (o_displ, o_phrase):
                                    v = ida_ua.get_operand_value(insn, i)
                                    if v == f_off:
                                        return True
                        except Exception:
                            return False
                        return False

                    code_refs = []
                    funcs_scanned = 0
                    insns_scanned = 0
                    truncated_scan = False
                    for func_ea in idautils.Functions():
                        if funcs_scanned >= MAX_FIELD_SCAN_FUNCS or insns_scanned >= MAX_FIELD_SCAN_INSNS:
                            truncated_scan = True
                            break
                        funcs_scanned += 1
                        found_in_func = False
                        for item_ea in idautils.FuncItems(func_ea):
                            insns_scanned += 1
                            if insns_scanned >= MAX_FIELD_SCAN_INSNS:
                                truncated_scan = True
                                break
                            if not _insn_field_matches(item_ea, field_offset):
                                continue
                            disasm = ida_lines.tag_remove(idc.generate_disasm_line(item_ea, 0) or "")
                            code_refs.append({
                                "ea": hex_ea(item_ea),
                                "func": hex_ea(func_ea),
                                "func_name": ida_funcs.get_func_name(func_ea) or "",
                                "disasm": disasm[:80],
                            })
                            found_in_func = True
                            if len(code_refs) >= max_items:
                                break
                        if found_in_func and len(code_refs) >= max_items:
                            break
                        if truncated_scan:
                            break

                    if not code_refs:
                        note = (f"No struct field xrefs found: no instruction in "
                                f"{funcs_scanned} scanned functions accesses "
                                f"{found_struct}.{actual_field} at offset {hex(field_offset)}")
                    else:
                        note = f"Found {len(code_refs)} code references to {found_struct}.{actual_field} (offset {hex(field_offset)})"
                    result_entry = {
                        "ok": True,
                        "field": field_name,
                        "struct": found_struct,
                        "offset": field_offset,
                        "offset_hex": hex(field_offset),
                        "field_type": field_type_str,
                        "xrefs": code_refs,
                        "count": len(code_refs),
                        "note": note,
                    }
                    if truncated_scan:
                        result_entry["truncated"] = True
                        result_entry["scan_budget"] = {
                            "funcs": MAX_FIELD_SCAN_FUNCS,
                            "insns": MAX_FIELD_SCAN_INSNS,
                        }
                    results.append(result_entry)
                except Exception as e:
                    results.append(make_error(MCPError.IDA_ERROR, f"Error searching for field: {str(e)}", details={"addr": addr}))
                continue

            elif action == "find_paths":
                # Find path(s) from addr to target
                if not target:
                    results.append(make_error(MCPError.INVALID_ARGS, "target required"))
                    continue

                target_ea, error = validate_addr(target)
                if error:
                    results.append({"addr": addr, **error})
                    continue

                # Simple BFS
                queue = [(ea, [hex(ea)])]
                visited = {ea}
                paths = []

                while queue and len(paths) < max_items:
                    curr, path = queue.pop(0)
                    if curr == target_ea:
                        paths.append(path)
                        continue

                    if len(path) >= max_depth:
                        continue

                    # Get succs
                    succs = []
                    func = _compat.get_func_start(curr) # if callgraph
                    if func is not None:
                        # Intra-procedural flow? Or callgraph? Let's do callgraph for now as it's more useful typically
                        for item in idautils.FuncItems(func):
                            for xref in idautils.XrefsFrom(item, 0):
                                if xref.iscode:
                                    tf = _compat.get_func_start(xref.to)
                                    if tf is not None and tf != func:
                                        succs.append(tf)

                    for s in succs:
                        if s == target_ea:
                            # Do not mark the target visited: each distinct
                            # route to it is a separate path. The target is
                            # never expanded (it short-circuits above), so this
                            # cannot loop.
                            queue.append((s, path + [hex(s)]))
                        elif s not in visited:
                            visited.add(s)
                            queue.append((s, path + [hex(s)]))

                results.append({"ok": True, "from": addr, "to": target, "paths": paths})

            elif action == "strings_in_func":
                func = _compat.get_func_start(ea)
                if func is None:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue

                entries = _collect_function_string_entries(func, result_limit=max_items)
                str_lines = [f"{e['addr']}  {e['value']}" for e in entries]
                entry: dict = {
                    "ok": True,
                    "addr": addr,
                    "strings": "\n".join(str_lines),
                    "count": len(str_lines),
                }
                if not entries:
                    # Symbol-poor raw firmware: no strlit xrefs AND no resolvable
                    # constant load. On RISC-V a common cause is GP-relative
                    # string/table references (the GP register was never set),
                    # so probe GP once and say so.
                    entry["note"] = ("No string references found (no strlit xrefs or "
                                     "resolvable constant loads in function)")
                    if is_riscv_family() and callable(_detect_riscv_gp):
                        try:
                            gp_info = _detect_riscv_gp()
                            if isinstance(gp_info, dict):
                                if gp_info.get("found"):
                                    entry["riscv_gp"] = gp_info
                                    if gp_info.get("applied"):
                                        # GP applied + reanalysis queued makes
                                        # cached reads stale — drop the read cache.
                                        _invalidate_tool_read_cache()
                                else:
                                    entry["note"] += (" — RISC-V GP (x3) unresolved: "
                                                      "GP-relative xrefs may be missed "
                                                      "until the GP value is known.")
                        except Exception:
                            pass
                results.append(entry)

            elif action == "diff_functions":
                # Compare two functions' decompilation
                addr_list = normalize_list_input(addrs)
                if len(addr_list) != 2:
                    return make_error(MCPError.INVALID_ARGS, "diff_functions requires exactly 2 addresses",
                                    hint='Use addrs=["0x401000", "0x402000"]')
                ea_a, err = validate_addr(addr_list[0], require_func=True)
                if err: return err
                ea_b, err = validate_addr(addr_list[1], require_func=True)
                if err: return err

                import difflib
                cfunc_a, err_a = _decompile_with_diagnostics(ea_a)
                cfunc_b, err_b = _decompile_with_diagnostics(ea_b)
                if err_a or err_b:
                    return make_error(
                        MCPError.DECOMPILER_FAILED,
                        "Decompilation failed for one or both functions",
                        hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                        details={
                            "func_a": {"addr": hex(ea_a), "error": err_a} if err_a else {"addr": hex(ea_a)},
                            "func_b": {"addr": hex(ea_b), "error": err_b} if err_b else {"addr": hex(ea_b)},
                        },
                    )

                code_a = str(cfunc_a) if cfunc_a else ""
                code_b = str(cfunc_b) if cfunc_b else ""
                name_a = idc.get_func_name(ea_a) or hex(ea_a)
                name_b = idc.get_func_name(ea_b) or hex(ea_b)

                diff = difflib.unified_diff(
                    code_a.splitlines(), code_b.splitlines(),
                    fromfile=name_a, tofile=name_b, lineterm=""
                )
                diff_text = "\n".join(diff)

                # Compute similarity ratio
                ratio = difflib.SequenceMatcher(None, code_a, code_b).ratio()

                return {
                    "ok": True,
                    "func_a": {"addr": hex(ea_a), "name": name_a, "lines": len(code_a.splitlines())},
                    "func_b": {"addr": hex(ea_b), "name": name_b, "lines": len(code_b.splitlines())},
                    "diff": diff_text if diff_text else "(identical)",
                    "similarity": round(ratio, 4),
                }

            elif action == "semantic_decompile":
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    results.append(_decompile_error_entry(addr, dec_err))
                    continue
                pseudo = str(cfunc)
                cfg_semantics = _compute_cfg_semantics(func)
                dataflow = _build_decompiler_dataflow(cfunc, max_items=max(200, min(1600, int(max_items))))
                results.append(
                    {
                        "ok": True,
                        "addr": hex_ea(func.start_ea),
                        "function": ida_funcs.get_func_name(func.start_ea),
                        "prototype": _compat.get_prototype_string(func.start_ea),
                        "pseudocode": pseudo,
                        "semantic_summary": _semantic_pseudocode_summary(pseudo),
                        "cfg_semantics": cfg_semantics,
                        "decomp_dataflow": dataflow,
                    }
                )

            elif action == "decomp_dataflow":
                func = _compat.get_func_start(ea)
                if func is None:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func)
                if not cfunc:
                    results.append(_decompile_error_entry(addr, dec_err))
                    continue
                flow = _build_decompiler_dataflow(cfunc, max_items=max(200, min(1600, int(max_items))))
                edge_lines = [
                    f"{e['from']} -> {e['to']}  {e['kind']}  {e.get('ea') or ''}".rstrip()
                    for e in flow.get("edges", [])[: max(1, min(400, int(max_items)))]
                ]
                results.append(
                    {
                        "ok": True,
                        "addr": hex_ea(func),
                        "function": ida_funcs.get_func_name(func),
                        "dataflow": flow,
                        "edges": "\n".join(edge_lines),
                        "count": len(flow.get("edges", [])),
                    }
                )

            elif action == "smart_decompile":
                # Best single call for understanding a function.
                # Returns pseudocode + behavior_tags + api_calls + crypto_hints +
                # dangerous_patterns + var_rename_hints + callers + callees +
                # strings + blackboard_context + complexity + suggested_next_actions.
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    results.append(_decompile_error_entry(addr, dec_err))
                    continue

                pseudo = str(cfunc)
                fname = ida_funcs.get_func_name(func.start_ea)
                enrichment = _build_decompile_enrichment(
                    func.start_ea,
                    cfunc,
                    pseudo,
                    detailed_dangerous=True,
                    include_switch_cases=True,
                    api_limit=15,
                )
                found_apis = enrichment["api_calls"]
                crypto_hints = enrichment["crypto_hints"]
                dangerous = enrichment["dangerous_patterns"]
                var_hints = enrichment["var_rename_hints"]
                bb_ctx = enrichment["blackboard_context"]
                complexity = enrichment["complexity"]

                callers_compact = _collect_compact_callers(func.start_ea)
                callees_compact = _collect_compact_callees(func.start_ea)
                str_refs = _collect_function_strings(func.start_ea)

                behavior_tags = list(set(
                    crypto_hints
                    + (["network"] if any(a in found_apis for a in ["recv","send","socket","connect"]) else [])
                    + (["file_io"] if any(a in found_apis for a in ["fopen","fread","fwrite","CreateFile","open","read","write"]) else [])
                    + (["memory_alloc"] if "malloc" in found_apis or "VirtualAlloc" in found_apis else [])
                    + (["process_exec"] if any(a in found_apis for a in ["system","exec","CreateProcess"]) else [])
                    + (["dangerous"] if dangerous else [])
                ))

                suggested = []
                if dangerous:
                    # Taint-trace next step: the standalone `security` module was
                    # deleted (commit b191581), so surface a static suggestion.
                    active_sources = [a for a in found_apis if a in TAINT_SOURCES]
                    if active_sources:
                        suggested.append({
                            "action": "taint(trace)",
                            "addr": hex_ea(func.start_ea),
                            "reason": f"Network input ({', '.join(active_sources)}) reaches dangerous patterns — trace data flow",
                        })
                    else:
                        suggested.append({"action": "taint(trace)", "reason": "Dangerous patterns — trace data flow"})
                if crypto_hints:
                    suggested.append({"action": "crypto_id(identify)", "addr": hex_ea(func.start_ea),
                                      "reason": f"Crypto signals: {', '.join(crypto_hints[:3])}"})
                if not bb_ctx:
                    suggested.append({"action": "blackboard(write, category=hypothesis)",
                                      "addr": hex_ea(func.start_ea),
                                      "reason": "No blackboard entry — record findings now"})
                if var_hints:
                    suggested.append({"action": "modify(rename) or funcs(suggest_names)",
                                      "reason": f"{len(var_hints)} variables could be renamed: "
                                                 + ", ".join(f"{h['var']}→{h['suggested']}" for h in var_hints[:3])})
                if len(callers_compact) == 0:
                    suggested.append({"action": "blackboard(write, category=dead_end) or check entry points",
                                      "reason": "No callers found — may be an entry point, callback, or dead code"})
                elif len(callers_compact) >= 5:
                    suggested.append({"action": "code(xrefs_to)",
                                      "addr": hex_ea(func.start_ea),
                                      "reason": f"Many callers ({len(callers_compact)}+) — this is a hot function, understand all call sites"})

                results.append({
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "prototype": _compat.get_prototype_string(func.start_ea),
                    "pseudocode": pseudo,
                    "behavior_tags": behavior_tags,
                    "api_calls": found_apis[:15],
                    "crypto_hints": crypto_hints,
                    "dangerous_patterns": dangerous,
                    "var_rename_hints": var_hints,
                    "strings": str_refs,
                    "callers": callers_compact,
                    "callees": callees_compact,
                    "blackboard_context": bb_ctx,
                    "complexity": complexity,
                    "suggested_next_actions": suggested[:4],
                })

            elif action == "explain":
                # Plain-English explanation of what a function does.
                # Decompiles, extracts signals, and synthesizes a structured summary
                # without requiring the LLM to read raw pseudocode.
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                cfunc, dec_err = _decompile_with_diagnostics(func.start_ea)
                if not cfunc:
                    entry = _decompile_error_entry(addr, dec_err)
                    entry["message"] = "Decompilation failed — cannot explain"
                    results.append(entry)
                    continue

                pseudo = str(cfunc)
                fname = ida_funcs.get_func_name(func.start_ea)
                proto = _compat.get_prototype_string(func.start_ea)

                # Collect signals
                _KNOWN_APIS = [
                    "malloc","free","memcpy","memset","strcpy","strncpy","sprintf","snprintf",
                    "recv","send","socket","connect","bind","listen","accept","recvfrom","sendto",
                    "fopen","fread","fwrite","fclose","fgets","fputs",
                    "system","exec","execve","popen","fork",
                    "CreateFile","ReadFile","WriteFile","VirtualAlloc","CreateProcess",
                    "RegSetValue","RegOpenKey","CryptEncrypt","CryptDecrypt","BCryptEncrypt",
                    "AES_encrypt","AES_decrypt","SHA256_Update","MD5_Update","HMAC",
                    "memcmp","strcmp","strstr","sscanf","gets","scanf","vsprintf",
                    "mmap","munmap","ioctl","open","read","write","close",
                ]
                found_apis = [a for a in _KNOWN_APIS if a in pseudo]
                pseudo.lower()

                # Callers/callees count
                n_callers = sum(1 for x in idautils.XrefsTo(func.start_ea, 0) if x.iscode)
                callees_set = set()
                for item in idautils.FuncItems(func.start_ea):
                    for xr in idautils.XrefsFrom(item, 0):
                        if xr.type in (idaapi.fl_CN, idaapi.fl_CF):
                            callees_set.add(idc.get_name(xr.to) or hex(xr.to))

                # Strings referenced
                str_refs = []
                for item in idautils.FuncItems(func.start_ea):
                    for xr in idautils.XrefsFrom(item, 0):
                        s = idc.get_strlit_contents(xr.to)
                        if s:
                            with contextlib.suppress(Exception):
                                str_refs.append(s.decode("utf-8", errors="replace")[:80])
                str_refs = list(dict.fromkeys(str_refs))[:6]

                # Complexity
                n_blocks = sum(1 for _ in (_compat.get_flow_chart(func.start_ea) or []))
                n_lines = len(pseudo.splitlines())

                # Symbol-free firmware signals (MMIO stores, traps, CSR access,
                # table constants) — the bare-metal analog of libc API calls.
                firmware_signals = _detect_firmware_signals(func.start_ea, pseudo)

                # Build plain-English summary
                purpose_parts = []
                if any(a in found_apis for a in ["recv","recvfrom","socket","connect","bind","listen","accept"]):
                    purpose_parts.append("handles network I/O")
                if any(a in found_apis for a in ["fopen","fread","fwrite","CreateFile","open","read","write"]):
                    purpose_parts.append("performs file I/O")
                if any(a in found_apis for a in ["malloc","VirtualAlloc","mmap"]):
                    purpose_parts.append("allocates memory")
                if any(a in found_apis for a in ["system","exec","execve","popen","CreateProcess"]):
                    purpose_parts.append("executes external commands")
                if any(a in found_apis for a in ["CryptEncrypt","CryptDecrypt","BCryptEncrypt","AES_encrypt","AES_decrypt"]):
                    purpose_parts.append("performs cryptographic operations")
                if any(a in found_apis for a in ["SHA256_Update","MD5_Update","HMAC"]):
                    purpose_parts.append("computes a hash or MAC")
                if any(a in found_apis for a in ["RegSetValue","RegOpenKey"]):
                    purpose_parts.append("accesses the Windows registry")
                if any(a in found_apis for a in ["memcpy","memset","strcpy","strncpy","sprintf","snprintf"]):
                    purpose_parts.append("manipulates buffers/strings")
                if any(a in found_apis for a in ["gets","scanf","sscanf","vsprintf"]):
                    purpose_parts.append("reads user/external input (potentially unsafe)")
                if not purpose_parts:
                    # No libc API matched — check for symbol-free firmware
                    # signals before falling back to the generic line. On
                    # opaque device blobs "no APIs" usually means bare-metal
                    # firmware, not "does nothing".
                    if firmware_signals:
                        purpose_parts.append("performs bare-metal/RTOS firmware operations (no libc APIs detected — bare-metal firmware?)")
                    else:
                        purpose_parts.append("performs internal computation")

                # Danger signals
                _DANGEROUS = {"gets","strcpy","sprintf","system","exec","execve","popen","memcpy","strncpy"}
                dangerous_calls = [a for a in found_apis if a in _DANGEROUS]

                summary_lines = [
                    f"Function: {fname}",
                    f"Prototype: {proto}" if proto else "",
                    f"Purpose: This function {', '.join(purpose_parts)}.",
                ]
                if str_refs:
                    summary_lines.append(f"Key strings: {', '.join(repr(s) for s in str_refs[:4])}")
                if found_apis:
                    summary_lines.append(f"API calls: {', '.join(found_apis[:10])}")
                if dangerous_calls:
                    summary_lines.append(f"⚠ Dangerous calls: {', '.join(dangerous_calls)} — review for buffer overflows / injection")
                summary_lines.append(f"Complexity: {n_blocks} basic blocks, {n_lines} pseudocode lines")
                summary_lines.append(f"Called by: {n_callers} function(s)")
                if callees_set:
                    summary_lines.append(f"Calls: {', '.join(sorted(callees_set)[:8])}")

                results.append({
                    "ok": True,
                    "addr": hex_ea(func.start_ea),
                    "name": fname,
                    "summary": "\n".join(l for l in summary_lines if l),
                    "purpose": purpose_parts,
                    "api_calls": found_apis[:15],
                    "dangerous_calls": dangerous_calls,
                    "strings": str_refs,
                    "complexity": {"blocks": n_blocks, "pseudocode_lines": n_lines},
                    "callers": n_callers,
                    "callees": sorted(callees_set)[:12],
                })
                if firmware_signals:
                    results[-1]["firmware_signals"] = firmware_signals
                if not found_apis:
                    results[-1]["api_note"] = "no libc APIs detected — bare-metal firmware?"

            elif action == "trace_argument_origin":
                func = _compat.get_func_info(ea)
                if not func:
                    results.append(make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex_ea(ea)}"))
                    continue
                arg_index = int(kwargs.get("arg_index", 0))
                max_depth = int(kwargs.get("max_depth", 4))
                max_callers = int(kwargs.get("max_callers_per_level", 10))
                results.append(_trace_argument_origin(func, arg_index, max_depth, max_callers))

            else:
                return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

        # Attach GP note to every disasm result on RISC-V so agents know
        # GP-relative xrefs may be unresolved without the GP value set.
        if _riscv_gp_info is not None:
            for r in results:
                if isinstance(r, dict) and ("disasm" in r or "instructions" in r):
                    r["riscv_gp"] = _riscv_gp_info

        return results[0] if len(results) == 1 else results
    except Exception as e:
        return handle_error(e)


# ============================================================================
# Argument origin tracing
# ============================================================================


# ---------------------------------------------------------------------------
# Argument origin tracer — backward BFS through callers
# ---------------------------------------------------------------------------
