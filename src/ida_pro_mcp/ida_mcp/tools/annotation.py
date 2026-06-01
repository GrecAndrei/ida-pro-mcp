import re

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .governance_engine import evaluate_operation
except ImportError:
    from governance_engine import evaluate_operation  # type: ignore[import-not-found]

try:
    from .memrl import emit_memrl_suggestion
except ImportError:
    try:
        from memrl import emit_memrl_suggestion  # type: ignore[import-not-found]
    except ImportError:
        # No-op fallback if MemRL not available
        def emit_memrl_suggestion(*args, **kwargs):  # type: ignore
            return ""


# ============================================================================
# ANNOTATION - Intelligent Bulk Annotation for LLMs
# ============================================================================

try:
    from ..support._api_categories import (
        DANGEROUS_APIS as _DANGEROUS_APIS,
        MAGIC_CONSTANTS as _MAGIC_CONSTANTS,
        TAG_CATEGORIES as _TAG_CATEGORIES,
        API_TO_TAG as _API_TO_TAG,
    )
except ImportError:
    from support._api_categories import (
        DANGEROUS_APIS as _DANGEROUS_APIS,
        MAGIC_CONSTANTS as _MAGIC_CONSTANTS,
        TAG_CATEGORIES as _TAG_CATEGORIES,
        API_TO_TAG as _API_TO_TAG,
    )  # type: ignore[import-not-found]


def _get_func_callees_with_addr(func_ea):
    """Return list of (call_addr, callee_name) for actual CALL instructions only."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    callees = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        mnem = (idc.print_insn_mnem(head) or "").lower()
        if not (mnem.startswith("call") or mnem in {"bl", "blr", "jal", "jalr"}):
            continue
        for target in idautils.CodeRefsFrom(head, 0):
            name = idc.get_func_name(target)
            if not name:
                name = idc.get_name(target) or ""
            if name:
                callees.append((head, name))
    return callees


def _get_func_strings(func_ea):
    """Return list of strings referenced by the function."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    strings = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for dref in idautils.DataRefsFrom(head):
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                s = idc.get_strlit_contents(dref, -1, stype)
                if s:
                    s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    if s not in strings:
                        strings.append(s)
    return strings


def _strip_api_suffix(name):
    """Strip common API suffixes (A/W, @plt) for matching."""
    for suffix in ("A", "W", "@plt", "@PLT"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _is_probable_mmio(value: int) -> bool:
    return (
        0x40000000 <= value <= 0x5FFFFFFF
        or 0xE0000000 <= value <= 0xE00FFFFF
        or 0xF0000000 <= value <= 0xFFFFFFFF
    )


def _mmio_label(addr: int) -> str:
    bases = (
        (0x40000000, "PERIPH"),
        (0x50000000, "PERIPH_HI"),
        (0xE0000000, "SYSCTRL"),
    )
    for base, name in bases:
        if addr >= base:
            return f"{name}+0x{addr - base:x}"
    return f"MMIO+0x{addr:x}"


def _detect_crypto_algorithm(func_ea: int) -> str:
    alg = "unknown"
    try:
        fn = ida_funcs.get_func(func_ea)
        if not fn:
            return alg
        text = []
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            dis = ida_lines.tag_remove(idc.generate_disasm_line(head, 0) or "")
            if dis:
                text.append(dis.lower())
            for dref in idautils.DataRefsFrom(head):
                stype = idc.get_str_type(dref)
                if stype is not None and stype >= 0:
                    sval = idc.get_strlit_contents(dref, -1, stype)
                    if sval:
                        sval = sval.decode("utf-8", errors="replace") if isinstance(sval, bytes) else sval
                        text.append(sval.lower())
        blob = " ".join(text)
        if "aes" in blob:
            alg = "AES"
        elif "sha256" in blob or "sha-256" in blob:
            alg = "SHA-256"
        elif "sha1" in blob or "sha-1" in blob:
            alg = "SHA-1"
        elif "md5" in blob:
            alg = "MD5"
        elif "des" in blob:
            alg = "DES"
        elif "rc4" in blob:
            alg = "RC4"
    except Exception:
        return alg
    return alg


def _set_inline_comment(addr: int, comment: str, dry_run: bool) -> None:
    if dry_run:
        return
    existing = idc.get_cmt(addr, 0) or ""
    if comment in existing:
        return
    new_cmt = f"{existing}  {comment}" if existing else comment
    idc.set_cmt(addr, new_cmt, 0)


def _auto_comment_one(addr_ea: int, prefix: str, dry_run: bool = False) -> dict:
    mnem = (idc.print_insn_mnem(addr_ea) or "").lower()
    comment = ""
    reason = ""

    # Call-site annotation: calls callee(args) -> ret
    if mnem.startswith("call") or mnem in {"bl", "blr", "jal", "jalr"}:
        for xr in idautils.CodeRefsFrom(addr_ea, 0):
            target = getattr(xr, "to", None)
            if target is None:
                target = xr
            callee = idc.get_func_name(target) or idc.get_name(target) or f"sub_{int(target):x}"
            arg_types = "?"
            ret_type = "?"
            tdecl = idc.get_type(target)
            if tdecl:
                if "(" in tdecl and ")" in tdecl:
                    arg_types = tdecl[tdecl.find("(") + 1:tdecl.rfind(")")] or "void"
                ret_type = tdecl.split("(", 1)[0].strip() or "?"
            comment = f"{prefix}calls {callee}({arg_types}) -> {ret_type}"
            reason = "call_site"
            break

    # String reference annotation
    if not comment:
        for dref in idautils.DataRefsFrom(addr_ea):
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                sval = idc.get_strlit_contents(dref, -1, stype)
                if sval:
                    sval = sval.decode("utf-8", errors="replace") if isinstance(sval, bytes) else sval
                    comment = f'{prefix}references: "{sval[:80]}"'
                    reason = "string_ref"
                    break

    # MMIO access annotation
    if not comment:
        for op_idx in range(4):
            val = idc.get_operand_value(addr_ea, op_idx)
            if isinstance(val, int) and _is_probable_mmio(val):
                comment = f"{prefix}MMIO: {_mmio_label(val)}"
                reason = "mmio"
                break

    # Crypto behavior annotation (function-level behavior at this instruction)
    if not comment:
        fn = idaapi.get_func(addr_ea)
        if fn:
            try:
                from ida_pro_mcp.host.intelligence_core import BgeCodeEmbedder, BehaviorClassifier
                pseudo = ""
                try:
                    pseudo = str(idaapi.decompile(fn.start_ea) or "")
                except Exception:
                    pseudo = ""
                if pseudo:
                    clf = BehaviorClassifier.instance(BgeCodeEmbedder())
                    hits = clf.classify(pseudo, threshold=0.25, top_k=3, block=False)
                    if any("crypto" in str(h.get("behavior", "")).lower() for h in hits):
                        comment = f"{prefix}CRYPTO: {_detect_crypto_algorithm(fn.start_ea)}"
                        reason = "crypto"
            except Exception:
                pass

    if not comment:
        return {"ok": True, "addr": hex(addr_ea), "applied": False, "reason": "no_interesting_signal"}

    _set_inline_comment(addr_ea, comment, dry_run=dry_run)
    return {"ok": True, "addr": hex(addr_ea), "applied": True, "reason": reason, "comment": comment}


# ============================================================================
# VOERA: Neuro-Symbolic Governance Layer for Annotations
# ============================================================================

def _governance_check_proposed_comment(addr: int, proposed_comment: str, action_type: str) -> dict:
    """Deterministic symbolic rule-check before annotation commit.

    Delegates to governance engine for consistent enforcement
    across all write operations.

    Returns {"approved": bool, "violations": list[str], "redacted_comment": str}
    """
    # Gather metadata from IDA for context-aware checks
    metadata = {}
    context = {"action": action_type}

    fn = ida_funcs.get_func(addr)
    if fn:
        api_calls = []
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            for xref in idautils.CodeRefsFrom(head, 0):
                callee = idc.get_func_name(xref) or ""
                if callee:
                    api_calls.append(callee)
        metadata["api_calls"] = ", ".join(api_calls)

        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, addr):
            fi = idaapi.func_type_data_t()
            if tif.get_func_details(fi):
                metadata["arg_count"] = fi.size()

    # Delegate to governance engine
    gov_result = evaluate_operation(
        operation_type="annotation",
        addr=addr,
        proposed_value=proposed_comment,
        context=context,
        metadata=metadata,
    )

    # Convert governance result to annotation.py's expected format
    violations = []
    for v in gov_result.get("violations", []):
        desc = v.get("description", "")
        if v.get("rule"):
            desc = f"[{v['rule']}] {desc}"
        violations.append(desc)

    return {
        "approved": gov_result.get("approved", True) and len(violations) == 0,
        "violations": violations,
        "redacted_comment": gov_result.get("redacted_content", proposed_comment),
    }


@tool
@idawrite
def annotation(
    action: Annotated[Literal["auto_comment", "auto_comment_function", "label_loops", "label_branches",
                               "mark_dangerous", "annotate_constants",
                               "tag_functions", "document_args",
                               "mark_error_paths", "propagate_names", "cleanup", "validate",
                               "get_context", "set_structured", "bulk_set",
                               "export_md", "import_md", "summary"],
                      "Annotation action"],
    addr: Annotated[Optional[str], "Function address to annotate"] = None,
    limit: Annotated[int, "Max annotations to add"] = 100,
    prefix: Annotated[str, "Prefix for auto-generated comments"] = "[MCP] ",
    dry_run: Annotated[bool, "Preview without writing"] = False,
    text: Annotated[Optional[str], "Comment text (for set_structured)"] = None,
    items: Annotated[Optional[str], "JSON list of {addr, text} for bulk_set"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
    fmt: Annotated[Optional[str], "Comment format: plain|markdown|structured (alias: format)"] = None,
) -> dict:
    """
    Intelligent bulk annotation tool optimized for LLMs.

    All auto-generated comments are prefixed (default '[MCP] ') for easy cleanup.

    ACTIONS:

    auto_comment - Auto-generate a context-aware comment for one instruction address.
        Params: addr (required), prefix, dry_run
        Returns: {annotations, count}

    auto_comment_function - Batch auto-comment all interesting instructions in a function.
        Params: addr (required), prefix, dry_run, limit
        Returns: {annotations, count}

    label_loops - Add comments to loop headers (back-edges in CFG).
        Params: addr (required), prefix, dry_run
        Returns: {loops, count}

    label_branches - Add comments to conditional branches describing the condition.
        Params: addr (required), prefix, dry_run
        Returns: {branches, count}

    mark_dangerous - Mark dangerous API calls with warning comments.
        Params: addr (optional, all functions if omitted), limit, prefix, dry_run
        Returns: {warnings, count}

    annotate_constants - Replace magic numbers with named constants in comments.
        Params: addr (required), prefix, dry_run
        Returns: {constants, count}

    tag_functions - Tag functions with category labels via repeatable comments.
        Params: addr (optional, all functions if omitted), limit, prefix, dry_run
        Returns: {tagged, count}

    document_args - Add parameter documentation comments based on usage analysis.
        Params: addr (required), prefix, dry_run
        Returns: {params, count}

    mark_error_paths - Annotate error handling paths (branches after API call failures).
        Params: addr (required), prefix, dry_run
        Returns: {error_paths, count}

    propagate_names - Propagate meaningful names through call chains
                      (suggest names for sub_ callees).
        Params: addr (required), limit, prefix, dry_run
        Returns: {suggestions, count}

    cleanup - Remove auto-generated annotations by prefix marker.
        Params: addr (optional, all functions if omitted), prefix, dry_run
        Returns: {removed, count}

    validate - Neuro-symbolic governance check for a proposed annotation.
        Params: addr (required), value (proposed comment text)
        Returns: {approved, violations, redacted_comment}
        Use before committing annotations to catch contradictions, PII, and misleading claims.

    COMMENT MANAGEMENT (merged from the old comment_mgr tool):

    get_context - Get all comments around an address with context.
        Params: addr
        Returns: {func_comment, comment, comment_repeatable, anterior, posterior, nearby_comments}

    set_structured - Set a structured comment (plain | markdown | structured).
        Params: addr, text, fmt
        Returns: {ok, addr, fmt, length}

    bulk_set - Set multiple comments from a JSON list of {addr, text, type}.
        Params: items (JSON string)
        Returns: {ok, set_count, error_count, errors?}

    export_md - Export all comments to a markdown file.
        Params: path
        Returns: {ok, exported, path, comment_count}

    import_md - Import comments from a markdown file.
        Params: path
        Returns: {ok, imported, count, errors?}

    summary - Commenting coverage statistics.
        Returns: {total_functions, functions_commented, coverage_pct, inline_comments, avg_comments_per_func}
    """
    try:
        # ----------------------------------------------------------------
        # ACTION: auto_comment
        # ----------------------------------------------------------------
        if action == "auto_comment":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=False)
            if err:
                return err
            out = _auto_comment_one(ea, prefix=prefix, dry_run=dry_run)
            return {
                "ok": True,
                "annotations": str(out),
                "count": 1 if out.get("applied") else 0,
                "dry_run": dry_run,
            }

        elif action == "auto_comment_function":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)
            annotations = []
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                if len(annotations) >= limit:
                    break
                one = _auto_comment_one(head, prefix=prefix, dry_run=dry_run)
                if one.get("applied"):
                    annotations.append(one)

            return {"ok": True, "function": fname, "annotations": "\n".join(str(x) for x in annotations),
                    "count": len(annotations), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: label_loops
        # ----------------------------------------------------------------
        elif action == "label_loops":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)
            fc = idaapi.FlowChart(fn)

            loops = []
            for block in fc:
                if len(loops) >= limit:
                    break
                for succ in block.succs():
                    # Back-edge: successor starts before or at block start
                    if succ.start_ea <= block.start_ea:
                        loop_head = succ.start_ea
                        cmt = (f"{prefix}loop header "
                               f"(back-edge from {hex(block.start_ea)})")
                        loops.append({
                            "loop_head": hex(loop_head),
                            "back_edge_from": hex(block.start_ea),
                            "comment": cmt,
                        })
                        if not dry_run:
                            existing = idc.get_cmt(loop_head, 0) or ""
                            if prefix not in existing:
                                new_cmt = f"{existing}  {cmt}" if existing else cmt
                                idc.set_cmt(loop_head, new_cmt, 0)

            return {"ok": True, "function": fname, "loops": "\n".join(str(x) for x in loops),
                    "count": len(loops), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: label_branches
        # ----------------------------------------------------------------
        elif action == "label_branches":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)
            fc = idaapi.FlowChart(fn)

            branches = []
            for block in fc:
                if len(branches) >= limit:
                    break
                if block.nsucc() == 2:
                    # Conditional branch at the end of the block
                    last_insn = idc.prev_head(block.end_ea, block.start_ea)
                    if last_insn == idaapi.BADADDR:
                        last_insn = block.start_ea
                    disasm = ida_lines.tag_remove(idc.generate_disasm_line(last_insn, 0))
                    succs = list(block.succs())
                    if len(succs) >= 2:
                        true_target = succs[0].start_ea
                        false_target = succs[1].start_ea
                    else:
                        continue
                    cmt = (f"{prefix}branch: {disasm.strip()} "
                           f"-> T:{hex(true_target)} F:{hex(false_target)}")
                    branches.append({
                        "addr": hex(last_insn),
                        "disasm": disasm.strip(),
                        "true_target": hex(true_target),
                        "false_target": hex(false_target),
                        "comment": cmt,
                    })
                    if not dry_run:
                        existing = idc.get_cmt(last_insn, 0) or ""
                        if prefix not in existing:
                            new_cmt = f"{existing}  {cmt}" if existing else cmt
                            idc.set_cmt(last_insn, new_cmt, 0)

            return {"ok": True, "function": fname, "branches": "\n".join(str(x) for x in branches),
                    "count": len(branches), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: mark_dangerous
        # ----------------------------------------------------------------
        elif action == "mark_dangerous":
            func_eas = []
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_eas.append(ea)
            else:
                _func_limit = max(limit, 5000)
                for _fc, fea in enumerate(idautils.Functions()):
                    if _fc >= _func_limit:
                        break
                    func_eas.append(fea)

            warnings = []
            for func_ea in func_eas:
                if len(warnings) >= limit:
                    break
                callees = _get_func_callees_with_addr(func_ea)
                for call_addr, callee_name in callees:
                    if len(warnings) >= limit:
                        break
                    base = _strip_api_suffix(callee_name)
                    reason = _DANGEROUS_APIS.get(callee_name) or _DANGEROUS_APIS.get(base)
                    if reason:
                        cmt = f"{prefix}WARNING: {callee_name} - {reason}"
                        fname = idc.get_func_name(func_ea)
                        warnings.append({
                            "addr": hex(call_addr),
                            "function": fname,
                            "api": callee_name,
                            "reason": reason,
                            "comment": cmt,
                        })
                        if not dry_run:
                            existing = idc.get_cmt(call_addr, 0) or ""
                            if prefix not in existing:
                                new_cmt = f"{existing}  {cmt}" if existing else cmt
                                idc.set_cmt(call_addr, new_cmt, 0)

            return {"ok": True, "warnings": "\n".join(str(x) for x in warnings),
                    "count": len(warnings), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: annotate_constants
        # ----------------------------------------------------------------
        elif action == "annotate_constants":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)
            constants = []

            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                if len(constants) >= limit:
                    break
                # Check operands for magic constants
                for op_idx in range(4):
                    op_val = idc.get_operand_value(head, op_idx)
                    if op_val in _MAGIC_CONSTANTS:
                        meaning = _MAGIC_CONSTANTS[op_val]
                        cmt = f"{prefix}{hex(op_val)} = {meaning}"
                        constants.append({
                            "addr": hex(head),
                            "value": hex(op_val),
                            "meaning": meaning,
                            "comment": cmt,
                        })
                        if not dry_run:
                            existing = idc.get_cmt(head, 0) or ""
                            if prefix not in existing:
                                new_cmt = f"{existing}  {cmt}" if existing else cmt
                                idc.set_cmt(head, new_cmt, 0)
                        break  # one annotation per instruction

            return {"ok": True, "function": fname, "constants": "\n".join(str(x) for x in constants),
                    "count": len(constants), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: tag_functions
        # ----------------------------------------------------------------
        elif action == "tag_functions":
            func_eas = []
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_eas.append(ea)
            else:
                _func_limit = max(limit, 5000)
                for _fc, fea in enumerate(idautils.Functions()):
                    if _fc >= _func_limit:
                        break
                    func_eas.append(fea)

            tagged = []
            for func_ea in func_eas:
                if len(tagged) >= limit:
                    break
                callees = _get_func_callees_with_addr(func_ea)
                tags = set()
                for _, callee_name in callees:
                    base = _strip_api_suffix(callee_name).lower()
                    for tag in _API_TO_TAG.get(base, []):
                        tags.add(tag)
                    for tag in _API_TO_TAG.get(callee_name.lower(), []):
                        tags.add(tag)

                if tags:
                    fname = idc.get_func_name(func_ea)
                    tag_str = ", ".join(sorted(tags))
                    cmt = f"{prefix}tags: [{tag_str}]"
                    tagged.append({
                        "addr": hex(func_ea),
                        "function": fname,
                        "tags": sorted(tags),
                        "comment": cmt,
                    })
                    if not dry_run:
                        existing = idc.get_func_cmt(func_ea, 1) or ""
                        if prefix not in existing:
                            new_cmt = f"{existing}\n{cmt}" if existing else cmt
                            idc.set_func_cmt(func_ea, new_cmt, 1)

            return {"ok": True, "tagged": "\n".join(str(x) for x in tagged),
                    "count": len(tagged), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: document_args
        # ----------------------------------------------------------------
        elif action == "document_args":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)

            # Try to get function type info for parameter names
            tif = ida_typeinf.tinfo_t()
            params = []
            if ida_nalt.get_tinfo(tif, ea):
                fi = idaapi.func_type_data_t()
                if tif.get_func_details(fi):
                    for i in range(fi.size()):
                        param = fi[i]
                        pname = param.name or f"arg{i}"
                        ptype = str(param.type)
                        params.append({
                            "index": i,
                            "name": pname,
                            "type": ptype,
                        })

            # Analyze how arguments are used in the function body
            callees = _get_func_callees_with_addr(ea)
            api_usage = []
            for call_addr, callee_name in callees:
                api_usage.append(callee_name)

            # Build documentation comment
            doc_parts = []
            if params:
                for p in params:
                    doc_parts.append(f"  {p['name']} ({p['type']})")
            else:
                doc_parts.append("  (no type info available)")

            if api_usage:
                doc_parts.append(f"  Uses: {', '.join(api_usage[:6])}")

            cmt = f"{prefix}params:\n" + "\n".join(doc_parts)
            result_params = params if params else [{"note": "no type information"}]
            annotations = [{"addr": hex(ea), "comment": cmt, "type": "function"}]

            if not dry_run:
                existing = idc.get_func_cmt(ea, 1) or ""
                if prefix not in existing:
                    new_cmt = f"{existing}\n{cmt}" if existing else cmt
                    idc.set_func_cmt(ea, new_cmt, 1)

            return {"ok": True, "function": fname, "params": result_params,
                    "apis_used": api_usage[:10], "annotations": "\n".join(str(x) for x in annotations),
                    "count": len(annotations), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: mark_error_paths
        # ----------------------------------------------------------------
        elif action == "mark_error_paths":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)

            # Find call sites, then look for conditional branches immediately
            # after that might be error checks (e.g., test eax,eax / jz)
            error_check_apis = {
                "malloc", "calloc", "realloc", "fopen", "CreateFile",
                "CreateFileA", "CreateFileW", "OpenProcess", "VirtualAlloc",
                "HeapAlloc", "GlobalAlloc", "LocalAlloc", "RegOpenKeyEx",
                "RegOpenKeyExA", "RegOpenKeyExW", "socket", "connect",
                "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
                "GetProcAddress", "MapViewOfFile", "mmap",
                "InternetOpen", "InternetOpenA", "InternetConnect",
                "HttpOpenRequest", "WinHttpOpen", "WinHttpConnect",
            }

            callees = _get_func_callees_with_addr(ea)
            error_paths = []

            for call_addr, callee_name in callees:
                if len(error_paths) >= limit:
                    break
                base = _strip_api_suffix(callee_name)
                if base not in error_check_apis and callee_name not in error_check_apis:
                    continue

                # Look at instructions after the call for error checking pattern
                next_ea = idc.next_head(call_addr, fn.end_ea)
                if next_ea == idaapi.BADADDR:
                    continue

                # Check a few instructions after the call for a conditional jump
                check_ea = next_ea
                for _ in range(4):
                    if check_ea >= fn.end_ea or check_ea == idaapi.BADADDR:
                        break
                    mnem = idc.print_insn_mnem(check_ea)
                    if mnem and ((mnem.lower().startswith("j") and mnem.lower() != "jmp") or
                                  mnem.lower() in ("cbz", "cbnz", "beq", "bne", "bcs", "bcc",
                                                    "bmi", "bpl", "bvs", "bvc", "bhi", "bls",
                                                    "bge", "blt", "bgt", "ble", "tbz", "tbnz")):
                        cmt = (f"{prefix}error check: {callee_name} return value "
                               f"tested here")
                        error_paths.append({
                            "call_addr": hex(call_addr),
                            "check_addr": hex(check_ea),
                            "api": callee_name,
                            "branch_insn": ida_lines.tag_remove(idc.generate_disasm_line(check_ea, 0)).strip(),
                            "comment": cmt,
                        })
                        if not dry_run:
                            existing = idc.get_cmt(check_ea, 0) or ""
                            if prefix not in existing:
                                new_cmt = f"{existing}  {cmt}" if existing else cmt
                                idc.set_cmt(check_ea, new_cmt, 0)
                        break
                    check_ea = idc.next_head(check_ea, fn.end_ea)

            return {"ok": True, "function": fname, "error_paths": "\n".join(str(x) for x in error_paths),
                    "count": len(error_paths), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: propagate_names
        # ----------------------------------------------------------------
        elif action == "propagate_names":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)

            # Only propagate from meaningfully named functions
            if fname.startswith("sub_"):
                return make_error(MCPError.INVALID_ARGS,
                                 "source function has default name (sub_) - "
                                 "rename it first for meaningful propagation")

            callees = _get_func_callees_with_addr(ea)
            suggestions = []

            for call_idx, (call_addr, callee_name) in enumerate(callees):
                if len(suggestions) >= limit:
                    break
                if not callee_name.startswith("sub_"):
                    continue

                # Suggest a name based on caller context and call order
                suggested = f"{fname}_helper{call_idx + 1}"
                cmt = f"{prefix}suggested name: {suggested} (called from {fname})"
                suggestions.append({
                    "addr": hex(call_addr),
                    "callee_addr": callee_name,
                    "suggested_name": suggested,
                    "comment": cmt,
                })
                if not dry_run:
                    callee_ea = idc.get_name_ea_simple(callee_name)
                    if callee_ea != idaapi.BADADDR:
                        existing = idc.get_func_cmt(callee_ea, 1) or ""
                        if prefix not in existing:
                            new_cmt = f"{existing}\n{cmt}" if existing else cmt
                            idc.set_func_cmt(callee_ea, new_cmt, 1)

            return {"ok": True, "function": fname, "suggestions": "\n".join(str(x) for x in suggestions),
                    "count": len(suggestions), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: cleanup
        # ----------------------------------------------------------------
        elif action == "cleanup":
            func_eas = []
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_eas.append(ea)
            else:
                _func_limit = max(limit, 5000)
                for _fc, fea in enumerate(idautils.Functions()):
                    if _fc >= _func_limit:
                        break
                    func_eas.append(fea)

            removed = []
            for func_ea in func_eas:
                if len(removed) >= limit:
                    break
                fn = ida_funcs.get_func(func_ea)
                if not fn:
                    continue

                # Clean function-level comments
                for repeatable in (0, 1):
                    func_cmt = idc.get_func_cmt(func_ea, repeatable)
                    if func_cmt and prefix in func_cmt:
                        # Remove lines containing the prefix
                        lines = func_cmt.split("\n")
                        cleaned = [l for l in lines if prefix not in l]
                        new_cmt = "\n".join(cleaned).strip()
                        if not dry_run:
                            idc.set_func_cmt(func_ea, new_cmt, repeatable)
                        removed.append({
                            "addr": hex(func_ea),
                            "type": "func_comment",
                            "repeatable": bool(repeatable),
                        })

                # Clean inline comments
                curr = fn.start_ea
                while curr < fn.end_ea:
                    if len(removed) >= limit:
                        break
                    for repeatable in (0, 1):
                        cmt = idc.get_cmt(curr, repeatable)
                        if cmt and prefix in cmt:
                            # Remove segments containing the prefix
                            parts = cmt.split("  ")
                            cleaned = [p for p in parts if prefix not in p]
                            new_cmt = "  ".join(cleaned).strip()
                            if not dry_run:
                                idc.set_cmt(curr, new_cmt, repeatable)
                            removed.append({
                                "addr": hex(curr),
                                "type": "inline_comment",
                                "repeatable": bool(repeatable),
                            })
                    curr = idc.next_head(curr, fn.end_ea)
                    if curr == idaapi.BADADDR: break

            return {"ok": True, "removed": "\n".join(str(x) for x in removed),
                    "count": len(removed), "dry_run": dry_run}

        # ----------------------------------------------------------------
        # ACTION: validate (Neuro-Symbolic Governance)
        # ----------------------------------------------------------------
        elif action == "validate":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for validate")
            ea, err = validate_addr(addr)
            if err:
                return err
            proposed = kwargs.get("value", "")
            if not proposed:
                return make_error(MCPError.INVALID_ARGS, "value (proposed comment) required for validate")
            
            result = _governance_check_proposed_comment(ea, proposed, "comment")
            response = {
                "ok": True,
                "addr": hex(ea),
                "approved": result["approved"],
                "violations": result["violations"],
                "redacted_comment": result["redacted_comment"],
                "original_comment": proposed,
            }
            # Log the validation to MemRL as a suggestion
            try:
                sug_id = emit_memrl_suggestion(
                    "annotation", "validate", addr, proposed
                )
                if sug_id:
                    response["memrl_suggestion_id"] = sug_id
            except Exception:
                pass
            return response

        # ----------------------------------------------------------------
        # COMMENT MANAGEMENT (merged from comment_mgr tool)
        # ----------------------------------------------------------------
        elif action in ("get_context", "set_structured", "bulk_set",
                        "export_md", "import_md", "summary"):
            return _annotation_comment_mgr_action(
                action, addr, text, items, path, fmt,
            )

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# Comment-management helper (merged from comment_mgr)
# ============================================================================


def _annotation_comment_mgr_action(action, addr, text, items, path, fmt):
    """
    Backbone for get_context / set_structured / bulk_set / export_md /
    import_md / summary on the annotation tool.

    These actions used to live in a separate `comment_mgr` tool (315
    LOC). They were absorbed into `annotation` so that all comment CRUD
    and AI-driven annotation work live in one tool. Payload shape is
    preserved verbatim.
    """
    import json as json_module
    import os
    import re

    # `fmt` is an alias for the old `format` parameter (Python's
    # `format` is a builtin; we accept either via `fmt`).
    fmt_value = fmt or "plain"

    if action == "get_context":
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required")
        ea, err = validate_addr(addr)
        if err:
            return err

        func = ida_funcs.get_func(ea)

        result = {
            "ok": True,
            "addr": hex(ea),
            "name": idc.get_name(ea),
        }

        if func:
            result["func_name"] = idc.get_func_name(func.start_ea)
            result["func_comment"] = idc.get_func_cmt(func.start_ea, 0)
            result["func_comment_repeatable"] = idc.get_func_cmt(func.start_ea, 1)

        result["comment"] = idc.get_cmt(ea, 0)
        result["comment_repeatable"] = idc.get_cmt(ea, 1)

        anterior = []
        for i in range(10):
            line = idc.get_extra_cmt(ea, idc.E_PREV + i)
            if line:
                anterior.append(line)
            else:
                break
        result["anterior"] = anterior

        posterior = []
        for i in range(10):
            line = idc.get_extra_cmt(ea, idc.E_NEXT + i)
            if line:
                posterior.append(line)
            else:
                break
        result["posterior"] = posterior

        nearby = []
        if func:
            curr = func.start_ea
            while curr < func.end_ea and len(nearby) < 20:
                cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                if cmt:
                    nearby.append({
                        "addr": hex(curr),
                        "comment": cmt[:100],
                        "offset": hex(curr - func.start_ea),
                    })
                curr = idc.next_head(curr, func.end_ea)
                if curr == idaapi.BADADDR:
                    break
        result["nearby_comments"] = nearby

        return result

    if action == "set_structured":
        if not addr or not text:
            return make_error(MCPError.INVALID_ARGS, "addr and text required")
        ea, err = validate_addr(addr)
        if err:
            return err

        if fmt_value == "structured":
            formatted = "/* Analysis:\n"
            for line in text.split("\n"):
                formatted += f" * {line}\n"
            formatted += " */"
        else:
            formatted = text

        idc.set_cmt(ea, formatted, 0)
        return {"ok": True, "addr": hex(ea), "format": fmt_value, "length": len(formatted)}

    if action == "bulk_set":
        if not items:
            return make_error(MCPError.INVALID_ARGS, "items required (JSON list)")
        try:
            item_list = json_module.loads(items) if isinstance(items, str) else items
        except json_module.JSONDecodeError as e:
            return make_error(MCPError.INVALID_ARGS, f"Invalid JSON: {e}")
        if not isinstance(item_list, list):
            return make_error(MCPError.INVALID_ARGS, "items must be a JSON array")

        set_count = 0
        errors = []
        for item in item_list:
            try:
                item_addr = item.get("addr")
                item_text = item.get("text") or item.get("comment")
                if not item_addr:
                    errors.append({"item": item, "error": "missing addr"})
                    continue
                if not item_text:
                    errors.append({"addr": item_addr, "error": "missing text"})
                    continue
                ea, err = validate_addr(item_addr)
                if err:
                    errors.append({"addr": item_addr, "error": "invalid address"})
                    continue
                cmt_type = item.get("type", "regular")
                if cmt_type == "repeatable":
                    idc.set_cmt(ea, item_text, 1)
                elif cmt_type == "func":
                    idc.set_func_cmt(ea, item_text, 0)
                else:
                    idc.set_cmt(ea, item_text, 0)
                set_count += 1
            except Exception as e:
                errors.append({"addr": item.get("addr"), "error": str(e)})

        return {
            "ok": True,
            "set_count": set_count,
            "error_count": len(errors),
            "errors": errors[:10] if errors else None,
        }

    if action == "export_md":
        if not path:
            return make_error(MCPError.INVALID_ARGS, "path required")
        path, err = validate_path_safe(path)
        if err:
            return err

        lines = ["# IDA Comments Export\n\n"]
        lines.append(f"Generated from: {idc.get_input_file_path()}\n\n")
        count = 0
        _func_limit = 5000
        _func_count = 0
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                func_name = idc.get_func_name(func_ea)
                func_cmt = idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1)
                func_comments = []
                if func_cmt:
                    func_comments.append(f"**Function**: {func_cmt}")
                    count += 1
                func = ida_funcs.get_func(func_ea)
                if func:
                    curr = func.start_ea
                    while curr < func.end_ea:
                        cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                        if cmt:
                            func_comments.append(f"- `{hex(curr)}`: {cmt}")
                            count += 1
                        curr = idc.next_head(curr, func.end_ea)
                        if curr == idaapi.BADADDR:
                            break
                if func_comments:
                    lines.append(f"## {func_name} (`{hex(func_ea)}`)\n\n")
                    lines.extend([c + "\n" for c in func_comments])
                    lines.append("\n")
                _func_count += 1
                if _func_count >= _func_limit:
                    break
            if _func_count >= _func_limit:
                break

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return {"ok": True, "exported": True, "path": path, "comment_count": count}

    if action == "import_md":
        if not path:
            return make_error(MCPError.INVALID_ARGS, "path required")
        path, err = validate_path_safe(path)
        if err:
            return err
        if not os.path.exists(path):
            return make_error(MCPError.FILE_NOT_FOUND, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        imported = 0
        errors = []
        pattern = r"`(0x[0-9a-fA-F]+)`:\s*(.+?)(?:\n|$)"
        for match in re.finditer(pattern, content):
            addr_str = match.group(1)
            comment = match.group(2).strip()
            try:
                ea = parse_address(addr_str)
                idc.set_cmt(ea, comment, 0)
                imported += 1
            except Exception as e:
                errors.append({"addr": addr_str, "error": str(e)})
        return {"ok": True, "imported": True, "count": imported, "errors": len(errors)}

    if action == "summary":
        _func_limit = 10000
        _func_count = 0
        total = 0
        commented = 0
        inline_comments = 0
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                total += 1
                func_cmt = idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1)
                if func_cmt:
                    commented += 1
                func = ida_funcs.get_func(func_ea)
                if func:
                    curr = func.start_ea
                    while curr < func.end_ea:
                        if idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1):
                            inline_comments += 1
                        curr = idc.next_head(curr, func.end_ea)
                        if curr == idaapi.BADADDR:
                            break
                _func_count += 1
                if _func_count >= _func_limit:
                    break
            if _func_count >= _func_limit:
                break
        return {
            "ok": True,
            "total_functions": total,
            "functions_commented": commented,
            "coverage_pct": round(commented / total * 100, 1) if total else 0,
            "inline_comments": inline_comments,
            "avg_comments_per_func": round(inline_comments / total, 2) if total else 0,
        }

    return make_error(MCPError.INVALID_ARGS, f"Unknown comment-mgr action: {action}")
