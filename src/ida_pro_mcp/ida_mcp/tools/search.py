
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re
try:
    from .semantic_matching import normalize_action, semantic_score, semantic_tokens
except ImportError:
    from semantic_matching import normalize_action, semantic_score, semantic_tokens  # type: ignore[import-not-found]


_SEARCH_ACTIONS = {
    "bytes", "string", "immediate", "name", "insns", "text", "operand", "comment",
    "data_ref", "code_ref", "regex", "func_by_sig", "find", "callers", "callees",
    "api", "vulnerable", "constants", "decompiled",
}

_SEARCH_ACTION_ALIASES = {
    "byte": "bytes",
    "bytesearch": "bytes",
    "str": "string",
    "strings": "string",
    "literal": "string",
    "imm": "immediate",
    "constant": "immediate",
    "symbol": "name",
    "names": "name",
    "instruction": "insns",
    "instructions": "insns",
    "disasm": "text",
    "disassembly": "text",
    "ops": "operand",
    "operands": "operand",
    "comments": "comment",
    "xref": "code_ref",
    "xrefs": "code_ref",
    "datarefs": "data_ref",
    "coderefs": "code_ref",
    "function_signature": "func_by_sig",
    "signature": "func_by_sig",
    "lookup": "find",
    "discover": "find",
    "caller": "callers",
    "callee": "callees",
    "imports": "api",
    "import": "api",
    "apis": "api",
    "vuln": "vulnerable",
    "vulns": "vulnerable",
    "crypto_constants": "constants",
    "magic_constants": "constants",
    "pseudo": "decompiled",
    "pseudocode": "decompiled",
}

_SEARCH_INTENT_PATTERNS = [
    (re.compile(r"^\s*(?:who\s+)?(?:callers?|calls?)\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callers"),
    (re.compile(r"^\s*(?:what\s+)?callees?\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callees"),
    (re.compile(r"^\s*(?:api|import)s?(?:\s+usage|\s+calls?)?\s+(?:of|for)?\s+(.+)$", re.IGNORECASE), "api"),
    (re.compile(r"^\s*(?:code\s+)?xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "code_ref"),
    (re.compile(r"^\s*data\s+xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "data_ref"),
    (re.compile(r"^\s*(?:decompiled|pseudocode)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "decompiled"),
]


def _semantic_tokens(text: str) -> list[str]:
    """Extract lowercase alphanumeric tokens (length >= 2) for semantic comparisons."""
    return semantic_tokens(text)


def _semantic_score(query: str, candidate: str) -> float:
    """Score semantic similarity (higher is better) using exact/substring/token/fuzzy signals.

    Heuristic weights:
    - Exact match bonus: +120
    - Substring bonus: +60
    - Token overlap bonus: up to +45
    - Sequence similarity bonus: up to +20
    """
    return semantic_score(query, candidate, substring_bonus=60.0)


def _normalize_search_action(raw_action: Optional[str], *, fallback: str = "find") -> str:
    """Normalize action through exact match, alias map, then fuzzy semantic lookup.

    Falls back to *fallback* when semantic confidence remains low (< 35.0).
    """
    return normalize_action(
        raw_action,
        actions=tuple(_SEARCH_ACTIONS),
        aliases=_SEARCH_ACTION_ALIASES,
        fallback=fallback,
        threshold=35.0,
        substring_bonus=60.0,
    )


# ============================================================================
# 4. SEARCH - Find patterns, bytes, references
# ============================================================================

@tool
@idaread
def search(
    action: Annotated[Literal["bytes", "string", "immediate", "name", "insns", "text", "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig", "find", "callers", "callees", "api", "vulnerable", "constants", "decompiled"],
                       "Action: bytes|string|immediate|name|insns|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled"],
    pattern: Annotated[Optional[str], "Pattern to search for"] = None,
    query: Annotated[Optional[str], "Alias for pattern (for compatibility)"] = None,
    limit: Annotated[int, "Max results"] = 100,
    offset: Annotated[int, "Results offset (skip first N matches)"] = 0,
    start: Annotated[Optional[str], "Start address for bounded searches"] = None,
    end: Annotated[Optional[str], "End address for bounded searches"] = None,
    case_sensitive: Annotated[bool, "Case sensitive search (for string/text/comment)"] = False,
    include_context: Annotated[bool, "Include surrounding context in results"] = False,
    include_items: Annotated[bool, "Include structured item arrays in output (default: false for context efficiency)"] = False,
    include_breakdown: Annotated[bool, "Include per-type breakdown fields for multi-source actions"] = False,
    semantic_action: Annotated[Optional[str], "Optional semantic action alias (e.g. 'xrefs', 'pseudocode', 'imports')"] = None,
    intent: Annotated[Optional[str], "Optional natural-language query alias for pattern"] = None,
    semantic_min_score: Annotated[float, "Minimum semantic score threshold for semantic target resolution (0-200)"] = 0.0,
    include_semantic_alternatives: Annotated[bool, "Include semantic alternatives in semantic target resolution"] = False,
    **kwargs
) -> dict:
    """
    Search for patterns, specific bytes, or references in the binary.
    All results use compact text format (one match per line) to minimize LLM context usage.
    
    QUICK ACTIONS (LLM-friendly):
    
    find - Smart unified search (auto-detects what you want)
        Params: pattern (any text, address, or name)
        Returns: {names, strings, imports, code_refs?, data_refs?} as compact text
        Example: search(action="find", pattern="malloc") - finds all malloc-related items
        
    callers - Find all functions that call a target function
        Params: pattern (function name or address)
        Returns: {callers: "addr  name  call@site\\n...", count}
        Example: search(action="callers", pattern="malloc")
        
    callees - Find all functions called by a target function
        Params: pattern (function name or address)
        Returns: {callees: "addr  name  call@site\\n...", count}
        Example: search(action="callees", pattern="main")
        
    api - Find all uses of an API/import function
        Params: pattern (API name, supports wildcards)
        Returns: {usages: "call_addr  func_name\\n...", total_calls}
        Example: search(action="api", pattern="*alloc*")
    
    vulnerable - Find potentially vulnerable code patterns
        Params: limit, include_context
        Returns: {findings: "addr  vuln_type  dangerous_func  in:caller\\n...", total_findings}
        Example: search(action="vulnerable") - finds strcpy, printf format strings, etc.
        
    constants - Find crypto/magic constants in code
        Params: limit, include_context, start, end
        Returns: {findings: "addr  value  const_name  in:func\\n...", total_found}
        Example: search(action="constants") - finds MD5/SHA/AES constants, magic numbers
    
    DETAILED ACTIONS (all return {matches: "line\\nline\\n...", count, total, truncated}):
    
    bytes - Search for byte patterns with wildcards
        Params: pattern (e.g. "55 8B EC" or "E8 ?? ?? ?? ??" for x86, "00 B0 A0 E3" for ARM), start, end
        
    string - Search string literals by content
        Params: pattern (substring), case_sensitive
        
    immediate - Search for immediate value usage in code
        Params: pattern/query (value as hex or decimal)
        
    name - Search symbol names by glob pattern
        Params: pattern (e.g. "*printf*", "sub_*")
        
    insns - Search for instruction mnemonic sequences
        Params: pattern (comma-separated, e.g. "push, mov, sub"), wildcards supported (*)
        
    text - Search disassembly text
        Params: pattern (substring), case_sensitive, include_context
        
    operand - Search operands for patterns
        Params: pattern (e.g. "rsp", "sp", "r0", "qword ptr")
        
    comment - Search comments
        Params: pattern
        
    data_ref - Find data references to target
        Params: pattern (address or name)
        
    code_ref - Find code references to target
        Params: pattern (address or name)
        
    regex - Search with regular expression in disassembly
        Params: pattern (regex)
        
    func_by_sig - Find functions by signature characteristics
        Params: pattern (e.g. "args:3+", "calls:malloc", "size:>100")

    decompiled - Search through decompiled pseudocode (Hex-Rays)
        Params: pattern, case_sensitive, limit
                Optional guardrails: addr (single function scope), timeout_ms,
                max_functions, sample, sample_max_funcs
        Returns: {matches: "addr  func_name  L42: matching line\\n...", count}
        Example: search(action="decompiled", pattern="memcpy.*sizeof")

    EXTRA:
    - semantic_action: Optional alias/intent action override (e.g. "xrefs", "imports", "pseudocode")
    - intent: Optional natural-language alias for query text
    - semantic_min_score: Optional threshold to reduce weak semantic target matches
    - include_semantic_alternatives: Return alternative semantic target candidates
    """
    try:
        interpreted_action = None
        interpreted_pattern = None

        # Support both pattern and query for compatibility
        if not pattern and query:
            pattern = query
        if not pattern and intent:
            pattern = intent
        try:
            semantic_min_score = float(semantic_min_score)
        except Exception:
            semantic_min_score = 0.0
        semantic_min_score = max(0.0, min(200.0, semantic_min_score))

        # Semantic/alias action normalization.
        requested_action = str(action)
        normalized_action = _normalize_search_action(semantic_action or requested_action, fallback=requested_action)
        if normalized_action != requested_action:
            interpreted_action = normalized_action
            action = normalized_action
        for intent_re, intent_action in _SEARCH_INTENT_PATTERNS:
            if action != "find" or not pattern:
                break
            m = intent_re.match(pattern)
            if m:
                extracted = (m.group(1) or "").strip()
                if extracted:
                    action = intent_action
                    interpreted_action = intent_action
                    interpreted_pattern = extracted
                    pattern = extracted
                    break

        # Some actions don't need pattern parameter
        pattern_not_required = ["vulnerable", "constants"]
        if not pattern and action not in pattern_not_required:
            return make_error(MCPError.INVALID_ARGS, "pattern or query parameter required")
            
        import ida_search
        import re as re_module

        MAX_LIMIT = 500
        LINE_MAX = 240
        results = []
        truncated = False
        matches_seen = 0
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        if limit <= 0:
            limit = 1
        if limit > MAX_LIMIT:
            limit = MAX_LIMIT
        try:
            offset = max(0, int(offset))
        except Exception:
            offset = 0

        def _clip(text: Optional[str], max_len: int = LINE_MAX) -> str:
            if text is None:
                return ""
            compact = " ".join(str(text).split())
            if len(compact) <= max_len:
                return compact
            return compact[: max_len - 3] + "..."

        def _paginate_records(records, *, sort_key=None, reverse=True):
            rows = list(records)
            if sort_key is not None:
                rows.sort(key=sort_key, reverse=reverse)
            total = len(rows)
            page = rows[offset : offset + limit]
            is_truncated = (offset + len(page)) < total
            return page, total, is_truncated

        def _xref_count_limited(ea: int, max_count: int = 256) -> int:
            count = 0
            for _ in idautils.XrefsTo(ea, 0):
                count += 1
                if count >= max_count:
                    break
            return count

        def _resolve_semantic_target(raw_target: Optional[str], *, require_function: bool = False, include_imports: bool = False):
            """
            Resolve a target address/name using exact and semantic matching.

            Returns:
                tuple[int, Optional[str], dict]:
                    (resolved_ea, error_message_or_none, metadata)
            """
            if raw_target is None:
                return idaapi.BADADDR, "target is required", {}
            target = str(raw_target).strip()
            if not target:
                return idaapi.BADADDR, "target is required", {}
            ea, err = validate_addr(target)
            if not err and ea != idaapi.BADADDR:
                if require_function and not idaapi.get_func(ea):
                    return idaapi.BADADDR, f"No function at {hex(ea)}", {}
                return ea, None, {"match": "address"}
            exact_ea = idc.get_name_ea_simple(target)
            if exact_ea != idaapi.BADADDR:
                if require_function and not idaapi.get_func(exact_ea):
                    return idaapi.BADADDR, f"No function at {hex(exact_ea)}", {}
                return exact_ea, None, {"match": "exact_name"}

            matcher = compile_smart_pattern(target, case_sensitive=False)
            prelim = []
            max_candidates = 512

            def _record_candidate(
                *,
                ea: int,
                raw_name: str,
                display_name: str,
                kind: str,
                module_name: Optional[str] = None,
                exact_bonus: float = 0.0,
            ):
                # Phase 1 uses non-fuzzy scoring only to cheaply shortlist candidates.
                # Fuzzy SequenceMatcher scoring is deferred to phase 2 on the shortlist.
                quick_score = semantic_score(target, raw_name, substring_bonus=60.0, include_fuzzy=False)
                if raw_name.lower() == target.lower():
                    quick_score += exact_bonus
                if quick_score <= 0:
                    return
                prelim.append((quick_score, ea, raw_name, display_name, kind, module_name))

            for sym_ea, sym_name in idautils.Names():
                if not sym_name or not matcher(sym_name):
                    continue
                is_func = bool(idaapi.get_func(sym_ea))
                if require_function and not is_func:
                    continue
                _record_candidate(
                    ea=sym_ea,
                    raw_name=sym_name,
                    display_name=sym_name,
                    kind="function" if is_func else "symbol",
                    exact_bonus=40.0,
                )

            if include_imports:
                for mod_idx in range(ida_nalt.get_import_module_qty()):
                    mod_name = ida_nalt.get_import_module_name(mod_idx) or f"mod_{mod_idx}"

                    def _cb(import_ea, import_name, _ordinal):
                        if not import_name or not matcher(import_name):
                            return True
                        _record_candidate(
                            ea=import_ea,
                            raw_name=import_name,
                            display_name=f"{mod_name}!{import_name}",
                            kind="import",
                            module_name=mod_name,
                            exact_bonus=45.0,
                        )
                        return True

                    ida_nalt.enum_import_names(mod_idx, _cb)

            if not prelim:
                return idaapi.BADADDR, f"Target '{target}' not found", {}

            prelim.sort(key=lambda r: (r[0], r[1]), reverse=True)
            ranked = []
            for _, cand_ea, raw_name, display_name, kind, module_name in prelim[:max_candidates]:
                final_score = semantic_score(target, raw_name, substring_bonus=60.0)
                if raw_name.lower() == target.lower():
                    final_score += 45.0 if kind == "import" else 40.0
                final_score += min(_xref_count_limited(cand_ea, max_count=64), 64)
                ranked.append((final_score, cand_ea, display_name, kind, module_name))

            ranked.sort(key=lambda r: (r[0], r[1]), reverse=True)
            top_score, top_ea, top_name, top_kind, top_module = ranked[0]
            if require_function:
                top_func = idaapi.get_func(top_ea)
                if top_func:
                    top_ea = top_func.start_ea
            if top_score < semantic_min_score:
                return idaapi.BADADDR, (
                    f"Target '{target}' best semantic match below threshold "
                    f"({top_score:.2f} < {semantic_min_score:.2f})"
                ), {}

            details = {
                "match": "semantic",
                "semantic_target": top_name,
                "semantic_kind": top_kind,
                "semantic_score": round(top_score, 2),
            }
            if top_kind == "import" and top_module:
                details["semantic_module"] = top_module
            if include_semantic_alternatives and len(ranked) > 1:
                details["semantic_alternatives"] = [
                    {
                        "name": row[2],
                        "address": hex(row[1]),
                        "kind": row[3],
                        "score": round(row[0], 2),
                        **({"module": row[4]} if row[3] == "import" and row[4] else {}),
                    }
                    for row in ranked[1:6]
                ]
            return top_ea, None, details

        def maybe_add(line):
            nonlocal matches_seen, truncated
            matches_seen += 1
            if matches_seen <= offset:
                return False
            results.append(line)
            if len(results) >= limit:
                truncated = True
                return True
            return False

        def _extract_module_name_from_qualified(qualified_name: Optional[str]) -> Optional[str]:
            if not qualified_name:
                return None
            q = str(qualified_name)
            if "!" not in q:
                return None
            return q.split("!", 1)[0] or None
            
        def _search_result(**extra):
            """Common return format for search results."""
            response = {"ok": True, "matches": "\n".join(results), "offset": offset, "count": len(results), "total": matches_seen, "truncated": truncated, **extra}
            if interpreted_action:
                response["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                response["interpreted_query"] = interpreted_pattern
            return response

        range_start = None
        range_end = None
        if start is not None or end is not None:
            if start is None or end is None:
                return make_error(MCPError.INVALID_ARGS, "start and end must be provided together")
            range_start, range_end, err = validate_range(start, end)
            if err:
                return err
        seg_list = None
        if range_start is not None:
            seg_list = []
            seg = idaapi.getseg(range_start)
            while seg and seg.start_ea < range_end:
                seg_list.append(seg.start_ea)
                seg = idaapi.get_next_seg(seg.end_ea)

        if action == "bytes":
            seg = idaapi.getseg(range_start) if range_start is not None else idaapi.get_first_seg()
            while seg and len(results) < limit:
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        seg = idaapi.get_next_seg(seg.end_ea)
                        continue
                        
                if hasattr(ida_bytes, "compiled_binpat_vec_t"):
                    pt = ida_bytes.compiled_binpat_vec_t()
                    err = ida_bytes.parse_binpat_str(pt, 0, pattern, 16)
                    if err:
                        return make_error(MCPError.INVALID_ARGS, f"Invalid pattern: {err}")

                    ea, _ = ida_bytes.bin_search(seg_start, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
                    while ea != idaapi.BADADDR:
                        line = hex(ea)
                        if include_context:
                            match_bytes = ida_bytes.get_bytes(ea, min(32, seg_end - ea))
                            if match_bytes:
                                line += f"  {match_bytes.hex()}"
                            line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}"
                        if maybe_add(line):
                            break
                        ea, _ = ida_bytes.bin_search(ea + 1, seg_end, pt, ida_bytes.BIN_SEARCH_FORWARD)
                else:
                    # Fallback for older IDA builds lacking compiled_binpat_vec_t.
                    def _parse_pat_tokens(text: str):
                        toks = [t.strip() for t in text.split() if t.strip()]
                        parsed = []
                        for tok in toks:
                            tok = tok.upper()
                            if tok in ("?", "??"):
                                parsed.append(None)
                                continue
                            if len(tok) != 2 or any(c not in "0123456789ABCDEF?" for c in tok):
                                raise ValueError(f"Invalid byte token: {tok}")
                            hi = None if tok[0] == "?" else int(tok[0], 16)
                            lo = None if tok[1] == "?" else int(tok[1], 16)
                            parsed.append((hi, lo))
                        return parsed

                    def _match_pat(byte_val: int, spec) -> bool:
                        if spec is None:
                            return True
                        hi, lo = spec
                        if hi is not None and ((byte_val >> 4) & 0xF) != hi:
                            return False
                        if lo is not None and (byte_val & 0xF) != lo:
                            return False
                        return True

                    try:
                        if hasattr(ida_search, "find_binary"):
                            flags = getattr(ida_search, "SEARCH_DOWN", 0)
                            ea = ida_search.find_binary(seg_start, seg_end, pattern, 16, flags)
                            while ea != idaapi.BADADDR:
                                line = hex(ea)
                                if include_context:
                                    match_bytes = ida_bytes.get_bytes(ea, min(32, seg_end - ea))
                                    if match_bytes:
                                        line += f"  {match_bytes.hex()}"
                                    line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}"
                                if maybe_add(line):
                                    break
                                ea = ida_search.find_binary(ea + 1, seg_end, pattern, 16, flags)
                        else:
                            pat_specs = _parse_pat_tokens(pattern)
                            if not pat_specs:
                                return make_error(MCPError.INVALID_ARGS, "Empty byte pattern")
                            seg_bytes = ida_bytes.get_bytes(seg_start, max(0, seg_end - seg_start)) or b""
                            plen = len(pat_specs)
                            if len(seg_bytes) >= plen:
                                for i in range(0, len(seg_bytes) - plen + 1):
                                    ok = True
                                    for j, spec in enumerate(pat_specs):
                                        if not _match_pat(seg_bytes[i + j], spec):
                                            ok = False
                                            break
                                    if not ok:
                                        continue
                                    ea = seg_start + i
                                    line = hex(ea)
                                    if include_context:
                                        match_bytes = seg_bytes[i : i + min(32, len(seg_bytes) - i)]
                                        if match_bytes:
                                            line += f"  {match_bytes.hex()}"
                                        line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}"
                                    if maybe_add(line):
                                        break
                    except Exception as e:
                        return make_error(MCPError.IDA_ERROR, f"Byte search fallback failed: {e}")
                        
                if range_end is not None and seg.end_ea >= range_end:
                    break
                seg = idaapi.get_next_seg(seg.end_ea)
            return _search_result(pattern=pattern)
        
        elif action == "string":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            for i in range(idaapi.get_strlist_qty()):
                if truncated:
                    break
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if content:
                            s = content.decode("utf-8", errors="replace")
                            if _matcher(s):
                                line = f"{hex(sc.ea)}  {s[:500]}"
                                if include_context:
                                    xref_count = len(list(idautils.XrefsTo(sc.ea)))
                                    line += f"  xrefs={xref_count}"
                                if maybe_add(line):
                                    break
                    except Exception:
                        pass
            return _search_result(pattern=pattern)
        
        elif action == "immediate":
            semantic_meta = {}
            try:
                value = int(pattern, 0)
            except Exception:
                resolved_ea, sem_err, sem_meta = _resolve_semantic_target(pattern, require_function=False, include_imports=False)
                if sem_err:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid immediate value: {sem_err}")
                value = resolved_ea
                semantic_meta = sem_meta

            import ida_ua
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                curr = seg_ea
                seg_end = range_end if range_end is not None else idc.get_segm_end(seg_ea)
                while curr < seg_end:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, curr) > 0:
                        for op in insn.ops:
                            if op.type == ida_ua.o_imm and op.value == value:
                                line = f"{hex(curr)}  {hex(value)}"
                                if include_context:
                                    line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))}"
                                    func = idaapi.get_func(curr)
                                    if func:
                                        line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                                if maybe_add(line):
                                    break
                                break
                        curr += insn.size
                    else:
                        curr = idc.next_head(curr, seg_end)
                    if truncated:
                        break
                if truncated:
                    break
            return _search_result(value=hex(value), **semantic_meta)
        
        elif action == "name":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            for ea, name in idautils.Names():
                if truncated:
                    break
                if _matcher(name):
                    kind = "func" if idaapi.get_func(ea) else ("data" if ida_bytes.is_data(ida_bytes.get_flags(ea)) else "label")
                    if maybe_add(f"{hex(ea)}  {kind}  {name}"):
                        break
            return _search_result(pattern=pattern)
        
        elif action == "insns":
            mnemonics = [m.strip().lower() for m in pattern.split(",")]

            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue

                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue

                ea = seg_start
                while ea < seg_end and not truncated:
                    flags_val = ida_bytes.get_flags(ea)
                    if ida_bytes.is_code(flags_val):
                        match = True
                        check_ea = ea
                        sequence = []
                        for mnem in mnemonics:
                            curr_mnem = idc.print_insn_mnem(check_ea).lower()
                            if mnem != "*" and curr_mnem != mnem:
                                match = False
                                break
                            sequence.append(curr_mnem)
                            check_ea = idc.next_head(check_ea, seg_end)
                            if check_ea == idaapi.BADADDR:
                                match = False
                                break
                        if match:
                            line = hex(ea)
                            if include_context:
                                line += f"  [{','.join(sequence)}]"
                                func = idaapi.get_func(ea)
                                if func:
                                    line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "text":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        line_clean = ida_lines.tag_remove(line)
                        if _matcher(line_clean):
                            result_line = f"{hex(ea)}  {line_clean}"
                            if include_context:
                                func = idaapi.get_func(ea)
                                if func:
                                    result_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(result_line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "operand":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    ops = []
                    for i in range(8):
                        if idc.get_operand_type(ea, i) == idaapi.o_void:
                            break
                        ops.append(idc.print_operand(ea, i) or "")
                    op_text = ", ".join(ops)
                    if op_text and _matcher(op_text):
                        line = f"{hex(ea)}  {idc.print_insn_mnem(ea)}  {op_text}"
                        if include_context:
                            line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))}"
                        if maybe_add(line):
                            break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "comment":
            _matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue
                ea = seg_start
                while ea < seg_end and not truncated:
                    cmt = idc.get_cmt(ea, 0)
                    cmt_type = "regular"
                    if not cmt:
                        cmt = idc.get_cmt(ea, 1)
                        cmt_type = "repeatable"
                    if cmt:
                        if _matcher(cmt):
                            if maybe_add(f"{hex(ea)}  {cmt_type}  {cmt}"):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)

        elif action == "data_ref":
            target_ea, error, sem_meta = _resolve_semantic_target(pattern, require_function=False, include_imports=True)
            if error:
                return make_error(MCPError.INVALID_ARGS, error)

            for xref in idautils.XrefsTo(target_ea, 0):
                if truncated:
                    break
                if not xref.iscode:
                    line = f"{hex(xref.frm)} -> {hex(xref.to)}  data"
                    if include_context:
                        from_name = idc.get_name(xref.frm)
                        if from_name:
                            line += f"  {from_name}"
                    if maybe_add(line):
                        break
            return _search_result(target=pattern, target_addr=hex(target_ea), **sem_meta)
        
        elif action == "code_ref":
            target_ea, error, sem_meta = _resolve_semantic_target(pattern, require_function=False, include_imports=True)
            if error:
                return make_error(MCPError.INVALID_ARGS, error)

            for xref in idautils.XrefsTo(target_ea, 0):
                if truncated:
                    break
                if xref.iscode:
                    func = idaapi.get_func(xref.frm)
                    fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                    line = f"{hex(xref.frm)} -> {hex(xref.to)}  code  {fn_name}"
                    if include_context:
                        line += f"  {ida_lines.tag_remove(idc.generate_disasm_line(xref.frm, 0))}"
                    if maybe_add(line):
                        break
            return _search_result(target=pattern, target_addr=hex(target_ea), **sem_meta)
        
        elif action == "regex":
            try:
                regex = re_module.compile(pattern, 0 if case_sensitive else re_module.IGNORECASE)
            except re_module.error as e:
                return make_error(MCPError.INVALID_ARGS, f"Invalid regex: {e}")
                
            segments = seg_list if seg_list is not None else list(idautils.Segments())
            for seg_ea in segments:
                if truncated:
                    break
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                ea = seg_start
                while ea < seg_end and not truncated:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        line_clean = ida_lines.tag_remove(line)
                        match = regex.search(line_clean)
                        if match:
                            result_line = f"{hex(ea)}  {line_clean}"
                            if include_context:
                                func = idaapi.get_func(ea)
                                if func:
                                    result_line += f"  in:{ida_funcs.get_func_name(func.start_ea)}"
                            if maybe_add(result_line):
                                break
                    ea = idc.next_head(ea, seg_end)
            return _search_result(pattern=pattern)
            
        elif action == "func_by_sig":
            # Parse signature criteria (supports semantic/natural-language style).
            criteria = pattern.lower()
            filter_matcher = compile_smart_pattern(pattern, case_sensitive=False)
            size_rules = []
            call_pattern = None
            args_rule = None

            for m in re_module.finditer(r"size\s*[:=]\s*([<>]?)(\d+)(?:\s*-\s*(\d+))?", criteria):
                op, val1, val2 = m.groups()
                size_rules.append((op or "=", int(val1), int(val2) if val2 else None))
            for m in re_module.finditer(r"(?:larger|greater|bigger)\s+than\s+(\d+)", criteria):
                size_rules.append((">", int(m.group(1)), None))
            for m in re_module.finditer(r"(?:smaller|less)\s+than\s+(\d+)", criteria):
                size_rules.append(("<", int(m.group(1)), None))

            m_calls = re_module.search(r"(?:calls?|invoke(?:s|d)?|callee)\s*[:=]?\s*([^\s,;]+)", criteria)
            if m_calls:
                call_pattern = m_calls.group(1).strip()

            m_args = re_module.search(r"(?:args?|arguments?|params?)\s*[:=]?\s*(\d+)\s*(\+|or\s+more)?", criteria)
            if m_args:
                args_rule = (int(m_args.group(1)), bool(m_args.group(2)))

            for ea in idautils.Functions():
                if truncated:
                    break
                    
                func = idaapi.get_func(ea)
                if not func:
                    continue
                    
                name = ida_funcs.get_func_name(ea)
                size = func.end_ea - func.start_ea
                matched = False
                reason = []
                
                # Size filter: size:>100, size:<50, size:100-500
                if size_rules:
                    size_ok = False
                    for op, val1, val2 in size_rules:
                        if op == ">" and size > val1:
                            size_ok = True
                            reason.append(f"size={size}>{val1}")
                        elif op == "<" and size < val1:
                            size_ok = True
                            reason.append(f"size={size}<{val1}")
                        elif val2 is not None and val1 <= size <= val2:
                            size_ok = True
                            reason.append(f"size={size} in [{val1},{val2}]")
                        elif op in ("", "=") and val2 is None and size == val1:
                            size_ok = True
                            reason.append(f"size={size}")
                    matched = matched or size_ok
                
                # Calls filter: calls:malloc, calls:*alloc*
                if call_pattern:
                    call_matcher = compile_smart_pattern(call_pattern, case_sensitive=False)
                    for xref in idautils.XrefsFrom(ea):
                        if xref.type in [17, 18, 19, 20, 21]:  # Call types
                            callee_name = idc.get_name(xref.to) or ""
                            if call_matcher(callee_name):
                                matched = True
                                reason.append(f"calls:{callee_name}")
                                break
                
                # Args filter: args:3+, args:0
                if args_rule:
                    arg_count, plus = args_rule
                    # Try to get prototype
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, ea):
                        func_data = ida_typeinf.func_type_data_t()
                        if tif.get_func_details(func_data):
                            actual_args = func_data.size()
                            if plus and actual_args >= arg_count:
                                matched = True
                                reason.append(f"args={actual_args}>={arg_count}")
                            elif not plus and actual_args == arg_count:
                                matched = True
                                reason.append(f"args={actual_args}")

                # Generic semantic fallback on function name when no explicit criteria matched.
                if not (size_rules or call_pattern or args_rule) and filter_matcher(name):
                    matched = True
                    reason.append("semantic:name")
                
                if matched:
                    if maybe_add(f"{hex(ea)}  {name}  size={size}  {', '.join(reason)}"):
                        break
                        
            return _search_result(pattern=pattern)
        
        elif action == "find":
            # Smart unified search - auto-detects what user wants
            _find_matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            ranked = []

            def _add_find(kind: str, ea: int, line: str, score: int):
                ranked.append(
                    {
                        "type": kind,
                        "address": hex(ea),
                        "address_ea": ea,
                        "score": score,
                        "line": line,
                    }
                )

            # 1. If pattern looks like an address, surface xrefs first.
            if looks_like_address(pattern):
                ea, addr_err = validate_addr(pattern)
                if addr_err:
                    try:
                        ea = int(pattern, 16)
                    except Exception:
                        ea = idaapi.BADADDR
                if ea != idaapi.BADADDR:
                    for xref in idautils.XrefsTo(ea, 0):
                        func = idaapi.get_func(xref.frm)
                        fn_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                        if xref.iscode:
                            _add_find("code_ref", xref.frm, f"{hex(xref.frm)}  {fn_name}", 300)
                        else:
                            _add_find("data_ref", xref.frm, f"{hex(xref.frm)}  {fn_name}", 260)

            # 2. Search names (functions, globals)
            for ea, name in idautils.Names():
                if _find_matcher(name):
                    kind = "func" if idaapi.get_func(ea) else "data"
                    xref_count = _xref_count_limited(ea)
                    score = 180 + min(xref_count, 64)
                    _add_find("names", ea, f"{hex(ea)}  {kind}  {name}  xrefs={xref_count}", score)

            # 3. Search strings
            for i in range(idaapi.get_strlist_qty()):
                sc = idaapi.string_info_t()
                if idaapi.get_strlist_item(sc, i):
                    try:
                        content = idc.get_strlit_contents(sc.ea)
                        if not content:
                            continue
                        s = content.decode("utf-8", errors="replace")
                        if _find_matcher(s):
                            xref_count = _xref_count_limited(sc.ea)
                            score = 100 + min(xref_count, 64)
                            _add_find(
                                "strings",
                                sc.ea,
                                f"{hex(sc.ea)}  xrefs={xref_count}  {_clip(s, 180)}",
                                score,
                            )
                    except Exception:
                        pass

            # 4. Search imports
            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i) or f"mod_{i}"

                def cb(ea, name, ordinal):
                    if name and _find_matcher(name):
                        xref_count = _xref_count_limited(ea)
                        score = 220 + min(xref_count, 64)
                        _add_find(
                            "imports",
                            ea,
                            f"{hex(ea)}  {mod_name}  {name}  xrefs={xref_count}",
                            score,
                        )
                    return True

                ida_nalt.enum_import_names(i, cb)

            page, total, is_truncated = _paginate_records(
                ranked, sort_key=lambda r: (r["score"], r["address_ea"])
            )
            by_type = {"names": [], "strings": [], "imports": [], "code_refs": [], "data_refs": []}
            type_to_key = {
                "names": "names",
                "strings": "strings",
                "imports": "imports",
                "code_ref": "code_refs",
                "data_ref": "data_refs",
            }
            for row in page:
                key = type_to_key.get(row["type"])
                if key:
                    by_type[key].append(row["line"])

            result = {
                "ok": True,
                "action": "find",
                "query": pattern,
                "matches": "\n".join(row["line"] for row in page),
                "offset": offset,
                "count": len(page),
                "total": total,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            if include_items:
                result["items"] = [
                    {"type": row["type"], "address": row["address"], "score": row["score"], "text": row["line"]}
                    for row in page
                ]
            if include_breakdown:
                result["type_totals"] = {
                    "names": sum(1 for r in ranked if r["type"] == "names"),
                    "strings": sum(1 for r in ranked if r["type"] == "strings"),
                    "imports": sum(1 for r in ranked if r["type"] == "imports"),
                    "code_refs": sum(1 for r in ranked if r["type"] == "code_ref"),
                    "data_refs": sum(1 for r in ranked if r["type"] == "data_ref"),
                }
                result["names"] = "\n".join(by_type["names"])
                result["strings"] = "\n".join(by_type["strings"])
                result["imports"] = "\n".join(by_type["imports"])
                result["code_refs"] = "\n".join(by_type["code_refs"])
                result["data_refs"] = "\n".join(by_type["data_refs"])
            return result
        
        elif action == "callers":
            # Find all functions that call the target
            target_ea, error, sem_meta = _resolve_semantic_target(pattern, require_function=True, include_imports=False)
            if error:
                return make_error(MCPError.INVALID_ARGS, error)
            
            func = idaapi.get_func(target_ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

            callers = {}
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if not xref.iscode:
                    continue
                caller_func = idaapi.get_func(xref.frm)
                if not caller_func:
                    continue
                key = caller_func.start_ea
                if key not in callers:
                    callers[key] = {
                        "address_ea": key,
                        "address": hex(key),
                        "name": ida_funcs.get_func_name(key),
                        "call_sites": [],
                    }
                callers[key]["call_sites"].append(xref.frm)

            ranked = []
            for row in callers.values():
                call_sites = sorted(set(row["call_sites"]))
                first_site = call_sites[0] if call_sites else row["address_ea"]
                line = f"{row['address']}  {row['name']}  calls={len(call_sites)}  first@{hex(first_site)}"
                if include_context and call_sites:
                    line += f"  {_clip(ida_lines.tag_remove(idc.generate_disasm_line(first_site, 0)))}"
                row["line"] = line
                row["score"] = len(call_sites)
                row["first_site"] = hex(first_site)
                ranked.append(row)

            page, total, is_truncated = _paginate_records(
                ranked, sort_key=lambda r: (r["score"], r["address_ea"])
            )
            result = {
                "ok": True,
                "action": "callers",
                "target": idc.get_name(target_ea) or hex(target_ea),
                "target_addr": hex(func.start_ea),
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            result.update(sem_meta)
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "name": r["name"],
                        "call_count": r["score"],
                        "first_call_site": r["first_site"],
                    }
                    for r in page
                ]
            return result
        
        elif action == "callees":
            # Find all functions called by the target
            target_ea, error, sem_meta = _resolve_semantic_target(pattern, require_function=True, include_imports=False)
            if error:
                return make_error(MCPError.INVALID_ARGS, error)
            
            func = idaapi.get_func(target_ea)
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")

            callees = {}
            for item in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type not in [17, 18, 19, 20, 21]:
                        continue
                    callee_func = idaapi.get_func(xref.to)
                    if not callee_func:
                        continue
                    key = callee_func.start_ea
                    if key not in callees:
                        callees[key] = {
                            "address_ea": key,
                            "address": hex(key),
                            "name": ida_funcs.get_func_name(key),
                            "call_sites": [],
                        }
                    callees[key]["call_sites"].append(item)

            ranked = []
            for row in callees.values():
                call_sites = sorted(set(row["call_sites"]))
                first_site = call_sites[0] if call_sites else row["address_ea"]
                line = f"{row['address']}  {row['name']}  calls={len(call_sites)}  first@{hex(first_site)}"
                if include_context and call_sites:
                    line += f"  {_clip(ida_lines.tag_remove(idc.generate_disasm_line(first_site, 0)))}"
                row["line"] = line
                row["score"] = len(call_sites)
                row["first_site"] = hex(first_site)
                ranked.append(row)

            page, total, is_truncated = _paginate_records(
                ranked, sort_key=lambda r: (r["score"], r["address_ea"])
            )
            result = {
                "ok": True,
                "action": "callees",
                "target": idc.get_name(target_ea) or hex(target_ea),
                "target_addr": hex(func.start_ea),
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            result.update(sem_meta)
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "name": r["name"],
                        "call_count": r["score"],
                        "first_call_site": r["first_site"],
                    }
                    for r in page
                ]
            return result
        
        elif action == "api":
            # Find all uses of an API/import function
            matcher = compile_smart_pattern(pattern, case_sensitive=False)
            matched_apis = []

            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i) or f"mod_{i}"

                def cb(ea, name, ordinal):
                    if name and matcher(name):
                        matched_apis.append(
                            {
                                "ea": ea,
                                "name": name,
                                "module": mod_name,
                                "score": _semantic_score(pattern, name) + min(_xref_count_limited(ea, 64), 64),
                            }
                        )
                    return True

                ida_nalt.enum_import_names(i, cb)

            if not matched_apis:
                target_ea, sem_err, sem_meta = _resolve_semantic_target(pattern, require_function=False, include_imports=True)
                if not sem_err and target_ea != idaapi.BADADDR:
                    target_name = idc.get_name(target_ea) or sem_meta.get("semantic_target") or pattern
                    module_name = sem_meta.get("semantic_module") or _extract_module_name_from_qualified(target_name)
                    matched_apis.append(
                        {
                            "ea": target_ea,
                            "name": target_name,
                            "module": module_name or "unknown",
                            "score": sem_meta.get("semantic_score", 0),
                        }
                    )

            if not matched_apis:
                return make_error(MCPError.NO_RESULTS, f"API {pattern} not found")

            matched_apis.sort(key=lambda r: (r.get("score", 0), r["ea"]), reverse=True)

            usage_rows = []
            for api_row in matched_apis:
                ea = api_row["ea"]
                name = api_row["name"]
                mod_name = api_row["module"]
                xrefs = [xr for xr in idautils.XrefsTo(ea, 0) if xr.iscode]
                call_total = len(xrefs)
                for xr in xrefs:
                    func = idaapi.get_func(xr.frm)
                    fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                    line = f"{hex(xr.frm)}  {fn_name}  -> {name} ({mod_name})  calls={call_total}"
                    if include_context:
                        line += f"  {_clip(ida_lines.tag_remove(idc.generate_disasm_line(xr.frm, 0)))}"
                    usage_rows.append(
                        {
                            "api": name,
                            "module": mod_name,
                            "api_ea": ea,
                            "address_ea": xr.frm,
                            "address": hex(xr.frm),
                            "function": fn_name,
                            "score": call_total,
                            "line": line,
                        }
                    )

            page, total, is_truncated = _paginate_records(
                usage_rows, sort_key=lambda r: (r["score"], r["address_ea"])
            )
            api_summary = sorted(
                (
                    {"api": r["name"], "module": r["module"], "address": hex(r["ea"]), "xref_count": _xref_count_limited(r["ea"])}
                    for r in matched_apis
                ),
                key=lambda x: x["xref_count"],
                reverse=True,
            )

            result = {
                "ok": True,
                "action": "api",
                "api": api_summary[0]["api"],
                "api_addr": api_summary[0]["address"],
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "function": r["function"],
                        "api": r["api"],
                        "module": r["module"],
                        "api_addr": hex(r["api_ea"]),
                        "api_xref_count": r["score"],
                    }
                    for r in page
                ]
            if include_breakdown:
                result["matched_apis"] = api_summary
                result["total_calls"] = total
            return result
        
        elif action == "vulnerable":
            # Find potentially vulnerable patterns
            vuln_matcher = compile_smart_pattern(pattern, case_sensitive=False) if pattern else None
            DANGEROUS_FUNCS = {
                # Format string vulnerabilities
                "printf": "format_string",
                "sprintf": "format_string", 
                "fprintf": "format_string",
                "snprintf": "format_string",
                "vprintf": "format_string",
                "vsprintf": "format_string",
                "vsnprintf": "format_string",
                "syslog": "format_string",
                # Buffer overflow risks
                "strcpy": "buffer_overflow",
                "strcat": "buffer_overflow",
                "gets": "buffer_overflow",
                "scanf": "buffer_overflow",
                "sscanf": "buffer_overflow",
                "fscanf": "buffer_overflow",
                "vscanf": "buffer_overflow",
                "strncpy": "potential_overflow",  # Still risky if not null-terminated
                "strncat": "potential_overflow",
                "memcpy": "buffer_overflow",
                "memmove": "buffer_overflow",
                # Integer overflow
                "atoi": "integer_overflow",
                "atol": "integer_overflow", 
                "atoll": "integer_overflow",
                # Command injection
                "system": "command_injection",
                "popen": "command_injection",
                "execl": "command_injection",
                "execle": "command_injection",
                "execlp": "command_injection",
                "execv": "command_injection",
                "execve": "command_injection",
                "execvp": "command_injection",
                "ShellExecute": "command_injection",
                "ShellExecuteA": "command_injection",
                "ShellExecuteW": "command_injection",
                "WinExec": "command_injection",
                "CreateProcess": "command_injection",
                "CreateProcessA": "command_injection",
                "CreateProcessW": "command_injection",
                # Memory issues
                "malloc": "memory_alloc",
                "calloc": "memory_alloc",
                "realloc": "memory_alloc",
                "free": "use_after_free",
                "HeapAlloc": "memory_alloc",
                "HeapFree": "use_after_free",
                "VirtualAlloc": "memory_alloc",
                "VirtualFree": "use_after_free",
                # File operations (path traversal)
                "fopen": "path_traversal",
                "open": "path_traversal",
                "CreateFile": "path_traversal",
                "CreateFileA": "path_traversal",
                "CreateFileW": "path_traversal",
                # Crypto weaknesses
                "rand": "weak_random",
                "srand": "weak_random",
                "random": "weak_random",
                "MD5": "weak_crypto",
                "SHA1": "weak_crypto",
                "DES": "weak_crypto",
                "RC4": "weak_crypto",
            }
            
            findings = []
            severity_rank = {
                "command_injection": 5,
                "buffer_overflow": 5,
                "format_string": 5,
                "use_after_free": 4,
                "path_traversal": 4,
                "integer_overflow": 3,
                "weak_crypto": 3,
                "weak_random": 2,
                "memory_alloc": 1,
                "potential_overflow": 2,
            }

            # Search for dangerous function calls
            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i) or f"mod_{i}"

                def cb(ea, name, ordinal):
                    if not name:
                        return True

                    # Check if this is a dangerous function
                    vuln_type = None
                    for dangerous, vtype in DANGEROUS_FUNCS.items():
                        lname = name.lower()
                        if lname == dangerous.lower() or lname.startswith(dangerous.lower() + "@") or lname.startswith(dangerous.lower() + "_"):
                            vuln_type = vtype
                            break

                    if vuln_type:
                        # Find all callers of this dangerous function
                        for xref in idautils.XrefsTo(ea, 0):
                            if xref.iscode:
                                func = idaapi.get_func(xref.frm)
                                fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                                if vuln_matcher and not vuln_matcher(f"{vuln_type} {name} {fn_name} {mod_name}"):
                                    continue
                                sev = severity_rank.get(vuln_type, 1)
                                line = f"{hex(xref.frm)}  sev={sev}  {vuln_type}  {name}  in:{fn_name}"
                                if include_context:
                                    line += f"  {_clip(ida_lines.tag_remove(idc.generate_disasm_line(xref.frm, 0)))}"
                                findings.append(
                                    {
                                        "address_ea": xref.frm,
                                        "address": hex(xref.frm),
                                        "function": fn_name,
                                        "api": name,
                                        "module": mod_name,
                                        "vuln_type": vuln_type,
                                        "severity": sev,
                                        "line": line,
                                    }
                                )
                    return True
                ida_nalt.enum_import_names(i, cb)

            page, total, is_truncated = _paginate_records(
                findings, sort_key=lambda r: (r["severity"], r["address_ea"])
            )
            by_type = {}
            for row in findings:
                by_type[row["vuln_type"]] = by_type.get(row["vuln_type"], 0) + 1
            result = {
                "ok": True,
                "action": "vulnerable",
                "total_findings": total,
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "function": r["function"],
                        "type": r["vuln_type"],
                        "severity": r["severity"],
                        "api": r["api"],
                        "module": r["module"],
                    }
                    for r in page
                ]
            if include_breakdown:
                result["type_totals"] = by_type
            if pattern:
                result["query"] = pattern
            return result
        
        elif action == "constants":
            # Find crypto/magic constants
            import ida_ua
            const_matcher = compile_smart_pattern(pattern, case_sensitive=False) if pattern else None
            
            KNOWN_CONSTANTS = {
                # MD5 initialization constants
                0x67452301: "MD5_A",
                0xEFCDAB89: "MD5_B",
                0x98BADCFE: "MD5_C",
                0x10325476: "MD5_D",
                # SHA-1 initialization constants (overlap with MD5)
                0xC3D2E1F0: "SHA1_H4",
                # SHA-256 initialization constants
                0x6A09E667: "SHA256_H0",
                0xBB67AE85: "SHA256_H1",
                0x3C6EF372: "SHA256_H2",
                0xA54FF53A: "SHA256_H3",
                0x510E527F: "SHA256_H4",
                0x9B05688C: "SHA256_H5",
                0x1F83D9AB: "SHA256_H6",
                0x5BE0CD19: "SHA256_H7",
                # AES S-box first/last values
                0x63: "AES_SBOX_0",
                0x7C: "AES_SBOX_1",
                0x16: "AES_SBOX_LAST",
                # AES round constants
                0x01000000: "AES_RCON_1",
                0x02000000: "AES_RCON_2",
                # RC4 
                0x100: "RC4_STATE_SIZE",
                # RSA common exponent
                0x10001: "RSA_E_65537",
                0x3: "RSA_E_3",
                # CRC32 polynomial
                0xEDB88320: "CRC32_POLY",
                0x04C11DB7: "CRC32_POLY_REV",
                # Blowfish P-array
                0x243F6A88: "BLOWFISH_P0",
                0x85A308D3: "BLOWFISH_P1",
                # TEA/XTEA
                0x9E3779B9: "TEA_DELTA",
                # Salsa20/ChaCha
                0x61707865: "SALSA_CONST_0",
                0x3320646E: "SALSA_CONST_1", 
                0x79622D32: "SALSA_CONST_2",
                0x6B206574: "SALSA_CONST_3",
                # Common magic numbers
                0xDEADBEEF: "MAGIC_DEADBEEF",
                0xCAFEBABE: "MAGIC_CAFEBABE",
                0xFEEDFACE: "MAGIC_FEEDFACE",
                0xC0FFEE: "MAGIC_COFFEE",
                0xBADC0DE: "MAGIC_BADCODE",
                # Windows PE
                0x5A4D: "MZ_HEADER",
                0x00004550: "PE_SIGNATURE",
                # ELF
                0x464C457F: "ELF_MAGIC",
                # ZIP
                0x04034B50: "ZIP_LOCAL_HEADER",
                0x02014B50: "ZIP_CENTRAL_HEADER",
            }
            
            found_rows = []
            segments = seg_list if seg_list is not None else list(idautils.Segments())

            # Single-pass scan over instructions for known constants.
            for seg_ea in segments:
                seg = idaapi.getseg(seg_ea)
                if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue

                seg_start = seg.start_ea
                seg_end = seg.end_ea
                if range_start is not None:
                    seg_start = max(seg_start, range_start)
                    seg_end = min(seg_end, range_end)
                    if seg_start >= seg_end:
                        continue

                curr = seg_start
                while curr < seg_end:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, curr) > 0:
                        for op in insn.ops:
                            if op.type != ida_ua.o_imm:
                                continue
                            const_name = KNOWN_CONSTANTS.get(op.value)
                            if not const_name:
                                continue
                            func = idaapi.get_func(curr)
                            fn_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                            if const_matcher and not const_matcher(f"{const_name} {hex(op.value)} {fn_name}"):
                                continue
                            line = f"{hex(curr)}  {hex(op.value)}  {const_name}  in:{fn_name}"
                            if include_context:
                                line += f"  {_clip(ida_lines.tag_remove(idc.generate_disasm_line(curr, 0)))}"
                            found_rows.append(
                                {
                                    "address_ea": curr,
                                    "address": hex(curr),
                                    "value": hex(op.value),
                                    "name": const_name,
                                    "function": fn_name,
                                    "line": line,
                                }
                            )
                            break
                        curr += insn.size
                    else:
                        curr = idc.next_head(curr, seg_end)

            page, total, is_truncated = _paginate_records(
                found_rows, sort_key=lambda r: r["address_ea"], reverse=False
            )
            result = {
                "ok": True,
                "action": "constants",
                "total_found": total,
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "value": r["value"],
                        "name": r["name"],
                        "function": r["function"],
                    }
                    for r in page
                ]
            if pattern:
                result["query"] = pattern
            return result

        elif action == "decompiled":
            # Search through decompiled pseudocode of all functions
            if not pattern:
                return make_error(MCPError.INVALID_ARGS, "pattern required for decompiled search")
            matcher = compile_smart_pattern(pattern, case_sensitive=case_sensitive)
            import time as _time
            if not hasattr(ida_hexrays, "init_hexrays_plugin") or not ida_hexrays.init_hexrays_plugin():
                return make_error(
                    MCPError.DECOMPILER_UNAVAILABLE,
                    "Hex-Rays decompiler not available for decompiled search",
                    hint=ERROR_HINTS.get(MCPError.DECOMPILER_UNAVAILABLE),
                )

            # Guardrails: allow scoped decompilation, bounded function scan, and timeout budget.
            scope_addr = kwargs.get("addr") or kwargs.get("func") or kwargs.get("function") or kwargs.get("scope")
            timeout_ms = kwargs.get("timeout_ms", 8000)
            try:
                timeout_ms = int(timeout_ms)
            except Exception:
                timeout_ms = 8000
            timeout_ms = max(250, min(timeout_ms, 120000))
            timeout_s = timeout_ms / 1000.0

            max_functions = kwargs.get("max_functions", kwargs.get("sample_max_funcs", 180))
            try:
                max_functions = int(max_functions)
            except Exception:
                max_functions = 180
            max_functions = max(1, min(max_functions, 5000))
            sample = bool(kwargs.get("sample", False))

            target_funcs = []
            scope_func = None
            all_func_count = 0
            if scope_addr:
                target_ea, err = validate_addr(str(scope_addr))
                if err:
                    target_ea = idc.get_name_ea_simple(str(scope_addr))
                    if target_ea == idaapi.BADADDR:
                        return make_error(MCPError.INVALID_ARGS, f"Scope '{scope_addr}' not found")
                scope_func = idaapi.get_func(target_ea)
                if not scope_func:
                    return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(target_ea)}")
                target_funcs = [scope_func.start_ea]
            else:
                all_funcs = list(idautils.Functions())
                all_func_count = len(all_funcs)
                if sample and len(all_funcs) > max_functions:
                    step = max(1, len(all_funcs) // max_functions)
                    target_funcs = all_funcs[::step][:max_functions]
                else:
                    target_funcs = all_funcs[:max_functions]

            scan_truncated = False
            if not scope_func and len(target_funcs) >= max_functions:
                scan_truncated = all_func_count > len(target_funcs)

            rows = []
            scanned_functions = 0
            timed_out = False
            decompiled_functions = 0
            decompile_failures = 0
            failure_samples = []
            started_at = _time.time()
            for func_ea in target_funcs:
                if (_time.time() - started_at) >= timeout_s:
                    timed_out = True
                    break
                scanned_functions += 1
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        decompile_failures += 1
                        continue
                    decompiled_functions += 1
                    pseudocode = str(cfunc)
                    for line_num, line in enumerate(pseudocode.splitlines(), 1):
                        if matcher(line):
                            func_name = idc.get_func_name(func_ea) or hex(func_ea)
                            text = _clip(line.strip(), 220)
                            rows.append(
                                {
                                    "address_ea": func_ea,
                                    "address": hex(func_ea),
                                    "function": func_name,
                                    "line_num": line_num,
                                    "line": f"{hex(func_ea)}  {func_name}  L{line_num}: {text}",
                                }
                            )
                except Exception as e:
                    decompile_failures += 1
                    if len(failure_samples) < 5:
                        failure_samples.append(str(e))
                    continue

            if scanned_functions > 0 and decompiled_functions == 0 and decompile_failures > 0:
                return make_error(
                    MCPError.DECOMPILER_FAILED,
                    "Decompiled search failed to decompile any function in scope",
                    hint=ERROR_HINTS.get(MCPError.DECOMPILER_FAILED),
                    details={
                        "scanned_functions": scanned_functions,
                        "decompile_failures": decompile_failures,
                        "sample_errors": failure_samples,
                    },
                )

            page, total, is_truncated = _paginate_records(
                rows, sort_key=lambda r: (r["address_ea"], r["line_num"]), reverse=False
            )
            result = {
                "ok": True,
                "action": "decompiled",
                "pattern": pattern,
                "matches": "\n".join(r["line"] for r in page),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
                "scanned_functions": scanned_functions,
                "decompiled_functions": decompiled_functions,
                "decompile_failures": decompile_failures,
                "scan_limit": max_functions if not scope_func else 1,
                "timeout_ms": timeout_ms,
                "timed_out": timed_out,
            }
            if interpreted_action:
                result["interpreted_action"] = interpreted_action
            if interpreted_pattern:
                result["interpreted_query"] = interpreted_pattern
            if scope_func:
                result["scope"] = hex(scope_func.start_ea)
            if scan_truncated or timed_out:
                result["analysis_truncated"] = True
                if timed_out:
                    result["hint"] = "Increase timeout_ms or scope with addr to search one function."
                elif not scope_func:
                    result["hint"] = "Increase max_functions or set sample=false for broader coverage."
            if include_items:
                result["items"] = [
                    {
                        "address": r["address"],
                        "function": r["function"],
                        "line_num": r["line_num"],
                    }
                    for r in page
                ]
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 5. TYPES - Type operations (structs, enums, prototypes)
# ============================================================================
