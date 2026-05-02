
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 34. NAV - Navigation Helpers
# ============================================================================

@tool
@idaread
def nav(
    action: Annotated[Literal["goto", "cursor", "interesting", "semantic_goto"],
                      "Action: goto|cursor|interesting|semantic_goto"],
    addr: Annotated[Optional[str], "Address to navigate to"] = None,
    **kwargs
) -> dict:
    """
    Navigation helpers for triage and analysis context.
    
    Actions:
    - goto: Get detailed analysis context for an address.
    - cursor: Get current pseudo-cursor position (screen ea).
    - interesting: Find high-value triage points (crypto, syscalls, anti-debug).
    - semantic_goto: Navigate by natural language intent (e.g., "main", "network handler", "decryptor").
        Params: addr (natural language query describing the target)
        Returns: {addr, name, score, matched_by, note}
    """
    try:
        if action == "goto":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            return {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea),
                "function": idc.get_func_name(func.start_ea) if func else None,
                "disasm": ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            }

        elif action == "cursor":
            ea = ida_kernwin.get_screen_ea()
            if ea == idaapi.BADADDR:
                return {"ok": True, "addr": None, "name": None, "warning": "Cursor unavailable in headless mode"}
            return {"ok": True, "addr": hex(ea), "name": idc.get_name(ea)}

        elif action == "interesting":
            findings = []
            # Instruction-based triage
            targets = INTERESTING_INSTRUCTIONS
            scanned = 0
            max_scan = 500000
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg or not (seg.perm & idaapi.SEGPERM_EXEC): continue
                curr = seg.start_ea
                while curr < seg.end_ea and len(findings) < 100 and scanned < max_scan:
                    insn = idc.print_insn_mnem(curr).lower()
                    if insn in targets:
                        findings.append({"addr": hex(curr), "type": targets[insn], "disasm": ida_lines.tag_remove(idc.generate_disasm_line(curr, 0))})
                    curr = idc.next_head(curr, seg.end_ea)
                    scanned += 1
                    if curr == idaapi.BADADDR: break
            return {"ok": True, "findings": findings}

        elif action == "semantic_goto":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr (natural language query) required for semantic_goto")
            query = str(addr).lower().strip()
            
            # Score candidates by semantic relevance
            candidates = []
            
            # Check entry points first
            import ida_entry
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ""
                score = 0
                if query in name.lower():
                    score += 100
                if "main" in query and "main" in name.lower():
                    score += 200
                if "start" in query and "start" in name.lower():
                    score += 150
                if score > 0:
                    candidates.append({"addr": ea, "name": name, "score": score, "matched_by": "entry_point"})
            
            # Check all functions (capped to prevent hangs)
            max_funcs = 50000
            func_count = 0
            for func_ea in idautils.Functions():
                func_count += 1
                if func_count > max_funcs: break
                fname = idc.get_func_name(func_ea) or ""
                score = 0
                matched_by = []
                
                # Name matching
                if query in fname.lower():
                    score += 80
                    matched_by.append("name")
                
                # Semantic intent matching
                intent_map = {
                    "main": ["main", "winmain", "dllmain", "entry", "start"],
                    "init": ["init", "setup", "initialize", "constructor", "ctor"],
                    "network": ["network", "socket", "connect", "http", "recv", "send", "server", "client"],
                    "crypto": ["crypto", "encrypt", "decrypt", "hash", "aes", "rsa", "sha", "md5"],
                    "file": ["file", "read", "write", "open", "save", "load"],
                    "registry": ["registry", "regopen", "regset", "regquery"],
                    "debug": ["debug", "trace", "log", "assert"],
                    "string": ["string", "strcpy", "strlen", "sprintf", "format"],
                    "memory": ["memory", "malloc", "free", "alloc", "memcpy"],
                    "thread": ["thread", "create_thread", "mutex", "lock", "sync"],
                    "gui": ["gui", "window", "dialog", "messagebox", "menu"],
                    "decode": ["decode", "decrypt", "uncompress", "decompress", "unpack"],
                    "encode": ["encode", "encrypt", "compress", "pack", "serialize"],
                }
                
                for intent, keywords in intent_map.items():
                    if intent in query:
                        for kw in keywords:
                            if kw in fname.lower():
                                score += 60
                                matched_by.append(f"intent:{intent}")
                                break
                
                # API category matching
                try:
                    from .classify import _classify_func
                except ImportError:
                    from classify import _classify_func  # type: ignore[import-not-found]
                
                cat, _, _ = _classify_func(func_ea)
                if cat in query:
                    score += 40
                    matched_by.append(f"category:{cat}")
                
                if score > 0:
                    candidates.append({"addr": func_ea, "name": fname, "score": score, "matched_by": matched_by})
            
            if not candidates:
                return make_error(MCPError.NOT_FOUND, f"No function matches semantic query: '{query}'", "Try a more specific query or use search(action='find', pattern=...)")
            
            # Sort by score descending
            candidates.sort(key=lambda x: -x["score"])
            top = candidates[0]
            
            return {
                "ok": True,
                "query": query,
                "addr": hex(top["addr"]),
                "name": top["name"],
                "score": top["score"],
                "matched_by": top["matched_by"],
                "alternatives": [{"addr": hex(c["addr"]), "name": c["name"], "score": c["score"]} for c in candidates[1:5]],
                "note": "Semantic navigation resolved the query to the best-matching function. Use alternatives if this is not the intended target.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 35. COLORIZE - Code Region Coloring
# ============================================================================
