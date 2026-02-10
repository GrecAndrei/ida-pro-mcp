
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# LLM_HELPERS - LLM-Specific Helper Actions for Optimized Interaction
# ============================================================================

# Common API categories for quick classification (multi-platform)
_API_CATEGORIES = {
    "network": {"socket", "connect", "bind", "listen", "accept", "send", "recv",
                "sendto", "recvfrom", "sendmsg", "recvmsg",
                "WSAStartup", "InternetOpen", "HttpOpenRequest", "WinHttpOpen",
                "getaddrinfo", "gethostbyname", "URLDownloadToFile",
                "curl_easy_perform", "SSL_read", "SSL_write"},
    "file_io": {"CreateFile", "ReadFile", "WriteFile", "DeleteFile", "fopen",
                "fclose", "fread", "fwrite", "open", "close", "read", "write",
                "FindFirstFile", "FindNextFile",
                "opendir", "readdir", "stat", "lstat", "unlink", "rename"},
    "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptHashData", "BCryptEncrypt",
               "AES_encrypt", "EVP_EncryptInit", "MD5Init", "SHA256_Init",
               "EVP_DigestInit", "EVP_CipherInit", "RAND_bytes"},
    "process": {"CreateProcess", "OpenProcess", "CreateThread", "CreateRemoteThread",
                "ExitProcess", "TerminateProcess", "fork", "exec", "system",
                "execve", "posix_spawn", "clone", "pthread_create",
                "waitpid", "kill", "signal"},
    "registry": {"RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey",
                 "RegDeleteKey"},
    "memory": {"VirtualAlloc", "VirtualProtect", "HeapAlloc", "malloc", "mmap",
               "memcpy", "memset", "mprotect", "brk", "munmap", "calloc", "realloc"},
}


def _count_functions():
    """Count total functions."""
    return sum(1 for _ in idautils.Functions())


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
    return len(text) // 4 if text else 0


@tool
@idaread
def llm_helpers(
    action: Annotated[Literal["context_window", "function_digest", "binary_digest", "explain_address", "suggest_next", "progress_report", "focus_area", "question_answer", "guided_analysis", "cheatsheet"],
                      "LLM helper action"],
    addr: Annotated[Optional[str], "Address for context"] = None,
    query: Annotated[Optional[str], "Question or topic"] = None,
    max_tokens: Annotated[int, "Target token budget"] = 2000,
    limit: Annotated[int, "Max results to return"] = 10,
    history: Annotated[Optional[str], "Comma-separated previously analyzed addresses"] = None,
) -> dict:
    """
    LLM-specific helper actions to optimize binary analysis interaction.

    Actions:
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
    """
    try:
        info = idaapi.get_inf_structure() if hasattr(idaapi, 'get_inf_structure') else None

        if action == "context_window":
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
            for xref in idautils.XrefsTo(ea):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.append(idc.get_func_name(caller_func.start_ea) or hex(caller_func.start_ea))
            callers = list(set(callers))[:10]

            # Xrefs from this function
            callees = []
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, 0):
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
            for item in idautils.FuncItems(ea):
                for dref in idautils.DataRefsFrom(item):
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                str_refs.append(raw.decode("utf-8", errors="replace")[:80])
                            except Exception:
                                pass
            if str_refs:
                parts.append(f"Strings: {'; '.join(str_refs[:10])}")

            # Add disassembly up to budget
            current_size = sum(len(p) for p in parts)
            remaining = budget - current_size - 50
            disasm_text = "\n".join(disasm_lines)
            if len(disasm_text) > remaining:
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
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, 0):
                    target_name = idc.get_func_name(xref)
                    if target_name and not target_name.startswith("sub_"):
                        apis.append(target_name)
            apis = list(dict.fromkeys(apis))[:8]

            # Strings referenced
            strs = []
            for item in idautils.FuncItems(ea):
                for dref in idautils.DataRefsFrom(item):
                    st = idc.get_str_type(dref)
                    if st not in (None, -1):
                        raw = idc.get_strlit_contents(dref, -1, st)
                        if raw:
                            try:
                                strs.append(raw.decode("utf-8", errors="replace")[:40])
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
                        top_strings.append(raw.decode("utf-8", errors="replace")[:60])
                    except Exception:
                        pass
                    if len(top_strings) >= 20:
                        break

            if info:
                file_type_name = "PE" if info.filetype in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1)) else \
                                 "ELF" if info.filetype == getattr(idaapi, 'f_ELF', -1) else \
                                 "Mach-O" if info.filetype == getattr(idaapi, 'f_MACHO', -1) else "other"
            else:
                file_type_name = "unknown"

            image_size = (info.max_ea - info.min_ea) if info else 0
            seg_count = sum(1 for _ in idautils.Segments())

            proc_name = info.procname if info else ""
            bits = (64 if info.is_64bit() else 32) if info else 0
            min_ea = info.min_ea if info else 0
            max_ea = info.max_ea if info else 0
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
                            explanation.append(f"String: {raw.decode('utf-8', errors='replace')[:100]}")
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
                for ea in idautils.Functions():
                    fname = idc.get_func_name(ea) or ""
                    if any(kw in fname.lower() for kw in ("main", "init", "start", "entry", "setup")):
                        suggestions.append(f"Key function: {fname} @ {hex(ea)}")
                    if len(suggestions) >= 10:
                        break
            else:
                # Find connected functions not yet analyzed
                for analyzed_ea in analyzed:
                    func = ida_funcs.get_func(analyzed_ea)
                    if not func:
                        continue
                    for item in idautils.FuncItems(func.start_ea):
                        for xref in idautils.CodeRefsFrom(item, 0):
                            target = ida_funcs.get_func(xref)
                            if target and target.start_ea not in analyzed:
                                tname = idc.get_func_name(target.start_ea) or hex(target.start_ea)
                                suggestion = f"Called by analyzed: {tname} @ {hex(target.start_ea)}"
                                if suggestion not in suggestions:
                                    suggestions.append(suggestion)
                    # Also check callers
                    for xref in idautils.XrefsTo(func.start_ea):
                        caller = ida_funcs.get_func(xref.frm)
                        if caller and caller.start_ea not in analyzed:
                            cname = idc.get_func_name(caller.start_ea) or hex(caller.start_ea)
                            suggestion = f"Calls analyzed: {cname} @ {hex(caller.start_ea)}"
                            if suggestion not in suggestions:
                                suggestions.append(suggestion)
                    if len(suggestions) >= 15:
                        break

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
            for ea in idautils.Functions():
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
            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                name = idc.get_func_name(ea) or ""
                size = func.end_ea - func.start_ea
                xref_count = len(list(idautils.XrefsTo(ea)))

                # Score based on multiple factors
                score = 0
                if not name.startswith("sub_"):
                    score += 5
                score += min(xref_count, 20)
                score += min(size // 100, 10)

                # Check for interesting API calls
                for item in idautils.FuncItems(ea):
                    for xref in idautils.CodeRefsFrom(item, 0):
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
                            strs.append(f"{hex(s.ea)}  {raw.decode('utf-8', errors='replace')[:80]}")
                        except Exception:
                            pass
                        if len(strs) >= 30:
                            break
                answer_parts.append(f"Strings found ({len(strs)}):")
                answer_parts.extend(strs[:20])

            elif any(kw in q for kw in ("function", "func", "routine", "subroutine")):
                func_count = _count_functions()
                named = sum(1 for ea in idautils.Functions() if not (idc.get_func_name(ea) or "").startswith("sub_"))
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
                answer_parts.append(f"Binary: {info.procname if info else ''} {'64-bit' if (info and info.is_64bit()) else '32-bit'}")
                answer_parts.append(f"Functions: {_count_functions()}")
                modules, imports = _get_imports_summary()
                answer_parts.append(f"Imports: {len(imports)} from {len(modules)} modules")
                answer_parts.append(f"Query '{query}' - use more specific keywords (import, string, function, segment) for detailed answers")

            return {"ok": True, "answer": "\n".join(answer_parts)}

        elif action == "guided_analysis":
            file_type = info.filetype if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            steps = [
                "1. Get binary overview: binary_info(action='headers')",
                "2. Check sections: binary_info(action='sections')",
                "3. Get binary digest: llm_helpers(action='binary_digest')",
            ]

            if is_pe:
                steps.extend([
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find suspicious strings: string_ops(action='suspicious')",
                    "6. Check for C2 indicators: c2_detect(action='summary')",
                    "7. Detect crypto: crypto_id(action='scan')",
                    "8. Analyze entry point: llm_helpers(action='function_digest', addr='entry')",
                    "9. Check for obfuscation: cfg_analysis(action='flatten_detect', addr='main')",
                    "10. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])
            elif is_elf:
                steps.extend([
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find URLs/IPs: string_ops(action='find_urls')",
                    "6. Find commands: string_ops(action='find_commands')",
                    "7. Analyze main: llm_helpers(action='function_digest', addr='main')",
                    "8. Check complexity: cfg_analysis(action='complexity', addr='main')",
                    "9. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])
            else:
                steps.extend([
                    "4. Check imports: imports_deep(action='summary')",
                    "5. Find interesting strings: string_ops(action='suspicious')",
                    "6. Focus on interesting areas: llm_helpers(action='focus_area')",
                ])

            return {"ok": True, "guided_steps": "\n".join(steps)}

        elif action == "cheatsheet":
            file_type = info.filetype if info else 0
            is_pe = file_type in (getattr(idaapi, 'f_PE', -1), getattr(idaapi, 'f_COFF', -1))
            is_elf = file_type == getattr(idaapi, 'f_ELF', -1)

            cheat = ["=== Quick Reference for This Binary ==="]
            cheat.append(f"Arch: {info.procname if info else ''} | {'64-bit' if (info and info.is_64bit()) else '32-bit'}")
            cheat.append("")
            cheat.append("-- Overview --")
            cheat.append("binary_info(action='headers')        # PE/ELF headers")
            cheat.append("binary_info(action='sections')       # Sections with entropy")
            cheat.append("llm_helpers(action='binary_digest')  # Compact overview")
            cheat.append("")
            cheat.append("-- Functions --")
            cheat.append("llm_helpers(action='function_digest', addr='0xADDR')  # One-line summary")
            cheat.append("llm_helpers(action='context_window', addr='0xADDR')   # Full context")
            cheat.append("cfg_analysis(action='complexity', addr='0xADDR')       # Complexity")
            cheat.append("")
            cheat.append("-- Strings --")
            cheat.append("string_ops(action='find_urls')       # URLs")
            cheat.append("string_ops(action='find_commands')   # Shell commands")
            cheat.append("string_ops(action='suspicious')      # Passwords/keys/tokens")

            if is_pe:
                cheat.append("")
                cheat.append("-- PE-Specific --")
                cheat.append("string_ops(action='find_registry')   # Registry keys")
                cheat.append("binary_info(action='resources')      # PE resources")
                cheat.append("c2_detect(action='summary')          # Malware indicators")

            if is_elf:
                cheat.append("")
                cheat.append("-- ELF-Specific --")
                cheat.append("string_ops(action='find_paths')      # Unix paths")
                cheat.append("string_ops(action='find_commands')    # Shell commands")

            cheat.append("")
            cheat.append("-- Navigation --")
            cheat.append("llm_helpers(action='focus_area')              # What to look at next")
            cheat.append("llm_helpers(action='suggest_next', history=...)  # Based on analysis history")
            cheat.append("llm_helpers(action='progress_report', history=...)  # Track progress")

            return {"ok": True, "cheatsheet": "\n".join(cheat)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
