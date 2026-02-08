
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# ANNOTATION - Intelligent Bulk Annotation for LLMs
# ============================================================================

# Dangerous APIs that warrant warning comments
_DANGEROUS_APIS = {
    "strcpy": "unbounded copy - use strncpy/strlcpy",
    "strcat": "unbounded concat - use strncat/strlcat",
    "sprintf": "unbounded format - use snprintf",
    "gets": "no bounds checking - use fgets",
    "scanf": "no bounds checking - use fgets+sscanf",
    "vsprintf": "unbounded format - use vsnprintf",
    "wcscpy": "unbounded wide copy - use wcsncpy",
    "wcscat": "unbounded wide concat - use wcsncat",
    "lstrcpy": "unbounded copy - use StringCchCopy",
    "lstrcpyA": "unbounded copy - use StringCchCopyA",
    "lstrcpyW": "unbounded copy - use StringCchCopyW",
    "lstrcat": "unbounded concat - use StringCchCat",
    "lstrcatA": "unbounded concat - use StringCchCatA",
    "lstrcatW": "unbounded concat - use StringCchCatW",
    "memcpy": "verify size parameter - potential overflow",
    "memmove": "verify size parameter - potential overflow",
    "RtlCopyMemory": "verify size parameter - potential overflow",
    "VirtualAlloc": "check for RWX permissions (PAGE_EXECUTE_READWRITE)",
    "VirtualProtect": "check for RWX permissions - code injection indicator",
    "CreateRemoteThread": "remote thread creation - injection technique",
    "WriteProcessMemory": "remote memory write - injection technique",
    "NtWriteVirtualMemory": "remote memory write - injection technique",
    "ShellExecute": "command execution - check for user-controlled input",
    "ShellExecuteA": "command execution - check for user-controlled input",
    "ShellExecuteW": "command execution - check for user-controlled input",
    "WinExec": "command execution - check for user-controlled input",
    "system": "shell command execution - check for injection",
    "popen": "shell command execution - check for injection",
    "exec": "process execution - check for injection",
    "execl": "process execution - check for injection",
    "execv": "process execution - check for injection",
    "execve": "process execution - check for injection",
    "LoadLibrary": "dynamic library loading - check source",
    "LoadLibraryA": "dynamic library loading - check source",
    "LoadLibraryW": "dynamic library loading - check source",
    "GetProcAddress": "dynamic API resolution - evasion technique",
    "URLDownloadToFile": "file download - check URL source",
    "URLDownloadToFileA": "file download - check URL source",
    "InternetReadFile": "network read - validate buffer size",
    "RegSetValueEx": "registry modification - persistence indicator",
    "RegSetValueExA": "registry modification - persistence indicator",
    "RegSetValueExW": "registry modification - persistence indicator",
    "SetWindowsHookEx": "global hook - keylogger/injection indicator",
    "SetWindowsHookExA": "global hook - keylogger/injection indicator",
    "SetWindowsHookExW": "global hook - keylogger/injection indicator",
    "NtCreateThreadEx": "thread creation - injection technique",
    "RtlCreateUserThread": "thread creation - injection technique",
    "AdjustTokenPrivileges": "privilege escalation",
    "ImpersonateLoggedOnUser": "privilege escalation via impersonation",
}

# Well-known magic constants
_MAGIC_CONSTANTS = {
    0x5A4D: "IMAGE_DOS_SIGNATURE ('MZ')",
    0x4550: "IMAGE_NT_SIGNATURE ('PE')",
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
    0xFEEDFACE: "MH_MAGIC (Mach-O 32-bit)",
    0xFEEDFACF: "MH_MAGIC_64 (Mach-O 64-bit)",
    0x464C457F: "ELF_MAGIC",
    0xDEADBEEF: "common debug marker",
    0xCAFEBABE: "Java class / universal binary magic",
    0xD00DFEED: "device tree blob magic",
    0x80000000: "GENERIC_READ / sign bit",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0xC0000000: "GENERIC_READ | GENERIC_WRITE",
    0x00000001: "FILE_SHARE_READ / TRUE",
    0x00000002: "FILE_SHARE_WRITE",
    0x00000003: "OPEN_EXISTING",
    0x00000004: "OPEN_ALWAYS / FILE_SHARE_DELETE",
    0x00000005: "TRUNCATE_EXISTING",
    0x00000040: "PAGE_EXECUTE_READWRITE",
    0x00000080: "FILE_ATTRIBUTE_NORMAL",
    0x00001000: "MEM_COMMIT / PAGE_SIZE",
    0x00002000: "MEM_RESERVE",
    0x00004000: "MEM_DECOMMIT",
    0x00008000: "MEM_RELEASE",
    0xFFFFFFFF: "INVALID_HANDLE_VALUE (-1)",
    0x0200: "WM_CHAR",
    0x0100: "WM_KEYDOWN",
    0x0101: "WM_KEYUP",
    0x000F: "WM_PAINT",
    0x0010: "WM_CLOSE",
    0x0002: "WM_DESTROY",
    0x0012: "WM_QUIT",
    0x0111: "WM_COMMAND",
    0x0400: "WM_USER",
    0x8000: "MEM_RELEASE / INTERNET_FLAG_RELOAD",
    0x1F0FFF: "PROCESS_ALL_ACCESS",
    0x001F03FF: "THREAD_ALL_ACCESS",
}

# Function tag categories based on API patterns
_TAG_CATEGORIES = {
    "crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt", "CryptDecrypt",
               "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
               "EVP_EncryptInit", "EVP_DecryptInit", "AES_encrypt", "AES_decrypt",
               "SHA256", "SHA1", "MD5_Init", "HMAC"],
    "network": ["socket", "connect", "send", "recv", "bind", "listen", "accept",
                "WSAStartup", "InternetOpen", "HttpOpenRequest", "HttpSendRequest",
                "WinHttpOpen", "curl_easy_init", "getaddrinfo", "gethostbyname"],
    "file_io": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile",
                "fopen", "fread", "fwrite", "open", "read", "write", "stat"],
    "process": ["CreateProcess", "OpenProcess", "CreateThread", "CreateRemoteThread",
                "fork", "exec", "system", "ShellExecute", "TerminateProcess"],
    "registry": ["RegOpenKey", "RegOpenKeyEx", "RegSetValueEx", "RegQueryValueEx",
                 "RegCreateKeyEx", "RegDeleteKey", "RegDeleteValue"],
    "memory": ["VirtualAlloc", "VirtualProtect", "HeapAlloc", "malloc", "calloc",
               "mmap", "mprotect", "VirtualFree", "HeapFree"],
    "string_ops": ["strcpy", "strcat", "strlen", "strcmp", "sprintf", "strstr",
                   "wcslen", "wcscpy", "MultiByteToWideChar", "WideCharToMultiByte"],
    "ui": ["CreateWindow", "MessageBox", "ShowWindow", "DialogBox", "SendMessage",
           "GetMessage", "DispatchMessage"],
    "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess", "OutputDebugString"],
    "persistence": ["RegSetValueEx", "CreateService", "RegCreateKeyEx",
                    "SetWindowsHookEx", "schtasks"],
    "evasion": ["GetProcAddress", "LoadLibrary", "VirtualProtect",
                "NtUnmapViewOfSection", "NtWriteVirtualMemory"],
}

# Build reverse lookup
_API_TO_TAG = {}
for _tag, _apis in _TAG_CATEGORIES.items():
    for _api in _apis:
        _API_TO_TAG.setdefault(_api.lower(), []).append(_tag)


def _get_func_callees_with_addr(func_ea):
    """Return list of (call_addr, callee_name) for the function."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    callees = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            name = idc.get_func_name(xref)
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


@tool
@idawrite
def annotation(
    action: Annotated[Literal["auto_comment", "label_loops", "label_branches",
                               "mark_dangerous", "annotate_constants",
                               "tag_functions", "document_args",
                               "mark_error_paths", "propagate_names", "cleanup"],
                      "Annotation action"],
    addr: Annotated[Optional[str], "Function address to annotate"] = None,
    limit: Annotated[int, "Max annotations to add"] = 100,
    prefix: Annotated[str, "Prefix for auto-generated comments"] = "[MCP] ",
    dry_run: Annotated[bool, "Preview without writing"] = False,
) -> dict:
    """
    Intelligent bulk annotation tool optimized for LLMs.

    All auto-generated comments are prefixed (default '[MCP] ') for easy cleanup.

    ACTIONS:

    auto_comment - Auto-generate comments for a function based on APIs called,
                   strings used, and code patterns.
        Params: addr (required), prefix, dry_run
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
    """
    try:
        # ----------------------------------------------------------------
        # ACTION: auto_comment
        # ----------------------------------------------------------------
        if action == "auto_comment":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fn = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea)
            callees = _get_func_callees_with_addr(ea)
            strings = _get_func_strings(ea)

            annotations = []

            # Summarize API calls at call sites
            for call_addr, callee_name in callees:
                if len(annotations) >= limit:
                    break
                base = _strip_api_suffix(callee_name)
                cmt = f"{prefix}calls {callee_name}"
                annotations.append({"addr": hex(call_addr), "comment": cmt})
                if not dry_run:
                    existing = idc.get_cmt(call_addr, 0) or ""
                    if prefix not in existing:
                        new_cmt = f"{existing}  {cmt}" if existing else cmt
                        idc.set_cmt(call_addr, new_cmt, 0)

            # Annotate string references
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                if len(annotations) >= limit:
                    break
                for dref in idautils.DataRefsFrom(head):
                    stype = idc.get_str_type(dref)
                    if stype is not None and stype >= 0:
                        s = idc.get_strlit_contents(dref, -1, stype)
                        if s:
                            s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                            cmt = f'{prefix}ref: "{s[:60]}"'
                            annotations.append({"addr": hex(head), "comment": cmt})
                            if not dry_run:
                                existing = idc.get_cmt(head, 0) or ""
                                if prefix not in existing:
                                    new_cmt = f"{existing}  {cmt}" if existing else cmt
                                    idc.set_cmt(head, new_cmt, 0)

            # Generate function-level summary
            api_names = [c[1] for c in callees]
            summary_parts = []
            if api_names:
                summary_parts.append(f"APIs: {', '.join(api_names[:8])}")
            if strings:
                summary_parts.append(f"Strings: {', '.join(s[:30] for s in strings[:4])}")
            if summary_parts:
                func_cmt = f"{prefix}{'; '.join(summary_parts)}"
                annotations.append({"addr": hex(ea), "comment": func_cmt, "type": "function"})
                if not dry_run:
                    existing = idc.get_func_cmt(ea, 1) or ""
                    if prefix not in existing:
                        new_cmt = f"{existing}\n{func_cmt}" if existing else func_cmt
                        idc.set_func_cmt(ea, new_cmt, 1)

            return {"ok": True, "function": fname, "annotations": annotations,
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
                for succ_idx in range(block.nsucc()):
                    succ = block.succ(succ_idx)
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

            return {"ok": True, "function": fname, "loops": loops,
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
                    disasm = idc.GetDisasm(last_insn)
                    true_target = block.succ(0).start_ea
                    false_target = block.succ(1).start_ea
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

            return {"ok": True, "function": fname, "branches": branches,
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
                for fea in idautils.Functions():
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

            return {"ok": True, "warnings": warnings,
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

            return {"ok": True, "function": fname, "constants": constants,
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
                for fea in idautils.Functions():
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

            return {"ok": True, "tagged": tagged,
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
                    "apis_used": api_usage[:10], "annotations": annotations,
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
                            "branch_insn": idc.GetDisasm(check_ea).strip(),
                            "comment": cmt,
                        })
                        if not dry_run:
                            existing = idc.get_cmt(check_ea, 0) or ""
                            if prefix not in existing:
                                new_cmt = f"{existing}  {cmt}" if existing else cmt
                                idc.set_cmt(check_ea, new_cmt, 0)
                        break
                    check_ea = idc.next_head(check_ea, fn.end_ea)

            return {"ok": True, "function": fname, "error_paths": error_paths,
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

            return {"ok": True, "function": fname, "suggestions": suggestions,
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
                for fea in idautils.Functions():
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

            return {"ok": True, "removed": removed,
                    "count": len(removed), "dry_run": dry_run}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
