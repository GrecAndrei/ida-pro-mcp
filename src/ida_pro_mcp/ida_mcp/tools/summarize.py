
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re


# ============================================================================
# SUMMARIZE - LLM-Friendly Binary/Function Summarization
# ============================================================================

# Import category mappings for known APIs
_IMPORT_CATEGORIES = {
    "file_io": [
        "CreateFile", "ReadFile", "WriteFile", "CloseHandle", "DeleteFile",
        "CopyFile", "MoveFile", "GetFileSize", "SetFilePointer",
        "FindFirstFile", "FindNextFile", "FindClose",
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
        "open", "close", "read", "write", "lseek", "stat", "fstat",
        "unlink", "rename", "mkdir", "rmdir", "opendir", "readdir",
    ],
    "network": [
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "select", "poll", "shutdown", "closesocket",
        "WSAStartup", "WSACleanup", "WSAGetLastError",
        "getaddrinfo", "gethostbyname", "inet_addr", "inet_ntoa",
        "htons", "htonl", "ntohs", "ntohl",
        "InternetOpen", "InternetConnect", "HttpOpenRequest",
        "HttpSendRequest", "InternetReadFile", "URLDownloadToFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    ],
    "crypto": [
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
        "CryptGenRandom", "CryptReleaseContext",
        "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey",
        "BCryptEncrypt", "BCryptDecrypt",
        "MD5Init", "MD5Update", "MD5Final",
        "SHA1Init", "SHA1Update", "SHA1Final",
        "EVP_EncryptInit", "EVP_DecryptInit", "EVP_DigestInit",
        "AES_encrypt", "AES_decrypt", "RSA_public_encrypt",
    ],
    "memory": [
        "malloc", "calloc", "realloc", "free",
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
        "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
        "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
        "mmap", "munmap", "mprotect", "brk", "sbrk",
        "memcpy", "memmove", "memset", "memcmp",
    ],
    "registry": [
        "RegOpenKey", "RegOpenKeyEx", "RegCloseKey",
        "RegQueryValue", "RegQueryValueEx", "RegSetValue", "RegSetValueEx",
        "RegCreateKey", "RegCreateKeyEx", "RegDeleteKey", "RegDeleteValue",
        "RegEnumKey", "RegEnumKeyEx", "RegEnumValue",
    ],
    "process": [
        "CreateProcess", "OpenProcess", "TerminateProcess", "ExitProcess",
        "GetCurrentProcess", "GetCurrentProcessId", "GetProcessId",
        "CreateThread", "CreateRemoteThread", "ExitThread",
        "GetCurrentThread", "GetCurrentThreadId",
        "WaitForSingleObject", "WaitForMultipleObjects",
        "fork", "exec", "execl", "execv", "execve", "execvp",
        "system", "popen", "kill", "waitpid", "wait",
    ],
    "sync": [
        "InitializeCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "DeleteCriticalSection",
        "CreateMutex", "ReleaseMutex", "CreateEvent", "SetEvent",
        "CreateSemaphore", "ReleaseSemaphore",
        "pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock",
        "pthread_create", "pthread_join",
    ],
    "string": [
        "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp",
        "strncmp", "strstr", "strchr", "strrchr", "strtok",
        "sprintf", "snprintf", "sscanf", "printf", "fprintf",
        "wcslen", "wcscpy", "wcscat", "wcscmp",
        "lstrcpy", "lstrcat", "lstrlen", "lstrcmp",
        "MultiByteToWideChar", "WideCharToMultiByte",
    ],
    "gui": [
        "CreateWindow", "CreateWindowEx", "ShowWindow", "UpdateWindow",
        "GetMessage", "TranslateMessage", "DispatchMessage",
        "PostMessage", "SendMessage", "DefWindowProc",
        "MessageBox", "DialogBox", "GetDlgItem",
        "RegisterClass", "RegisterClassEx",
    ],
    "service": [
        "OpenSCManager", "CreateService", "OpenService",
        "StartService", "ControlService", "DeleteService",
        "RegisterServiceCtrlHandler", "SetServiceStatus",
        "StartServiceCtrlDispatcher",
    ],
    "debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "OutputDebugString", "DebugBreak",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "ptrace",
    ],
}

# String classification patterns
_STRING_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
    "file_paths": re.compile(r"(?:[A-Za-z]:\\|/(?:usr|etc|tmp|var|home|opt|bin|sbin|lib))[^\s\"']*"),
    "registry_keys": re.compile(r"HKEY_|\\Software\\|\\System\\|\\CurrentVersion\\", re.IGNORECASE),
    "format_strings": re.compile(r"%[-+0 #]*\d*\.?\d*[diouxXeEfgGcsSpn%]"),
    "ip_addresses": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "email_addresses": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "error_messages": re.compile(r"(?:error|fail|exception|invalid|cannot|unable|denied)", re.IGNORECASE),
    "debug_strings": re.compile(r"(?:debug|trace|verbose|assert|TODO|FIXME|HACK)", re.IGNORECASE),
}

# Dangerous APIs for security posture assessment
_DANGEROUS_APIS = {
    "buffer_overflow": ["strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf"],
    "format_string": ["printf", "fprintf", "sprintf", "syslog"],
    "command_injection": ["system", "popen", "exec", "ShellExecute", "WinExec", "CreateProcess"],
    "memory_unsafe": ["memcpy", "memmove", "realloc"],
    "deprecated_crypto": ["MD5Init", "MD5Update", "SHA1Init", "DES_ecb_encrypt", "RC4"],
}

_MITIGATION_CHECKS = {
    "stack_canary": ["__stack_chk_fail", "__stack_chk_guard", "__security_check_cookie"],
    "aslr_related": ["__security_init_cookie", "IsProcessorFeaturePresent"],
    "safe_functions": ["strcpy_s", "strcat_s", "sprintf_s", "snprintf", "strncat", "strncpy"],
    "cfi": ["__cfi_check", "__cfi_slowpath"],
}


def _get_all_strings(max_items):
    """Collect defined strings from the IDB."""
    strings = []
    sc = idautils.Strings()
    for s in sc:
        if len(strings) >= max_items * 5:
            break
        val = str(s)
        if val and len(val) > 2:
            strings.append((s.ea, val))
    return strings


def _get_all_imports():
    """Collect all imported function names."""
    imports = []

    def imp_cb(ea, name, ordinal):
        if name:
            imports.append(name)
        return True

    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        idaapi.enum_import_names(i, imp_cb)
    return imports


def _categorize_import(name, categories):
    """Check which category an import belongs to."""
    base = name.rstrip("AaWw")
    for cat, funcs in categories.items():
        for f in funcs:
            n = name.lower()
            fl = f.lower()
            if n == fl or n == fl + "a" or n == fl + "w":
                return cat
            if base.lower() == fl:
                return cat
    return "other"


def _get_func_name_safe(ea):
    """Get function name for an address, or hex address."""
    name = idc.get_func_name(ea)
    return name if name else hex_ea(ea)


def _count_basic_blocks(func):
    """Count basic blocks in a function using IDA's flowchart."""
    try:
        fc = idaapi.FlowChart(func)
        return sum(1 for _ in fc)
    except Exception:
        return 0


def _get_cfg_edges(func):
    """Count edges in the control flow graph."""
    try:
        fc = idaapi.FlowChart(func)
        edges = 0
        for block in fc:
            for _ in block.succs():
                edges += 1
        return edges
    except Exception:
        return 0


def _get_func_calls(func_ea):
    """Get list of functions called from a function."""
    calls = []
    func = idaapi.get_func(func_ea)
    if not func:
        return calls
    for item in idautils.FuncItems(func_ea):
        for xref in idautils.XrefsFrom(item, 0):
            if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                name = idc.get_name(xref.to)
                if name and name not in calls:
                    calls.append(name)
    return calls


def _get_func_strings(func_ea):
    """Get strings referenced by a function."""
    strings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return strings
    for item in idautils.FuncItems(func_ea):
        for xref in idautils.XrefsFrom(item, 0):
            flags = ida_bytes.get_flags(xref.to)
            if ida_bytes.is_strlit(flags):
                contents = idc.get_strlit_contents(xref.to)
                if contents:
                    try:
                        s = contents.decode("utf-8", errors="ignore")
                    except Exception:
                        s = str(contents)
                    if s and s not in strings:
                        strings.append(s)
    return strings


def _get_file_type_name():
    """Get IDA's file type description."""
    info = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
    if info and hasattr(info, "filetype"):
        ft = info.filetype
        type_map = {
            0: "Unknown", 1: "EXE (old)", 2: "COM (old)", 3: "BIN",
            4: "DRV", 5: "WinPE", 11: "ELF", 13: "Mach-O",
            25: "PE+", 18: "COFF",
        }
        return type_map.get(ft, f"type_{ft}")
    return "Unknown"


def _decompile_preview(ea, max_lines=20):
    """Try to get a decompiled preview of a function."""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return None
        text = str(cfunc)
        lines = text.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines)"
        return text
    except Exception:
        return None


@tool
@idaread
def summarize(
    action: Annotated[Literal["binary", "function", "segment", "imports_by_category",
                               "strings_by_category", "complexity", "call_hierarchy",
                               "data_flow", "security_posture", "statistics"],
                      "Summarization action"],
    addr: Annotated[Optional[str], "Address for function/segment actions"] = None,
    depth: Annotated[int, "Depth for hierarchy actions"] = 3,
    max_items: Annotated[int, "Max items in lists"] = 30,
) -> dict:
    """
    LLM-friendly binary and function summarization for reverse engineering.

    Actions:
    - binary: High-level binary summary (type, compiler, purpose guess, key functions, strings, imports)
    - function: Summarize a single function (args, return, side effects, strings, API calls)
    - segment: Summarize a segment (code vs data, function count, interesting items)
    - imports_by_category: Categorize all imports by functionality (file I/O, network, crypto, etc.)
    - strings_by_category: Categorize strings by type (URLs, file paths, error messages, etc.)
    - complexity: Cyclomatic complexity and metrics for a function (requires addr)
    - call_hierarchy: Summarize the call hierarchy from a root function (requires addr)
    - data_flow: Summarize data flow through a function (inputs → transformations → outputs)
    - security_posture: Assess overall security posture (dangerous APIs, mitigations)
    - statistics: Binary statistics (function count, avg size, code/data ratio, named %, etc.)
    """
    try:
        # ----------------------------------------------------------------
        # binary
        # ----------------------------------------------------------------
        if action == "binary":
            file_path = idaapi.get_input_file_path()
            file_type = _get_file_type_name()

            # Compiler info
            comp_info = None
            if hasattr(ida_typeinf, "get_compiler_name"):
                try:
                    comp_info = ida_typeinf.get_compiler_name(
                        ida_typeinf.default_compiler())
                except Exception:
                    pass

            # Count functions
            func_count = sum(1 for _ in idautils.Functions())
            named_count = 0
            key_functions = []
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    named_count += 1
                    if len(key_functions) < max_items:
                        key_functions.append({"name": name, "addr": hex_ea(ea)})

            # Import categories summary
            all_imports = _get_all_imports()
            import_cats = {}
            for imp in all_imports:
                cat = _categorize_import(imp, _IMPORT_CATEGORIES)
                import_cats[cat] = import_cats.get(cat, 0) + 1

            # Interesting strings sample
            all_strings = _get_all_strings(max_items)
            interesting = []
            for s_ea, s_val in all_strings[:max_items]:
                if len(s_val) > 5:
                    interesting.append(s_val[:120])

            # Entry points
            entries = []
            for i in range(idaapi.get_entry_qty()):
                ordinal = idaapi.get_entry_ordinal(i)
                ep_ea = idaapi.get_entry(ordinal)
                ep_name = idaapi.get_entry_name(ordinal)
                if ep_ea != idaapi.BADADDR:
                    entries.append({"name": ep_name or "", "addr": hex_ea(ep_ea)})

            return {
                "ok": True,
                "file_path": file_path,
                "file_type": file_type,
                "compiler": comp_info,
                "function_count": func_count,
                "named_function_count": named_count,
                "import_count": len(all_imports),
                "import_categories": import_cats,
                "string_count": len(all_strings),
                "key_functions": "\n".join(str(x) for x in key_functions[:max_items]),
                "interesting_strings": interesting[:max_items],
                "entry_points": "\n".join(str(x) for x in entries),
            }

        # ----------------------------------------------------------------
        # function
        # ----------------------------------------------------------------
        elif action == "function":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for function action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)

            name = idc.get_func_name(func.start_ea)
            proto = get_prototype(func.start_ea)
            size = func.end_ea - func.start_ea
            bb_count = _count_basic_blocks(func)

            # Strings used
            strings_used = _get_func_strings(func.start_ea)

            # API calls
            calls = _get_func_calls(func.start_ea)

            # Decompiled preview
            preview = _decompile_preview(func.start_ea)

            # Side effects heuristic: writes to globals, calls to I/O
            io_calls = [c for c in calls if _categorize_import(c, _IMPORT_CATEGORIES) in
                        ("file_io", "network", "registry", "gui")]
            mem_calls = [c for c in calls if _categorize_import(c, _IMPORT_CATEGORIES) == "memory"]

            return {
                "ok": True,
                "name": name,
                "addr": hex_ea(func.start_ea),
                "end_addr": hex_ea(func.end_ea),
                "size": size,
                "prototype": proto,
                "basic_blocks": bb_count,
                "strings_used": strings_used[:max_items],
                "apis_called": calls[:max_items],
                "io_side_effects": io_calls,
                "memory_operations": mem_calls,
                "decompiled_preview": preview,
            }

        # ----------------------------------------------------------------
        # segment
        # ----------------------------------------------------------------
        elif action == "segment":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for segment action")
            ea, err = validate_addr(addr)
            if err:
                return err
            seg = idaapi.getseg(ea)
            if not seg:
                return make_error(MCPError.INVALID_ARGS, f"No segment at {hex_ea(ea)}")

            seg_name = ida_segment.get_segm_name(seg)
            seg_class = ida_segment.get_segm_class(seg)
            is_code = bool(seg.perm & idaapi.SFL_CODE) if hasattr(idaapi, "SFL_CODE") else (seg_class == "CODE")

            # Count functions in segment
            func_count = 0
            func_names = []
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                func_count += 1
                fn = idc.get_func_name(func_ea)
                if fn and not fn.startswith("sub_") and len(func_names) < max_items:
                    func_names.append(fn)

            # Count defined items
            defined = 0
            undefined = 0
            cur = seg.start_ea
            while cur < seg.end_ea:
                flags = ida_bytes.get_flags(cur)
                if ida_bytes.is_head(flags):
                    defined += 1
                else:
                    undefined += 1
                nxt = idc.next_head(cur, seg.end_ea)
                if nxt == idaapi.BADADDR or nxt <= cur:
                    break
                cur = nxt

            perms = ""
            sfl_r = getattr(ida_segment, "SFL_READ", 0)
            sfl_w = getattr(ida_segment, "SFL_WRITE", 0)
            sfl_x = getattr(ida_segment, "SFL_EXEC", 0)
            if sfl_r and (seg.perm & sfl_r):
                perms += "R"
            elif not sfl_r:
                perms += "R"
            if sfl_w and (seg.perm & sfl_w):
                perms += "W"
            if sfl_x and (seg.perm & sfl_x):
                perms += "X"

            return {
                "ok": True,
                "name": seg_name,
                "class": seg_class,
                "start": hex_ea(seg.start_ea),
                "end": hex_ea(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": perms,
                "is_code": is_code,
                "function_count": func_count,
                "named_functions": func_names,
                "defined_items": defined,
                "undefined_items": undefined,
            }

        # ----------------------------------------------------------------
        # imports_by_category
        # ----------------------------------------------------------------
        elif action == "imports_by_category":
            all_imports = _get_all_imports()
            categorized = {}
            for imp in all_imports:
                cat = _categorize_import(imp, _IMPORT_CATEGORIES)
                if cat not in categorized:
                    categorized[cat] = []
                if len(categorized[cat]) < max_items:
                    categorized[cat].append(imp)

            summary = {cat: len(funcs) for cat, funcs in categorized.items()}
            return {
                "ok": True,
                "total_imports": len(all_imports),
                "category_counts": summary,
                "categories": categorized,
            }

        # ----------------------------------------------------------------
        # strings_by_category
        # ----------------------------------------------------------------
        elif action == "strings_by_category":
            all_strings = _get_all_strings(max_items * 10)
            categorized = {}
            uncategorized = []

            for s_ea, s_val in all_strings:
                matched = False
                for cat, pattern in _STRING_PATTERNS.items():
                    if pattern.search(s_val):
                        if cat not in categorized:
                            categorized[cat] = []
                        if len(categorized[cat]) < max_items:
                            categorized[cat].append(s_val[:200])
                        matched = True
                        break
                if not matched and len(uncategorized) < max_items:
                    uncategorized.append(s_val[:200])

            summary = {cat: len(items) for cat, items in categorized.items()}
            return {
                "ok": True,
                "total_strings": len(all_strings),
                "category_counts": summary,
                "categories": categorized,
                "uncategorized_sample": uncategorized[:max_items],
            }

        # ----------------------------------------------------------------
        # complexity
        # ----------------------------------------------------------------
        elif action == "complexity":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for complexity action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)

            nodes = _count_basic_blocks(func)
            edges = _get_cfg_edges(func)
            # Cyclomatic complexity: V(G) = E - N + 2P (P=1 for single function)
            cyclomatic = edges - nodes + 2

            # Function size
            size = func.end_ea - func.start_ea

            # Instruction count
            insn_count = sum(1 for _ in idautils.FuncItems(func.start_ea))

            # Call count
            calls = _get_func_calls(func.start_ea)

            # Local variable count
            local_vars = 0
            try:
                frame = ida_frame.get_frame(func)
                if frame:
                    local_vars = frame.memqty
            except Exception:
                pass

            return {
                "ok": True,
                "name": _get_func_name_safe(func.start_ea),
                "addr": hex_ea(func.start_ea),
                "cyclomatic_complexity": cyclomatic,
                "basic_blocks": nodes,
                "cfg_edges": edges,
                "instructions": insn_count,
                "size_bytes": size,
                "calls_made": len(calls),
                "called_functions": calls[:max_items],
                "local_variables": local_vars,
                "complexity_rating": (
                    "low" if cyclomatic <= 5 else
                    "moderate" if cyclomatic <= 10 else
                    "high" if cyclomatic <= 20 else
                    "very_high"
                ),
            }

        # ----------------------------------------------------------------
        # call_hierarchy
        # ----------------------------------------------------------------
        elif action == "call_hierarchy":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for call_hierarchy action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            visited = set()

            def build_tree(func_ea, current_depth):
                if current_depth <= 0 or func_ea in visited:
                    return None
                visited.add(func_ea)
                name = _get_func_name_safe(func_ea)
                calls = _get_func_calls(func_ea)
                children = []
                for call_name in calls[:max_items]:
                    call_ea = idc.get_name_ea_simple(call_name)
                    if call_ea != idaapi.BADADDR:
                        child_func = idaapi.get_func(call_ea)
                        if child_func:
                            child = build_tree(child_func.start_ea, current_depth - 1)
                            if child:
                                children.append(child)
                            else:
                                children.append({"name": call_name, "addr": hex_ea(call_ea)})
                        else:
                            children.append({"name": call_name, "addr": hex_ea(call_ea), "type": "import"})
                    else:
                        children.append({"name": call_name, "type": "external"})
                return {
                    "name": name,
                    "addr": hex_ea(func_ea),
                    "calls": "\n".join(str(x) for x in children),
                }

            tree = build_tree(ea, depth)
            # Also get callers (who calls this function)
            callers = []
            for xref in idautils.XrefsTo(ea, 0):
                if xref.iscode:
                    caller_name = _get_func_name_safe(xref.frm)
                    if caller_name not in [c["name"] for c in callers]:
                        callers.append({"name": caller_name, "addr": hex_ea(xref.frm)})
                        if len(callers) >= max_items:
                            break

            return {
                "ok": True,
                "root": tree,
                "callers": "\n".join(str(x) for x in callers),
                "total_unique_functions": len(visited),
            }

        # ----------------------------------------------------------------
        # data_flow
        # ----------------------------------------------------------------
        elif action == "data_flow":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for data_flow action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            func = idaapi.get_func(ea)

            # Inputs: function arguments from prototype
            proto = get_prototype(func.start_ea)

            # Get calls for transformation analysis
            calls = _get_func_calls(func.start_ea)
            strings_used = _get_func_strings(func.start_ea)

            # Analyze instruction patterns
            reads_from_global = []
            writes_to_global = []
            arithmetic_ops = 0
            comparison_ops = 0
            branch_ops = 0

            for item in idautils.FuncItems(func.start_ea):
                mnem = idc.print_insn_mnem(item)
                if not mnem:
                    continue
                mnem_l = mnem.lower()

                if mnem_l in ("add", "sub", "mul", "imul", "div", "idiv",
                              "shl", "shr", "sar", "and", "or", "xor", "not", "neg",
                              # ARM arithmetic
                              "adds", "subs", "muls", "lsl", "lsr", "asr", "eor", "orr", "mvn"):
                    arithmetic_ops += 1
                elif mnem_l in ("cmp", "test", "tst", "cmn"):
                    comparison_ops += 1
                elif (mnem_l.startswith("j") and mnem_l != "jmp") or \
                     (mnem_l.startswith("b") and mnem_l not in (
                         "b", "bl", "blx", "blr", "bx",  # unconditional branch/call
                         "bic", "bfi", "bfxil",  # ARM logical/bitfield ops starting with 'b'
                     )):
                    branch_ops += 1

                # Check for global references
                for xref in idautils.XrefsFrom(item, 0):
                    if xref.type == idaapi.dr_R:
                        target_func = idaapi.get_func(xref.to)
                        if not target_func or target_func.start_ea != func.start_ea:
                            name = idc.get_name(xref.to)
                            if name and name not in reads_from_global:
                                reads_from_global.append(name)
                    elif xref.type == idaapi.dr_W:
                        target_func = idaapi.get_func(xref.to)
                        if not target_func or target_func.start_ea != func.start_ea:
                            name = idc.get_name(xref.to)
                            if name and name not in writes_to_global:
                                writes_to_global.append(name)

            # Categorize called functions as transformations
            transformations = []
            for c in calls:
                cat = _categorize_import(c, _IMPORT_CATEGORIES)
                transformations.append({"function": c, "category": cat})

            return {
                "ok": True,
                "name": _get_func_name_safe(func.start_ea),
                "addr": hex_ea(func.start_ea),
                "prototype": proto,
                "inputs": {
                    "globals_read": reads_from_global[:max_items],
                    "strings_used": strings_used[:max_items],
                },
                "transformations": {
                    "function_calls": "\n".join(str(x) for x in transformations[:max_items]),
                    "arithmetic_operations": arithmetic_ops,
                    "comparisons": comparison_ops,
                    "branches": branch_ops,
                },
                "outputs": {
                    "globals_written": writes_to_global[:max_items],
                },
            }

        # ----------------------------------------------------------------
        # security_posture
        # ----------------------------------------------------------------
        elif action == "security_posture":
            all_imports = _get_all_imports()
            import_set = set(i.lower() for i in all_imports)

            # Check for dangerous APIs
            dangerous_found = {}
            for category, funcs in _DANGEROUS_APIS.items():
                found = []
                for f in funcs:
                    fl = f.lower()
                    if fl in import_set or (fl + "a") in import_set or (fl + "w") in import_set:
                        found.append(f)
                if found:
                    dangerous_found[category] = found

            # Check for mitigations
            mitigations_found = {}
            for category, funcs in _MITIGATION_CHECKS.items():
                found = []
                for f in funcs:
                    fl = f.lower()
                    # Check imports and all names
                    if fl in import_set:
                        found.append(f)
                    elif idc.get_name_ea_simple(f) != idaapi.BADADDR:
                        found.append(f)
                if found:
                    mitigations_found[category] = found

            # Count uses of dangerous functions
            dangerous_usage = []
            for category, funcs in dangerous_found.items():
                for f in funcs:
                    f_ea = idc.get_name_ea_simple(f)
                    if f_ea == idaapi.BADADDR:
                        for suffix in ("A", "W", "a", "w"):
                            f_ea = idc.get_name_ea_simple(f + suffix)
                            if f_ea != idaapi.BADADDR:
                                break
                    if f_ea != idaapi.BADADDR:
                        xref_count = sum(1 for x in idautils.XrefsTo(f_ea, 0) if x.iscode)
                        if xref_count > 0:
                            dangerous_usage.append({
                                "function": f,
                                "category": category,
                                "call_count": xref_count,
                            })

            # Overall risk rating
            risk_score = 0
            for item in dangerous_usage:
                if item["category"] in ("buffer_overflow", "command_injection"):
                    risk_score += item["call_count"] * 3
                elif item["category"] in ("format_string", "deprecated_crypto"):
                    risk_score += item["call_count"] * 2
                else:
                    risk_score += item["call_count"]

            mitigation_score = sum(len(v) for v in mitigations_found.values())

            if risk_score == 0:
                risk_level = "low"
            elif risk_score <= 10 or mitigation_score >= 2:
                risk_level = "moderate"
            elif risk_score <= 30:
                risk_level = "high"
            else:
                risk_level = "critical"

            return {
                "ok": True,
                "dangerous_apis": dangerous_found,
                "dangerous_usage": "\n".join(str(x) for x in dangerous_usage[:max_items]),
                "mitigations": mitigations_found,
                "risk_score": risk_score,
                "mitigation_score": mitigation_score,
                "risk_level": risk_level,
            }

        # ----------------------------------------------------------------
        # statistics
        # ----------------------------------------------------------------
        elif action == "statistics":
            # Function stats
            func_count = 0
            named_count = 0
            total_func_size = 0
            largest_func = {"name": "", "size": 0}
            smallest_func = {"name": "", "size": float("inf")}

            for ea in idautils.Functions():
                func = idaapi.get_func(ea)
                if not func:
                    continue
                func_count += 1
                size = func.end_ea - func.start_ea
                total_func_size += size
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    named_count += 1
                if size > largest_func["size"]:
                    largest_func = {"name": name or hex_ea(ea), "size": size, "addr": hex_ea(ea)}
                if size < smallest_func["size"]:
                    smallest_func = {"name": name or hex_ea(ea), "size": size, "addr": hex_ea(ea)}

            avg_func_size = round(total_func_size / func_count, 1) if func_count else 0

            # Segment stats
            seg_count = 0
            total_code_size = 0
            total_data_size = 0
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                seg_count += 1
                seg_class = ida_segment.get_segm_class(seg)
                if seg_class == "CODE":
                    total_code_size += seg.end_ea - seg.start_ea
                else:
                    total_data_size += seg.end_ea - seg.start_ea

            total_size = total_code_size + total_data_size
            code_ratio = round(total_code_size / total_size, 4) if total_size else 0

            # Strings and imports
            all_strings = _get_all_strings(10000)
            all_imports = _get_all_imports()

            # Named percentage
            named_pct = round(named_count / func_count * 100, 1) if func_count else 0

            if smallest_func["size"] == float("inf"):
                smallest_func = {"name": "N/A", "size": 0}

            return {
                "ok": True,
                "functions": {
                    "total": func_count,
                    "named": named_count,
                    "unnamed": func_count - named_count,
                    "named_percentage": named_pct,
                    "average_size": avg_func_size,
                    "total_code_in_functions": total_func_size,
                    "largest": largest_func,
                    "smallest": smallest_func,
                },
                "segments": {
                    "count": seg_count,
                    "total_code_size": total_code_size,
                    "total_data_size": total_data_size,
                    "code_data_ratio": code_ratio,
                },
                "strings": {
                    "count": len(all_strings),
                },
                "imports": {
                    "count": len(all_imports),
                },
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
