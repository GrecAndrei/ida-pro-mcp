
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 37. HOOKS - API Hook Suggestions and Script Generation
# ============================================================================

@tool
@idaread
def hooks(
    action: Annotated[Literal["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"],
                      "Action: suggest|generate_frida|generate_detours|find_targets|inline_hooks"],
    category: Annotated[Optional[str], "Hook category: network|file|crypto|registry|process"] = None,
    addr: Annotated[Optional[str], "Specific function address to hook"] = None,
    func_name: Annotated[Optional[str], "Function name to hook"] = None,
    **kwargs
) -> dict:
    """
    Generate hook scripts and suggestions for dynamic analysis.

    ACTIONS:

    suggest - Suggest functions to hook based on category
        Params: category (network|file|crypto|registry|process)
        Returns: {suggestions: [{name, addr, reason}]}

    generate_frida - Generate Frida hook script for function
        Params: addr or func_name
        Returns: {script: "JavaScript code"}

    generate_detours - Generate Microsoft Detours template
        Params: addr or func_name
        Returns: {code: "C++ template"}

    find_targets - Find interesting hook targets in binary
        Returns: {targets: [{addr, name, category, importance}]}

    inline_hooks - Suggest inline hook points (for trampolines)
        Params: addr
        Returns: {hook_points: [{addr, bytes_available, safe}]}
    """
    try:
        # Category-based function patterns
        HOOK_PATTERNS = {
            "network": ["send", "recv", "connect", "socket", "WSA", "accept", "bind", "listen",
                       "getaddrinfo", "gethostby", "inet_", "http", "curl", "ssl", "tls"],
            "file": ["CreateFile", "ReadFile", "WriteFile", "fopen", "fread", "fwrite",
                    "open", "read", "write", "close", "NtCreateFile", "NtReadFile"],
            "crypto": ["Crypt", "BCrypt", "NCrypt", "AES", "RSA", "SHA", "MD5", "hash",
                      "encrypt", "decrypt", "cipher", "key", "EVP_"],
            "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreate", "NtOpenKey"],
            "process": ["CreateProcess", "VirtualAlloc", "VirtualProtect", "LoadLibrary",
                       "GetProcAddress", "NtAllocate", "mmap", "mprotect", "execve", "fork"]
        }

        if action == "suggest":
            cat = (category or "").lower()
            if not cat:
                return {"ok": True, "categories": list(HOOK_PATTERNS.keys()), "hint": "Provide category for suggestions"}
            if cat not in HOOK_PATTERNS:
                return make_error(MCPError.INVALID_ARGS, f"Unknown category. Use: {', '.join(HOOK_PATTERNS.keys())}")

            patterns = HOOK_PATTERNS[cat]
            suggestions = []

            # Search imports
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg and seg.type == ida_segment.SEG_XTRN:  # Import segment
                    for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                        if len(suggestions) >= 10000:
                            break
                        name = idc.get_name(head)
                        if name:
                            for pattern in patterns:
                                if pattern.lower() in name.lower():
                                    suggestions.append({
                                        "name": name,
                                        "addr": hex(head),
                                        "pattern_match": pattern,
                                        "type": "import"
                                    })
                                    break

            # Search named functions
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if len(suggestions) >= 10000:
                        break
                    name = idc.get_func_name(func_ea)
                    if name:
                        for pattern in patterns:
                            if pattern.lower() in name.lower():
                                suggestions.append({
                                    "name": name,
                                    "addr": hex(func_ea),
                                    "pattern_match": pattern,
                                    "type": "function"
                                })
                                break
                if len(suggestions) >= 10000:
                    break

            return {"ok": True, "category": cat, "suggestions": suggestions[:50]}

        elif action == "generate_frida":
            if not addr and not func_name:
                return make_error(MCPError.INVALID_ARGS, "addr or func_name required")

            ea, err = validate_addr(addr or func_name)
            if err: return err

            func = ida_funcs.get_func(ea)
            if not func: return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            name = idc.get_func_name(ea)
            tif = ida_typeinf.tinfo_t()
            arg_count = 0
            if ida_nalt.get_tinfo(tif, ea) and tif.is_func():
                arg_count = tif.get_nargs()

            # Fallback to stack frame if no type info
            if arg_count == 0:
                frame = ida_frame.get_frame(func)
                if frame: arg_count = min(8, ida_frame.get_frame_size(func) // 8)

            # Generate arg loggers
            arg_logs = "\n".join([f'        console.log("    arg{i}:", args[{i}]);' for i in range(min(8, arg_count))])
            module_hint = os.path.basename(idaapi.get_input_file_path() or "").lower()
            offset = hex(ea - idaapi.get_imagebase())

            script = f'''// Frida hook for {name} at {hex(ea)}
const moduleHint = "{module_hint}";
const targetModule = Process.enumerateModules().find(m => m.name.toLowerCase() === moduleHint) || Process.mainModule;
if (!targetModule) {{
    throw new Error("Unable to resolve target module");
}}
const funcAddr = targetModule.base.add({offset});

Interceptor.attach(funcAddr, {{
    onEnter: function(args) {{
        console.log("[+] {name} called @ " + funcAddr + " (module=" + targetModule.name + ")");
{arg_logs}
    }},
    onLeave: function(retval) {{
        console.log("[+] {name} returned:", retval);
    }}
}});
'''
            return {"ok": True, "function": name, "addr": hex(ea), "script": script}

        elif action == "generate_detours":
            if not addr and not func_name:
                return make_error(MCPError.INVALID_ARGS, "addr or func_name required")

            ea, err = validate_addr(addr or func_name)
            if err: return err

            name = idc.get_func_name(ea) or f"sub_{ea:x}"

            # Get prototype
            proto = get_prototype(ida_funcs.get_func(ea)) or f"void* __stdcall {name}(...)"

            code = f'''// Microsoft Detours hook for {name}
#include <windows.h>
#include <detours.h>

// Original function prototype: {proto}
typedef {proto.replace(name, f"(*Orig_{name}_t)")};
Orig_{name}_t pOrig_{name} = (Orig_{name}_t){hex(ea)};

// Hook function (adjust signature to match prototype)
// Example:
// {proto.replace(name, f"Hook_{name}")} {{
//     OutputDebugStringA("[HOOK] {name} called\\n");
//     return pOrig_{name}(...);
// }}

void Install{name}Hook() {{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOrig_{name}, Hook_{name});
    DetourTransactionCommit();
}}
'''
            return {"ok": True, "function": name, "addr": hex(ea), "code": code}

        elif action == "find_targets":
            targets = []
            importance_keywords = {
                "high": ["password", "key", "crypt", "auth", "token", "secret", "license"],
                "medium": ["send", "recv", "file", "read", "write", "execute", "load"],
                "normal": []
            }

            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if len(targets) >= 10000:
                        break
                    name = idc.get_func_name(func_ea)
                    if not name or name.startswith("sub_"):
                        continue

                    name_lower = name.lower()
                    importance = "normal"
                    cat = "other"

                    # Determine category
                    for category, patterns in HOOK_PATTERNS.items():
                        for p in patterns:
                            if p.lower() in name_lower:
                                cat = category
                                break

                    # Determine importance
                    for level, keywords in importance_keywords.items():
                        for kw in keywords:
                            if kw in name_lower:
                                importance = level
                                break

                    if cat != "other" or importance != "normal":
                        targets.append({
                            "addr": hex(func_ea),
                            "name": name,
                            "category": cat,
                            "importance": importance
                        })
                if len(targets) >= 10000:
                    break

            # Sort by importance
            importance_order = {"high": 0, "medium": 1, "normal": 2}
            targets.sort(key=lambda x: importance_order.get(x["importance"], 2))

            return {"ok": True, "targets": targets[:100]}

        elif action == "inline_hooks":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")

            ea, err = validate_addr(addr)
            if err: return err
            func = ida_funcs.get_func(ea)

            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {addr}")

            hook_points = []
            current = func.start_ea

            while current < func.end_ea and len(hook_points) < 20:
                insn = idaapi.insn_t()
                length = idaapi.decode_insn(insn, current)

                if length >= 5:  # Need at least 5 bytes for JMP
                    # Check if this is a safe hook point (not in middle of instruction)
                    hook_points.append({
                        "addr": hex(current),
                        "bytes_available": length,
                        "safe": length >= 5,
                        "disasm": ida_lines.tag_remove(idc.generate_disasm_line(current, 0) or "")
                    })

                current += length if length > 0 else 1

            return {"ok": True, "function": idc.get_func_name(ea) or hex(ea), "hook_points": hook_points}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 38. TAINT - Static Taint/Data Flow Analysis
# ============================================================================
