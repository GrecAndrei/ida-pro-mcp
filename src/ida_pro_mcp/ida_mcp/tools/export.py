
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re


# ============================================================================
# 28. EXPORT - Export Database in Various Formats
# ============================================================================

# ============================================================================
# VOERA: Neuro-Symbolic Redaction for Exports
# ============================================================================

_REDACTION_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "EMAIL"),
    (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), "IP"),
    (re.compile(r'\b[a-f0-9]{32}\b'), "MD5"),
    (re.compile(r'\b[a-f0-9]{40}\b'), "SHA1"),
    (re.compile(r'\b[a-f0-9]{64}\b'), "SHA256"),
    (re.compile(r'\bhttps?://[^\s"\']+'), "URL"),
    (re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b'), "BASE64"),
]


def _redact_content(content: str, patterns: list = None) -> tuple[str, list[str]]:
    """Redact sensitive data from exported content.
    Returns (redacted_content, list_of_redactions).
    """
    patterns = patterns or _REDACTION_PATTERNS
    redacted = content
    redactions = []
    for pattern, label in patterns:
        matches = pattern.findall(redacted)
        for match in matches:
            redactions.append(f"{label}: {match[:30]}...")
        redacted = pattern.sub(f"[{label}_REDACTED]", redacted)
    return redacted, redactions


@tool
@idaread
def export(
    action: Annotated[Literal["listing", "html", "idc", "json", "binexport", "headers", "redact"],
                      "Action: listing|html|idc|json|binexport|headers|redact"],
    path: Annotated[Optional[str], "Output file path"] = None,
    addr: Annotated[Optional[str], "Address or range (for partial export)"] = None,
    include_decompile: Annotated[bool, "Include decompiled code"] = False,
    **kwargs
) -> dict:
    """
    Export IDB data in various formats for external use.
    
    ACTIONS:
    
    listing - Generate assembly listing file
        Params: path, addr (optional range)
        Returns: {exported, path, lines}
        
    html - Generate HTML report with navigation
        Params: path
        Returns: {exported, path}
        
    idc - Generate IDC script to recreate annotations
        Params: path
        Returns: {exported, path, commands}
        
    json - Export database metadata as JSON
        Params: path
        Returns: {exported, path}
        
    binexport - Export for BinDiff (if plugin available)
        Params: path
        Returns: {exported, path}
        
    headers - Export C headers for types
        Params: path
        Returns: {exported, path, types_count}

    redact - Preview redaction of sensitive data from a text snippet (neuro-symbolic governance).
        Params: addr (not used), path (text to redact, or omit to redact all strings from binary)
        Returns: {redacted, redactions, count}
    """
    try:
        import os
        import tempfile
        import json as json_module

        def _escape_idc_string(value: str) -> str:
            return (
                value.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\r", "\\r")
                .replace("\n", "\\n")
            )

        def _ensure_parent_dir(p: str):
            parent = os.path.dirname(p)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

        def _is_writable_dir(d: str) -> bool:
            if not d:
                return False
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                return False
            return os.path.isdir(d) and os.access(d, os.W_OK)

        def _default_export_path(ext: str) -> str:
            input_path = idaapi.get_input_file_path() or ""
            base_name = os.path.basename(input_path) if input_path else "ida_export.bin"
            stem = os.path.splitext(base_name)[0] or "ida_export"
            candidate_dirs = [
                os.path.dirname(input_path) if input_path else "",
                os.environ.get("IDA_MCP_CACHE_DIR", ""),
                os.path.join(tempfile.gettempdir(), "ida_mcp_exports"),
                os.getcwd(),
            ]
            for d in candidate_dirs:
                if _is_writable_dir(d):
                    return os.path.join(d, f"{stem}{ext}")
            return os.path.join(tempfile.gettempdir(), f"{stem}{ext}")
        
        # Validate path if provided
        if path:
            path, err = validate_path_safe(path)
            if err: return err

        if action == "listing":
            if not path:
                path = _default_export_path(".lst")
            _ensure_parent_dir(path)
            
            lines = []
            
            # Determine range
            if addr:
                if ':' in addr:
                    start_s, end_s = addr.split(':')
                    start_ea = parse_address(start_s)
                    end_ea = parse_address(end_s)
                else:
                    ea = parse_address(addr)
                    func = ida_funcs.get_func(ea)
                    if func:
                        start_ea = func.start_ea
                        end_ea = func.end_ea
                    else:
                        start_ea = ea
                        end_ea = ea + 0x100
            else:
                # Export first segment only to avoid huge files
                segs = list(idautils.Segments())
                if segs:
                    seg = ida_segment.getseg(segs[0])
                    start_ea = seg.start_ea
                    end_ea = min(seg.end_ea, start_ea + 0x10000)  # Limit size
                else:
                    return make_error(MCPError.IDA_ERROR, "No segments found")
            
            current = start_ea
            while current < end_ea and len(lines) < 10000:
                disasm = idc.generate_disasm_line(current, 0)
                if disasm:
                    lines.append(f"{hex(current)}: {ida_lines.tag_remove(disasm)}")
                current = idc.next_head(current)
                if current == idaapi.BADADDR:
                    break
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"; IDA Pro Listing\n")
                f.write(f"; File: {idaapi.get_input_file_path()}\n")
                f.write(f"; Range: {hex(start_ea)} - {hex(end_ea)}\n\n")
                f.write('\n'.join(lines))
            
            return {"ok": True, "exported": True, "path": path, "lines": len(lines)}
        
        elif action == "html":
            if not path:
                path = _default_export_path(".html")
            _ensure_parent_dir(path)
            
            # Generate simple HTML report
            html = []
            html.append("<!DOCTYPE html><html><head>")
            html.append("<title>IDA Analysis Report</title>")
            html.append("<style>body{font-family:monospace;} .func{margin:10px 0;padding:10px;border:1px solid #ccc;} .addr{color:blue;}</style>")
            html.append("</head><body>")
            html.append(f"<h1>Analysis: {os.path.basename(idaapi.get_input_file_path())}</h1>")
            
            # List functions
            html.append("<h2>Functions</h2>")
            func_count = 0
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if func_count >= 100:  # Limit
                        break
                    name = idc.get_func_name(func_ea)
                    html.append(f'<div class="func"><span class="addr">{hex(func_ea)}</span> - {name}</div>')
                    func_count += 1
            
            # List strings
            html.append("<h2>Strings</h2>")
            str_count = 0
            for s in idautils.Strings():
                if str_count >= 100:
                    break
                html.append(f'<div><span class="addr">{hex(s.ea)}</span>: {str(s)[:100]}</div>')
                str_count += 1
            
            html.append("</body></html>")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            
            return {"ok": True, "exported": True, "path": path, "functions": func_count, "strings": str_count}
        
        elif action == "idc":
            if not path:
                path = _default_export_path(".idc")
            _ensure_parent_dir(path)
            
            commands = []
            commands.append("// IDC script generated by IDA MCP")
            commands.append('#include <idc.idc>')
            commands.append("static main() {")
            
            # Export renames
            _IDC_RENAME_LIMIT = 50000
            _rename_count = 0
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        name_escaped = _escape_idc_string(name)
                        commands.append(f'  MakeName({hex(func_ea)}, "{name_escaped}");')
                        _rename_count += 1
                        if _rename_count >= _IDC_RENAME_LIMIT:
                            break
                if _rename_count >= _IDC_RENAME_LIMIT:
                    break
            
            # Export comments (sample)
            comment_count = 0
            for seg_ea in idautils.Segments():
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    cmt = idc.get_cmt(head, 0)
                    if cmt:
                        cmt_escaped = _escape_idc_string(cmt)
                        commands.append(f'  MakeComm({hex(head)}, "{cmt_escaped}");')
                        comment_count += 1
                        if comment_count >= 1000:
                            break
                if comment_count >= 1000:
                    break
            
            commands.append("}")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(commands))
            
            return {"ok": True, "exported": True, "path": path, "commands": len(commands)}
        
        elif action == "json":
            if not path:
                path = _default_export_path("_export.json")
            _ensure_parent_dir(path)
            
            data = {
                "file": idaapi.get_input_file_path(),
                "md5": idaapi.retrieve_input_file_md5().hex() if hasattr(idaapi, 'retrieve_input_file_md5') else None,
                "base_address": hex(idaapi.get_imagebase()),
                "functions": [],
                "strings": [],
                "imports": [],
                "exports": []
            }
            
            # Functions
            _JSON_FUNC_LIMIT = 5000
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    data["functions"].append({
                        "addr": hex(func_ea),
                        "name": idc.get_func_name(func_ea),
                        "size": func.end_ea - func.start_ea if func else 0
                    })
                    if len(data["functions"]) >= _JSON_FUNC_LIMIT:
                        break
                if len(data["functions"]) >= _JSON_FUNC_LIMIT:
                    break
            
            # Strings (sample)
            for s in idautils.Strings():
                if len(data["strings"]) >= 1000:
                    break
                data["strings"].append({
                    "addr": hex(s.ea),
                    "value": str(s)[:200]
                })
            
            with open(path, 'w', encoding='utf-8') as f:
                json_module.dump(data, f, indent=2)
            
            return {"ok": True, "exported": True, "path": path, "functions": len(data["functions"]), "strings": len(data["strings"])}
        
        elif action == "binexport":
            if not path:
                path = _default_export_path(".BinExport")
            _ensure_parent_dir(path)
            
            # Try to run BinExport plugin
            try:
                import ida_loader
                result = ida_loader.load_and_run_plugin("binexport", 0)
                if result:
                    return {"ok": True, "exported": True, "path": path, "note": "BinExport plugin executed"}
                # Plugin unavailable: emit structured JSON fallback artifact.
                fallback_path = f"{path}.fallback.json"
                _BINEXPORT_MAX = 100000
                def _count_bounded(iterable, limit):
                    c = 0
                    for _ in iterable:
                        c += 1
                        if c >= limit:
                            break
                    return c
                fallback = {
                    "format": "binexport-fallback",
                    "source_file": idaapi.get_input_file_path(),
                    "imagebase": hex(idaapi.get_imagebase()),
                    "functions": _count_bounded(idautils.Functions(), _BINEXPORT_MAX),
                    "names": _count_bounded(idautils.Names(), _BINEXPORT_MAX),
                    "segments": len(list(idautils.Segments())),
                    "note": "BinExport plugin unavailable; emitted fallback metadata artifact.",
                }
                with open(fallback_path, "w", encoding="utf-8") as f:
                    json_module.dump(fallback, f, indent=2)
                return {
                    "ok": True,
                    "exported": False,
                    "path": fallback_path,
                    "fallback": True,
                    "binexport_available": False,
                    "note": "BinExport plugin unavailable; emitted fallback metadata artifact instead of a .BinExport file.",
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"BinExport failed: {e}", "Install BinExport plugin from Google")
        
        elif action == "headers":
            if not path:
                path = _default_export_path(".h")
            _ensure_parent_dir(path)
            
            headers = []
            headers.append("// Type definitions exported from IDA")
            headers.append(f"// Source: {idaapi.get_input_file_path()}\n")
            
            # Export structures
            til = ida_typeinf.get_idati()
            type_count = 0
            if til:
                qty_func = getattr(ida_typeinf, 'get_ordinal_qty', None) or getattr(ida_typeinf, 'get_ordinal_count', None)
                count = qty_func(til) if qty_func else 0
                for ordinal in range(1, min(count + 1, 500)):  # Limit
                    tinfo = ida_typeinf.tinfo_t()
                    if tinfo.get_numbered_type(til, ordinal):
                        type_str = str(tinfo)
                        type_name = tinfo.get_type_name()
                        if type_name and tinfo.is_struct():
                            headers.append(f"// Ordinal {ordinal}")
                            headers.append(f"// {type_str}")
                            headers.append("")
                            type_count += 1
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(headers))
            
            return {"ok": True, "exported": True, "path": path, "types_count": type_count}

        elif action == "redact":
            if path:
                # Redact provided text
                content = str(path)
                redacted, redactions = _redact_content(content)
                return {
                    "ok": True,
                    "original_length": len(content),
                    "redacted_length": len(redacted),
                    "redactions": redactions,
                    "count": len(redactions),
                    "redacted": redacted,
                }
            else:
                # Redact all strings from binary
                all_strings = []
                for s in idautils.Strings():
                    if len(all_strings) >= 500:
                        break
                    val = str(s)
                    if val and len(val) > 3:
                        all_strings.append(val)
                combined = "\n".join(all_strings)
                redacted, redactions = _redact_content(combined)
                return {
                    "ok": True,
                    "source": "binary_strings",
                    "redactions": redactions[:50],
                    "count": len(redactions),
                    "note": "Redacted sensitive patterns (IPs, emails, hashes, URLs, base64). Review before sharing externally.",
                }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 29. HISTORY - Database Version Control and Undo Management
# ============================================================================
