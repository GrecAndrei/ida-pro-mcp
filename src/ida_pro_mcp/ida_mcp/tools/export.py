
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re


# ============================================================================
# 28. EXPORT - Export Database in Various Formats
# ============================================================================

# ============================================================================
# Neuro-Symbolic Redaction for Exports
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
    action: Annotated[Literal["listing", "html", "idc", "json", "sarif", "binexport", "headers", "redact"],
                      "Action: listing|html|idc|json|sarif|binexport|headers|redact"],
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
            
            # Export names for all named symbols.
            rename_count = 0
            for ea, nm in idautils.Names():
                if not nm:
                    continue
                nm_esc = _escape_idc_string(str(nm))
                commands.append(f'  MakeName({hex(ea)}, "{nm_esc}");')
                rename_count += 1
                if rename_count >= 100000:
                    break

            # Export function definitions.
            func_count = 0
            for fea in idautils.Functions():
                fn = ida_funcs.get_func(fea)
                if not fn:
                    continue
                commands.append(f'  MakeFunction({hex(fn.start_ea)}, {hex(fn.end_ea)});')
                func_count += 1
                if func_count >= 100000:
                    break

            # Export comments (both regular and repeatable).
            comment_count = 0
            for seg_ea in idautils.Segments():
                seg_end = idc.get_segm_end(seg_ea)
                for head in idautils.Heads(seg_ea, seg_end):
                    c0 = idc.get_cmt(head, 0)
                    c1 = idc.get_cmt(head, 1)
                    if c0:
                        commands.append(f'  MakeComm({hex(head)}, "{_escape_idc_string(str(c0))}");')
                        comment_count += 1
                    if c1:
                        commands.append(f'  MakeRptCmt({hex(head)}, "{_escape_idc_string(str(c1))}");')
                        comment_count += 1
                    if comment_count >= 50000:
                        break
                if comment_count >= 50000:
                    break

            # Export inferred types (function signatures + named item types).
            type_count = 0
            for ea, nm in idautils.Names():
                t = idc.get_type(ea)
                if not t:
                    continue
                commands.append(f'  SetType({hex(ea)}, "{_escape_idc_string(str(t))}");')
                type_count += 1
                if type_count >= 50000:
                    break
            
            commands.append("}")
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(commands))
            
            return {"ok": True, "exported": True, "path": path, "commands": len(commands), "renames": rename_count, "functions": func_count, "comments": comment_count, "types": type_count}
        
        elif action == "json":
            if not path:
                path = _default_export_path("_export.json")
            _ensure_parent_dir(path)
            
            import hashlib
            data = {
                "binary_metadata": {
                    "file": idaapi.get_input_file_path(),
                    "md5": idaapi.retrieve_input_file_md5().hex() if hasattr(idaapi, 'retrieve_input_file_md5') else None,
                    "imagebase": hex(idaapi.get_imagebase()),
                    "ida_version": getattr(idaapi, "get_kernel_version", lambda: "unknown")(),
                },
                "functions": [],
                "strings": [],
                "imports": [],
                "exports": [],
                "types": [],
                "comments": [],
            }
            
            # Functions
            _JSON_FUNC_LIMIT = 5000
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    xref_to = len(list(idautils.XrefsTo(func_ea, 0)))
                    data["functions"].append({
                        "addr": hex(func_ea),
                        "name": idc.get_func_name(func_ea),
                        "size": func.end_ea - func.start_ea if func else 0,
                        "xref_to_count": xref_to,
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

            # Imports
            try:
                for i in range(idaapi.get_import_module_qty()):
                    mod_name = idaapi.get_import_module_name(i) or f"mod_{i}"
                    def _cb(ea, name, ord_):
                        data["imports"].append({"module": mod_name, "addr": hex(ea), "name": name or "", "ordinal": int(ord_ or 0)})
                        return True
                    idaapi.enum_import_names(i, _cb)
            except Exception:
                pass

            # Exports
            try:
                for idx, ord_, ea, nm in idautils.Entries():
                    data["exports"].append({"index": int(idx), "ordinal": int(ord_), "addr": hex(ea), "name": nm or ""})
            except Exception:
                pass

            # Types (named ordinals)
            try:
                qty = int(getattr(ida_typeinf, "get_ordinal_qty", lambda: 0)() or 0)
                tif = ida_typeinf.tinfo_t()
                for ord_ in range(1, qty + 1):
                    try:
                        if ida_typeinf.get_numbered_type(None, ord_, tif):
                            n = str(tif.get_type_name() or "")
                            if n:
                                data["types"].append({"ordinal": ord_, "name": n, "decl": str(tif)})
                    except Exception:
                        continue
                    if len(data["types"]) >= 2000:
                        break
            except Exception:
                pass

            # Comments
            for seg_ea in idautils.Segments():
                seg_end = idc.get_segm_end(seg_ea)
                for head in idautils.Heads(seg_ea, seg_end):
                    c = idc.get_cmt(head, 0) or idc.get_cmt(head, 1)
                    if c:
                        data["comments"].append({"addr": hex(head), "comment": str(c)[:500]})
                    if len(data["comments"]) >= 5000:
                        break
                if len(data["comments"]) >= 5000:
                    break

            # Cap ~10MB by trimming large sections.
            raw = json_module.dumps(data)
            cap = 10 * 1024 * 1024
            if len(raw.encode("utf-8")) > cap:
                for k in ("comments", "strings", "types", "functions"):
                    arr = data.get(k, [])
                    if isinstance(arr, list) and len(arr) > 100:
                        data[k] = arr[: max(100, len(arr) // 2)]
                        raw = json_module.dumps(data)
                        if len(raw.encode("utf-8")) <= cap:
                            break
            
            with open(path, 'w', encoding='utf-8') as f:
                json_module.dump(data, f, indent=2)
            
            return {"ok": True, "exported": True, "path": path, "functions": len(data["functions"]), "strings": len(data["strings"]), "imports": len(data["imports"]), "exports": len(data["exports"]), "types": len(data["types"]), "comments": len(data["comments"])}

        elif action == "sarif":
            if not path:
                path = _default_export_path(".sarif.json")
            _ensure_parent_dir(path)
            findings = []
            try:
                try: from .blackboard import BlackboardStore  # type: ignore
                except ImportError: from blackboard import BlackboardStore  # type: ignore[import-not-found]
                bb = BlackboardStore()
                findings = bb.list(category="vuln", include_resolved=False, limit=2000)
            except Exception:
                findings = []
            results = []
            # Every named function as a SARIF result entry.
            for fea in idautils.Functions():
                nm = idc.get_func_name(fea) or f"sub_{fea:x}"
                results.append({
                    "ruleId": "ida.named.function",
                    "level": "note",
                    "message": {"text": f"Function discovered: {nm}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": idaapi.get_input_file_path() or ""}, "region": {"startLine": 1}, "address": {"absoluteAddress": hex(fea)}}}],
                })
                if len(results) >= 5000:
                    break
            for f in findings:
                a = str(f.get("addr") or "")
                msg = str(f.get("title") or f.get("content") or "vulnerability finding")
                results.append({
                    "ruleId": "ida.blackboard.vuln",
                    "level": "warning",
                    "message": {"text": msg},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": idaapi.get_input_file_path() or ""}, "region": {"startLine": 1}, "address": {"absoluteAddress": a or "0x0"}}}],
                })
                if len(results) >= 10000:
                    break
            sarif = {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [{
                    "tool": {"driver": {"name": "ida-pro-mcp", "informationUri": "https://github.com", "rules": [
                        {"id": "ida.named.function", "name": "NamedFunction", "shortDescription": {"text": "Named function entry"}},
                        {"id": "ida.blackboard.vuln", "name": "BlackboardVulnerability", "shortDescription": {"text": "Blackboard vulnerability finding"}},
                    ]}},
                    "results": results,
                }],
            }
            with open(path, "w", encoding="utf-8") as f:
                json_module.dump(sarif, f, indent=2)
            return {"ok": True, "exported": True, "path": path, "results": len(results)}
        
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
                    "redacted": redacted[:20000],
                    "note": "Redacted sensitive patterns (IPs, emails, hashes, URLs, base64). Review before sharing externally.",
                }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 29. HISTORY - Database Version Control and Undo Management
# ============================================================================
