
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 28. EXPORT - Export Database in Various Formats
# ============================================================================

@tool
@idaread
def export(
    action: Annotated[Literal["listing", "html", "idc", "json", "binexport", "headers"],
                      "Action: listing|html|idc|json|binexport|headers"],
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
    """
    try:
        import os
        import json as json_module
        
        if action == "listing":
            if not path:
                path = idaapi.get_input_file_path() + ".lst"
            
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
                path = idaapi.get_input_file_path() + ".html"
            
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
                path = idaapi.get_input_file_path() + ".idc"
            
            commands = []
            commands.append("// IDC script generated by IDA MCP")
            commands.append('#include <idc.idc>')
            commands.append("static main() {")
            
            # Export renames
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    name = idc.get_func_name(func_ea)
                    if name and not name.startswith("sub_"):
                        commands.append(f'  MakeName({hex(func_ea)}, "{name}");')
            
            # Export comments (sample)
            comment_count = 0
            for seg_ea in idautils.Segments():
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    cmt = idc.get_cmt(head, 0)
                    if cmt:
                        cmt_escaped = cmt.replace('"', '\\"').replace('\n', '\\n')
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
                path = idaapi.get_input_file_path() + "_export.json"
            
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
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    func = ida_funcs.get_func(func_ea)
                    data["functions"].append({
                        "addr": hex(func_ea),
                        "name": idc.get_func_name(func_ea),
                        "size": func.end_ea - func.start_ea if func else 0
                    })
            
            # Limit for size
            data["functions"] = data["functions"][:5000]
            
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
                path = idaapi.get_input_file_path() + ".BinExport"
            
            # Try to run BinExport plugin
            try:
                import ida_loader
                result = ida_loader.load_and_run_plugin("binexport", 0)
                if result:
                    return {"ok": True, "exported": True, "path": path, "note": "BinExport plugin executed"}
                else:
                    return make_error(MCPError.NOT_IMPLEMENTED, "BinExport plugin not available or failed")
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"BinExport failed: {e}", "Install BinExport plugin from Google")
        
        elif action == "headers":
            if not path:
                path = idaapi.get_input_file_path() + ".h"
            
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
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 29. HISTORY - Database Version Control and Undo Management
# ============================================================================
