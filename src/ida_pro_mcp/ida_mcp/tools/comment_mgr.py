
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 33. COMMENT_MGR - Comment Management
# ============================================================================

@tool
@idawrite
def comment_mgr(
    action: Annotated[Literal["get_context", "set_structured", "bulk_set", "export_md", "import_md", "summary"],
                      "Action: get_context|set_structured|bulk_set|export_md|import_md|summary"],
    addr: Annotated[Optional[str], "Address for comment"] = None,
    text: Annotated[Optional[str], "Comment text or markdown content"] = None,
    items: Annotated[Optional[str], "JSON list of {addr, text} for bulk operations"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
    format: Annotated[str, "Comment format: plain|markdown|structured"] = "plain",
    **kwargs
) -> dict:
    """
    Comment management with structured formats and bulk operations.

    ACTIONS:

    get_context - Get all comments around an address with context
        Params: addr
        Returns: {func_comment, inline_comments, repeatable, anterior, posterior, nearby_comments}

    set_structured - Set a structured comment (supports formats: plain, markdown, structured)
        Params: addr, text, format
        Returns: {ok, addr, format}

    bulk_set - Set multiple comments from JSON list
        Params: items (JSON: [{"addr": "0x...", "text": "..."}])
        Returns: {set_count, errors}

    export_md - Export all comments to markdown
        Params: path
        Returns: {exported, path, comment_count}

    import_md - Import comments from markdown
        Params: path
        Returns: {imported, count}

    summary - Get commenting coverage statistics
        Returns: {total_functions, functions_commented, coverage_pct, inline_comments}
    """
    import json as json_module
    
    try:
        if action == "get_context":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            
            ea, err = validate_addr(addr)
            if err: return err
            
            func = ida_funcs.get_func(ea)
            
            result = {
                "ok": True,
                "addr": hex(ea),
                "name": idc.get_name(ea)
            }
            
            # Function comment
            if func:
                result["func_name"] = idc.get_func_name(func.start_ea)
                result["func_comment"] = idc.get_func_cmt(func.start_ea, 0)
                result["func_comment_repeatable"] = idc.get_func_cmt(func.start_ea, 1)
            
            # Inline comment at address
            result["comment"] = idc.get_cmt(ea, 0)
            result["comment_repeatable"] = idc.get_cmt(ea, 1)
            
            # Anterior/posterior comments
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
            
            # Nearby comments in function
            nearby = []
            if func:
                curr = func.start_ea
                while curr < func.end_ea and len(nearby) < 20:
                    cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                    if cmt:
                        nearby.append({
                            "addr": hex(curr),
                            "comment": cmt[:100],
                            "offset": hex(curr - func.start_ea)
                        })
                    curr = idc.next_head(curr, func.end_ea)
                    if curr == idaapi.BADADDR: break
            result["nearby_comments"] = nearby
            
            return result
        
        elif action == "set_structured":
            if not addr or not text:
                return make_error(MCPError.INVALID_ARGS, "addr and text required")
            
            ea, err = validate_addr(addr)
            if err: return err
            
            # Format the comment based on format type
            if format == "structured":
                # Parse key:value pairs into a structured block
                formatted = "/* Analysis:\n"
                for line in text.split('\n'):
                    formatted += f" * {line}\n"
                formatted += " */"
            elif format == "markdown":
                formatted = text
            else:
                formatted = text
            
            # Set the comment
            idc.set_cmt(ea, formatted, 0)
            
            return {"ok": True, "addr": hex(ea), "format": format, "length": len(formatted)}
        
        elif action == "bulk_set":
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
            
            return {"ok": True, "set_count": set_count, "error_count": len(errors), "errors": errors[:10] if errors else None}
        
        elif action == "export_md":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            
            path, err = validate_path_safe(path)
            if err: return err
            
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
                    
                    # Get inline comments
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        curr = func.start_ea
                        while curr < func.end_ea:
                            cmt = idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1)
                            if cmt:
                                func_comments.append(f"- `{hex(curr)}`: {cmt}")
                                count += 1
                            curr = idc.next_head(curr, func.end_ea)
                            if curr == idaapi.BADADDR: break
                    
                    if func_comments:
                        lines.append(f"## {func_name} (`{hex(func_ea)}`)\n\n")
                        lines.extend([c + "\n" for c in func_comments])
                        lines.append("\n")
                    _func_count += 1
                    if _func_count >= _func_limit:
                        break
                if _func_count >= _func_limit:
                    break
            
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            return {"ok": True, "exported": True, "path": path, "comment_count": count}
        
        elif action == "import_md":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            
            path, err = validate_path_safe(path)
            if err: return err
            
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, path)
            
            import re
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse markdown for comments
            imported = 0
            errors = []
            
            # Look for patterns like `0x12345`: comment
            pattern = r'`(0x[0-9a-fA-F]+)`:\s*(.+?)(?:\n|$)'
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
        
        elif action == "summary":
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
                    
                    # Count inline comments
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        curr = func.start_ea
                        while curr < func.end_ea:
                            if idc.get_cmt(curr, 0) or idc.get_cmt(curr, 1):
                                inline_comments += 1
                            curr = idc.next_head(curr, func.end_ea)
                            if curr == idaapi.BADADDR: break
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
                "avg_comments_per_func": round(inline_comments / total, 2) if total else 0
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 34. NAV - Navigation Helpers
# ============================================================================
