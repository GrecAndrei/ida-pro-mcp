
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 23. LUMINA - Cloud-Based Function Recognition
# ============================================================================

@tool
@idaread
def lumina(
    action: Annotated[Literal["pull", "push", "status", "history", "search", "get_metadata"],
                      "Action: pull|push|status|history|search|get_metadata"],
    addr: Annotated[Optional[str], "Address of function"] = None,
    query: Annotated[Optional[str], "Search query for function names"] = None,
    push_all: Annotated[bool, "Push all functions (for push action)"] = False,
    limit: Annotated[int, "Max results for search"] = 50,
    offset: Annotated[int, "Search pagination offset"] = 0,
    include_items: Annotated[bool, "Include structured search items"] = False,
    **kwargs
) -> dict:
    """
    Interact with Hex-Rays Lumina server for function recognition.

    Actions:
    - pull: Get metadata from Lumina.
    - push: Contribute metadata to Lumina.
    - status: Check connection and authentication.
    - history: Get history for a specific function.
    - search: Search the cloud by name.
    """
    try:
        def action_available(action_name):
            try:
                return ida_kernwin.find_action(action_name) is not None
            except Exception:
                return False

        def run_action(action_name, note=None):
            if not action_available(action_name):
                payload = {
                    "ok": True,
                    "action": action_name,
                    "action_available": False,
                    "action_triggered": False,
                    "note": "Lumina UI action is unavailable in this IDA build/runtime.",
                }
                if note:
                    payload["requested_note"] = note
                return payload
            res = ida_kernwin.process_ui_action(action_name)
            payload = {"ok": True, "action": action_name, "action_triggered": res}
            if note:
                payload["note"] = note
            return payload

        if action == "status":
            actions = [
                "LuminaPull",
                "LuminaPullAll",
                "LuminaPush",
                "LuminaPushAll",
                "LuminaViewHistory",
            ]
            availability = {a: action_available(a) for a in actions}
            details = {"actions": availability}
            try:
                import ida_lumina
                details["module_loaded"] = True
                for attr in ["is_inited", "is_connected", "get_lumina_server"]:
                    if hasattr(ida_lumina, attr):
                        try:
                            details[attr] = getattr(ida_lumina, attr)()
                        except Exception:
                            details[attr] = None
            except Exception:
                details["module_loaded"] = False
            return {"ok": True, "status": "Lumina actions inspected", "details": details}

        elif action == "pull":
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                idc.jumpto(ea)
                return run_action("LuminaPull", note="Pulled metadata for current function")
            return run_action("LuminaPullAll", note="Pulled metadata for all functions")

        elif action == "push":
            if push_all:
                return run_action("LuminaPushAll", note="Pushed metadata for all functions")
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err: return err
                idc.jumpto(ea)
                return run_action("LuminaPush", note="Pushed metadata for current function")
            return make_error(MCPError.INVALID_ARGS, "addr or push_all=True required")

        elif action == "history":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr, require_func=True)
            if err: return err
            idc.jumpto(ea)
            return run_action("LuminaViewHistory", note="Opened Lumina history for current function")

        elif action == "search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            try:
                matcher = compile_smart_pattern(query, case_sensitive=False)
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"Invalid search query: {e}")

            try:
                limit = max(1, min(500, int(limit)))
            except Exception:
                limit = 50
            try:
                offset = max(0, int(offset))
            except Exception:
                offset = 0

            records = []
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea) or ""
                if not matcher(name):
                    continue
                fn = ida_funcs.get_func(func_ea)
                size = (fn.end_ea - fn.start_ea) if fn else 0
                meta = {
                    "addr": hex_ea(func_ea),
                    "name": name or f"sub_{func_ea:x}",
                    "size": hex_size(size),
                    "is_named": not name.startswith("sub_") if name else False,
                }
                records.append(meta)

            records.sort(key=lambda r: (not r["is_named"], r["name"], r["addr"]))
            total = len(records)
            page = records[offset : offset + limit]
            truncated = (offset + len(page)) < total
            lines = [
                f'{r["addr"]}  {r["name"]}  size={r["size"]}  named={1 if r["is_named"] else 0}'
                for r in page
            ]
            result = {
                "ok": True,
                "query": query,
                "matches": "\n".join(lines),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": truncated,
                "source": "local_function_index",
                "note": "Local searchable fallback. Direct Lumina cloud search is unavailable via stable API in this runtime.",
            }
            if include_items:
                result["items"] = page
            return result
        
        elif action == "get_metadata":
            # Try to get Lumina metadata for a function programmatically
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            
            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(ea)
            
            result = {
                "ok": True,
                "addr": hex(ea),
                "current_name": func_name,
                "has_lumina_name": False,
                "lumina_available": False
            }
            
            try:
                import ida_lumina
                result["lumina_available"] = True
                
                # Check if ida_lumina has the APIs we need
                if hasattr(ida_lumina, 'is_inited') and ida_lumina.is_inited():
                    result["lumina_initialized"] = True
                    
                    # Try to get function info from Lumina
                    # The API varies by IDA version
                    if hasattr(ida_lumina, 'get_func_info'):
                        try:
                            info = ida_lumina.get_func_info(ea)
                            if info:
                                result["lumina_info"] = {
                                    "name": getattr(info, 'name', None),
                                    "popularity": getattr(info, 'popularity', None),
                                }
                                if info.name and info.name != func_name:
                                    result["has_lumina_name"] = True
                                    result["lumina_name"] = info.name
                        except Exception as e:
                            result["get_info_error"] = str(e)
                    
                    # Alternative: Check if function was renamed by Lumina
                    # Functions from Lumina often have specific characteristics
                    if hasattr(ida_lumina, 'is_func_from_lumina'):
                        try:
                            result["is_from_lumina"] = ida_lumina.is_func_from_lumina(ea)
                        except Exception:
                            pass
                else:
                    result["lumina_initialized"] = False
                    result["note"] = "Lumina not initialized - check Tools > Lumina > Options"
                    
            except ImportError:
                result["lumina_available"] = False
                result["note"] = "ida_lumina module not available in this IDA version"
            except Exception as e:
                result["error"] = str(e)
            
            # Provide alternative: check if name looks like it came from Lumina
            # Lumina names often follow certain patterns
            if func_name and not func_name.startswith("sub_"):
                # Check for common patterns that suggest external source
                result["name_analysis"] = {
                    "has_real_name": True,
                    "is_library_func": bool(func.flags & ida_funcs.FUNC_LIB),
                    "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
                    "name_source": "unknown"
                }
                if result["name_analysis"]["is_library_func"]:
                    result["name_analysis"]["name_source"] = "FLIRT/library"
                elif result.get("is_from_lumina"):
                    result["name_analysis"]["name_source"] = "Lumina"
            
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================  
# 24. SYMBOLS - Debug Symbol Loading (PDB, DWARF, COFF)
# ============================================================================
