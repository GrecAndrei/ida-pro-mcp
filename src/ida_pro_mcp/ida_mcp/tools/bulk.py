
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 20. BULK - Bulk operations for LLMs (multi-target rename/comment/type)
# ============================================================================

@tool
@unsafe
@idawrite
def bulk(
    action: Annotated[Literal["rename", "comment", "apply_type", "rename_stack", "import_annotations", "export_annotations"],
                      "Action: rename|comment|apply_type|rename_stack|import_annotations|export_annotations"],
    items: Annotated[Optional[list[dict]], "List of {addr, value} dicts for bulk operations"] = None,
    path: Annotated[Optional[str], "File path for import/export"] = None,
    continue_on_error: Annotated[bool, "Continue processing after errors"] = True,
    **kwargs
) -> dict:
    """
    Bulk operations for efficient multi-target modifications.

    ACTIONS:

    rename - Bulk rename items
        Params: items (list of {addr, value/name})
        Returns: {success, failed, errors}
        Example: [{"addr": "0x401000", "value": "main"}, {"addr": "0x401100", "name": "init_crypto"}]

    comment - Bulk add comments
        Params: items (list of {addr, value/text, type?})
        Returns: {success, failed}
        Example: [{"addr": "0x401000", "text": "Entry point", "type": "repeatable"}]

    apply_type - Bulk apply type declarations
        Params: items (list of {addr, value/type})
        Returns: {success, failed, errors}
        Example: [{"addr": "0x401000", "type": "int __cdecl(int, char **)"}]

    rename_stack - Bulk rename stack variables
        Params: items (list of {addr, old, new})
        Returns: {success, failed}
        Example: [{"addr": "0x401000", "old": "var_8", "new": "buffer"}]

    import_annotations - Load names/comments from JSON
        Params: path
        Returns: {names, comments}

    export_annotations - Save annotations to JSON
        Params: path (optional - returns data if not provided)
        Returns: {path?, counts} or {annotations}
    """
    try:
        if action == "rename":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"))
                    if err:
                        failed.append({"addr": item.get("addr"), "error": "Invalid address"})
                        if not continue_on_error:
                            break
                        continue
                    # Support both 'value' and 'name' keys
                    new_name = item.get("value") or item.get("name")
                    if not new_name:
                        failed.append({"addr": hex(ea), "error": "No name provided"})
                        if not continue_on_error:
                            break
                        continue
                    if idc.set_name(ea, new_name, ida_name.SN_FORCE | ida_name.SN_NOWARN):
                        success += 1
                    else:
                        failed.append({"addr": hex(ea), "name": new_name, "error": "set_name failed"})
                        if not continue_on_error:
                            break
                except Exception as e:
                    failed.append({"addr": item.get("addr"), "error": str(e)})
                    if not continue_on_error:
                        break
            return {"ok": True, "success": success, "failed": len(failed), "errors": failed[:20]}

        elif action == "comment":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"))
                    if err:
                        failed.append({"addr": item.get("addr"), "error": "Invalid address"})
                        if not continue_on_error:
                            break
                        continue
                    # Support both 'value' and 'text' keys
                    comment_text = item.get("value") or item.get("text")
                    if not comment_text:
                        failed.append({"addr": hex(ea), "error": "No comment text provided"})
                        if not continue_on_error:
                            break
                        continue
                    cmt_type = item.get("type", "regular")
                    if cmt_type == "repeatable":
                        idc.set_cmt(ea, comment_text, 1)
                    elif cmt_type == "func":
                        idc.set_func_cmt(ea, comment_text, 0)
                    elif cmt_type == "func_repeatable":
                        idc.set_func_cmt(ea, comment_text, 1)
                    else:
                        idc.set_cmt(ea, comment_text, 0)
                    success += 1
                except Exception as e:
                    failed.append({"addr": item.get("addr"), "error": str(e)})
                    if not continue_on_error:
                        break
            return {"ok": True, "success": success, "failed": len(failed), "errors": failed[:20] if failed else None}

        elif action == "apply_type":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"))
                    if err:
                        failed.append({"addr": item.get("addr"), "error": "Invalid address"})
                        if not continue_on_error:
                            break
                        continue
                    # Support both 'value' and 'type' keys
                    type_str = item.get("value") or item.get("type")
                    if not type_str:
                        failed.append({"addr": hex(ea), "error": "No type provided"})
                        if not continue_on_error:
                            break
                        continue

                    tif = ida_typeinf.tinfo_t()
                    if not ida_typeinf.parse_decl(tif, None, type_str, ida_typeinf.PT_SIL):
                        failed.append({"addr": hex(ea), "type": type_str, "error": "Failed to parse type"})
                        if not continue_on_error:
                            break
                        continue

                    if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                        success += 1
                    else:
                        failed.append({"addr": hex(ea), "type": type_str, "error": "Failed to apply type"})
                        if not continue_on_error:
                            break
                except Exception as e:
                    failed.append({"addr": item.get("addr"), "error": str(e)})
                    if not continue_on_error:
                        break
            return {"ok": True, "success": success, "failed": len(failed), "errors": failed[:20] if failed else None}

        elif action == "rename_stack":
            if not items: return make_error(MCPError.INVALID_ARGS, "items required")
            success, failed = 0, []
            for item in items:
                try:
                    ea, err = validate_addr(item.get("addr"), require_func=True)
                    if err:
                        failed.append({"addr": item.get("addr"), "error": "Invalid address or not in function"})
                        if not continue_on_error:
                            break
                        continue
                    old_name = item.get("old")
                    new_name = item.get("new")
                    if not old_name or not new_name:
                        failed.append({"addr": hex(ea), "error": "Both 'old' and 'new' required"})
                        if not continue_on_error:
                            break
                        continue

                    # Get function and frame
                    func = ida_funcs.get_func(ea)
                    if not func:
                        failed.append({"addr": hex(ea), "error": "No function at address"})
                        if not continue_on_error:
                            break
                        continue

                    frame = ida_frame.get_frame(func)
                    if not frame:
                        failed.append({"addr": hex(ea), "error": "No frame for function"})
                        if not continue_on_error:
                            break
                        continue

                    # Iterate frame members by index using get_member_by_id
                    renamed = False
                    for idx in range(frame.memqty):
                        try:
                            member = ida_struct.get_member(frame, idx)
                            if not member:
                                continue
                            mname = ida_struct.get_member_name(member.id) or ""
                            if mname == old_name:
                                if ida_struct.set_member_name(frame, member.soff, new_name):
                                    renamed = True
                                    success += 1
                                break
                        except Exception:
                            break

                    if not renamed:
                        failed.append({"addr": hex(ea), "var": old_name, "error": "Variable not found or rename failed"})
                        if not continue_on_error:
                            break
                except Exception as e:
                    failed.append({"addr": item.get("addr"), "error": str(e)})
                    if not continue_on_error:
                        break
            return {"ok": True, "success": success, "failed": len(failed), "errors": failed[:20] if failed else None}

        elif action == "export_annotations":
            annotations = {"names": [], "comments": [], "types": []}
            MAX_NAMES = 5000
            MAX_HEADS = 20000
            MAX_FUNCS = 5000

            # Export names (excluding auto-generated)
            for ea, name in idautils.Names():
                if len(annotations["names"]) >= MAX_NAMES:
                    break
                if not name.startswith(("sub_", "loc_", "unk_", "off_", "byte_", "word_", "dword_", "qword_")):
                    entry = {"addr": hex(ea), "name": name}
                    # Also export type if available
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, ea):
                        entry["type"] = str(tif)
                    annotations["names"].append(entry)

            # Export comments
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                heads_seen = 0
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    heads_seen += 1
                    if heads_seen > MAX_HEADS:
                        break
                    cmt = idc.get_cmt(head, 0)
                    cmt_rep = idc.get_cmt(head, 1)
                    if cmt:
                        annotations["comments"].append({"addr": hex(head), "comment": cmt, "type": "regular"})
                    if cmt_rep:
                        annotations["comments"].append({"addr": hex(head), "comment": cmt_rep, "type": "repeatable"})

            # Export function comments
            funcs_seen = 0
            for func_ea in idautils.Functions():
                funcs_seen += 1
                if funcs_seen > MAX_FUNCS:
                    break
                func_cmt = idc.get_func_cmt(func_ea, 0)
                func_cmt_rep = idc.get_func_cmt(func_ea, 1)
                if func_cmt:
                    annotations["comments"].append({"addr": hex(func_ea), "comment": func_cmt, "type": "func"})
                if func_cmt_rep:
                    annotations["comments"].append({"addr": hex(func_ea), "comment": func_cmt_rep, "type": "func_repeatable"})

            if path:
                path, err = validate_path_safe(path)
                if err: return err
                import json
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(annotations, f, indent=2)
                return {"ok": True, "path": path, "counts": {k: len(v) for k, v in annotations.items()}}
            return {"ok": True, "annotations": annotations, "counts": {k: len(v) for k, v in annotations.items()}}

        elif action == "import_annotations":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            if not os.path.exists(path): return make_error(MCPError.FILE_NOT_FOUND, path)
            import json
            with open(path, encoding='utf-8') as f:
                data = json.load(f)

            n_applied, c_applied, t_applied = 0, 0, 0
            errors = []

            MAX_IMPORT_ITEMS = 5000

            # Import names
            for item in data.get("names", [])[:MAX_IMPORT_ITEMS]:
                try:
                    ea = parse_address(item["addr"])
                    if idc.set_name(ea, item["name"], ida_name.SN_FORCE | ida_name.SN_NOWARN):
                        n_applied += 1
                    # Also apply type if present
                    if "type" in item:
                        tif = ida_typeinf.tinfo_t()
                        if ida_typeinf.parse_decl(tif, None, item["type"], ida_typeinf.PT_SIL):
                            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                                t_applied += 1
                except Exception as e:
                    errors.append({"addr": item.get("addr"), "error": str(e)})

            # Import comments
            for item in data.get("comments", [])[:MAX_IMPORT_ITEMS]:
                try:
                    ea = parse_address(item["addr"])
                    cmt_type = item.get("type", "regular")
                    cmt_text = item["comment"]

                    if cmt_type == "func":
                        idc.set_func_cmt(ea, cmt_text, 0)
                    elif cmt_type == "func_repeatable":
                        idc.set_func_cmt(ea, cmt_text, 1)
                    elif cmt_type == "repeatable":
                        idc.set_cmt(ea, cmt_text, 1)
                    else:
                        idc.set_cmt(ea, cmt_text, 0)
                    c_applied += 1
                except Exception as e:
                    errors.append({"addr": item.get("addr"), "error": str(e)})

            return {"ok": True, "names": n_applied, "comments": c_applied, "types": t_applied,
                    "errors": len(errors), "error_samples": errors[:10] if errors else None}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 21. CTREE - Hex-Rays AST/CTree Access for Deep Decompiler Analysis
# ============================================================================
