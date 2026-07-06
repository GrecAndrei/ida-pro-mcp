
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .governance_engine import evaluate_operation
except ImportError:
    from governance_engine import evaluate_operation  # type: ignore[import-not-found]

import hashlib

# ============================================================================
# 7. MODIFY - Rename, comments, set type
# ============================================================================

def _gather_governance_metadata(action: str, ea: int, value: str) -> dict:
    """Gather IDA-specific metadata for governance checks."""
    metadata: dict = {}

    if action == "patch_asm":
        # Check if address is in import/plt section
        seg = ida_segment.getseg(ea)
        if seg:
            sname = ida_segment.get_segm_name(seg)
            metadata["section_type"] = sname or ""
            metadata["is_import_addr"] = sname in (".idata", ".plt", ".edata", ".iat")

    elif action == "rename":
        fn = ida_funcs.get_func(ea)
        if fn:
            metadata["is_library_function"] = (fn.flags & ida_funcs.FUNC_LIB) != 0
            metadata["is_flirt_identified"] = (fn.flags & ida_funcs.FUNC_THUNK) != 0
            # Gather API calls for misleading rename check
            api_calls = []
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                for xref in idautils.CodeRefsFrom(head, 0):
                    callee = idc.get_func_name(xref) or ""
                    if callee:
                        api_calls.append(callee)
            metadata["api_calls"] = ", ".join(api_calls)
            # Get argument count for main() signature check
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, ea):
                fi = idaapi.func_type_data_t()
                if tif.get_func_details(fi):
                    metadata["arg_count"] = fi.size()

    elif action == "set_type":
        fn = ida_funcs.get_func(ea)
        if fn:
            metadata["targets_stack"] = True
            # Heuristic: if the type string mentions frame size changes
            metadata["changes_frame_size"] = "__frame" in value or "__sp" in value

    return metadata


def _persist_symbol_knowledge(func_ea: int, name: str) -> None:
    """Persist a rename event to cross-session symbol DB."""
    if not name or name.startswith("sub_"):
        return
    try:
        from ida_pro_mcp.services import SymbolDB
    except Exception:
        try:
            from host.symbol_db import SymbolDB  # type: ignore
        except Exception:
            return
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return
    callers = sorted({ida_funcs.get_func(x).start_ea for x in idautils.CodeRefsTo(fn.start_ea, 0) if ida_funcs.get_func(x)})
    callees = set()
    for item_ea in idautils.FuncItems(fn.start_ea):
        for ref in idautils.CodeRefsFrom(item_ea, 0):
            cf = ida_funcs.get_func(ref)
            if cf and cf.start_ea != fn.start_ea:
                callees.add(cf.start_ea)
    strs = []
    for item_ea in idautils.FuncItems(fn.start_ea):
        for ref in idautils.DataRefsFrom(item_ea):
            s = idc.get_strlit_contents(ref, -1, idc.STRTYPE_C)
            if not s:
                continue
            txt = s.decode(errors="ignore").strip()
            if txt and txt not in strs:
                strs.append(txt[:120])
            if len(strs) >= 24:
                break
        if len(strs) >= 24:
            break
    graph = "|".join([f"c:{hex(x)}" for x in callers[:32]] + [f"d:{hex(x)}" for x in sorted(callees)[:64]])
    fingerprint = hashlib.sha1((graph + "||" + "|".join(sorted(strs)[:32])).encode("utf-8")).hexdigest()
    callgraph_hash = hashlib.sha1(graph.encode("utf-8")).hexdigest()
    try:
        SymbolDB().upsert_symbol(
            {
                "symbol_name": name,
                "source_binary": idc.get_idb_path() or "",
                "source_addr": hex(fn.start_ea),
                "fingerprint": fingerprint,
                "callgraph_hash": callgraph_hash,
                "strings": strs,
                "confidence": 1.0,
            }
        )
    except Exception:
        return


@tool
@idawrite
def modify(
    action: Annotated[Literal["rename", "comment", "set_type", "patch_asm"],
                      "Action: rename|comment|set_type|patch_asm"],
    addr: Annotated[str, "Address"],
    value: Annotated[Optional[str], "New name, comment text, type declaration, or assembly instruction(s)"] = None,
    # Aliases for compatibility
    name: Annotated[Optional[str], "Alias for value (when action=rename)"] = None,
    text: Annotated[Optional[str], "Alias for value (when action=comment)"] = None,
    type_str: Annotated[Optional[str], "Alias for value (when action=set_type)"] = None,
    asm: Annotated[Optional[str], "Alias for value (when action=patch_asm)"] = None,
    comment_type: Annotated[Literal["regular", "repeatable", "anterior", "posterior"],
                            "Comment type (for action=comment)"] = "regular",
    governed: Annotated[bool, "Enable deterministic governance pre-check"] = True,
    **kwargs
) -> dict:
    """
    Modify the database: renaming, commenting, types, and assembly patching.

    Actions:
    - rename: Change the name of a function, label, or data item at `addr`.
    - comment: Add a comment. Supports regular, repeatable, anterior (above), posterior (below).
    - set_type: Apply a type declaration to `addr` (similar to types.apply).
    - patch_asm: Assemble and patch instructions at `addr`.
      Supports single instructions (e.g. "mov eax, 1") or multiple instructions
      separated by semicolons (e.g. "nop; nop; nop" or "push ebp; mov ebp, esp").
      Each instruction is assembled and patched sequentially at consecutive addresses.

    Arguments:
    - value (or name/text/type_str/asm): The content to apply.
    - comment_type: One of 'regular', 'repeatable', 'anterior', 'posterior'.
    - governed: If True (default), run governance pre-check before
      committing. Blocks dangerous patches, redacts PII, warns on misleading
      renames. Set to False to bypass (not recommended).
    """
    try:
        # Support multiple parameter names for compatibility
        if not value:
            if action == "rename" and name:
                value = name
            elif action == "comment" and text:
                value = text
            elif action == "comment" and kwargs.get("comment"):
                value = kwargs["comment"]
            elif action == "set_type" and type_str:
                value = type_str
            elif action == "patch_asm" and asm:
                value = asm

        if not value:
            return make_error(MCPError.INVALID_ARGS, f"value parameter required (or use {action}-specific alias: name/text/type_str/asm)")

        ea, error = validate_addr(addr)
        if error:
            return error

        # ----------------------------------------------------------------
        # Governance pre-check
        # ----------------------------------------------------------------
        if governed:
            op_type_map = {
                "rename": "rename",
                "comment": "comment",
                "set_type": "type_change",
                "patch_asm": "patch",
            }
            op_type = op_type_map.get(action)
            if op_type:
                metadata = _gather_governance_metadata(action, ea, value)
                gov_result = evaluate_operation(
                    operation_type=op_type,
                    addr=ea,
                    proposed_value=value,
                    context={"tool": "modify", "action": action, "comment_type": comment_type},
                    metadata=metadata,
                )

                if not gov_result["approved"]:
                    return make_error(
                        MCPError.GOVERNANCE_BLOCKED,
                        f"Governance blocked {action}: {gov_result['verdict']}",
                        {
                            "violations": gov_result["violations"],
                            "ontology_class": gov_result.get("ontology_class"),
                            "axiom_score": gov_result.get("axiom_score"),
                        }
                    )

                # Apply redactions if content was modified
                redacted = gov_result.get("redacted_content")
                if redacted and redacted != value:
                    value = redacted
                    # Update aliases so downstream code sees redacted value
                    if action == "rename":
                        name = value
                    elif action == "comment":
                        text = value
                    elif action == "set_type":
                        type_str = value
                    elif action == "patch_asm":
                        asm = value

                # Include warnings in response (non-blocking)
                gov_warnings = gov_result.get("warnings", [])
            else:
                gov_warnings = []
        else:
            gov_warnings = []

        if action == "rename":
            if idc.set_name(ea, value, ida_name.SN_FORCE):
                result = {"ok": True, "addr": addr, "name": value}
                if gov_warnings:
                    result["governance_warnings"] = gov_warnings
                # Decompiler feedback loop: re-embed this function and propagate
                # semantic understanding to callees in the background.
                _trigger_rename_propagation(ea, value)
                _persist_symbol_knowledge(ea, value)
                return result
            return make_error(MCPError.IDA_ERROR, "Failed to rename", "Check if name is valid C identifier and not duplicate")

        elif action == "comment":
            if comment_type == "regular":
                idc.set_cmt(ea, value, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, value, 1)
            else:
                # Anterior/Posterior
                import ida_lines
                is_anterior = (comment_type == "anterior")
                if hasattr(ida_lines, "add_extra_cmt"):
                    ida_lines.add_extra_cmt(ea, is_anterior, value)
                else:
                    # Fallback: preserve intent in regular comment channel.
                    prefix = "[anterior] " if is_anterior else "[posterior] "
                    existing = idc.get_cmt(ea, 0) or ""
                    merged = (existing + "\n" if existing else "") + prefix + value
                    idc.set_cmt(ea, merged, 0)
            result = {"ok": True, "addr": addr, "comment_type": comment_type, "comment": value}
            if gov_warnings:
                result["governance_warnings"] = gov_warnings
            return result

        elif action == "set_type":
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, value, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse type: {value}", "Check C declaration syntax")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                result = {"ok": True, "addr": addr, "type": str(tif)}
                if gov_warnings:
                    result["governance_warnings"] = gov_warnings
                return result
            return make_error(MCPError.IDA_ERROR, "Failed to apply type", "Check if type is compatible with address")

        elif action == "patch_asm":
            # Assemble and patch - supports multiple instructions separated by semicolons
            import ida_idp

            # Split multiple instructions by semicolons
            instructions = [inst.strip() for inst in value.split(";") if inst.strip()]
            if not instructions:
                return make_error(MCPError.INVALID_ARGS, "No valid instructions provided")

            current_ea = ea
            total_size = 0
            patched = []

            for inst in instructions:
                # IDA assemble API
                res = ida_idp.assemble(current_ea, 0, current_ea, True, inst)
                if isinstance(res, tuple):
                    success, code = res
                else:
                    # Fallback for older IDA versions
                    success = res is not None and res not in {b'', 0}
                    code = res

                if not success or not code:
                    hint = f"Check instruction syntax for your target architecture. Failed at instruction: '{inst}'"
                    if patched:
                        hint += f". Note: {len(patched)} instruction(s) were already patched before this failure."
                    return make_error(
                        MCPError.IDA_ERROR,
                        f"Failed to assemble: '{inst}' at {hex(current_ea)}",
                        hint,
                    )

                code_bytes = bytes(code)
                ida_bytes.patch_bytes(current_ea, code_bytes)
                patched.append({"addr": hex(current_ea), "size": len(code_bytes), "asm": inst})
                current_ea += len(code_bytes)
                total_size += len(code_bytes)

            if len(patched) == 1:
                result = {"ok": True, "addr": addr, "size": total_size, "asm": instructions[0]}
            else:
                result = {"ok": True, "addr": addr, "total_size": total_size, "instructions": patched, "count": len(patched)}
            if gov_warnings:
                result["governance_warnings"] = gov_warnings
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _trigger_rename_propagation(func_ea: int, new_name: str) -> None:
    """
    Decompiler feedback loop: after a rename, re-embed the function and
    propagate semantic understanding to its callees.

    Algorithm:
      1. Re-decompile and re-embed the renamed function (now has a meaningful name)
      2. Find all callees (functions this one calls)
      3. For each unnamed callee, check if the new embedding suggests a name
         (cosine similarity against the updated index)
      4. Write propagation suggestions to the blackboard for the LLM to review

    Runs in a background thread — never blocks the rename response.
    """
    import threading

    def _propagate():
        try:
            from ida_pro_mcp.services import BgeCodeEmbedder, FunctionEmbeddingIndex  # noqa: F401
        except ImportError:
            try:
                from host.intelligence.core import (  # type: ignore
                    BgeCodeEmbedder,
                    FunctionEmbeddingIndex,
                )
            except ImportError:
                return
        try:
            import ida_funcs as _ida_funcs
            import ida_hexrays as _ida_hexrays
            import idautils as _idautils
            import idc as _idc

            idb_path = _idc.get_idb_path() or ""
            if not idb_path:
                return

            embedder = BgeCodeEmbedder()
            idx = FunctionEmbeddingIndex(idb_path + ".embeddings.db", embedder)

            # Step 1: Re-embed the renamed function
            pseudo = None
            try:
                cfunc = _ida_hexrays.decompile(func_ea)
                if cfunc:
                    pseudo = str(cfunc)
            except Exception:
                pass
            if pseudo:
                idx.index(hex(func_ea), new_name, pseudo)

            # Step 2: Find callees
            callees = []
            for item in _idautils.FuncItems(func_ea):
                for xref in _idautils.XrefsFrom(item, 0):
                    if xref.type in (17, 18):  # fl_CF, fl_CN
                        callee_fn = _ida_funcs.get_func(xref.to)
                        if callee_fn and callee_fn.start_ea != func_ea:
                            callees.append(callee_fn.start_ea)

            if not callees or not pseudo:
                return

            # Skip similarity if index is empty
            if idx.size == 0:
                _result["embedding_suggestions"] = []
                _result["embedding_note"] = "No index — run intelligence(action='index_fast') for rename suggestions."
                return

            # Step 3: For each unnamed callee, check embedding similarity
            suggestions = []
            for callee_ea in set(callees[:20]):
                callee_name = _idc.get_func_name(callee_ea) or ""
                if not callee_name.startswith("sub_"):
                    continue  # already named
                callee_pseudo = None
                try:
                    cfunc = _ida_hexrays.decompile(callee_ea)
                    if cfunc:
                        callee_pseudo = str(cfunc)
                except Exception:
                    pass
                if not callee_pseudo:
                    continue
                similar = idx.similar(callee_pseudo, top_k=8, exclude_ea=hex(callee_ea), threshold=0.0)
                named = [s for s in similar if not s["name"].startswith("sub_") and not s["name"].startswith("0x")]
                if named:
                    vals = sorted(float(s.get("similarity", 0.0) or 0.0) for s in named)
                    q50 = vals[len(vals) // 2]
                    q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
                    gate = q50 + max(0.0, q75 - q50)
                    named = [s for s in named if float(s.get("similarity", 0.0) or 0.0) >= gate]
                if named:
                    suggestions.append({
                        "callee_addr": hex(callee_ea),
                        "callee_current": callee_name,
                        "suggested_name": named[0]["name"],
                        "confidence": named[0]["similarity"],
                        "reason": f"callee of {new_name}, similar to {named[0]['name']}",
                    })

            # Step 4: Write propagation suggestions to blackboard
            if suggestions:
                try:
                    from ida_pro_mcp.ida_mcp.tools.blackboard import BlackboardStore
                except ImportError:
                    try:
                        from blackboard import BlackboardStore  # type: ignore
                    except ImportError:
                        return
                store = BlackboardStore()
                for s in suggestions:
                    store.write(
                        title=f"Rename suggestion: {s['callee_addr']} → {s['suggested_name']}",
                        content=f"Callee of {new_name}. Confidence: {s['confidence']:.2f}. {s['reason']}",
                        category="rename_suggestion",
                        addr=s["callee_addr"],
                        tags=["auto", "propagation", "rename"],
                        confidence=s["confidence"],
                        source="rename_propagation",
                    )
        except Exception:
            pass

    threading.Thread(target=_propagate, daemon=True, name="rename-propagation").start()


# ============================================================================
# 8. MISC - Python exec, signatures, bookmarks, undo, stack
# ============================================================================
