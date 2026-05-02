
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .cybercane import evaluate_operation
except ImportError:
    from cybercane import evaluate_operation  # type: ignore[import-not-found]

try:
    from .memrl import emit_memrl_suggestion, REWARD_ACCEPT, REWARD_PARTIAL, REWARD_REJECT
except ImportError:
    try:
        from memrl import emit_memrl_suggestion, REWARD_ACCEPT, REWARD_PARTIAL, REWARD_REJECT  # type: ignore[import-not-found]
    except ImportError:
        # No-op fallback if MemRL not available
        def emit_memrl_suggestion(*args, **kwargs):  # type: ignore
            return ""
        REWARD_ACCEPT = 1.0
        REWARD_PARTIAL = 0.5
        REWARD_REJECT = -0.5


# ============================================================================
# 7. MODIFY - Rename, comments, set type
# ============================================================================

def _gather_governance_metadata(action: str, ea: int, value: str) -> dict:
    """Gather IDA-specific metadata for CyberCane governance checks."""
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


# ---------------------------------------------------------------------------
# MemRL feedback helper
# ---------------------------------------------------------------------------

def _apply_memrl_feedback(suggestion_id: str, feedback_type: str) -> dict:
    """Apply a feedback signal to a MemRL suggestion.

    Maps human-readable feedback types to reward values:

        'accept'  -> +1.0
        'partial' -> +0.5
        'skip'    ->  0.0
        'reject'  -> -0.5

    Uses the MemRLBank directly. Returns {"ok": True/False, ...}.
    """
    reward_map = {
        "accept": REWARD_ACCEPT,
        "partial": REWARD_PARTIAL,
        "reject": REWARD_REJECT,
        "skip": 0.0,
    }
    reward = reward_map.get(feedback_type)
    if reward is None:
        return {"ok": False, "error": f"Unknown feedback type: {feedback_type}"}

    try:
        from .memrl import MemRLBank
    except ImportError:
        try:
            from memrl import MemRLBank  # type: ignore[import-not-found]
        except ImportError:
            return {"ok": False, "error": "MemRLBank not available"}

    bank = MemRLBank()
    return bank.process_feedback(suggestion_id, reward)


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
    governed: Annotated[bool, "Enable CyberCane neuro-symbolic governance pre-check"] = True,
    feedback: Annotated[Optional[Literal["accept", "reject", "partial", "skip"]],
                         "Optional feedback signal to MemRL after this operation"] = None,
    memrl_suggestion_id: Annotated[Optional[str],
                                    "Suggestion ID from a prior MemRL ingest for feedback attribution"] = None,
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
    - governed: If True (default), run CyberCane governance pre-check before
      committing. Blocks dangerous patches, redacts PII, warns on misleading
      renames. Set to False to bypass (not recommended).
    - feedback: Optional feedback signal to MemRL:
        'accept' = +1.0 (analyst accepted suggestion)
        'partial' = +0.5 (analyst made minor edits)
        'reject' = -0.5 (analyst rejected suggestion)
        'skip' = 0.0 (suggestion ignored)
    - memrl_suggestion_id: If provided, the feedback is applied to this
      specific MemRL suggestion instead of creating a new one.
    """
    try:
        # Support multiple parameter names for compatibility
        if not value:
            if action == "rename" and name:
                value = name
            elif action == "comment" and text:
                value = text
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
        # CyberCane Governance Pre-Check
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
                        f"CyberCane blocked {action}: {gov_result['verdict']}",
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
                # Auto-ingest suggestion to MemRL
                try:
                    sug_id = emit_memrl_suggestion(
                        "modify", "rename", addr, value
                    )
                    if sug_id:
                        result["memrl_suggestion_id"] = sug_id
                except Exception:
                    pass
                # Apply explicit feedback if provided
                if feedback and memrl_suggestion_id:
                    _apply_memrl_feedback(memrl_suggestion_id, feedback)
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
            # Auto-ingest suggestion to MemRL
            try:
                sug_id = emit_memrl_suggestion(
                    "modify", "comment", addr, value
                )
                if sug_id:
                    result["memrl_suggestion_id"] = sug_id
            except Exception:
                pass
            # Apply explicit feedback if provided
            if feedback and memrl_suggestion_id:
                _apply_memrl_feedback(memrl_suggestion_id, feedback)
            return result

        elif action == "set_type":
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, value, ida_typeinf.PT_SIL):
                return make_error(MCPError.TYPE_ERROR, f"Failed to parse type: {value}", "Check C declaration syntax")
            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                result = {"ok": True, "addr": addr, "type": str(tif)}
                if gov_warnings:
                    result["governance_warnings"] = gov_warnings
                # Auto-ingest suggestion to MemRL
                try:
                    sug_id = emit_memrl_suggestion(
                        "modify", "set_type", addr, value
                    )
                    if sug_id:
                        result["memrl_suggestion_id"] = sug_id
                except Exception:
                    pass
                # Apply explicit feedback if provided
                if feedback and memrl_suggestion_id:
                    _apply_memrl_feedback(memrl_suggestion_id, feedback)
                return result
            return make_error(MCPError.IDA_ERROR, "Failed to apply type", "Check if type is compatible with address")

        elif action == "patch_asm":
            # Assemble and patch - supports multiple instructions separated by semicolons
            import ida_idp
            import ida_ua

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
                    success = res is not None and res != b'' and res != 0
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
            # Auto-ingest suggestion to MemRL
            try:
                sug_id = emit_memrl_suggestion(
                    "modify", "patch_asm", addr, "; ".join(instructions)
                )
                if sug_id:
                    result["memrl_suggestion_id"] = sug_id
            except Exception:
                pass
            # Apply explicit feedback if provided
            if feedback and memrl_suggestion_id:
                _apply_memrl_feedback(memrl_suggestion_id, feedback)
            return result

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 8. MISC - Python exec, signatures, bookmarks, undo, stack
# ============================================================================
