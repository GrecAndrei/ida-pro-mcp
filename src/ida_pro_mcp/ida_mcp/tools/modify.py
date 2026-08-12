
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

try:
    from .governance_engine import evaluate_operation
except ImportError:
    from governance_engine import evaluate_operation  # type: ignore[import-not-found]

import hashlib

# ============================================================================
# 7. MODIFY - Rename, comments, set type, data authoring, undo
# ============================================================================

# item_type -> (ida_bytes flag name, numeric fallback, element size in bytes)
# used by the create_data action. Pointers are laid as FF_DWORD items (the
# work-order contract); 'array' lays count dword-sized elements so a single
# call can define a vector/MMIO table region. The flag is resolved through
# getattr so the same code runs against real IDA and fake modules in tests.
_ITEM_TYPE_SPEC: dict[str, tuple[str, int, int]] = {
    "byte": ("FF_BYTE", 0x00, 1),
    "word": ("FF_WORD", 0x1000, 2),
    "dword": ("FF_DWORD", 0x2000, 4),
    "qword": ("FF_QWORD", 0x3000, 8),
    "pointer": ("FF_DWORD", 0x2000, 4),
    "array": ("FF_DWORD", 0x2000, 4),
}

# strtype -> (idc constant name, numeric fallback) for create_strlit.
_STRTYPE_SPEC: dict[str, tuple[str, int]] = {
    "c": ("STRTYPE_C", 0),
    "c16": ("STRTYPE_C_16", 2),
    "c32": ("STRTYPE_C_32", 3),
}

def _gather_governance_metadata(action: str, ea: int, value: str) -> dict:
    """Gather IDA-specific metadata for governance checks."""
    metadata: dict = {}

    if action in ("patch_asm", "patch_bytes"):
        # Check if address is in import/plt section or executable code
        seg = _compat.get_segment(ea)
        if seg:
            sname = _compat.get_segment_name(ea)
            metadata["section_type"] = sname or ""
            metadata["is_import_addr"] = sname in (".idata", ".plt", ".edata", ".iat")
            # Patching bytes in an executable section rewrites code flow.
            executable = (_compat.get_segment_perm(ea) or 0) & getattr(ida_segment, "SEGPERM_X", 1) != 0
            if executable or sname in (".text", ".code"):
                metadata["modifies_control_flow"] = True

    elif action in ("rename", "rename_local"):
        fn = _compat.get_func_info(ea)
        if fn:
            flags = _compat.get_func_flags(ea)
            # FLIRT-identified library functions are marked FUNC_LIB; FUNC_THUNK
            # only denotes jump stubs (which are not FLIRT matches).
            metadata["is_library_function"] = ((flags or 0) & ida_funcs.FUNC_LIB) != 0
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
        if _compat.get_func_start(ea) is not None:
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
            from host.stores.symbol_db import SymbolDB  # type: ignore
        except Exception:
            return
    fn = _compat.get_func_start(func_ea)
    if fn is None:
        return
    callers = sorted({_compat.get_func_start(x) for x in idautils.CodeRefsTo(fn, 0) if _compat.get_func_start(x) is not None})
    callees = set()
    for item_ea in idautils.FuncItems(fn):
        for ref in idautils.CodeRefsFrom(item_ea, 0):
            cf = _compat.get_func_start(ref)
            if cf is not None and cf != fn:
                callees.add(cf)
    strs = []
    for item_ea in idautils.FuncItems(fn):
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
                "source_addr": hex(fn),
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
    action: Annotated[
        Literal["rename", "comment", "set_type", "patch_asm", "patch_bytes", "rename_local",
                "create_data", "create_strlit", "undo_begin", "undo_end"],
        "Action: rename|comment|set_type|patch_asm|patch_bytes|rename_local|"
        "create_data|create_strlit|undo_begin|undo_end"],
    addr: Annotated[Optional[str], "Address (not required for undo_begin/undo_end)"] = None,
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
    Modify the database: renaming, commenting, types, assembly patching, and
    the raw-blob authoring/reversibility primitives.

    Actions:
    - rename: Change the name of a function, label, or data item at `addr`.
    - comment: Add a comment. Supports regular, repeatable, anterior (above), posterior (below).
    - set_type: Apply a type declaration to `addr` (similar to types.apply).
    - patch_asm: Assemble and patch instructions at `addr`.
      Supports single instructions (e.g. "mov eax, 1") or multiple instructions
      separated by semicolons (e.g. "nop; nop; nop" or "push ebp; mov ebp, esp").
      Each instruction is assembled and patched sequentially at consecutive addresses.
    - create_data: Define a data item (or a run of them) at `addr`, so raw
      blobs become analyzable without redeclaring types. `item_type` selects
      the item kind (byte|word|dword|qword|pointer|array) and `count` the
      number of consecutive items laid (default 1). 'pointer' lays FF_DWORD
      items; 'array' lays count dword-sized elements (vector/MMIO tables).
      Extra kwargs: item_type, count.
    - create_strlit: Define a string literal covering [addr, addr+size).
      `strtype` is 'c' (C string), 'c16' (UTF-16), or 'c32' (UTF-32).
      Extra kwargs: size (required, byte length), strtype.
    - undo_begin / undo_end: Wrap a batch-patch or experiment in an undo
      transaction; call undo_end to commit the wrapped changes. Recommended
      around ida_batch runs so a failing batch can be rolled back. These two
      actions take no address.

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
            elif action == "patch_bytes" and kwargs.get("hex_bytes"):
                value = kwargs["hex_bytes"]
            elif action == "rename_local" and kwargs.get("new_name"):
                value = kwargs["new_name"]

        if not value:
            # patch_bytes via nop-only, rename_local, the data-authoring
            # primitives, and the undo pair carry their own args; their
            # branches validate the specifics.
            value_optional = (
                (action == "patch_bytes" and kwargs.get("nop"))
                or action in ("create_data", "create_strlit", "undo_begin", "undo_end")
            )
            if not value_optional:
                return make_error(MCPError.INVALID_ARGS, f"value parameter required (or use {action}-specific alias: name/text/type_str/asm)")

        # undo_begin/undo_end bracket an edit batch and take no address.
        if action in ("undo_begin", "undo_end"):
            ea = None
        else:
            ea, error = validate_addr(addr)
            if error:
                return error

        # ----------------------------------------------------------------
        # Governance pre-check
        # ----------------------------------------------------------------
        if governed:
            op_type_map = {
                "rename": "rename",
                "rename_local": "rename",
                "comment": "comment",
                "set_type": "type_change",
                "patch_asm": "patch",
                "patch_bytes": "patch",
                "create_data": "type_change",
                "create_strlit": "type_change",
            }
            op_type = op_type_map.get(action)
            if op_type:
                metadata = _gather_governance_metadata(action, ea, value)
                gov_result = evaluate_operation(
                    operation_type=op_type,
                    addr=ea,
                    # Data-authoring actions carry no `value`; the governance
                    # engine's PII redaction must still receive a string.
                    proposed_value=value or "",
                    context={"tool": "modify", "action": action, "comment_type": comment_type},
                    metadata=metadata,
                )

                if not gov_result["approved"]:
                    return make_error(
                        MCPError.GOVERNANCE_BLOCKED,
                        f"Governance blocked {action}: {gov_result['verdict']}",
                        details={
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
                # Cross-session side effect beyond the acknowledged IDB write:
                # the rename is upserted into the symbol database. Report it so
                # the caller knows the ack covers more than the IDB.
                _persist_symbol_knowledge(ea, value)
                result["side_effects"] = {
                    "symbol_db": "cross-session symbol DB upsert (beyond the acknowledged IDB write)",
                }
                return result
            return make_error(MCPError.IDA_ERROR, "Failed to rename", "Check if name is valid C identifier and not duplicate")

        elif action == "comment":
            # idc.set_cmt / ida_lines.add_extra_cmt return True on success and
            # False on failure (comment too long, ea not writable); a falsy
            # return must surface as an error, not an ok:true envelope.
            if comment_type == "regular":
                ok = idc.set_cmt(ea, value, 0)
            elif comment_type == "repeatable":
                ok = idc.set_cmt(ea, value, 1)
            else:
                # Anterior/Posterior
                import ida_lines
                is_anterior = (comment_type == "anterior")
                if hasattr(ida_lines, "add_extra_cmt"):
                    ok = ida_lines.add_extra_cmt(ea, is_anterior, value)
                else:
                    # Fallback: preserve intent in regular comment channel.
                    prefix = "[anterior] " if is_anterior else "[posterior] "
                    existing = idc.get_cmt(ea, 0) or ""
                    merged = (existing + "\n" if existing else "") + prefix + value
                    ok = idc.set_cmt(ea, merged, 0)
            if not ok:
                return make_error(
                    MCPError.ANNOTATION_ERROR,
                    f"Failed to set {comment_type} comment at {addr}",
                    "The comment may be too long or the address may not accept annotations.",
                )
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

        elif action == "patch_bytes":
            hex_bytes = kwargs.get("hex_bytes") or value
            nop = kwargs.get("nop") or False
            if not hex_bytes and not nop:
                return make_error(MCPError.INVALID_ARGS, "hex_bytes or nop=true required for patch_bytes")
            if nop:
                nop_count = kwargs.get("count")
                if nop_count:
                    patch_size = int(nop_count)
                else:
                    insn = idaapi.insn_t()
                    patch_size = idaapi.decode_insn(insn, ea)
                    if not patch_size:
                        patch_size = 1
                # Use arch-appropriate NOP; fall back to x86 0x90.
                # idaapi.get_inf_structure() was removed in IDA 9 — use the
                # portable _inf_procname() helper so ARM/RISC-V NOP bytes are
                # still chosen on IDA 9 instead of silently writing 0x90.
                nop_byte = 0x90
                try:
                    proc = _inf_procname().lower()
                    if "riscv" in proc:
                        # RISC-V 32-bit NOP = addi x0, x0, 0 = 0x00000013
                        nop_bytes = b"\x13\x00\x00\x00" * (patch_size // 4)
                        if patch_size % 4:
                            nop_bytes += bytes([0x00] * (patch_size % 4))
                    elif "arm" in proc:
                        nop_bytes = b"\x00\xf0\x20\xe3" * (patch_size // 4)  # ARM NOP
                        if patch_size % 4:
                            nop_bytes += bytes([0x00] * (patch_size % 4))
                    else:
                        nop_bytes = bytes([nop_byte] * patch_size)
                except Exception:
                    nop_bytes = bytes([nop_byte] * patch_size)
                ida_bytes.patch_bytes(ea, nop_bytes)
                return {"ok": True, "addr": addr, "size": patch_size, "action": "nop"}
            else:
                hex_str = hex_bytes.replace(" ", "").replace("0x", "")
                try:
                    raw = bytes.fromhex(hex_str)
                except ValueError:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid hex string: {hex_bytes!r}")
                ida_bytes.patch_bytes(ea, raw)
                return {"ok": True, "addr": addr, "size": len(raw), "hex": hex_str}

        elif action == "rename_local":
            var_name = kwargs.get("var_name") or name
            new_name = kwargs.get("new_name") or value
            if not var_name or not new_name:
                return make_error(MCPError.INVALID_ARGS, "var_name and new_name required for rename_local")
            func = _compat.get_func_start(ea)
            if func is None:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
            try:
                cfunc = ida_hexrays.decompile(func)
                if not cfunc:
                    return make_error(MCPError.IDA_ERROR, "Decompilation failed")
                lvar = next((lv for lv in cfunc.lvars if lv.name == var_name), None)
                if not lvar:
                    available = [lv.name for lv in cfunc.lvars if lv.name]
                    return make_error(MCPError.INVALID_ARGS,
                                      f"Local variable '{var_name}' not found. "
                                      f"Available: {', '.join(available[:15])}")

                class _rename_modifier_t(ida_hexrays.user_lvar_modifier_t):
                    def __init__(self, old, new):
                        ida_hexrays.user_lvar_modifier_t.__init__(self)
                        self.old = old
                        self.new = new
                    def modify_lvars(self, lvinf):
                        for lv in lvinf.lvvec:
                            if lv.name == self.old:
                                lv.name = self.new
                                return True
                        return False

                modifier = _rename_modifier_t(var_name, new_name)
                if ida_hexrays.modify_user_lvars(func, modifier):
                    return {"ok": True, "addr": hex(func), "var": var_name, "new_name": new_name}
                return make_error(MCPError.IDA_ERROR, f"Failed to rename '{var_name}' — variable may be optimized out")
            except Exception as e:
                return handle_error(e, context="rename_local")

        elif action == "create_data":
            # Define data items over raw bytes so a blob becomes analyzable
            # without redeclaring types. `count` consecutive items are laid
            # (default 1); item_type picks the flag and element size.
            item_type = str(kwargs.get("item_type") or "byte").lower()
            try:
                count = int(kwargs.get("count") or 1)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "count must be an integer")
            if count < 1:
                return make_error(MCPError.INVALID_ARGS, "count must be at least 1")
            spec = _ITEM_TYPE_SPEC.get(item_type)
            if spec is None:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown item_type: {item_type}",
                    hint="Use one of: byte, word, dword, qword, array, pointer.",
                )
            flag_name, flag_fallback, elem_size = spec
            flag = getattr(ida_bytes, flag_name, flag_fallback)
            laid = 0
            cur = ea
            for _ in range(count):
                if ida_bytes.create_data(cur, flag, elem_size, 0):
                    laid += 1
                    cur += elem_size
                else:
                    break
            if laid == 0:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"create_data failed at {addr}",
                    hint="The address may already be defined, or the range may be unmapped.",
                )
            result = {
                "ok": True,
                "addr": addr,
                "item_type": item_type,
                "count": laid,
                "size": laid * elem_size,
                "end": hex(cur),
            }
            if laid < count:
                result["partial"] = True
            if gov_warnings:
                result["governance_warnings"] = gov_warnings
            return result

        elif action == "create_strlit":
            # Define a string literal over [addr, addr+size). Useful on raw
            # blobs where IDA found no strlit marks during auto-analysis.
            try:
                size = int(kwargs.get("size"))
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "size (byte length) is required for create_strlit")
            if size <= 0:
                return make_error(MCPError.INVALID_ARGS, "size must be a positive integer")
            strtype = str(kwargs.get("strtype") or "c").lower()
            st_spec = _STRTYPE_SPEC.get(strtype)
            if st_spec is None:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown strtype: {strtype}",
                    hint="Use one of: c, c16, c32.",
                )
            st_name, st_fallback = st_spec
            st = getattr(idc, st_name, st_fallback)
            try:
                # ida_bytes.create_strlit takes (start, len, strtype) — the
                # length, not an end address. Passing ea+size would define a
                # string up to the segment end (wrong size) or fail outright.
                length = ida_bytes.create_strlit(ea, size, st)
            except Exception as e:
                return handle_error(e, context="create_strlit")
            if not length:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"create_strlit failed at {addr}",
                    hint="The range may already be defined, or the address may be unmapped.",
                )
            result = {
                "ok": True,
                "addr": addr,
                "size": size,
                "strtype": strtype,
                "length": length,
            }
            if gov_warnings:
                result["governance_warnings"] = gov_warnings
            return result

        elif action == "undo_begin":
            # Open an undo transaction; wrapped edits can be reverted with
            # undo() or committed via undo_end(). Recommended around ida_batch
            # runs so a failed batch can be rolled back.
            try:
                started = ida_bytes.undo_begin()
            except Exception as e:
                return handle_error(e, context="undo_begin")
            if started is False:
                return make_error(MCPError.IDA_ERROR, "undo_begin failed", hint="Undo may be unavailable for this IDB.")
            return {
                "ok": True,
                "action": "undo_begin",
                "note": "Undo transaction started. Wrap a batch-patch or experiment between undo_begin and undo_end, then call undo_end to commit.",
            }

        elif action == "undo_end":
            # Commit the transaction opened by undo_begin(). After this, the
            # wrapped edits are permanent and no longer individually undoable.
            try:
                committed = ida_bytes.undo_end()
            except Exception as e:
                return handle_error(e, context="undo_end")
            if committed is False:
                return make_error(MCPError.IDA_ERROR, "undo_end failed", hint="There may be no open undo transaction.")
            return {
                "ok": True,
                "action": "undo_end",
                "note": "Undo transaction committed. Wrap a batch-patch or experiment between undo_begin and undo_end, then call undo_end to commit.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# End of MODIFY tool module
# ============================================================================
