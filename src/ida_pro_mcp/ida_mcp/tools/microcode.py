
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================

@tool
@idaread
def microcode(
    action: Annotated[Literal["get", "blocks", "instructions"], "Action: get|blocks|instructions"],
    addr: Annotated[str, "Function address"],
    maturity: Annotated[int, "Optimization maturity level (0-7)"] = 3,
    **kwargs
) -> dict:
    """
    Access Hex-Rays Microcode (IR) for low-level decompiler analysis.
    
    Actions:
    - get: Get high-level microcode summary for function.
    - blocks: List all micro-blocks (mblock_t) in the function.
    - instructions: List all micro-instructions (minsn_t) in the function.
    """
    try:
        ea, err = validate_addr(addr, require_func=True)
        if err: return err
        
        # Microcode requires Hex-Rays
        if not ida_hexrays.init_hexrays_plugin():
            return make_error(MCPError.IDA_ERROR, "Hex-Rays decompiler not available")
            
        func = ida_funcs.get_func(ea)
        if not func: return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")
        
        # IDA 9.2 requires mba_ranges_t
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        # gen_microcode(mbr, hf, retlist, decomp_flags, reqmat)
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, maturity)
        
        if not mba: return make_error(MCPError.IDA_ERROR, f"Failed to generate microcode: {hf.str}")
        
        func_name = idc.get_func_name(ea)
        
        if action == "get":
            return {"ok": True, "function": func_name, "blocks_count": mba.qty, "maturity": maturity}
            
        elif action == "blocks":
            block_lines = []
            for i in range(mba.qty):
                block = mba.get_mblock(i)
                block_lines.append(f"{i}  {hex(block.start)}-{hex(block.end)}  type={block.type}")
            return {"ok": True, "function": func_name, "blocks": "\n".join(block_lines), "count": len(block_lines)}
            
        elif action == "instructions":
            instr_lines = []
            # Iterate through blocks and instructions
            for i in range(mba.qty):
                block = mba.get_mblock(i)
                curr = block.head
                while curr:
                    # Use print1 instead of str() for better performance
                    text = ida_lines.tag_remove(curr._print())
                    instr_lines.append(f"{hex(curr.ea)}  {text}")
                    curr = curr.next
                    if len(instr_lines) >= 500: break
                if len(instr_lines) >= 500: break
            return {"ok": True, "function": func_name, "instructions": "\n".join(instr_lines), "count": len(instr_lines)}
            
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================
