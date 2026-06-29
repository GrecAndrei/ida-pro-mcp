
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 18. MICROCODE - Hex-Rays Intermediate Representation Access
# ============================================================================


def _microcode_def_use_graph(mba, max_edges=1200):
    """
    Build an IR-level def-use approximation by tokenizing micro-instruction text.
    """
    import re

    token_re = re.compile(r"[A-Za-z_]\w*|v\d+|r\d+|[a-z]{1,3}\.\d+")
    edges = []
    edge_seen = set()
    defs = {}
    uses = {}

    for i in range(mba.qty):
        block = mba.get_mblock(i)
        curr = block.head
        while curr:
            try:
                text = ida_lines.tag_remove(curr._print())
            except Exception:
                text = ""
            txt = (text or "").strip()
            if txt:
                lhs = ""
                rhs = ""
                if "=" in txt and "==" not in txt:
                    lhs, rhs = txt.split("=", 1)
                lhs_toks = set(token_re.findall(lhs))
                rhs_toks = set(token_re.findall(rhs or txt))
                for d in lhs_toks:
                    defs[d] = defs.get(d, 0) + 1
                    for u in rhs_toks:
                        if u == d:
                            continue
                        key = (u, d)
                        if key in edge_seen:
                            continue
                        edge_seen.add(key)
                        edges.append(
                            {
                                "from": u,
                                "to": d,
                                "ea": hex(curr.ea),
                                "block": i,
                                "kind": "def_use",
                            }
                        )
                for u in rhs_toks:
                    uses[u] = uses.get(u, 0) + 1
            if len(edges) >= max_edges:
                break
            curr = curr.next
        if len(edges) >= max_edges:
            break

    hot_defs = sorted(defs.items(), key=lambda kv: kv[1], reverse=True)[:20]
    hot_uses = sorted(uses.items(), key=lambda kv: kv[1], reverse=True)[:20]
    return {
        "edges": edges,
        "edge_count": len(edges),
        "hot_defs": [{"symbol": s, "count": c} for s, c in hot_defs],
        "hot_uses": [{"symbol": s, "count": c} for s, c in hot_uses],
    }


@tool
@idaread
def microcode(
    action: Annotated[Literal["get", "blocks", "instructions", "def_use_graph"], "Action: get|blocks|instructions|def_use_graph"],
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
    - def_use_graph: Build IR-level def-use graph from micro-instructions.
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

        elif action == "def_use_graph":
            graph = _microcode_def_use_graph(mba, max_edges=1400)
            edge_lines = [
                f"{e['from']} -> {e['to']}  {e['ea']}  block={e['block']}"
                for e in graph.get("edges", [])[:500]
            ]
            return {
                "ok": True,
                "function": func_name,
                "def_use_graph": graph,
                "edges": "\n".join(edge_lines),
                "count": graph.get("edge_count", 0),
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 19. GRAPH - Export call graphs and CFGs for visualization/analysis
# ============================================================================
