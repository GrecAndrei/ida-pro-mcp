
from typing import Annotated, Optional, Literal, Union, Any
import io
import sys
import os
import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_segment
import ida_funcs
import ida_kernwin
import ida_frame
import ida_lines

# Infrastructure discovery
try:
    # Package mode
    from ida_mcp.rpc import tool, unsafe
    from ida_mcp.sync import idaread, idawrite, IDAError
    from ida_mcp.utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from ida_mcp.error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )
except (ImportError, ValueError):
    # Standalone IDA mode
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _mcp_root = os.path.dirname(_this_dir)
    if _mcp_root not in sys.path:
        sys.path.insert(0, _mcp_root)
        
    from rpc import tool, unsafe
    from sync import idaread, idawrite, IDAError
    from utils import (
        parse_address, normalize_list_input, normalize_dict_list,
        get_function, get_prototype, get_image_size, looks_like_address,
        get_stack_frame_variables_internal, get_type_by_name, hex_ea, hex_size
    )
    from error_handling import (
        MCPError, make_error, handle_error,
        validate_addr, validate_range, check_debugger, validate_path_safe
    )


# ============================================================================
# 22. DIFF - Binary Comparison and Diffing
# ============================================================================

@tool
@idaread
def diff(
    action: Annotated[Literal["functions", "bytes", "signatures", "summary", "export_binexport"],
                      "Action: functions|bytes|signatures|summary|export_binexport"],
    addr1: Annotated[Optional[str], "First address/function"] = None,
    addr2: Annotated[Optional[str], "Second address/function"] = None,
    threshold: Annotated[float, "Similarity threshold (0.0-1.0)"] = 0.8,
    path: Annotated[Optional[str], "Export path for BinExport"] = None,
    **kwargs
) -> dict:
    """
    Surgical differential analysis and binary comparison.
    
    Actions:
    - functions: Diff two functions via pseudocode.
    - bytes: Detailed byte-by-byte comparison of two ranges.
    - signatures: Find similar functions using fuzzy byte matching.
    - summary: Compare global database metrics.
    - export_binexport: Generate a .BinExport file for use with BinDiff.
    """
    try:
        if action == "functions":
            if not addr1 or not addr2: return make_error(MCPError.INVALID_ARGS, "addr1 and addr2 required")
            ea1, err = validate_addr(addr1, require_func=True)
            if err: return err
            ea2, err = validate_addr(addr2, require_func=True)
            if err: return err
            
            import difflib
            def get_pseudo(ea):
                c = ida_hexrays.decompile(ea)
                return [ida_lines.tag_remove(l.line) for l in c.get_pseudocode()] if c else []
            
            lines1, lines2 = get_pseudo(ea1), get_pseudo(ea2)
            matcher = difflib.SequenceMatcher(None, lines1, lines2)
            diff = list(difflib.unified_diff(lines1, lines2, lineterm=''))
            
            return {
                "ok": True,
                "similarity": round(matcher.ratio(), 3),
                "added": len([l for l in diff if l.startswith('+')]),
                "removed": len([l for l in diff if l.startswith('-')]),
                "diff": diff[:50]
            }
        
        elif action == "bytes":
            if not addr1 or not addr2: return make_error(MCPError.INVALID_ARGS, "addr1 and addr2 required")
            # Expected format: "0x401000:0x401100"
            try:
                s1, e1 = addr1.split(':')
                s2, e2 = addr2.split(':')
                ea1_s, ea1_e = parse_address(s1), parse_address(e1)
                ea2_s, ea2_e = parse_address(s2), parse_address(e2)
            except: return make_error(MCPError.INVALID_ARGS, "Invalid range format (start:end)")
            
            b1, b2 = ida_bytes.get_bytes(ea1_s, ea1_e - ea1_s), ida_bytes.get_bytes(ea2_s, ea2_e - ea2_s)
            if not b1 or not b2: return make_error(MCPError.IDA_ERROR, "Could not read bytes")
            
            changes = []
            for i in range(min(len(b1), len(b2))):
                if b1[i] != b2[i]:
                    changes.append({"off": i, "v1": hex(b1[i]), "v2": hex(b2[i])})
                    if len(changes) >= 50: break
            
            return {"ok": True, "similarity": round(1.0 - (len(changes)/len(b1)), 3), "changes": changes}

        elif action == "signatures":
            if not addr1: return make_error(MCPError.INVALID_ARGS, "addr1 (target function) required")
            ea, err = validate_addr(addr1, require_func=True)
            if err: return err
            
            f = ida_funcs.get_func(ea)
            target_b = ida_bytes.get_bytes(f.start_ea, min(128, f.end_ea - f.start_ea))
            
            matches = []
            import difflib
            for other_ea in idautils.Functions():
                if other_ea == f.start_ea: continue
                of = ida_funcs.get_func(other_ea)
                if abs((of.end_ea - of.start_ea) - (f.end_ea - f.start_ea)) > 100: continue # Size heuristic
                
                other_b = ida_bytes.get_bytes(other_ea, len(target_b))
                if not other_b: continue
                
                sim = difflib.SequenceMatcher(None, target_b, other_b).ratio()
                if sim >= threshold:
                    matches.append({"addr": hex(other_ea), "name": idc.get_func_name(other_ea), "sim": round(sim, 3)})
                if len(matches) >= 20: break
            
            return {"ok": True, "matches": sorted(matches, key=lambda x: x["sim"], reverse=True)}

        elif action == "export_binexport":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            
            import ida_loader
            if ida_loader.load_and_run_plugin("binexport", 0):
                # BinExport usually triggers a file dialog or takes the path from a netnode/config
                # This is a stub - real implementation depends on BinExport version
                return {"ok": True, "path": path, "note": "BinExport triggered. Ensure plugin is configured to save to target path."}
            return make_error(MCPError.NOT_IMPLEMENTED, "BinExport plugin not found")

        elif action == "summary":
            return {"ok": True, "funcs": len(list(idautils.Functions())), "names": len(list(idautils.Names())), "segs": len(list(idautils.Segments()))}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
    
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


# ============================================================================
# 23. LUMINA - Cloud-Based Function Recognition
# ============================================================================
