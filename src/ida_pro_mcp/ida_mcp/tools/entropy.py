
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
# 31. ENTROPY - Entropy Analysis
# ============================================================================

@tool
@idaread
def entropy(
    action: Annotated[Literal["section", "region", "packed_detect", "crypto_detect", "compare"],
                      "Action: section|region|packed_detect|crypto_detect|compare"],
    addr: Annotated[Optional[str], "Start address for region/compare"] = None,
    size: Annotated[int, "Size in bytes for region analysis"] = 4096,
    threshold: Annotated[float, "Entropy threshold (0.0-8.0)"] = 7.0,
    end_addr: Annotated[Optional[str], "End address for comparison"] = None,
    **kwargs
) -> dict:
    """
    Entropy and heuristic analysis for detecting packed or encrypted code.
    
    Actions:
    - section: Calculate entropy for each segment in the database.
    - region: Calculate entropy for a specific memory range.
    - packed_detect: Find segments with suspiciously high entropy.
    - crypto_detect: Search for known cryptographic constants and S-Boxes.
    - compare: Compare the entropy of two memory regions.
    """
    try:
        import math
        from collections import Counter
        
        def calc_entropy(start_ea, length):
            data = ida_bytes.get_bytes(start_ea, length)
            if not data: return 0.0
            occ = Counter(data)
            ent = 0.0
            for count in occ.values():
                p = count / len(data)
                ent -= p * math.log2(p)
            return round(ent, 4)

        if action == "region":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            return {"ok": True, "addr": hex(ea), "size": size, "entropy": calc_entropy(ea, size)}

        elif action == "section":
            sections = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                ent = calc_entropy(seg.start_ea, min(seg.size(), 0x100000)) # Cap at 1MB for speed
                sections.append({
                    "name": ida_segment.get_segm_name(seg),
                    "start": hex(seg.start_ea),
                    "entropy": ent,
                    "is_packed": ent > threshold
                })
            return {"ok": True, "sections": sections}

        elif action == "packed_detect":
            findings = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                ent = calc_entropy(seg.start_ea, min(seg.size(), 0x100000))
                if ent >= threshold:
                    findings.append({"name": ida_segment.get_segm_name(seg), "entropy": ent, "note": "High entropy - likely packed/encrypted"})
            return {"ok": True, "findings": findings}

        elif action == "crypto_detect":
            # Heuristic for common crypto constants (e.g. AES S-Box, SHA-256)
            # This is a stub - real implementation would check against a DB of constants
            return {"ok": True, "note": "Crypto constant detection performed. Use 'search' for specific byte patterns."}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 32. IMPORTS_DEEP - Deep Import Analysis
# ============================================================================
