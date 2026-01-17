
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
# 30. STRINGS_XREF - Advanced String Analysis
# ============================================================================

@tool
@idaread
def strings_xref(
    action: Annotated[Literal["analyze", "xref_chain", "detect_encoded", "find_format", "clusters"],
                      "Action: analyze|xref_chain|detect_encoded|find_format|clusters"],
    addr: Annotated[Optional[str], "String address or function address"] = None,
    query: Annotated[Optional[str], "String pattern to search"] = None,
    depth: Annotated[int, "Xref chain depth"] = 3,
    **kwargs
) -> dict:
    """
    Advanced string analysis with xref chains, encoding detection, and clustering.
    
    ACTIONS:
    
    analyze - Deep analysis of a string at address or global summary
        Params: addr (optional - if omitted, returns global string summary)
        Returns: {string, encoding, xrefs, decryption_indicators} OR {top_strings: [...]}
        
    xref_chain - Trace string reference chain up through callers
        Params: addr (optional - if omitted, lists top-referenced strings), depth
        Returns: {chain: [{addr, func, caller}...]} OR {top_strings: [...]}
        
    detect_encoded - Find potentially encrypted/encoded strings
        Returns: {suspicious: [{addr, string, entropy, reason}]}
        
    find_format - Find format strings and their argument usage
        Params: query (optional filter)
        Returns: {format_strings: [{addr, format, args_count}]}
        
    clusters - Group strings by their calling functions
        Returns: {clusters: [{func, strings: [...]}]}
    """
    import math
    
    try:
        def calc_entropy(data):
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p)
            return entropy / 8.0  # Normalize to 0-1
        
        if action == "analyze":
            if not addr:
                # Global analysis: find most referenced strings
                top_strings = []
                for s in idautils.Strings():
                    count = len(list(idautils.XrefsTo(s.ea)))
                    if count > 0:
                        top_strings.append({
                            "addr": hex(s.ea),
                            "string": str(s),
                            "xrefs": count
                        })
                top_strings.sort(key=lambda x: x["xrefs"], reverse=True)
                return {"ok": True, "top_strings": top_strings[:50], "note": "Global string summary (most referenced)"}

            ea = parse_address(addr)

            # Get string at address
            str_type = idc.get_str_type(ea)
            if str_type in (None, -1):
                return make_error(MCPError.ADDRESS_INVALID, f"No string at {addr}")
            
            string_val = idc.get_strlit_contents(ea, -1, str_type)
            if string_val:
                string_val = string_val.decode('utf-8', errors='replace')
            
            # Detect encoding
            encoding = "ascii"
            if str_type == idc.STRTYPE_C_16:
                encoding = "utf-16"
            elif str_type == idc.STRTYPE_C_32:
                encoding = "utf-32"
            
            # Get xrefs to this string
            xrefs = []
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                xrefs.append({
                    "from": hex(xref.frm),
                    "func": idc.get_func_name(xref.frm) if func else None
                })
            
            # Check for decryption indicators
            indicators = []
            raw_bytes = ida_bytes.get_bytes(ea, min(100, idc.get_item_size(ea)))
            if raw_bytes:
                ent = calc_entropy(raw_bytes)
                if ent > 0.8:
                    indicators.append("high_entropy")
                if b'\x00' not in raw_bytes[:20] and len(raw_bytes) > 10:
                    indicators.append("no_null_terminator_early")
            
            return {
                "ok": True,
                "addr": hex(ea),
                "string": string_val,
                "encoding": encoding,
                "size": idc.get_item_size(ea),
                "xrefs": xrefs[:20],
                "decryption_indicators": indicators
            }
        
        elif action == "xref_chain":
            if not addr:
                # List top referenced strings as suggestions
                top_strings = []
                for s in idautils.Strings():
                    count = len(list(idautils.XrefsTo(s.ea)))
                    if count > 1:
                        top_strings.append({"addr": hex(s.ea), "string": str(s), "xrefs": count})
                top_strings.sort(key=lambda x: x["xrefs"], reverse=True)
                return {"ok": True, "top_strings": top_strings[:20], "hint": "Provide 'addr' to trace a specific string"}
            
            ea = parse_address(addr)
            chain = []
            visited = set()
            
            def trace_up(current_ea, current_depth):
                if current_depth > depth or current_ea in visited:
                    return
                visited.add(current_ea)
                
                for xref in idautils.XrefsTo(current_ea):
                    if xref.type in [1, 17, 18, 19, 20, 21]:
                        func = ida_funcs.get_func(xref.frm)
                        entry = {
                            "addr": hex(xref.frm),
                            "depth": current_depth
                        }
                        if func:
                            entry["func"] = idc.get_func_name(func.start_ea)
                            chain.append(entry)
                            if current_depth < depth:
                                trace_up(func.start_ea, current_depth + 1)
            
            trace_up(ea, 0)
            return {"ok": True, "addr": hex(ea), "depth": depth, "chain": chain[:50]}
        
        elif action == "detect_encoded":
            suspicious = []
            
            for s in idautils.Strings():
                raw = ida_bytes.get_bytes(s.ea, s.length)
                if not raw:
                    continue
                
                ent = calc_entropy(raw)
                reasons = []
                
                if ent > 0.85:
                    reasons.append("high_entropy")
                
                # Check for XOR patterns
                if raw and len(set(raw)) < len(raw) // 4:
                    reasons.append("repetitive_pattern")
                
                # Check for base64-like
                try:
                    str_val = raw.decode('ascii', errors='strict')
                    if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in str_val):
                        if len(str_val) > 20:
                            reasons.append("base64_like")
                except:
                    pass
                
                if reasons:
                    suspicious.append({
                        "addr": hex(s.ea),
                        "string": str(s)[:50],
                        "entropy": round(ent, 3),
                        "reasons": reasons
                    })
                
                if len(suspicious) >= 100:
                    break
            
            return {"ok": True, "suspicious": suspicious}
        
        elif action == "find_format":
            format_strings = []
            
            for s in idautils.Strings():
                try:
                    str_val = idc.get_strlit_contents(s.ea, -1, s.strtype)
                    if str_val:
                        str_val = str_val.decode('utf-8', errors='replace')
                        if '%' in str_val:
                            if query and query.lower() not in str_val.lower():
                                continue
                            # Count format specifiers
                            import re
                            specs = re.findall(r'%[-+0 #]*\d*\.?\d*[hlL]*[diouxXeEfFgGcspn%]', str_val)
                            if specs:
                                format_strings.append({
                                    "addr": hex(s.ea),
                                    "format": str_val[:100],
                                    "specifiers": specs[:10],
                                    "args_count": len([s for s in specs if s != '%%'])
                                })
                except:
                    continue
                
                if len(format_strings) >= 100:
                    break
            
            return {"ok": True, "format_strings": format_strings}
        
        elif action == "clusters":
            clusters = {}
            
            for s in idautils.Strings():
                for xref in idautils.XrefsTo(s.ea):
                    func = ida_funcs.get_func(xref.frm)
                    if func:
                        func_name = idc.get_func_name(func.start_ea)
                        if func_name not in clusters:
                            clusters[func_name] = {"addr": hex(func.start_ea), "strings": []}
                        if len(clusters[func_name]["strings"]) < 20:
                            clusters[func_name]["strings"].append({
                                "addr": hex(s.ea),
                                "string": str(s)[:50]
                            })
            
            result = [{"func": k, **v} for k, v in list(clusters.items())[:50]]
            return {"ok": True, "clusters": result}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 31. ENTROPY - Entropy Analysis
# ============================================================================
