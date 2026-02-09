
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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
                top_list = []
                for s in idautils.Strings():
                    count = len(list(idautils.XrefsTo(s.ea)))
                    if count > 0:
                        top_list.append((s.ea, str(s), count))
                top_list.sort(key=lambda x: x[2], reverse=True)
                top_lines = [f"{hex(ea)}  xrefs={cnt}  {text}" for ea, text, cnt in top_list[:50]]
                return {"ok": True, "top_strings": "\n".join(top_lines), "note": "Global string summary (most referenced)"}

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
            elif hasattr(idc, "STRTYPE_C_32") and str_type == idc.STRTYPE_C_32:
                encoding = "utf-32"
            
            # Get xrefs to this string
            xref_lines = []
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                fn_name = idc.get_func_name(xref.frm) if func else ""
                xref_lines.append(f"{hex(xref.frm)}  {fn_name}")
            
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
                "xrefs": "\n".join(xref_lines[:20]),
                "decryption_indicators": indicators
            }
        
        elif action == "xref_chain":
            if not addr:
                # List top referenced strings as suggestions
                top_list = []
                for s in idautils.Strings():
                    count = len(list(idautils.XrefsTo(s.ea)))
                    if count > 1:
                        top_list.append((s.ea, str(s), count))
                top_list.sort(key=lambda x: x[2], reverse=True)
                top_lines = [f"{hex(ea)}  xrefs={cnt}  {text}" for ea, text, cnt in top_list[:20]]
                return {"ok": True, "top_strings": "\n".join(top_lines), "hint": "Provide 'addr' to trace a specific string"}
            
            ea = parse_address(addr)
            chain_lines = []
            visited = set()
            
            def trace_up(current_ea, current_depth):
                if current_depth > depth or current_ea in visited:
                    return
                visited.add(current_ea)
                
                for xref in idautils.XrefsTo(current_ea):
                    if xref.type in [1, 17, 18, 19, 20, 21]:
                        func = ida_funcs.get_func(xref.frm)
                        if func:
                            indent = "  " * current_depth
                            chain_lines.append(f"{indent}{hex(xref.frm)}  d={current_depth}  {idc.get_func_name(func.start_ea)}")
                            if current_depth < depth:
                                trace_up(func.start_ea, current_depth + 1)
            
            trace_up(ea, 0)
            return {"ok": True, "addr": hex(ea), "depth": depth, "chain": "\n".join(chain_lines[:50])}
        
        elif action == "detect_encoded":
            suspicious_lines = []
            
            for s in idautils.Strings():
                raw = ida_bytes.get_bytes(s.ea, s.length)
                if not raw:
                    continue
                
                ent = calc_entropy(raw)
                reasons = []
                
                if ent > 0.85:
                    reasons.append("high_entropy")
                
                if raw and len(set(raw)) < len(raw) // 4:
                    reasons.append("repetitive_pattern")
                
                try:
                    str_val = raw.decode('ascii', errors='strict')
                    if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in str_val):
                        if len(str_val) > 20:
                            reasons.append("base64_like")
                except Exception:
                    pass
                
                if reasons:
                    suspicious_lines.append(f"{hex(s.ea)}  ent={round(ent, 3)}  [{','.join(reasons)}]  {str(s)[:50]}")
                
                if len(suspicious_lines) >= 100:
                    break
            
            return {"ok": True, "suspicious": "\n".join(suspicious_lines)}
        
        elif action == "find_format":
            fmt_lines = []
            
            for s in idautils.Strings():
                try:
                    str_val = idc.get_strlit_contents(s.ea, -1, s.strtype)
                    if str_val:
                        str_val = str_val.decode('utf-8', errors='replace')
                        if '%' in str_val:
                            if query and query.lower() not in str_val.lower():
                                continue
                            import re
                            specs = re.findall(r'%[-+0 #]*\d*\.?\d*[hlL]*[diouxXeEfFgGcspn%]', str_val)
                            if specs:
                                args_count = len([sp for sp in specs if sp != '%%'])
                                fmt_lines.append(f"{hex(s.ea)}  args={args_count}  {str_val[:100]}")
                except Exception:
                    continue
                
                if len(fmt_lines) >= 100:
                    break
            
            return {"ok": True, "format_strings": "\n".join(fmt_lines)}
        
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
                            clusters[func_name]["strings"].append(f"{hex(s.ea)}  {str(s)[:50]}")
            
            cluster_lines = []
            for func_name, info in list(clusters.items())[:50]:
                cluster_lines.append(f"[{func_name} @ {info['addr']}]")
                for st in info["strings"]:
                    cluster_lines.append(f"  {st}")
            return {"ok": True, "clusters": "\n".join(cluster_lines)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 31. ENTROPY - Entropy Analysis
# ============================================================================
