
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 39. COVERAGE - Code Coverage Import and Analysis
# ============================================================================

@tool
@idaread
def coverage(
    action: Annotated[Literal["import_drcov", "import_lighthouse", "highlight", "report", "uncovered", "filter"],
                      "Action: import_drcov|import_lighthouse|highlight|report|uncovered|filter"],
    path: Annotated[Optional[str], "Path to coverage file"] = None,
    addr: Annotated[Optional[str], "Function to analyze"] = None,
    color: Annotated[Optional[str], "Highlight color (green|yellow|red)"] = "green",
    addresses: Annotated[Optional[list[str]], "List of addresses to filter (for action=filter)"] = None,
    **kwargs
) -> dict:
    """
    Import and analyze code coverage data from various sources.
    
    ACTIONS:
    
    import_drcov - Import DynamoRIO coverage file (.log or .drcov)
        Params: path
        Returns: {imported, modules, basic_blocks}
        
    import_lighthouse - Import Lighthouse/coverage.py flat text format
        Params: path
        Returns: {imported, addresses}
        
    highlight - Apply color highlighting to executed items in the IDA viewport
        Params: path (coverage file), color (green|yellow|red)
        Returns: {highlighted, count}
        
    report - Detailed coverage analysis for a specific function
        Params: addr (optional - defaults to entry point), path (optional coverage data)
        Returns: {function, total_blocks, covered, percentage}
        
    uncovered - Identify and prioritize important functions without coverage
        Params: path
        Returns: {uncovered: [{name, importance, reason}]}
        
    filter - Test which of the provided addresses were actually executed
        Params: path (coverage file), addresses (list of hex strings)
        Returns: {executed: [hex_str], count}
    """
    try:
        import os
        import struct
        
        def parse_drcov(filepath):
            """Parse DynamoRIO drcov format"""
            if not os.path.exists(filepath):
                return None, "File not found"
            
            modules = []
            blocks = []
            
            with open(filepath, 'rb') as f:
                # Read header
                line = f.readline().decode('utf-8', errors='ignore').strip()
                if not line.startswith('DRCOV'):
                    return None, "Not a drcov file"
                
                # Skip to module table
                while True:
                    line = f.readline().decode('utf-8', errors='ignore').strip()
                    if line.startswith('Module Table'):
                        break
                    if not line:
                        return None, "Invalid format"
                
                # Read module count
                parts = line.split(':')
                if len(parts) >= 2:
                    count = int(parts[1].strip().split()[0])
                    for _ in range(count):
                        mod_line = f.readline().decode('utf-8', errors='ignore').strip()
                        # Parse: id, base, end, entry, checksum, timestamp, path
                        parts = mod_line.split(',')
                        if len(parts) >= 7:
                            modules.append({
                                "id": int(parts[0].strip()),
                                "base": int(parts[1].strip(), 16) if parts[1].strip().startswith('0x') else int(parts[1].strip()),
                                "path": parts[6].strip() if len(parts) > 6 else ""
                            })
                
                # Find BB Table
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.decode('utf-8', errors='ignore').strip()
                    if line.startswith('BB Table'):
                        break
                
                # Read basic blocks (binary format follows)
                while True:
                    data = f.read(8)  # start (4 bytes), size (2 bytes), mod_id (2 bytes)
                    if len(data) < 8:
                        break
                    start, size, mod_id = struct.unpack('<IHH', data)
                    blocks.append({
                        "start": start,
                        "size": size,
                        "module_id": mod_id
                    })
            
            return {"modules": modules, "blocks": blocks}, None
        
        def load_coverage_set(filepath):
            """Load coverage into a flat set of executed addresses"""
            addresses = set()
            
            # 1. Try simple text list
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith("DRCOV"): raise ValueError("Is binary")
                            try:
                                addresses.add(parse_address(line))
                            except: pass
                if addresses: return addresses
            except: pass
            
            # 2. Try drcov
            result, _ = parse_drcov(filepath)
            if result:
                base = idaapi.get_imagebase()
                # Determine relocation if possible (simplified)
                # Ideally match module names, but for now assume main binary matches IDB
                
                for block in result["blocks"]:
                    # Adjust relative to IDB base if module 0? 
                    # DRCOV is relative to module base. We need active IDB base.
                    # Simplification: Assume executing module matches IDB base
                    mod_base = result["modules"][block["module_id"]]["base"]
                    # If this matches current IDB logic... (TODO: robust module matching)
                    # For now, treat block.start as offset if module matches
                    # This is tricky without exact mapping.
                    # Let's assume user provides lighthouse trace which is already resolved or drcov for main module
                    
                    # Heuristic: If IDB is 0x140000000 and trace says module 0 is 0x140000000
                    # Just add them.
                    
                    start_ea = block["start"] + mod_base
                    for offset in range(block["size"]):
                        addresses.add(start_ea + offset)
            return addresses

        if action == "filter":
            if not path: return make_error(MCPError.INVALID_ARGS, "path (coverage file) required")
            if not addresses: return make_error(MCPError.INVALID_ARGS, "addresses list required")

            cov_set = load_coverage_set(path)
            if not cov_set: return make_error(MCPError.FILE_NOT_FOUND, "No coverage data loaded")
            
            executed = []
            for addr_str in addresses:
                try:
                    ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                    if ea in cov_set:
                        executed.append(addr_str)
                    else:
                        # Check if function start
                        func = ida_funcs.get_func(ea)
                        if func:
                            # If any instruction in function is covered?
                            # Or just the entry point?
                            # Strict: entry point must be executed
                            if func.start_ea in cov_set:
                                executed.append(addr_str)
                except: pass
            
            return {"ok": True, "path": path, "executed": executed, "count": len(executed)}

        if action == "import_drcov":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")

            result, error = parse_drcov(path)
            if error:
                return make_error(MCPError.FILE_NOT_FOUND, error)

            return {
                "ok": True,
                "imported": True,
                "path": path,
                "modules": len(result["modules"]),
                "basic_blocks": len(result["blocks"]),
                "module_names": [m["path"] for m in result["modules"][:10]]
            }
        
        elif action == "import_lighthouse":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")

            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")
            
            addresses = []
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            addr = int(line, 16) if line.startswith('0x') else int(line)
                            addresses.append(addr)
                        except:
                            pass
            
            return {
                "ok": True,
                "imported": True,
                "path": path,
                "addresses": len(addresses),
                "unique": len(set(addresses))
            }
        
        elif action == "highlight":
            if not path:
                return make_error(MCPError.INVALID_ARGS, "path required")
            
            # Try to parse as simple address list first
            addresses = set()
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                addresses.add(parse_address(line))
                            except:
                                pass
            
            if not addresses:
                # Try drcov
                result, _ = parse_drcov(path)
                if result:
                    base = idaapi.get_imagebase()
                    for block in result["blocks"]:
                        for offset in range(block["size"]):
                            addresses.add(base + block["start"] + offset)
            
            # Color mapping
            color_map = {
                "green": 0x90EE90,
                "yellow": 0x00FFFF,
                "red": 0x0000FF
            }
            bgr = color_map.get(color, 0x90EE90)
            
            count = 0
            for ea in addresses:
                if idc.is_mapped(ea):
                    idc.set_color(ea, idc.CIC_ITEM, bgr)
                    count += 1
            
            return {"ok": True, "highlighted": True, "count": count, "color": color}
        
        elif action == "report":
            # Entry point resolution compatible with IDA 7.x-9.x
            try:
                start_ea = idaapi.get_inf_structure().start_ea
            except AttributeError:
                import ida_ida
                start_ea = ida_ida.inf_get_start_ea()
                
            target = addr or hex(start_ea)
            ea = parse_address(target)
            func = ida_funcs.get_func(ea)
            
            if not func:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function found at {target}")
            
            # Load coverage if path provided
            covered_addrs = set()
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                covered_addrs.add(parse_address(line))
                            except:
                                pass
            
            # Analyze function blocks
            try:
                fc = idaapi.FlowChart(func)
                total = 0
                covered = 0
                blocks = []
                
                for block in fc:
                    total += 1
                    is_covered = any(ea in covered_addrs for ea in range(block.start_ea, block.end_ea))
                    if is_covered:
                        covered += 1
                    blocks.append({
                        "start": hex(block.start_ea),
                        "covered": is_covered
                    })
                
                return {
                    "ok": True,
                    "function": idc.get_func_name(ea) or hex(ea),
                    "total_blocks": total,
                    "covered_blocks": covered,
                    "percentage": round(covered / total * 100, 2) if total else 0,
                    "blocks": blocks[:20],
                    "note": "No coverage data loaded" if not covered_addrs else ""
                }
            except:
                return make_error(MCPError.IDA_ERROR, "Could not analyze function")
        
        elif action == "uncovered":
            # Load coverage data
            covered_funcs = set()
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        try:
                            ea = parse_address(line.strip())
                            func = ida_funcs.get_func(ea)
                            if func:
                                covered_funcs.add(func.start_ea)
                        except:
                            pass
            
            # Find uncovered functions
            uncovered = []
            importance_keywords = ["main", "init", "parse", "process", "handle", "check", "verify"]
            
            for seg_ea in idautils.Segments():
                for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                    if func_ea in covered_funcs:
                        continue
                    
                    name = idc.get_func_name(func_ea)
                    if not name or name.startswith("sub_"):
                        continue
                    
                    importance = "normal"
                    reason = ""
                    name_lower = name.lower()
                    
                    for kw in importance_keywords:
                        if kw in name_lower:
                            importance = "high"
                            reason = f"Contains '{kw}'"
                            break
                    
                    uncovered.append({
                        "addr": hex(func_ea),
                        "name": name,
                        "importance": importance,
                        "reason": reason
                    })
            
            # Sort by importance
            uncovered.sort(key=lambda x: 0 if x["importance"] == "high" else 1)
            
            return {"ok": True, "uncovered": uncovered[:50]}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# END OF DYNAMIC ANALYSIS TOOLS (36-39)
# Total tools: 39
# ============================================================================
