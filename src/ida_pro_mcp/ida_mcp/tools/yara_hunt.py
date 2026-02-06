
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

@tool
@idaread
def yara_hunt(
    action: Annotated[Literal["scan", "compile", "list_rules"], "Action: scan|compile|list_rules"],
    rules: Annotated[Optional[str], "YARA rules text or file path"] = None,
    addr: Annotated[Optional[str], "Specific address or segment to scan"] = None,
    size: Annotated[int, "Scan size (if addr specified)"] = 0,
    **kwargs
) -> dict:
    """
    Surgical pattern matching using YARA.
    
    Actions:
    - scan: Scan the binary or a memory range with YARA rules.
    - compile: Verify that a YARA rule string is valid.
    - list_rules: List pre-defined YARA rules in the 'rules/' directory.
    """
    try:
        try:
            import yara
        except ImportError:
            return make_error(MCPError.NOT_IMPLEMENTED, "yara-python not installed in IDA's environment", 
                              "Install with: pip install yara-python")

        # Use script path to find rules, not os.getcwd() which may be wrong
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
        rules_dir = os.path.join(_repo_root, "rules")
        
        if action == "scan":
            if not rules: return make_error(MCPError.INVALID_ARGS, "rules (text or path) required")
            
            # Compile rules
            try:
                if "rule" in rules and "{" in rules: # Direct text
                    compiled = yara.compile(source=rules)
                else: # Path
                    rule_path, err = validate_path_safe(rules)
                    if err: return err
                    compiled = yara.compile(filepath=rule_path)
            except yara.Error as e:
                return make_error(MCPError.INVALID_ARGS, f"YARA compilation failed: {e}")

            # Get data to scan
            if addr:
                ea = parse_address(addr)
                scan_size = size if size > 0 else 0x1000
                data = ida_bytes.get_bytes(ea, scan_size)
                if not data: return make_error(MCPError.ADDRESS_INVALID, hex(ea))
                matches = compiled.match(data=data)
            else:
                # Scan entire binary (chunked for safety)
                results = []
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg: continue
                    data = ida_bytes.get_bytes(seg.start_ea, seg.size())
                    if data:
                        matches = compiled.match(data=data)
                        for m in matches:
                            for off, name, val in m.strings:
                                results.append({
                                    "rule": m.rule,
                                    "addr": hex(seg.start_ea + off),
                                    "string": name,
                                    "data": val.hex(" ")[:32]
                                })
                return {"ok": True, "matches": results[:100]}

            # Process single region matches
            results = []
            for m in matches:
                for off, name, val in m.strings:
                    results.append({"rule": m.rule, "addr": hex(ea + off), "string": name})
            return {"ok": True, "matches": results}

        elif action == "compile":
            if not rules: return make_error(MCPError.INVALID_ARGS, "rules required")
            try:
                yara.compile(source=rules)
                return {"ok": True, "status": "Valid YARA rule"}
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"YARA compilation failed: {e}")

        elif action == "list_rules":
            if not os.path.exists(rules_dir): os.makedirs(rules_dir, exist_ok=True)
            files = [f for f in os.listdir(rules_dir) if f.endswith(".yar") or f.endswith(".yara")]
            return {"ok": True, "rules": files, "dir": rules_dir}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
