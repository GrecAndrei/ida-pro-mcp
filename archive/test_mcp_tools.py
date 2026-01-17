# -*- coding: utf-8 -*-
"""
IDA Pro MCP - Sequential Tool Tester
Tests each tool one at a time with error catching.
Designed to be run inside IDA via misc(python).
"""

import traceback

def test_one(api, tool_name, action, params=None, expect_error=False):
    """Test a single tool action with error handling."""
    params = params or {}
    test_id = f"{tool_name}.{action}"
    
    try:
        if not hasattr(api, tool_name):
            return (test_id, "SKIP", "Tool not found")
        
        func = getattr(api, tool_name)
        result = func(action=action, **params)
        
        if isinstance(result, dict) and "error" in result:
            err_msg = str(result.get("error", ""))[:40]
            if expect_error:
                return (test_id, "PASS", f"Expected error: {err_msg}")
            else:
                return (test_id, "FAIL", err_msg)
        else:
            if expect_error:
                return (test_id, "FAIL", "Expected error but got success")
            else:
                return (test_id, "PASS", "OK")
                
    except Exception as e:
        err = str(e)[:40]
        if expect_error:
            return (test_id, "PASS", f"Expected exception: {err}")
        else:
            return (test_id, "FAIL", f"EXCEPTION: {err}")

def run_all():
    """Run all tests sequentially."""
    from ida_mcp import api_consolidated as api
    
    results = {"PASS": [], "FAIL": [], "SKIP": []}
    
    # Define all tests: (tool, action, params, expect_error)
    tests = [
        # IDB
        ("idb", "meta", {}, False),
        ("idb", "segments", {}, False),
        ("idb", "cursor", {}, False),
        ("idb", "entrypoints", {}, False),
        
        # CODE
        ("code", "decompile", {"addrs": ["0x620000"]}, False),
        ("code", "disasm", {"addrs": ["0x620000"]}, False),
        ("code", "xrefs_to", {"addrs": ["0x620000"]}, False),
        ("code", "xrefs_from", {"addrs": ["0x620000"]}, False),
        ("code", "callees", {"addrs": ["0x620000"]}, False),
        ("code", "callers", {"addrs": ["0x620000"]}, False),
        ("code", "blocks", {"addrs": ["0x620000"]}, False),
        ("code", "analyze", {"addrs": ["0x620000"]}, False),
        ("code", "strings_in_func", {"addrs": ["0x620000"]}, False),
        
        # DATA
        ("data", "functions", {"count": 3}, False),
        ("data", "globals", {"count": 3}, False),
        ("data", "strings", {"count": 3}, False),
        ("data", "imports", {}, False),
        ("data", "exports", {}, False),
        ("data", "lookup", {"query": "0x620000"}, False),
        
        # SEARCH
        ("search", "bytes", {"pattern": "48 83"}, False),
        ("search", "string", {"pattern": "Dart"}, False),
        ("search", "name", {"pattern": "*"}, False),
        
        # TYPES
        ("types", "list", {}, False),
        ("types", "infer", {"addr": "0x620000"}, False),
        
        # MEMORY
        ("memory", "read", {"addr": "0x620000", "type": "bytes", "size": 4}, False),
        
        # MODIFY
        ("modify", "comment", {"addr": "0x620000", "value": "Test"}, False),
        
        # MISC
        ("misc", "python", {"code": "1+1"}, False),
        ("misc", "sig_list", {}, False),
        ("misc", "bookmark_list", {}, False),
        ("misc", "auto_wait", {}, False),
        
        # FUNCS
        ("funcs", "comment", {"addr": "0x620000", "comment": "Test"}, False),
        
        # SEGMENTS
        ("segments", "list", {}, False),
        
        # FILES
        ("files", "get_cwd", {}, False),
        ("files", "list_recent", {}, False),
        
        # PLUGINS - expect error
        ("plugins", "list", {}, True),
        
        # DEBUG - expect errors (no debugger)
        ("debug", "breakpoints", {}, True),
        ("debug", "regs", {}, True),
        
        # TRACE - expect error
        ("trace", "get", {}, True),
        
        # FIXUPS
        ("fixups", "list", {}, False),
        
        # DATA_OPS - skip destructive
        
        # AGENT
        ("agent", "explore_address", {"addr": "0x620000"}, False),
        ("agent", "search_all", {"query": "main"}, False),
    ]
    
    # Run each test
    for tool, action, params, expect_err in tests:
        try:
            test_id, status, msg = test_one(api, tool, action, params, expect_err)
            results[status].append(f"{test_id}: {msg}")
        except Exception as e:
            results["FAIL"].append(f"{tool}.{action}: Outer exception: {str(e)[:30]}")
    
    return results

def format_results(results):
    """Format results for display."""
    total = sum(len(v) for v in results.values())
    lines = [
        "=" * 50,
        f"MCP TEST RESULTS: {len(results['PASS'])}/{total} passed",
        "=" * 50,
    ]
    
    if results["FAIL"]:
        lines.append("\nFAILURES:")
        for f in results["FAIL"]:
            lines.append(f"  X {f}")
    
    if results["SKIP"]:
        lines.append("\nSKIPPED:")
        for s in results["SKIP"]:
            lines.append(f"  - {s}")
    
    lines.append("\nPASSED:")
    for p in results["PASS"][:15]:
        lines.append(f"  + {p}")
    if len(results["PASS"]) > 15:
        lines.append(f"  ... +{len(results['PASS'])-15} more")
    
    return "\n".join(lines)

# Execute
try:
    res = run_all()
    output = format_results(res)
except Exception as e:
    output = f"Test runner failed: {traceback.format_exc()}"

raise Exception(output)
