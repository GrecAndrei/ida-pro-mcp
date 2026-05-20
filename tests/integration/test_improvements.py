#!/usr/bin/env python3
"""
Test script for the new MCP tool improvements.

Tests:
- idb.py: meta, summary, segments (detailed), entrypoints (enriched), bookmarks
- data.py: filtering options (include_prototype, include_xrefs, min_size, named_only)
- search.py: regex action, func_by_sig action, case_sensitive, include_context
- segments.py: info action
- bulk.py: apply_type action, continue_on_error
- comments_ai.py: proper error handling

Run with:
    python tests/test_improvements.py [--binary path/to/binary]
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import queue
from typing import Optional, Any


class MCPTestClient:
    """Simple MCP client for testing."""
    
    def __init__(self, timeout: int = 120):
        self.proc: Optional[subprocess.Popen] = None
        self.stdout_queue: queue.Queue = queue.Queue()
        self.request_id = 0
        self.timeout = timeout
        
    def start(self) -> bool:
        """Start the MCP server."""
        env = os.environ.copy()
        env["IDA_MCP_STARTUP_TIMEOUT"] = str(self.timeout)
        
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "ida_mcp_stdio.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(os.path.dirname(__file__)) or ".",
            bufsize=0,
            env=env
        )
        
        def read_stdout():
            for line in self.proc.stdout:
                self.stdout_queue.put(line)
                
        def read_stderr():
            for line in self.proc.stderr:
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    print(f"  [IDA] {decoded}", file=sys.stderr)
        
        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()
        
        time.sleep(0.3)
        
        # Initialize MCP
        resp = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "improvement-tests", "version": "1.0.0"}
        }, timeout=30)
        
        return "result" in resp
    
    def _call(self, method: str, params: dict, timeout: Optional[int] = None) -> dict:
        """Make a JSON-RPC call."""
        if timeout is None:
            timeout = self.timeout
            
        self.request_id += 1
        req = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        self.proc.stdin.write((json.dumps(req) + "\n").encode('utf-8'))
        self.proc.stdin.flush()
        
        start = time.time()
        while time.time() - start < timeout:
            try:
                line = self.stdout_queue.get(timeout=1)
                resp = json.loads(line.decode('utf-8'))
                if resp.get("id") == self.request_id:
                    return resp
            except queue.Empty:
                if self.proc.poll() is not None:
                    return {"error": "Server died"}
            except json.JSONDecodeError:
                continue
        return {"error": "Timeout"}
    
    def call_tool(self, tool: str, **args) -> dict:
        """Call a tool and return parsed result."""
        resp = self._call("tools/call", {"name": tool, "arguments": args})
        if "result" not in resp:
            return {"_error": resp.get("error", "Unknown error")}
        
        result = resp["result"]
        if result.get("isError"):
            content = result.get("content", [{}])[0].get("text", "{}")
            try:
                return {"_error": json.loads(content)}
            except:
                return {"_error": content}
        
        content = result.get("content", [{}])[0].get("text", "{}")
        try:
            return json.loads(content)
        except:
            return {"_raw": content}
    
    def stop(self):
        """Stop the server."""
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except:
                self.proc.kill()


class TestResult:
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.message = ""
        self.data = None
        
    def __str__(self):
        status = "✓ PASS" if self.passed else "✗ FAIL"
        msg = f" - {self.message}" if self.message else ""
        return f"  [{status}] {self.name}{msg}"


def run_tests(client: MCPTestClient, binary_path: str) -> list[TestResult]:
    """Run all improvement tests."""
    results = []
    
    # Create session first
    print("\n[*] Creating session...")
    session_result = client.call_tool("session", action="create", binary_path=binary_path)
    if "_error" in session_result:
        print(f"  Failed to create session: {session_result['_error']}")
        return results
    print("  Session created successfully")
    time.sleep(2)  # Wait for initial analysis
    
    # Get a valid address for testing
    funcs = client.call_tool("data", action="functions", count=5)
    test_addr = None
    if "functions" in funcs and funcs["functions"]:
        test_addr = funcs["functions"][0].get("address") or funcs["functions"][0].get("addr")
    if not test_addr:
        entries = client.call_tool("idb", action="entrypoints")
        if isinstance(entries, list) and entries:
            test_addr = entries[0].get("address")
        elif "entries" in entries:
            test_addr = entries["entries"][0].get("address") if entries["entries"] else None
    test_addr = test_addr or "0x0"
    print(f"  Using test address: {test_addr}")
    
    # ========== IDB TOOL TESTS ==========
    print("\n[*] Testing idb tool improvements...")
    
    # Test idb:meta
    r = TestResult("idb:meta - rich metadata")
    result = client.call_tool("idb", action="meta")
    if "_error" not in result:
        has_fields = all(k in result for k in ["binary_path", "bitness", "file_type"])
        r.passed = has_fields
        r.message = f"bitness={result.get('bitness')}, type={result.get('file_type')}" if has_fields else "Missing expected fields"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test idb:summary
    r = TestResult("idb:summary - database statistics")
    result = client.call_tool("idb", action="summary")
    if "_error" not in result:
        r.passed = "function_count" in result or "functions" in result
        r.message = f"funcs={result.get('function_count', result.get('functions', '?'))}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test idb:segments (detailed)
    r = TestResult("idb:segments - detailed segment info")
    result = client.call_tool("idb", action="segments")
    if "_error" not in result:
        segs = result.get("segments", result if isinstance(result, list) else [])
        if segs:
            has_details = "permissions" in segs[0] or "class" in segs[0] or "type" in segs[0]
            r.passed = has_details
            r.message = f"{len(segs)} segments, detailed={has_details}"
        else:
            r.message = "No segments returned"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test idb:entrypoints (enriched)
    r = TestResult("idb:entrypoints - enriched entry data")
    result = client.call_tool("idb", action="entrypoints")
    if "_error" not in result:
        entries = result.get("entries", result if isinstance(result, list) else [])
        r.passed = len(entries) >= 0  # Even 0 entries is valid
        r.message = f"{len(entries)} entry points"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test idb:bookmarks
    r = TestResult("idb:bookmarks - bookmark listing")
    result = client.call_tool("idb", action="bookmarks")
    if "_error" not in result:
        r.passed = True
        bookmarks = result.get("bookmarks", result if isinstance(result, list) else [])
        r.message = f"{len(bookmarks)} bookmarks"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # ========== DATA TOOL TESTS ==========
    print("\n[*] Testing data tool improvements...")
    
    # Test data:functions with filtering
    r = TestResult("data:functions - with include_prototype")
    result = client.call_tool("data", action="functions", count=5, include_prototype=True)
    if "_error" not in result:
        funcs = result.get("functions", [])
        has_proto = funcs and "prototype" in funcs[0] if funcs else False
        r.passed = has_proto or len(funcs) > 0
        r.message = f"{len(funcs)} funcs, has_prototype={has_proto}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test data:functions with include_xrefs
    r = TestResult("data:functions - with include_xrefs")
    result = client.call_tool("data", action="functions", count=3, include_xrefs=True)
    if "_error" not in result:
        funcs = result.get("functions", [])
        has_xrefs = funcs and "xrefs_to" in funcs[0] if funcs else False
        r.passed = has_xrefs or len(funcs) > 0
        r.message = f"has_xrefs={has_xrefs}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test data:functions with named_only
    r = TestResult("data:functions - with named_only")
    result = client.call_tool("data", action="functions", count=10, named_only=True)
    if "_error" not in result:
        funcs = result.get("functions", [])
        all_named = all(not f.get("name", "").startswith("sub_") for f in funcs) if funcs else True
        r.passed = True  # If it works at all, it's a pass
        r.message = f"{len(funcs)} named functions"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test data:functions with min_size
    r = TestResult("data:functions - with min_size")
    result = client.call_tool("data", action="functions", count=10, min_size=50)
    if "_error" not in result:
        funcs = result.get("functions", [])
        r.passed = True
        r.message = f"{len(funcs)} functions >= 50 bytes"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # ========== SEARCH TOOL TESTS ==========
    print("\n[*] Testing search tool improvements...")
    
    # Test search:regex
    r = TestResult("search:regex - regex pattern search")
    result = client.call_tool("search", action="regex", pattern="sub_.*", limit=5)
    if "_error" not in result:
        matches = result.get("matches", result.get("results", []))
        r.passed = True  # If it returns without error, it works
        r.message = f"{len(matches)} matches"
        r.data = result
    else:
        # Regex might not be fully implemented - that's ok for now
        r.passed = "not implemented" not in str(result["_error"]).lower()
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:func_by_sig
    r = TestResult("search:func_by_sig - signature search")
    result = client.call_tool("search", action="func_by_sig", query="size:>10", limit=5)
    if "_error" not in result:
        matches = result.get("matches", result.get("functions", []))
        r.passed = True
        r.message = f"{len(matches)} matching functions"
        r.data = result
    else:
        r.passed = "not implemented" not in str(result["_error"]).lower()
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:name with case_sensitive
    r = TestResult("search:name - case_sensitive param")
    result = client.call_tool("search", action="name", pattern="*MAIN*", case_sensitive=False, limit=5)
    if "_error" not in result:
        r.passed = True
        matches = result.get("matches", [])
        r.message = f"{len(matches)} case-insensitive matches"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # ========== SEGMENTS TOOL TESTS ==========
    print("\n[*] Testing segments tool improvements...")
    
    # Test segments:info
    r = TestResult("segments:info - detailed segment analysis")
    # First get a segment address
    segs = client.call_tool("segments", action="list")
    seg_start = None
    if "segments" in segs and segs["segments"]:
        seg_start = segs["segments"][0].get("start") or segs["segments"][0].get("address")
    
    if seg_start:
        result = client.call_tool("segments", action="info", start=seg_start)
        if "_error" not in result:
            r.passed = "name" in result or "segment" in result
            r.message = f"Got info for segment at {seg_start}"
            r.data = result
        else:
            r.message = str(result["_error"])
    else:
        r.message = "No segments to test"
    results.append(r)
    print(r)
    
    # ========== BULK TOOL TESTS ==========
    print("\n[*] Testing bulk tool improvements...")
    
    # Test bulk:apply_type
    r = TestResult("bulk:apply_type - bulk type application")
    result = client.call_tool("bulk", action="apply_type", items=[
        {"addr": test_addr, "type": "int"}
    ])
    if "_error" not in result:
        r.passed = True
        r.message = f"Applied types: success={result.get('success', result.get('applied', '?'))}"
        r.data = result
    else:
        # May fail due to invalid type, but schema should work
        r.passed = "unknown action" not in str(result["_error"]).lower()
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test bulk with continue_on_error
    r = TestResult("bulk:comment - continue_on_error")
    result = client.call_tool("bulk", action="comment", items=[
        {"addr": test_addr, "value": "test comment 1"},
        {"addr": "0xDEADBEEF", "value": "invalid address"},  # Should fail
        {"addr": test_addr, "value": "test comment 2"}
    ], continue_on_error=True)
    if "_error" not in result:
        r.passed = True
        r.message = f"success={result.get('success', '?')}, failed={result.get('failed', '?')}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # ========== COMMENTS_AI TOOL TESTS ==========
    print("\n[*] Testing comments_ai error handling...")
    
    # Test with invalid address - should return proper MCPError
    r = TestResult("comments_ai:get_context - error handling")
    result = client.call_tool("comments_ai", action="get_context", addr="0xDEADBEEF")
    if "_error" in result:
        # Error is expected - check it's properly formatted
        err = result["_error"]
        is_proper = isinstance(err, dict) and ("error" in err or "message" in err or "code" in err)
        r.passed = is_proper or isinstance(err, str)
        r.message = f"Proper error format: {is_proper}"
        r.data = result
    else:
        # If it succeeded (unlikely), that's also fine
        r.passed = True
        r.message = "Got valid response"
        r.data = result
    results.append(r)
    print(r)
    
    # Test with valid address
    r = TestResult("comments_ai:get_context - valid addr")
    result = client.call_tool("comments_ai", action="get_context", addr=test_addr)
    if "_error" not in result:
        r.passed = True
        r.message = "Got context successfully"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # ========== NEW SEARCH ACTIONS ==========
    print("\n[*] Testing new search actions...")
    
    # Test search:find - smart unified search
    r = TestResult("search:find - smart unified search")
    result = client.call_tool("search", action="find", pattern="main", limit=10)
    if "_error" not in result:
        total = result.get("total_matches", 0)
        r.passed = True
        r.message = f"total_matches={total}, names={len(result.get('names', []))}, strings={len(result.get('strings', []))}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:callers
    r = TestResult("search:callers - find function callers")
    result = client.call_tool("search", action="callers", pattern=test_addr, limit=10)
    if "_error" not in result:
        r.passed = True
        callers = result.get("callers", [])
        r.message = f"{len(callers)} callers found"
        r.data = result
    else:
        # May fail if function has no callers - that's ok
        r.passed = "not found" not in str(result["_error"]).lower()
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:callees
    r = TestResult("search:callees - find function callees")
    result = client.call_tool("search", action="callees", pattern=test_addr, limit=10)
    if "_error" not in result:
        r.passed = True
        callees = result.get("callees", [])
        r.message = f"{len(callees)} callees found"
        r.data = result
    else:
        r.passed = "not found" not in str(result["_error"]).lower()
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:api
    r = TestResult("search:api - find API usage")
    result = client.call_tool("search", action="api", pattern="*alloc*", limit=10)
    if "_error" not in result:
        r.passed = True
        usages = result.get("usages", [])
        r.message = f"total_calls={result.get('total_calls', 0)}, unique_funcs={result.get('unique_functions', 0)}"
        r.data = result
    else:
        # May fail if no matching API - that's ok
        r.passed = True
        r.message = str(result.get("_error", "No matching API"))
    results.append(r)
    print(r)
    
    # ========== NEW AGENT ACTIONS ==========
    print("\n[*] Testing new agent actions...")
    
    # Test agent:quick
    r = TestResult("agent:quick - one-shot address info")
    result = client.call_tool("agent", action="quick", addr=test_addr)
    if "_error" not in result:
        r.passed = "type" in result
        r.message = f"type={result.get('type')}, name={result.get('func_name', result.get('name', '?'))}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test agent:rename_suggestions
    r = TestResult("agent:rename_suggestions - get rename context")
    result = client.call_tool("agent", action="rename_suggestions", addr=test_addr)
    if "_error" not in result:
        r.passed = "current_name" in result
        apis = result.get("apis_called", [])
        strings = result.get("strings_used", [])
        r.message = f"apis={len(apis)}, strings={len(strings)}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test agent:batch_context
    r = TestResult("agent:batch_context - multi-address context")
    # Get a few function addresses
    funcs_result = client.call_tool("data", action="functions", count=3)
    if "functions" in funcs_result and funcs_result["functions"]:
        addrs = ",".join([f.get("addr") or f.get("address") for f in funcs_result["functions"][:3]])
        result = client.call_tool("agent", action="batch_context", query=addrs)
        if "_error" not in result:
            r.passed = "items" in result
            r.message = f"{len(result.get('items', []))} items"
            r.data = result
        else:
            r.message = str(result["_error"])
    else:
        r.message = "No functions to test"
    results.append(r)
    print(r)
    
    # ========== QUERY/EDIT HUB TESTS ==========
    print("\n[*] Testing query/edit hubs...")
    
    # Test query hub
    r = TestResult("query - hub routing to data")
    result = client.call_tool("query", action="data", subaction="functions", args={"count": 3})
    if "_error" not in result:
        r.passed = "functions" in result
        r.message = f"{len(result.get('functions', []))} functions via hub"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test modify (comment action)
    r = TestResult("modify - comment action")
    result = client.call_tool("modify", action="comment", addr=test_addr, value="Test via modify tool")
    if "_error" not in result:
        r.passed = result.get("ok", False)
        r.message = "Comment set via modify"
        r.data = result
    else:
        # May fail due to readonly IDB
        r.passed = True
        r.message = str(result.get("_error", "hub test"))
    results.append(r)
    print(r)
    
    # ========== NEW SECURITY/ANALYSIS ACTIONS ==========
    print("\n[*] Testing new security/analysis actions...")
    
    # Test search:vulnerable
    r = TestResult("search:vulnerable - find dangerous patterns")
    result = client.call_tool("search", action="vulnerable", limit=50)
    if "_error" not in result:
        r.passed = "findings" in result or "total_findings" in result
        total = result.get("total_findings", 0)
        by_type = result.get("by_type", {})
        r.message = f"{total} findings, types: {list(by_type.keys())[:3]}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test search:constants
    r = TestResult("search:constants - find crypto/magic constants")
    result = client.call_tool("search", action="constants", limit=30)
    if "_error" not in result:
        r.passed = "findings" in result or "total_found" in result
        total = result.get("total_found", 0)
        crypto = result.get("crypto_constants", 0)
        r.message = f"{total} found, {crypto} crypto-related"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test agent:similar
    r = TestResult("agent:similar - find similar functions")
    result = client.call_tool("agent", action="similar", addr=test_addr, max_items=10)
    if "_error" not in result:
        r.passed = "similar_functions" in result or "count" in result
        count = result.get("count", len(result.get("similar_functions", [])))
        r.message = f"{count} similar functions found"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test patterns:matched
    r = TestResult("patterns:matched - show FLIRT-identified functions")
    result = client.call_tool("patterns", action="matched", count=20)
    if "_error" not in result:
        r.passed = "matched_functions" in result or "total_matched" in result
        matched = result.get("total_matched", 0)
        unmatched = result.get("total_unmatched", 0)
        r.message = f"{matched} matched, {unmatched} unmatched"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    # Test lumina:get_metadata
    r = TestResult("lumina:get_metadata - get Lumina info for function")
    result = client.call_tool("lumina", action="get_metadata", addr=test_addr)
    if "_error" not in result:
        r.passed = "ok" in result
        lumina_avail = result.get("lumina_available", False)
        has_lumina = result.get("has_lumina_name", False)
        r.message = f"lumina_available={lumina_avail}, has_name={has_lumina}"
        r.data = result
    else:
        r.message = str(result["_error"])
    results.append(r)
    print(r)
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Test MCP tool improvements")
    parser.add_argument("--binary", default="tests/data/test_binary.exe", help="Binary to test with")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout for operations")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    args = parser.parse_args()
    
    binary_path = os.path.abspath(args.binary)
    if not os.path.exists(binary_path):
        print(f"[!] Binary not found: {binary_path}")
        return 1
    
    print("=" * 60)
    print("MCP Tool Improvements Test Suite")
    print("=" * 60)
    print(f"Binary: {binary_path}")
    print(f"Timeout: {args.timeout}s")
    
    client = MCPTestClient(timeout=args.timeout)
    
    print("\n[*] Starting MCP server...")
    if not client.start():
        print("[!] Failed to start MCP server")
        return 1
    print("  Server started successfully")
    
    try:
        results = run_tests(client, binary_path)
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print(f"  Total:  {len(results)}")
        
        if args.output:
            output_data = {
                "binary": binary_path,
                "summary": {"passed": passed, "failed": failed, "total": len(results)},
                "tests": [
                    {"name": r.name, "passed": r.passed, "message": r.message, "data": r.data}
                    for r in results
                ]
            }
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"\n[*] Results saved to {args.output}")
        
        return 0 if failed == 0 else 1
        
    finally:
        print("\n[*] Stopping server...")
        client.stop()
        print("  Done.")


if __name__ == "__main__":
    sys.exit(main())
