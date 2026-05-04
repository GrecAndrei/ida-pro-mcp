#!/usr/bin/env python3
"""
Profile hot paths in the MCP server.
"""
import os, sys, time, cProfile, pstats, io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["IDA_MCP_DISABLE_STUCK_DETECTION"] = "1"
os.environ["IDA_MCP_DISABLE_RATE_LIMIT"] = "1"

from ida_pro_mcp.host.server import IDAMCPServer

def profile_tool_dispatch():
    server = IDAMCPServer()
    # Warmup
    for _ in range(5):
        server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "session", "arguments": {"action": "discover"}}})
    
    # Profile
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(100):
        server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "session", "arguments": {"action": "discover"}}})
        server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "blackboard", "arguments": {"action": "write", "title": "test", "category": "test"}}})
        server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "blackboard", "arguments": {"action": "list", "category": "test"}}})
    pr.disable()
    
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumtime")
    ps.print_stats(30)
    print(s.getvalue())

if __name__ == "__main__":
    profile_tool_dispatch()
