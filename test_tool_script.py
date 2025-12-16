import json
import sys

# Add API path
sys.path.insert(0, "C:\\Users\\REDACTED\\Desktop\\idamcp\\src\\ida_pro_mcp\\ida_mcp")

# Import the tool
from api_consolidated import idb

# Execute the tool with arguments
try:
    kwargs = json.loads('{"action":"meta"}')
    result = idb(**kwargs)
except Exception as e:
    result = {"error": str(e), "traceback": __import__("traceback").format_exc()}

# Write output
with open("C:\\Users\\REDACTED\\.ida_mcp_cache\\test_tool.json", "w") as f:
    json.dump(result, f, default=str)

import ida_pro
ida_pro.qexit(0)
