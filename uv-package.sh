#!/bin/bash
uv run server.py --generate-only
mkdir -p src/ida_pro_mcp
cp server.py src/ida_pro_mcp
cp mcp-plugin.py src/ida_pro_mcp
cp server_generated.py src/ida_pro_mcp
uv publish