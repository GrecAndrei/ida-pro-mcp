# IDA MCP Development - Parallel Session Coordination

## Session A (This Session) - Static Analysis Enhancements

**Tools being implemented:**

1. `emulate` - Code emulation (Appcall, snippet execution, crypto decryption)
2. `export` - Output formats (BinExport, IDC, listing, HTML reports)
3. `history` - Database versioning (undo tree, snapshots, annotation tracking)

**Files being modified:**

- `src/ida_pro_mcp/ida_mcp/api_consolidated.py` (lines 4680+)
- `ida_mcp_stdio.py` (TOOLS list, TOOL_DESCRIPTIONS)
- `README.md` (tool tables)

---

## Session B - Dynamic Analysis & Remaining Features

**Suggested tools to implement:**

1. `strings_xref` - Advanced string analysis (decryption detection, encoding inference)
2. `entropy` - Entropy analysis (packed sections, crypto detection)
3. `imports_deep` - Deep import analysis (thunk resolution, delay imports)
4. `comments_ai` - AI-optimized comment management (bulk, structured)
5. `nav` - Navigation helpers (bookmark management, cursor control)
6. `colorize` - Code region coloring and highlighting

**Files to modify:**

- `src/ida_pro_mcp/ida_mcp/api_consolidated.py` (add NEW section at END, after line ~5300)
- `ida_mcp_stdio.py` (TOOLS list, TOOL_DESCRIPTIONS)
- `README.md` (tool tables)

---

## Coordination Rules

1. **Session A adds tools 27-29** (emulate, export, history)
2. **Session B adds tools 30-35** (strings_xref, entropy, imports_deep, comments_ai, nav, colorize)
3. **Don't modify each other's tool implementations**
4. **Both can update README and stdio - just append to lists**
5. **Final step: One session consolidates and cleans up**

---

## Current Tool Count: 26

- After Session A: 29 tools
- After Session B: 35 tools
