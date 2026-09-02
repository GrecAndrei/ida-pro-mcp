# OpenCode Integration Guide

The installer configures OpenCode and installs one portable `ida-pro-mcp`
skill. Its operation reference is installed inside the skill directory, so it
remains readable outside the source checkout.

```bash
python install.py
```

The resulting MCP configuration starts `ida_pro_mcp.host.server`. Its default
tool surface is `agent`: action-specific `ida_*` tools with complete JSON
schemas.

```json
{
  "mcp": {
    "ida-pro-mcp": {
      "type": "local",
      "command": ["/home/user/.local/share/ida-pro-mcp/.venv/bin/python", "-u", "-m", "ida_pro_mcp.host.server"],
      "enabled": true,
      "environment": {
        "IDA_MCP_TOOL_SURFACE": "agent",
        "IDA_MCP_RESPONSE_MODE": "compact",
        "IDADIR": "/path/to/ida-pro"
      }
    }
  }
}
```

## First calls

```text
ida_open_binary(binary_path="/path/to/binary")
ida_session_state()
ida_overview()
ida_find(query="recv")
ida_decompile(address="0x401000")
```

Use `ida_help(topic="ida_decompile")` for an in-band schema and example. Call
`ida_session_state()` explicitly to orient before analysis.

Set `IDA_MCP_TOOL_SURFACE=legacy` only for existing scripts that still call
the older broad `tool(action=...)` APIs.
