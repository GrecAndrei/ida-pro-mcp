# OpenCode Integration Guide

This guide explains how IDA Pro MCP Server integrates with [OpenCode](https://opencode.ai), the open source AI coding agent.

## What is OpenCode?

OpenCode is an open source AI coding agent available as:
- Terminal-based interface (TUI)
- Desktop application
- IDE extension

It supports 75+ LLM providers through Models.dev and features multi-session support, LSP integration, and extensive customization through plugins, agents, and commands.

## Installation

The IDA Pro MCP installer automatically configures OpenCode. Simply run:

```bash
python install.py
```

The installer will:
1. Create the OpenCode configuration directory at `~/.config/opencode/`
2. Add the IDA Pro MCP server to `opencode.json`
3. Configure the server with proper environment variables (IDADIR)

## Configuration

OpenCode uses a different MCP schema than other clients. The installer creates a configuration like this:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ida-pro-mcp": {
      "type": "local",
      "command": [
        "/path/to/ida-pro-mcp/.venv/Scripts/python.exe",
        "-u",
        "/path/to/ida-pro-mcp/ida_mcp_stdio.py"
      ],
      "enabled": true,
      "environment": {
        "IDADIR": "/path/to/IDA"
      }
    }
  }
}
```

### Default environment injected by installer

The installer sets these defaults to maximize direct LLM usability:

- `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS=1`
- `IDA_MCP_TOOLS_LIST_MODE=full`
- `IDA_MCP_RESPONSE_MODE=compact`
- `IDA_MCP_QOL_MODE=balanced`

This means OpenCode receives full per-tool descriptions and full input schemas from `tools/list` by default.

### Key Differences from Other MCP Clients

- **Format**: OpenCode uses a `command` array (not separate `command` and `args`)
- **Type**: Must specify `"type": "local"` for local MCP servers
- **Schema**: Follows OpenCode's native MCP schema, not Claude Desktop's format
- **JSONC Support**: OpenCode supports JSON with comments (JSONC)

## Using IDA Pro MCP with OpenCode

Once configured, restart OpenCode if it's running. You can then use IDA Pro tools in your prompts:

```
Analyze the binary at /path/to/sample.exe using IDA Pro MCP.
First, open a session and get the entry points.
```

### Explicit Tool Usage

You can explicitly request OpenCode to use the IDA Pro MCP tools:

```
Use ida-pro-mcp to decompile the function at address 0x401000
```

### Agent-Level Configuration

For better control, you can configure specific agents to use IDA Pro MCP:

```json
{
  "mcp": {
    "ida-pro-mcp": {
      "type": "local",
      "command": ["python", "-u", "ida_mcp_stdio.py"],
      "enabled": true
    }
  },
  "tools": {
    "ida-pro-mcp*": false
  },
  "agent": {
    "reverse-engineer": {
      "description": "Specialized agent for binary analysis",
      "tools": {
        "ida-pro-mcp*": true
      }
    }
  }
}
```

This disables IDA Pro MCP globally but enables it for the `reverse-engineer` agent only.

## Verification

To verify the configuration:

```bash
# List all MCP servers
opencode mcp list

# Check if ida-pro-mcp is listed and enabled
```

## Troubleshooting

### Server Not Loading

If the server doesn't appear:

1. Check the config file exists at `~/.config/opencode/opencode.json`
2. Verify the `command` paths are correct
3. Ensure Python path points to the virtual environment
4. Check IDADIR environment variable is set correctly

### Permission Issues

On Unix-like systems, ensure the Python executable is executable:

```bash
chmod +x ~/.local/share/ida-pro-mcp/.venv/bin/python
```

### JSONC Parsing

OpenCode supports comments in JSON files. The installer strips comments before parsing, but you can add comments manually:

```jsonc
{
  "mcp": {
    "ida-pro-mcp": {
      // Local MCP server for IDA Pro
      "type": "local",
      "command": ["..."],
      "enabled": true
    }
  }
}
```

## Manual Configuration

If you need to manually configure OpenCode:

1. Create or edit `~/.config/opencode/opencode.json`
2. Add the MCP server under the `mcp` key
3. Use the schema shown above
4. Restart OpenCode

## Platform-Specific Notes

### Windows
- Config location: `%USERPROFILE%\.config\opencode\opencode.json`
- Use Windows-style paths with double backslashes or forward slashes
- Python executable: `.venv\Scripts\python.exe`

### Linux/macOS
- Config location: `~/.config/opencode/opencode.json`
- Python executable: `.venv/bin/python`
- May need to set executable permissions

## References

- [OpenCode Documentation](https://opencode.ai/docs)
- [OpenCode MCP Servers Guide](https://opencode.ai/docs/mcp-servers)
- [OpenCode Config Schema](https://opencode.ai/config.json)
- [IDA Pro MCP README](../README.md)
