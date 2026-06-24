# OpenCode Integration Guide

[OpenCode](https://opencode.ai) is an open source AI coding agent with MCP support.

## Installation

The IDA Pro MCP installer automatically configures OpenCode:

```bash
python install.py
```

The installer writes `~/.config/opencode/opencode.json` and installs skills to `~/.config/opencode/skills/`.

## Configuration

The installer creates a config like this:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ida-pro-mcp": {
      "type": "local",
      "command": [
        "/home/user/.local/share/ida-pro-mcp/.venv/bin/python",
        "-u",
        "-m",
        "ida_pro_mcp.host.server"
      ],
      "enabled": true,
      "environment": {
        "IDA_MCP_RESPONSE_MODE": "compact",
        "IDA_MCP_QOL_MODE": "balanced",
        "IDA_MCP_TOOLS_LIST_MODE": "ultra",
        "IDA_MCP_BATCH_COMPACT": "1",
        "IDA_MCP_COMPACT_MAX_ITEMS": "48",
        "IDA_MCP_COMPACT_MAX_STRING": "1400",
        "IDA_MCP_COMPACT_CHAR_BUDGET": "30000",
        "IDA_MCP_TRUNCATE_TOKENS": "2000",
        "IDADIR": "/path/to/ida-pro"
      }
    }
  }
}
```

### Key environment variables

| Variable | Value | Why |
|----------|-------|-----|
| `IDA_MCP_TOOLS_LIST_MODE` | `ultra` | ~9.5k tokens per `tools/list` call. Do not set to `full` (~58k tokens). |
| `IDA_MCP_RESPONSE_MODE` | `compact` | Compact responses by default. Use `_response_mode='full'` per-call when needed. |
| `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS` | _(unset or `0`)_ | Setting this to `1` overrides `TOOLS_LIST_MODE` to `full` unconditionally — do not set it. |

### MCP resources

MCP resources (`ida://state`, `ida://blackboard/frontier`, etc.) are defined in the protocol but are **application-driven** — OpenCode does not auto-inject them into context. The LLM cannot read them autonomously.

Use `session(action='state')` instead of `ida://state`.

## Skills

The installer copies auto-generated skills to `~/.config/opencode/skills/`:

- `ida-start` — orientation, IDA key shortcuts, first-turn playbook
- `ida-core` — session, batch, bookmarks, truncation
- `ida-analysis` — decompile, search, data, funcs, types, modify
- `ida-security` — classify, gadgets, crypto, ABI, deobfuscate
- `ida-advanced` — ctree, microcode, graph, imports, export, history
- `ida-debug` — debugger, coverage, traces
- `ida-workflow` — blackboard, firmware, intelligence, taint, governance
- `ida-project` — save/load IDB, scripts, recent files

Invoke with `/ida-start`, `/ida-analysis`, etc. in OpenCode.

Regenerate after tool metadata changes:
```bash
ida-pro-mcp-install --only skills
```

## Platform-specific notes

- **Linux/macOS**: config at `~/.config/opencode/opencode.json`, Python at `.venv/bin/python`
- **Windows**: config at `%USERPROFILE%\.config\opencode\opencode.json`, Python at `.venv\Scripts\python.exe`

## Troubleshooting

**Server not loading**: Verify the `command` path points to the venv python and `IDADIR` is correct.

**Large context usage**: Check that `IDA_MCP_TOOLS_LIST_MODE=ultra` and `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS` is unset.

**Changes not taking effect after reinstall**: Kill the running MCP server process so OpenCode relaunches it with the updated package.
