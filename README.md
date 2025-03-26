# User Feedback MCP

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

## Prompt Engineering

For the best results, add the following to your custom prompt:

> TODO

## Installation (Cline)

To install the MCP server in Cline, follow these steps:

1. Install [uv](https://github.com/astral-sh/uv) globally:
   - Windows: `pip install uv`
   - Linux/Mac: `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. Clone this repository, for this example `C:\MCP\user-feedback-mcp`.
3. Navigate to the Cline _MCP Servers_ configuration (see screenshot).
4. Click on the _Installed_ tab.
5. Click on _Configure MCP Servers_, which will open `cline_mcp_settings.json`.
6. Add the `ida-pro-mcp` server:

```json
{
  "mcpServers": {
    "github.com/mrexodia/ida-pro-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "c:\\MCP\\ida-pro-mcp",
        "run",
        "server.py"
      ],
      "timeout": 600,
      "autoApprove": [
        "user_feedback"
      ]
    }
  }
}

```

## Development

```sh
uv run fastmcp dev server.py
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

## Available tools

```
<use_mcp_tool>
<server_name>github.com/mrexodia/user-feedback-mcp</server_name>
<tool_name>user_feedback</tool_name>
<arguments>
{
  "project_directory": "C:/MCP/user-feedback-mcp",
  "summary": "I've implemented the changes you requested."
}
</arguments>
</use_mcp_tool>
```