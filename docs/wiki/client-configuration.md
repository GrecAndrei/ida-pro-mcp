# Configure an MCP client

The installer can configure supported MCP clients for the local server. This
is preferable to copying a guessed configuration: client file locations and
formats vary, while the installer knows the generated server configuration.

## Recommended path

From the repository root, run:

```bash
python install.py
```

In a non-interactive environment, use:

```bash
python install.py --yes --no-interactive
```

Review the installer output and the generated configuration
before starting the client. The installer writes a managed server entry named
`ida-pro-mcp`; it also creates backups when it updates an existing client
configuration.

If you use an editable checkout instead of the managed runtime, the source
launch form is:

```bash
python -u -m ida_pro_mcp.host.server
```

The server's supported public surface is the exact-schema `ida_*` catalog. Do
not configure a new client around the old broad `tool(action=...)` interface
unless you are maintaining an older script; that interface is a compatibility
backend selected with `IDA_MCP_TOOL_SURFACE=legacy`.

## Manual stdio entry

Use the installer when possible. If a client must be configured by hand, its
stdio entry needs the Python executable from the managed environment and the
module launch arguments. Replace the placeholders; do not copy a path from
another machine.

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "/path/to/managed-install-root/.venv/bin/python",
      "args": ["-u", "-m", "ida_pro_mcp.host.server"],
      "env": {
        "IDA_PRO_MCP_HOME": "/path/to/ida-pro-mcp-data",
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

The top-level key is client-specific: many JSON clients use `mcpServers`,
while some use `servers`, OpenCode uses `mcp`, and Codex uses TOML
`mcp_servers`. Let the installer generate the client-specific shape when it
supports that client.

## Verify the connection

After configuration, ask the client to discover or call:

```text
ida_help(query="ida_overview")
```

Then open a test binary and call `ida_session_state`. A successful first call
should identify the active session or explain that no binary is open.

If the client cannot start the server:

1. Confirm the configured executable or module launch points at the intended
   checkout or installed environment.
2. Run the source launch command directly to expose Python or IDA discovery
   errors.
3. Check that IDA Pro 9.2+ and Python 3.11+ are available.
4. Re-run `python install.py` rather than hand-editing an unknown client
   format.
5. Use `ida_session_health` after the server connects but a runtime fails.

The installer records an install report under its managed install root. On a
failed install it attempts to restore configuration backups by default; keep
the report and error log when diagnosing a partial setup.

## Optional retrieval configuration

Embedding and reranking are not needed for the first session. If you install
them later, use the installer options documented in the
[retrieval guide](search-and-retrieval). Local retrieval is the default
direction; Gemini is explicitly opt-in. Never place a cloud credential in a
shared or checked-in client configuration.

The installer may persist an AI Studio key into the generated MCP client's
environment block when you explicitly provide it. The key is not written to
`embedder.json`; still treat the client configuration as sensitive.

References: [installer README](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md),
[client configuration templates](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/installer/client_configs.json),
[installer source](https://github.com/GrecAndrei/ida-pro-mcp/tree/master/src/ida_pro_mcp/installer).
