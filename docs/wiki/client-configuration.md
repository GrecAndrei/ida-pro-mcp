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

The top-level key is client-specific:
- Standard JSON `mcpServers`: Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Gemini CLI, Antigravity, Pi Coding Agent, Prime Agent, ZCode, Kimi Code, MiniMax Code.
- JSON with `servers`: Copilot CLI, VS Code.
- JSON with `mcp`: OpenCode (`opencode.json`).
- JSON5 with nested `mcp.servers`: OpenClaw (`openclaw.json`).
- TOML with `mcp_servers`: Codex (`config.toml`).
- YAML with `mcp_servers`: Hermes Agent (`config.yaml`).

Let the installer generate the client-specific shape automatically.

### Automated and Uninstallation Options

For non-interactive unattended installation:

```bash
python install.py --auto
```

To cleanly uninstall the MCP server entries, launcher shims, and IDA plugins:

```bash
python install.py --uninstall
```

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

## Intelligence provider configuration

### Turning the whole layer off

`IDA_MCP_INTELLIGENCE_ENABLED` is the kill switch for the entire intelligence
layer. It is **orthogonal** to the mode, and the two combine:

| Value | Effect |
| --- | --- |
| unset | Follow the mode. This is the default. |
| `1` / `true` | Permit the selected provider, without choosing one. |
| `0` / `false` | **Disable the whole layer.** |

An explicit `false` is an unconditional kill switch and outranks every other
configuration source: the `IDA_MCP_INTELLIGENCE_MODE` environment variable, the
persisted `intelligence.json` state, and the mode the installer wrote into your
client configuration. It also short-circuits leftover provider, legacy, and
mode-conflict checks, so **switching off can never be blocked by other
configuration** and can never stop the host from starting deterministically.

Mode *values* are still validated first, so a typo such as `IDA_MCP_INTELLIGENCE_MODE=jevv`
is reported as an error rather than silently treated as off. A malformed
switch value fails closed.

With the layer off, no provider is constructed, and the deterministic pool
order, heuristic and structural ranking, and lexical signature retrieval all
remain available. Advisory calls degrade instead of failing: they keep the
fail-closed shape (`advisory_order` null, `applied` false, `fail_closed_order`
populated). `ida_intelligence_status` reports `intelligence_enabled`,
`deterministic_only`, and `disabled_reason` — either `kill_switch` or `mode`.

The installer always writes the resolved posture explicitly, so you can see the
state as one readable line in your client config rather than inferring it.

### Selecting a provider

The provider mode is explicit: `disabled` (default), `jev`, or `custom`.
Deterministic IDA analysis and lexical retrieval work in disabled mode. Jev
uses `TYPESAFE_API_KEY` over host-side HTTP; custom mode requires an HTTPS base
URL, an explicit origin allowlist, a model, and a credential environment
variable or file. Loopback HTTP requires an explicit opt-in flag. Legacy
embedding, Gemini, native, and reranker settings are rejected rather than
translated. Typed questions are `choice`/`noul`/`score` only; answers cannot
authorize mutations or write findings. The shared advisor stage returns
bounded advisory metadata and may suggest a deterministic `ida_*` follow-up;
it never invokes the suggestion. See [Intelligence](core/intelligence.md).

In the interactive wizard, choosing "Off (deterministic and lexical analysis
only)" is the first option. Selecting a provider *installs* it but only *arms*
it when you confirm, and the installer warns when a provider is configured while
the layer is off.

### Jev spend is opt-in

Jev is metered, so the host **never applies a price by default**. Leaving
`IDA_MCP_JEV_INPUT_USD_PER_MTOK` and `IDA_MCP_JEV_OUTPUT_USD_PER_MTOK` unset
leaves pricing unconfigured, and the usage ledger blocks every Jev request
*before transport* with `reason="unknown_pricing"`. Setting both prices is your
explicit acknowledgment that paid traffic is intended. Alternatively, set
`IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING=1` to accept unpriced usage.
`ida_usage_status` reports `pricing_configured` so the gate state is visible.
See [Intelligence](core/intelligence.md) for the reference rate and budget
ceilings.

### Credentials

The installer never writes API keys into client configuration. Providers read
credentials at request time. Review `ida_intelligence_status`,
`ida_usage_status`, and `ida_usage_report` after connecting.

References: [installer README](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md),
[client configuration templates](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/installer/client_configs.json),
[installer source](https://github.com/GrecAndrei/ida-pro-mcp/tree/master/src/ida_pro_mcp/installer).
