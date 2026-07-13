# IDA Pro MCP

> **Alpha (0.9.x)** — the public agent interface is evolving quickly.

`ida-pro-mcp` lets MCP clients inspect and annotate binaries through IDA Pro.
It runs deterministic IDA SDK operations; it does not run an LLM service.

## Agent-first MCP interface

The default MCP surface is a small set of action-specific `ida_*` operations.
Every advertised tool has an exact JSON schema, required operands, and an
example. Models do not need to infer arguments for a broad `tool(action=...)`
wrapper.

```text
ida_open_binary → ida_session_state → ida_overview → ida_find
→ ida_decompile / ida_disassemble / ida_xrefs_to → ida_write_finding
```

Use `ida_help(topic="ida_decompile")` for an exact operation contract or
`ida_help(query="strings")` to discover an operation. Help is served over MCP,
so it works in every client without filesystem access.

The previous broad tool/action API remains available only for compatibility
with existing scripts. Set `IDA_MCP_TOOL_SURFACE=legacy` to advertise it.

## Install

```bash
python install.py
```

The installer creates the runtime environment, finds IDA, configures supported
MCP clients, and installs the portable `ida-pro-mcp` skill with its reference
material for Codex, Claude Code, and OpenCode.

Requirements: IDA Pro 9.2+ and Python 3.11+.

For development:

```bash
git clone https://github.com/GrecAndrei/ida-pro-mcp.git
cd ida-pro-mcp
pip install -e .
python -u -m ida_pro_mcp.host.server
```

## Quick start

Open a binary:

```json
{"name":"ida_open_binary","arguments":{"binary_path":"/path/to/binary"}}
```

Orient yourself:

```json
{"name":"ida_session_state","arguments":{}}
{"name":"ida_overview","arguments":{}}
```

Find and inspect code:

```json
{"name":"ida_find","arguments":{"query":"recv","limit":20}}
{"name":"ida_decompile","arguments":{"address":"0x401000"}}
{"name":"ida_xrefs_to","arguments":{"address":"0x401000"}}
```

Record an evidence-backed finding:

```json
{
  "name":"ida_write_finding",
  "arguments":{
    "title":"packet receive handler",
    "content":"Parses inbound data before dispatching on the command byte.",
    "address":"0x401000",
    "confidence":0.8
  }
}
```

Mutations require an explicit acknowledgement:

```json
{"name":"ida_rename","arguments":{"address":"0x401000","name":"handle_recv","risk_ack":true}}
```

## Architecture

- `host.agent_operations` is the public operation contract: schemas,
  descriptions, examples, backend mappings, in-band help, and generated skill
  references all derive from it.
- `host.server` exposes MCP JSON-RPC over stdio and manages IDA sessions.
- `ida_mcp/tools/` remains the compatibility/runtime backend that performs
  IDA SDK work through the TCP bridge.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_TOOL_SURFACE` | `agent` | `agent` advertises exact `ida_*` operations; `legacy` exposes the previous broad tool/action catalog. |
| `IDA_MCP_RESPONSE_MODE` | `compact` | Use `full` for fuller result payloads. |
| `IDA_MCP_POLICY_MODE` | `assist` | Controls mutation policy and acknowledgements. |

## Skills and docs

The checked-in agent skill is generated from the operation registry:

```bash
python scripts/generate_tool_skills.py
```

It installs as `ida-pro-mcp/SKILL.md` with
`ida-pro-mcp/references/operations.md` beside it. The skill is guidance, not a
hidden schema dependency: MCP tool schemas and `ida_help` are authoritative.

## Development

```bash
ruff check .
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
pytest -q
```

Live IDA integration still requires a local IDA installation and target binary.
