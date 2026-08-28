# IDA Pro MCP Technical Reference

## Public contract

Repository-wide contribution and maintenance rules live in
[`AGENTS.md`](../AGENTS.md). This document focuses on implementation details.

`src/ida_pro_mcp/host/agent_operations.py` is the single source of truth for
the agent-facing MCP interface. Each `AgentOperation` contains:

- a public `ida_*` name and concise description;
- a strict JSON input schema and a valid example;
- a mapping to one legacy backend tool/action; and
- data used to generate `ida_help`, the installed skill reference, and
  `docs/TOOLS_REFERENCE.md`.

The host server advertises this catalog by default. It validates public
arguments before translating a call into the existing IDA backend dispatcher.
The backend continues to perform policy checks, session selection, RPC
admission, and execution.

## Compatibility backend

`src/ida_pro_mcp/ida_mcp/tools/` and the associated registry retain the older
`tool(action=...)` implementation for existing scripts. Set
`IDA_MCP_TOOL_SURFACE=legacy` to advertise that interface intentionally.

New agent-facing features must not add a broad action enum. Add an exact
`AgentOperation` instead, then expose only the operation needed by the
workflow.

## Adding an operation

1. Add an `AgentOperation` in `src/ida_pro_mcp/host/agent_operations.py` with a strict schema,
   example, backend mapping, and concise description.
2. Add a behavior-focused contract test for the public schema and mapping.
3. Run `python scripts/generate_tool_skills.py` to refresh the installed skill
   and documentation reference.
4. Run `python scripts/check_schema_integrity.py` and `pytest -q`.

## Architecture

```text
MCP client
  → agent_operations (schema validation + mapping)
  → host server (policy, sessions, response handling)
  → legacy tool/action dispatcher
  → local TCP bridge
  → IDA Pro SDK
```
