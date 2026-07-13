# Roadmap

## Public agent contract

The default MCP interface is the action-specific `ida_*` operation catalog in
`host.agent_operations`. It is the source of truth for:

- advertised `tools/list` schemas;
- backend dispatch mappings;
- `ida_help` responses;
- Codex, Claude Code, and OpenCode skill references; and
- operation contract tests.

The previous broad `tool(action=...)` backend remains behind
`IDA_MCP_TOOL_SURFACE=legacy` for compatibility, but is no longer the agent
surface or documentation source.

## Current focus

- Expand the action-specific catalog only when a workflow needs another exact
  operation.
- Promote advanced legacy capabilities after they have an operation schema,
  example, help entry, and behavioral test.
- Remove unused legacy backend routes once compatibility telemetry and release
  notes permit it.
- Keep live IDA validation separate from host-side operation contract tests.
