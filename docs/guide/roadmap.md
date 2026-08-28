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

## Product surface tiers

The default agent surface (`tool_surface == "agent"`) advertises every `ida_*`
operation from the catalog in `tools/list` — the full
`list_agent_operations()` catalog (104 operations; the count is pinned by
`tests/test_docs_sync.py` / `tests/host/test_swarm_p14_stale_docs.py`). There is
no hidden default subset:
what a fresh agent sees is the full catalog.

The tiering below applies only to the legacy `IDA_MCP_TOOL_SURFACE=legacy`
backend:

- **Tier A** — the legacy `tools/list` surface (`ADVERTISED_TOOLS` in
  `host/schemas_data.py`, ~17 tools). This is what a fresh agent sees on the
  legacy surface.
- **Tier B** — the full legacy `TOOLS` registry. Every Tier B tool remains
  callable by its exact name (backward compatible) but is hidden from the
  legacy `tools/list` (via `HIDDEN_TOOLS_IN_LIST`).
- **Tier C** — compact action enums (`ADVERTISED_ACTIONS`). High-cardinality
  tools advertise a reduced action set in lean/ultra schema mode; the full
  `TOOL_ACTIONS` enum is still accepted for exact-name calls.

Promotion rule: a capability moves into a higher tier only once it has an
operation schema, a valid example, an `ida_help` entry, and a behavioral test.

## Current focus

- Expand the action-specific catalog only when a workflow needs another exact
  operation.
- Promote advanced legacy capabilities after they have an operation schema,
  example, help entry, and behavioral test.
- Remove unused legacy backend routes once compatibility telemetry and release
  notes permit it.
- Keep live IDA validation separate from host-side operation contract tests.
