# IDA MCP Tool Doc: `xref_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `xref_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Cross-reference and callgraph analysis with compact output by default. Actions: `call_chain`, `common_callers`, `common_callees`, `hub_functions`, `leaf_functions`, `recursive`, `dominator`, `influence`, `dependency_graph`, `dead_functions`.

## Actions
- `call_chain`
- `common_callers`
- `common_callees`
- `hub_functions`
- `leaf_functions`
- `recursive`
- `dominator`
- `influence`
- `dependency_graph`
- `dead_functions`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- Core: `action`, `addr`, `addr2`, `addrs`, `depth`, `limit`, `offset`.
- Optional: `include_items=true` for structured arrays.
- Directional actions (`influence`, `dependency_graph`): `direction=forward|backward|both`.

## Invocation Guidance
- Prefer compact responses first, then zoom in via narrower `depth`, `offset`, and `limit`.
- Use `include_items=true` only when machine-readable arrays are needed.
- For graph exploration, start with `dependency_graph` + low depth before deep scans.
