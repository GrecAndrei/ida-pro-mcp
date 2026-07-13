---
name: "ida-pro-mcp"
description: "Use IDA Pro through the action-specific ida_* MCP operations."
---

# IDA Pro MCP
<!-- GENERATED: scripts/generate_tool_skills.py -->

Use the `ida_*` tools shown by MCP. Their JSON schemas are the complete call
contract; do not invent a `tool(action=...)` call when an `ida_*` operation is
available.

## First turn

1. `ida_open_binary(binary_path=...)` when no session is active.
2. `ida_session_state()` to see analysis progress and context.
3. `ida_overview()` for architecture and entry-point context.
4. Use `ida_find(query=...)`, then pass returned addresses verbatim to
   `ida_decompile`, `ida_disassemble`, `ida_xrefs_to`, `ida_callers`, or
   `ida_callees`.

## Working rules

- Build the semantic index with `ida_index_functions()` before
  `ida_semantic_search(...)`. Use `quality="full"` when retrieval quality
  matters; full indexing uses bounded passes, so repeat with the returned
  `next_cursor` until `complete` is true.
- Use hex address strings exactly as returned by tools.
- `ida_rename` and `ida_comment` mutate the IDB. Set `risk_ack=true` only
  after verifying the target and intended change.
- Record confirmed work with `ida_write_finding`; use `ida_next_target` to
  choose the next investigation point.
- If a result is truncated, call `ida_continue(token=...)`.

## Help

Call `ida_help(topic="ida_decompile")` for an exact schema and example, or
`ida_help(query="strings")` to discover an operation. This works through MCP
and does not depend on local workspace files.

## Reference

Read `references/operations.md` only when the MCP schema or `ida_help` does
not answer a specific question.
