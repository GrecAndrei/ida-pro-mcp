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
  matters; both index qualities include bounded CFG/call evidence, while full
  quality also includes ctree-derived control and local data-flow evidence.
  Indexing runs as a background job by default; poll `ida_index_status()` with
  the returned task ID. Use range, radius, size, or name filters for a scoped
  job. Exact matching binaries can reuse compatible indexes across sessions.
- Treat the `structure` field returned by `ida_decompile` and
  `ida_disassemble` as evidence: it summarizes CFG shape and call targets;
  decompilation additionally supplies bounded ctree control points and local
  data-flow. Use `ida_help` for exact schemas when the compact summary is
  insufficient.
- Use hex address strings exactly as returned by tools.
- `ida_rename` and `ida_comment` mutate the IDB. Set `risk_ack=true` only
  after verifying the target and intended change.
- Use `ida_python(code=..., risk_ack=true)` for narrowly scoped IDA-side
  scripting; it executes in the live IDA process and is policy-gated.
- Record confirmed work with `ida_write_finding`, and record dead ends with
  `ida_mark_examined(verdict="boring")`. A function you read and dismissed is
  worth one line: without it, the next session reads it again.
- Responses carry an injected recall channel:
  - `_recall` — what is already known about this address (prior findings,
    verdicts, and their `[mcp:]`-anchored claims). Read it before re-deriving
    anything.
  - `_already_examined` — addresses in the response you previously dismissed;
    do not re-read them as if they were new.
  - `_stale` — a claim whose underlying code changed after it was recorded.
    Re-check that claim rather than trusting it; a stale verdict means the
    code moved, not that the analysis was wrong.
  - `_recall_error` — when recall itself could not be loaded (e.g. no
    workspace). Proceed, but note that prior-session memory is unavailable.
- `ida_next_target(strategy=...)` picks the next investigation point:
  `unresolved` for open threads, `coverage` for functions nobody has read,
  `frontier` to expand from confirmed findings, `stale` and `conflict` for
  claims that need repair. Every candidate states why it was chosen. On
  opaque/raw binaries with no function inventory, `coverage` returns an
  explicit note (`coverage_pct=0`) instead of silently reporting an empty
  coverage.
- If `ida_write_finding` returns a `conflict`, two claims about the same thing
  disagree. Resolve it with `ida_update_finding` before building on either.
- Accept or reject background proposals explicitly. The crawler and trace
  machinery create real `proposed` entries and notify with the real entry id;
  respond with `ida_update_finding(entry_id=..., status="confirmed")` (accept)
  or `status="rejected"` with a reason, rather than leaving them in limbo.
- `ida_import_annotations` early in a session adopts names and comments the
  last analyst left in the IDB, so you inherit their work instead of redoing
  it. `ida_publish_findings(risk_ack=true)` writes confirmed findings back as
  comments and symbols; use `dry_run=true` first to see what it would change.
- If a result is truncated, read `_continue.token` and `_continue.fields`.
  Call `ida_continue(token=...)` when one field is listed; when multiple
  fields are listed, pass the exact selected name as `field=...` (for example
  `ida_continue(token="ABC123", field="code")`).

## Help

Call `ida_help(topic="ida_decompile")` for an exact schema and example, or
`ida_help(query="strings")` to discover an operation. This works through MCP
and does not depend on local workspace files.

## Reference

Read `references/operations.md` only when the MCP schema or `ida_help` does
not answer a specific question.
