# MCP Surface Deduplication Plan

This project keeps a small canonical MCP surface and supports older names via aliases.

## Goals

- Keep one canonical entrypoint per workflow.
- Preserve backward compatibility for existing clients and scripts.
- Keep behavior deterministic or local ML-powered (no backend LLM runtime).

## Canonical Tool Routing

- `plugins` -> `misc` (use `misc(action="plugin_list"|"plugin_run")`)
- `xfer_analysis` -> `xref_analysis`
- `comments_ai` -> `annotation`
- `annotations_ai` -> `annotation`
- `strings_xref` -> `xref_analysis`
- `emulate` -> `static_trace`
- `recommend` / `predict` / `next_tool` -> `predictor`

## Workflow Canonicals

- Commenting and annotation
  - Canonical: `annotation` for comment CRUD/export/import + bulk semantic annotation passes
  - Keep `modify(action="comment")` as low-level primitive

- Tracing and coverage
  - Canonical: `trace_analysis` for coverage-oriented trace analysis
  - Keep `coverage` as import/report helper
  - Keep `trace` as raw trace handling

- Orchestration and enrichment
  - Canonical: `agent` for guided investigative flow
  - Canonical: `threat_hunt` for malware/vuln/tracing pipelines
  - Canonical: `llm_helpers` for deterministic post-processing/enrichment
  - Canonical: `predictor` for local sequence/Q-value workflow prediction

## Action Alias Consolidation

Added action alias normalization for overlapping terms on:

- `agent`
- `llm_helpers`
- `trace_analysis`
- `annotation`

This reduces duplicate action naming in clients without widening the canonical API.

## Follow-up Work

1. Add a generated compatibility matrix in docs (`tool alias -> canonical tool`, `action alias -> canonical action`).
2. Add CI check to prevent adding new canonical duplicate tools when an alias is sufficient.
3. Extend sweep tests to include alias-routing assertions for compatibility names.

## Phase 1 Decisions (2026-06-02)

Conservative cleanup of the tool surface with the gate that the test failure
count stays at or below the baseline of 51.

- **Orphan tool registered**: `fixups` is a real, loadable tool in
  `src/ida_pro_mcp/ida_mcp/tools/fixups.py` but was missing from the
  `TOOLS` list in `schemas_data.py`. Added it (description, action list, and
  arg schema). The 4 `fixup_*` actions previously declared under `segments`
  were ghost entries (no implementation behind them) and have been removed.
  `fixups` was added to `WRITE_IDB_TOOLS` since add/delete mutate the IDB.

- **Legacy xref alias added at runtime**: `xref_analysis` is on disk (948
  lines) but is consolidated into `graph` in the host. The runtime alias
  `xref_analysis -> graph` is now declared in `server_script.TOOL_ALIASES`
  alongside the pre-existing `xfer_analysis` typo alias so requests land
  on the canonical tool regardless of which side resolves them.

- **Batch placeholder removed**: `TOOL_ACTIONS["batch"]` had the literal
  value `"(pass calls array)"`. Replaced with an empty list; `batch` is
  exposed as a registry entry with no declared actions (caller is
  expected to pass a `calls` array per the existing protocol).

- **Dead `memrl` removed**: `policy.WRITE_IDB_TOOLS` previously listed
  `"memrl"`, a tool that no longer exists. Removed.

- **Coverage name collision clarified**: `coverage` is a real canonical
  tool, but a duplicate alias `"coverage": "threat_hunt"` was declared in
  the host alias map. Because multiple tools share the name `coverage`
  (the real tool, the workflow enum, and the blackboard action), the
  resolver in `schemas._build_tool_aliases` already drops ambiguous
  aliases — the entry was non-functional and confused readers. Removed
  with a comment explaining the collision.

- **llm_helpers ghost action removed**: The action
  `protocol_format_reconstruction_assistant` was declared in
  `schemas_data.TOOL_ACTIONS["llm_helpers"]` and the override in
  `schemas.TOOL_ACTIONS["llm_helpers"]`, but had no implementation in
  `tools/llm_helpers.py`. The earlier cross-check (which assumed an
  `action == "..."` pattern) misidentified this; the action is actually
  dispatched via an `action in {...}` membership test. After auditing all
  62 remaining llm_helpers actions against the .py body (matching on any
  string-literal reference, not just `==`), zero ghosts remain. Removed
  from the schema and from the action list embedded in
  `scripts/generate_schemas.py`. The auto-generated
  `.agents/tool-docs/ida-tool-llm_helpers.md` and
  `docs/TOOLS_REFERENCE.md` still list the removed action and will be
  refreshed by the next regen pass.

- **Non-changes (kept as-is)**:
  - `colorize` and `schemaboot` remain in `TOOLS` but absent from
    `ADVERTISED_TOOLS`. This is intentional: they are infrastructure
    tools surfaced for internal use, not to LLM clients.
  - `xref_analysis.py` on disk was **not** deleted. The file is still
    importable for back-compat; the alias in the runtime layer redirects
    calls. A future phase may decide to delete the file once no callers
    import from it directly.
