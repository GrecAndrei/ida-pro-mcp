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

## Cross-Reference Notes (Phase 3, 2026-06-02)

The Phase 3 inventory revealed no name-collision action overlaps between
`agent`/`intelligence`/`llm_helpers` (the 50+ ghost-action concern from
the original plan was already addressed in Phase 1.6). What it did find
is a handful of *intentional* name reuses between tools with deliberately
different semantics. Cross-reference notes were added to the tool
descriptions in `TOOL_DESCRIPTIONS` so the LLM picks the right one; this
section is the human-readable index.

| Tool A action | Tool B action | What's different | When to use which |
|---|---|---|---|
| `classify.function` | `summarize.function` | `classify` returns category / behavior tag (BehaviorClassifier on a single function). `summarize` returns counts / structure (xrefs, insns, callee count, complexity). | Use `classify.function` to ask "what kind of function is this?". Use `summarize.function` to ask "what does this function look like (size, complexity, calls)?" |
| `classify.binary` | `summarize.binary` | `classify` returns the binary's overall type / purpose. `summarize` returns the binary's overall stats / breakdown. | Use `classify.binary` for "what is this binary?" (architecture, role). Use `summarize.binary` for "what's in this binary?" (segment sizes, file type, imports). |
| `agent.similar` | `intelligence.similar_functions` | Both find nearest-neighbor functions. `intelligence.similar_functions` is the canonical embedding-indexed search (bge-code-v1). `agent.similar` is the older "context pack" workflow that bundles similarity with surrounding code. | Prefer `intelligence.similar_functions` for new code. Keep `agent.similar` for back-compat with existing client scripts. |
| `agent.cfg_encode` / `agent.cfg_similar` / `agent.cfg_stats` | `graph.cfg` / `graph.*` | `agent.*` are agent-specific structural CFG features (encode for similarity search, etc.). `graph.*` is the canonical call-graph / CFG / xref-graph tool. | Use `agent.cfg_*` for the similarity/encoding workflow. Use `graph.*` for plain graph queries. |
| `agent.fingerprint` | `intelligence.index_function` | `agent.fingerprint` produces a structural signature (for clustering). `intelligence.index_function` adds a function to the embedding index. | Use `agent.fingerprint` for "give this function a structural hash". Use `intelligence.index_function` for "make this function retrievable by semantic similarity". |
| `search.nl` | `query.nl` | Both expose natural-language search. `search.nl` uses the bge-code-v1 embedding ranker directly. `query.nl` routes through the unified query dispatcher (multi-domain NL over the indexed IDB). | Use `search.nl` for behaviorally-precise RE queries. Use `query.nl` when you want the unified dispatcher to pick a target domain. |
| `search.behavior` | `classify.all_functions` | `search.behavior` finds all functions matching a behavior tag (precomputed). `classify.all_functions` runs the BehaviorClassifier on every unnamed function and produces tagged entries. | Use `search.behavior` for read-only lookup. Use `classify.all_functions` when you need to actually run classification on the current IDB. |
| `intelligence.classify_function` | `classify.function` | Both classify a single function. `intelligence.classify_function` uses the embedding-index classifier (fast, cached). `classify.function` is the direct BehaviorClassifier call. | Use `intelligence.classify_function` (faster, consistent with the index). `classify.function` is the older entry point. |
| `trace_analysis` | `coverage` | `trace_analysis` is coverage-oriented trace analysis. `coverage` is the import/report helper. | Use `trace_analysis` for trace-side queries. Use `coverage` to import / report coverage data. |
| `xref_analysis` (legacy) | `graph` | `xref_analysis.py` on disk is consolidated into `graph` at the host layer. The runtime alias redirects `xref_analysis` → `graph`. | Prefer `graph` for new code. The alias exists for back-compat. |

## Phase 4 Audit (2026-06-02)

The Phase 4 plan called for mixin / response-pipeline dedupe. An audit
of the 12 `host/server_*.py` files and the response-compaction pair
turned up no actionable dedupe targets:

- **Mixin composition is already clean.** `IDAMCPServer` is built from
  11 mixins (`ServerArgs`, `ServerResponse`, `ServerSemantic`, …) and
  each mixin lives in its own file with a unique class name. The
  parent/child pairs (`ServerResponse` extends
  `ServerResponseCompactMixin`; `ServerWorkflow` extends
  `ServerWorkflowBatchMixin`; etc.) compose via inheritance, not
  duplication. No method name is defined in more than one mixin.

- **`server_response.py` vs `server_response_compact.py` are
  intentionally layered.** The compact module (391 lines) holds
  low-level response-shaping helpers (`_compact_value`,
  `_maybe_tableify`, `_extract_response_options`); the response module
  (943 lines) extends it with the higher-level policy injection
  (`_inject_blackboard_policy_followup`, `_pointer_note_signal_*`).
  Zero method-name overlap. Splitting or merging would hurt locality.

- **No module-level helper duplication** across `server_*.py`. Every
  `def _foo` in those files is unique. The dispatch entry point
  (`ServerDispatchMixin.call_tool`) is the single funnel for tool
  invocations.

- **`validate_addr` (ida_mcp/error_handling) vs
  `_validate_address_lockstep` (host/server_response) are
  unrelated.** The first coerces a string/int to an IDA address; the
  second checks whether addresses in a call_args match the previous
  payload (a lockstep-consistency warning, not an address parser).

- **`_semantic_tokenize` (host/patterns) vs `_tokenize`
  (host/intelligence_embeddings) are unrelated.** The first
  normalizes + camelCase-expands text for semantic search; the second
  is a simple lowercased regex split for keyword indexing.

The mixin/response layer was likely tightened in a prior dedupe pass
(commit `ecc7db8 misc: split grab-bag into proper homes` and
`aa6bb72 Target D: merge xref_analysis into graph` both predate this
session). Phase 4 is recorded as audited-with-no-targets and no
code change is committed.
