# MCP Surface Deduplication Plan

This project keeps a small canonical MCP surface and supports older names via aliases.

## Goals

- Keep one canonical entrypoint per workflow.
- Preserve backward compatibility for existing clients and scripts.
- Keep behavior deterministic or local ML-powered (no backend LLM runtime).

## Canonical Tool Routing

- `plugins` -> `misc` (use `misc(action="plugin_list"|"plugin_run")`)
- `xfer_analysis` -> `xref_analysis`
- `comments_ai` -> `comment_mgr`
- `annotations_ai` -> `annotation`
- `strings_xref` -> `xref_analysis`
- `emulate` -> `static_trace`
- `recommend` / `predict` / `next_tool` -> `predictor`

## Workflow Canonicals

- Commenting and annotation
  - Canonical: `comment_mgr` for comment CRUD/export/import
  - Canonical: `annotation` for bulk semantic annotation passes
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
- `comment_mgr`
- `annotation`

This reduces duplicate action naming in clients without widening the canonical API.

## Follow-up Work

1. Add a generated compatibility matrix in docs (`tool alias -> canonical tool`, `action alias -> canonical action`).
2. Add CI check to prevent adding new canonical duplicate tools when an alias is sufficient.
3. Extend sweep tests to include alias-routing assertions for compatibility names.
