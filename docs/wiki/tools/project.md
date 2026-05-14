# project

Project-level operations: save, open, close IDBs, manage working directory, and advanced knowledge management with evidence graphs and casefile export.

## Actions
- `save` — Save current IDB to disk
- `close` — Close current IDB
- `open` — Open an existing IDB; params: `path`
- `load_binary` — Load a new binary for analysis; params: `path`, optional `loader`, `arch`
- `list_recent` — List recently opened files
- `get_cwd` — Get current working directory
- `set_cwd` — Set working directory; params: `path`
- `list_dir` — List directory contents; params: `path`, optional `pattern`
- `exists` — Check if a file or directory exists; params: `path`
- `evidence_graph` — Build a graph of findings and their relationships (supports, contradicts, implies); params: `scope`, `format`
- `knowledge_merge` — Combine findings from multiple sessions into a unified knowledge base; params: `session_ids`, `strategy`
- `confidence_model` — Compute confidence scores for findings based on evidence weight and corroboration; params: `finding_id`
- `replay_pipeline` — Re-run a previously recorded analysis workflow; params: `pipeline_id`, `target`
- `hypothesis_tracker` — Manage analysis hypotheses (create, update, link evidence); params: `hypothesis_id`, `action_type`
- `temporal_reasoning` — Reason about temporal ordering of events/artifacts (build timeline); params: `scope`
- `semantic_artifact_diff` — Compute semantic diff between two analysis artifacts or IDB states; params: `left`, `right`
- `ai_governance` — Review and audit AI-generated annotations for quality and correctness; params: `scope`, `threshold`
- `knowledge_debt` — Identify gaps in analysis coverage (unexplored functions, unresolved references); params: `scope`
- `casefile_export` — Export the full analysis as a structured report (annotations, bookmarks, types, findings); optional `path`, `format`

## Examples
```json
{"name": "project", "arguments": {"action": "save"}}
```
```json
{"name": "project", "arguments": {"action": "casefile_export", "path": "/tmp/case.json"}}
```
```json
{"name": "project", "arguments": {"action": "evidence_graph", "scope": "all"}}
```
```json
{"name": "project", "arguments": {"action": "knowledge_merge", "session_ids": ["AB12CD34", "EF56GH78"]}}
```
```json
{"name": "project", "arguments": {"action": "replay_pipeline", "pipeline_id": "triage_v2"}}
```
```json
{"name": "project", "arguments": {"action": "knowledge_debt", "scope": "all"}}
```

## Notes
- `load_binary` creates a new IDB from a raw binary; use `session(action="create")` for session-managed workflows.
- `evidence_graph` builds a directed graph of findings showing support/contradiction relationships — useful for validating conclusions.
- `knowledge_merge` combines findings from multiple sessions, resolving conflicts by evidence weight.
- `casefile_export` bundles all analysis artifacts for sharing, archival, or ingestion by external tools.
- `replay_pipeline` re-runs a recorded analysis workflow against a new target or updated binary.
- `set_cwd` affects relative path resolution for subsequent file operations.
- `knowledge_debt` helps identify what remains unexplored — useful for completeness checks before reporting.
- `ai_governance` audits AI-generated content for hallucinations, contradictions, and quality issues.
