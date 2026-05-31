# IDA MCP Tool Doc: `project`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `project` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Project I/O, file operations, and evidence management. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists, read, write, sessions, batch, evidence_graph, knowledge_merge, confidence_model, replay_pipeline, hypothesis_tracker, temporal_reasoning, semantic_artifact_diff, ai_governance, knowledge_debt, casefile_export.

## Actions
- `save` (tool-specific)
- `close` (destructive)
- `open` (tool-specific)
- `load_binary` (tool-specific)
- `list_recent` (tool-specific)
- `get_cwd` (tool-specific)
- `set_cwd` (tool-specific)
- `list_dir` (tool-specific)
- `exists` (tool-specific)
- `evidence_graph` (tool-specific)
- `knowledge_merge` (tool-specific)
- `confidence_model` (tool-specific)
- `replay_pipeline` (tool-specific)
- `hypothesis_tracker` (tool-specific)
- `temporal_reasoning` (tool-specific)
- `semantic_artifact_diff` (tool-specific)
- `ai_governance` (tool-specific)
- `knowledge_debt` (tool-specific)
- `casefile_export` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/project')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "project",
  "arguments": {
    "action": "save"
  }
}
```
```json
{
  "name": "project",
  "arguments": {
    "action": "grep",
    "source_action": "save",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
