# IDA MCP Tool Doc: `project`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `project` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Project I/O and file operations. Actions: save, close, open, load_binary, list_recent, get_cwd, set_cwd, list_dir, exists. Legacy actions read/write map to misc read_file/write_file.

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
- `grep` (host wrapper): run another action, then grep its output lines.

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
