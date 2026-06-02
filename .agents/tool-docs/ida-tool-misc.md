# IDA MCP Tool Doc: `misc`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `misc` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Utility grab-bag: run scripts and list loaded plugins. Actions: python, idc, load_sig, cache_stats, plugin_list. (read_file/write_file → memory, plugin_run → analysis, health → session.)

## Actions
- `python` (tool-specific)
- `idc` (tool-specific)
- `load_sig` (tool-specific)
- `cache_stats` (tool-specific)
- `plugin_list` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/misc')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `python, idc, load_sig, cache_stats, plugin_list`
- `code`: `string` - Multi-line Python code to execute
- `expr`: `string` - Python expression or IDC script to evaluate
- `name`: `string` - Signature name for load_sig
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "misc",
  "arguments": {
    "action": "python"
  }
}
```
```json
{
  "name": "misc",
  "arguments": {
    "action": "grep",
    "source_action": "python",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
