# IDA MCP Tool Doc: `wiki`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `wiki` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Built-in documentation system with ranked and semantic search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs. Actions: list_topics, read, search, semantic_search, sections, index.

## Actions
- `list_topics` (tool-specific)
- `read` (read/discovery)
- `search` (read/discovery)
- `semantic_search` (read/discovery)
- `sections` (read/discovery)
- `index` (read/discovery)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/wiki')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `list_topics, read, search, semantic_search, sections, index`
- `category`: `string|array`
- `context_lines`: `integer`
- `fuzzy`: `boolean`
- `include_related`: `boolean`
- `include_snippets`: `boolean`
- `limit`: `integer`
- `line_end`: `integer`
- `line_start`: `integer`
- `lines`: `string` - Line selector such as '10-40', '25', '10-', or '-40'.
- `max_results`: `integer`
- `offset`: `integer`
- `query`: `string`
- `section`: `string`
- `strict_topic`: `boolean`
- `topic`: `string`
- `verbose`: `boolean` - Include full structural metadata in wiki responses.
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "wiki",
  "arguments": {
    "action": "list_topics"
  }
}
```
```json
{
  "name": "wiki",
  "arguments": {
    "action": "grep",
    "source_action": "list_topics",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
