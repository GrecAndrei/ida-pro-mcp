# IDA MCP Tool Doc: `search`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `search` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Pattern, reference, and semantic search. nl: NL search via bge-code-v1 embeddings (best for RE queries). find: unified search over names/strings/imports/instructions. api: all call sites of an import. decompiled: grep pseudocode across all functions. vulnerable: scan for dangerous API patterns. outlier: structurally anomalous functions (size/complexity/orphan/hub). hunt: named recipes (backdoor/c2/crypto/anti_debug — pass recipe='list'). path: shortest call-graph path between two symbols. reach/noreach: reachability from a root. Actions: nl, behavior, find, semantic, smart_bundle, api, decompiled, structured, vulnerable, constants, callers, callees, bytes, string, immediate, name, insns, mnemonic, comment, regex, func_by_sig, bool, hunt, neighborhood, outlier, fingerprint, path, reach, noreach.

## Actions
- `nl` (tool-specific)
- `behavior` (tool-specific)
- `find` (tool-specific)
- `semantic` (tool-specific)
- `smart_bundle` (tool-specific)
- `api` (tool-specific)
- `decompiled` (tool-specific)
- `structured` (tool-specific)
- `vulnerable` (tool-specific)
- `constants` (tool-specific)
- `callers` (tool-specific)
- `callees` (tool-specific)
- `bytes` (tool-specific)
- `string` (tool-specific)
- `immediate` (tool-specific)
- `name` (tool-specific)
- `insns` (tool-specific)
- `mnemonic` (tool-specific)
- `instruction` (tool-specific)
- `text` (tool-specific)
- `operand` (tool-specific)
- `comment` (tool-specific)
- `data_ref` (tool-specific)
- `code_ref` (tool-specific)
- `regex` (tool-specific)
- `func_by_sig` (tool-specific)
- `type` (tool-specific)
- `export` (tool-specific)
- `summary` (read/discovery)
- `query_lang` (tool-specific)
- `bool` (tool-specific)
- `hunt` (tool-specific)
- `neighborhood` (tool-specific)
- `outlier` (tool-specific)
- `fingerprint` (tool-specific)
- `path` (tool-specific)
- `reach` (tool-specific)
- `noreach` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/search')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `38`
- `addr`: `string`
- `case_sensitive`: `boolean`
- `depth`: `integer` - reach/noreach BFS depth
- `dst`: `string` - path destination symbol/addr
- `end`: `string`
- `include_breakdown`: `boolean`
- `include_context`: `boolean`
- `include_items`: `boolean`
- `limit`: `integer`
- `max_depth`: `integer` - path/reach max BFS depth
- `max_functions`: `integer`
- `metric`: `string` - outlier metric: size|complexity|bb_count|orphan|leaf|hub|deep|tiny|huge
- `offset`: `integer`
- `pattern`: `string`
- `query`: `string`
- `radius`: `integer` - neighborhood radius (default 10)
- `sample`: `boolean`
- `sample_max_funcs`: `integer`
- `src`: `string` - path source symbol/addr
- `start`: `string`
- `timeout_ms`: `integer`
- `top`: `integer` - outlier top N (default 50)
- `top_k`: `integer` - fingerprint top K (default 20)
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "search",
  "arguments": {
    "action": "nl"
  }
}
```
```json
{
  "name": "search",
  "arguments": {
    "action": "grep",
    "source_action": "nl",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
