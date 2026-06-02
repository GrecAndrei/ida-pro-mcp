# IDA MCP Tool Doc: `search`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `search` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Pattern, reference, and semantic search across the binary. nl: natural language search using bge-code-v1 embeddings (most accurate for RE queries). behavior: find all functions matching a behavior tag (crypto_symmetric, network_http, etc.) via BehaviorClassifier. find: smart unified search (names/strings/imports/instructions, auto-ranked). semantic: NL search with embedding-aware ranking. smart_bundle: fused find+semantic with deduplicated structured items. api: find all usages of an imported API. decompiled: search pseudocode across all functions (auto-writes blackboard entries for matches). structured: schema-based pre-filtered search with behavior_tags constraints. vulnerable: scan for dangerous API patterns. constants: find crypto/magic constants. callers/callees, bytes/string/immediate/name/insns/mnemonic/instruction/text/operand/comment/data_ref/code_ref/regex/func_by_sig/type/export/summary/query_lang. Composition actions: bool (composite boolean query: '(api:Crypt* AND name:key) OR (string:password AND NOT obf:true)'), hunt (named workflow recipes: backdoor, anti_debug, c2, crypto, parser, etc. - pass recipe='list' to enumerate), neighborhood (360-degree context card around a function: callers, callees, similar, tags, blackboard), outlier (find structurally anomalous functions by metric: size, complexity, orphan, leaf, hub, deep, tiny, huge), fingerprint (structural callgraph similarity - distinct from embedding-based nl), path (shortest call-graph path between two symbols), reach (functions reachable from a root within N hops), noreach (functions NOT reachable from any entrypoint). NOTE: search.nl and query.nl both expose natural-language search. search.nl uses the bge-code-v1 embedding ranker directly; query.nl routes through the unified query dispatcher. Use search.nl for behaviorally-precise RE queries; use query.nl when you want the unified dispatcher to pick a target domain.

## Actions
- `text` (tool-specific)
- `bytes` (tool-specific)
- `regex` (tool-specific)
- `immediate` (tool-specific)
- `code_pattern` (tool-specific)
- `next` (tool-specific)
- `all` (tool-specific)
- `structured` (tool-specific)
- `string` (tool-specific)
- `name` (tool-specific)
- `comment` (tool-specific)
- `mnemonic` (tool-specific)
- `operand` (tool-specific)
- `insns` (tool-specific)
- `instruction` (tool-specific)
- `decompiled` (tool-specific)
- `constants` (tool-specific)
- `semantic` (tool-specific)
- `smart_bundle` (tool-specific)
- `func_by_sig` (tool-specific)
- `vulnerable` (tool-specific)
- `api` (tool-specific)
- `callees` (tool-specific)
- `callers` (tool-specific)
- `code_ref` (tool-specific)
- `data_ref` (tool-specific)
- `export` (tool-specific)
- `find` (tool-specific)
- `nl` (tool-specific)
- `behavior` (tool-specific)
- `query_lang` (tool-specific)
- `summary` (read/discovery)
- `type` (tool-specific)
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
- `action`: `string` - allowed_count: `41`
- `addr`: `string`
- `case_sensitive`: `boolean`
- `end`: `string`
- `include_breakdown`: `boolean`
- `include_context`: `boolean`
- `include_items`: `boolean`
- `limit`: `integer`
- `max_functions`: `integer`
- `offset`: `integer`
- `pattern`: `string`
- `query`: `string`
- `sample`: `boolean`
- `sample_max_funcs`: `integer`
- `start`: `string`
- `timeout_ms`: `integer`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "search",
  "arguments": {
    "action": "text"
  }
}
```
```json
{
  "name": "search",
  "arguments": {
    "action": "grep",
    "source_action": "text",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
