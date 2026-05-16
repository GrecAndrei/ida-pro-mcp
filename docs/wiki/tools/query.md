# query

Unified query interface that delegates to other tools (data, search, code, types, etc.) or performs natural-language semantic search.

## Actions
- `data` — proxy to `data` tool; pass through sub-action and params.
- `search` — proxy to `search` tool.
- `idb` — proxy to `idb` tool.
- `code` — proxy to `code` tool.
- `types` — proxy to `types` tool.
- `imports_deep` — proxy to `imports_deep` tool.
- `symbols` — proxy to `symbols` tool.
- `patterns` — proxy to `patterns` tool.
- `nl` — natural language query; embeds `query` string, cosine-searches FunctionEmbeddingIndex. Returns ranked function matches.

## Examples
```json
{"name": "query", "arguments": {"action": "nl", "query": "function that parses XML input"}}
```
```json
{"name": "query", "arguments": {"action": "data", "sub_action": "functions", "count": 20}}
```

## Notes
- `nl` requires target functions to be decompiled first (so they exist in the embedding index).
- `nl` now does embedding-driven query expansion via BehaviorClassifier tags and merges those neighbors into final ranking.
- `search` auto-routes to `search(action="nl")` when called without `subaction` and the query looks like natural language intent.
- Use `nl` for exploratory discovery when you don't know exact names or addresses.
- Other actions are convenience proxies; calling the underlying tool directly is equivalent.
