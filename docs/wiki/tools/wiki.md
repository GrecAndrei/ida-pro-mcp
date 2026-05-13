# wiki

In-band documentation system: browse, search, and read wiki content without leaving MCP context.

## Actions
- `list_topics` — list all available wiki topics
- `read` — read a topic. Params: `topic`
- `search` — keyword search across wiki. Params: `query`, optional `limit`
- `semantic_search` — semantic/fuzzy search. Params: `query`, optional `limit`
- `sections` — list sections within a topic. Params: `topic`
- `index` — rebuild wiki index

## Examples
```json
{"name": "wiki", "arguments": {"action": "search", "query": "vulnerability scanning"}}
```
```json
{"name": "wiki", "arguments": {"action": "read", "topic": "tools/search"}}
```

## Notes
- Wiki content lives in `docs/wiki/` (or `IDA_MCP_WIKI_DIR`).
- Use `search` for exact keyword matches; `semantic_search` for fuzzy/conceptual queries.
- Fallback docs are auto-generated for tools lacking static wiki pages.
