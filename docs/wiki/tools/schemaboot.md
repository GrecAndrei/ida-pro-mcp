# schemaboot

Structured semantic indexing: extracts function attributes into a SQLite index for fast structured queries with BM25 reranking.

## Actions
- `ingest` — extract structural attributes from all functions into SQLite index. Optional `addresses` to limit scope.
- `query` — SQL pre-filter + BM25 reranking. Params: `constraints` (dict of attribute filters), optional `text`, `limit`
- `refresh` — re-index changed functions
- `stats` — index statistics (function count, attribute coverage)
- `delete` — remove entries. Params: `addresses` (array)
- `get` — get indexed attributes for a function. Params: `address`

## Examples
```json
{"name": "schemaboot", "arguments": {"action": "ingest"}}
```
```json
{"name": "schemaboot", "arguments": {"action": "query", "constraints": {"calls_api": "CreateFile", "has_loops": true}, "limit": 10}}
```

## Notes
- Run `ingest` once after initial analysis; use `refresh` for incremental updates.
- `query` combines structured SQL filtering with BM25 text relevance for hybrid search.
- Attributes include: call targets, loop presence, string refs, argument count, complexity metrics.
