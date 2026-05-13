# bridgerag

Multi-hop bridge-conditioned search via the schemaboot index for discovering indirect relationships.

## Actions
- `search` — semantic search over indexed entries; params: `query`, `limit`
- `bridges` — find bridge entities connecting two concepts; params: `source`, `target`
- `multi_hop_search` — expand query through intermediate hops; params: `query`, `hops`, `limit`
- `candidates` — list candidate bridge entities for a query; params: `query`

## Examples
```json
{"name": "bridgerag", "arguments": {"action": "multi_hop_search", "query": "crypto key derivation", "hops": 2}}
```
```json
{"name": "bridgerag", "arguments": {"action": "bridges", "source": "recv", "target": "decrypt"}}
```

## Notes
- Requires schemaboot index to be populated first.
- Use `multi_hop_search` to discover indirect call chains or data flows.
- Results are ranked by bridge relevance score.
