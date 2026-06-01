# agent

AI-assisted analysis combining semantic embeddings, multi-hop search, and batch context gathering for reverse engineering workflows.

## Actions
- `analyze_function` — deep analysis of a single function; params: `address`
- `explore_address` — contextual exploration around an address; params: `address`
- `find_references` — find all references to/from a target; params: `address`
- `search_all` — broad search across functions, strings, imports; params: `query`
- `quick` — lightweight one-shot analysis; params: `address`
- `rename_suggestions` — suggest names for nearby unnamed functions with evidence-backed confidence; params: `address`, `top_k`, `include_evidence`
- `batch_context` — gather context for multiple addresses in one call; params: `addresses`
- `similar` — find semantically similar functions via cosine similarity on bge-code-v1 embeddings; params: `address`, `limit`
- `semantic_search` — semantic text query over function embedding index; params: `query`, `top_k`, `threshold`
- `blackboard_search` — behavior-centric semantic retrieval from blackboard memory; params: `query`, `top_k`, `threshold`
- `bridge_query` — multi-hop entity expansion across xrefs and data flow; params: `query`, `hops`
- `reflect` — introspect current analysis state and suggest next steps
- `cluster` — batch-embed all functions, k-means cluster, label with BehaviorClassifier; params: `max_items` (k), `func_limit`
- `fingerprint` — compare current binary's embedding index against other `.embeddings.db` files in the same directory

## Examples

```json
{"name": "agent", "arguments": {"action": "similar", "address": "0x401000", "limit": 5}}
```

```json
{"name": "agent", "arguments": {"action": "cluster", "max_items": 8, "func_limit": 200}}
```

## Notes
- `similar` uses FunctionEmbeddingIndex cosine search on bge-code-v1 vectors, not keyword/string matching.
- `bridge_query` expands entities across multiple hops — useful for tracing indirect relationships (e.g., callback registration chains).
- `cluster` and `fingerprint` require the embedding index to be built; they operate on the full binary scope.
- `rename_suggestions` does not auto-rename; it emits suggestions by default and persistence to blackboard/capsule is opt-in (`persist_blackboard=true`, `persist_capsule=true`).
