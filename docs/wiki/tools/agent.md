# agent

AI-assisted analysis combining search, context packing, multi-hop discovery, and CFG similarity for reverse engineering workflows. Embedding-based intelligence actions live in the dedicated [`intelligence`](intelligence.md) tool (extracted from `agent` in the dedup pass).

## Actions
- `analyze_function` — deep analysis of a single function; params: `address`
- `explore_address` — contextual exploration around an address; params: `address`
- `find_references` — find all references to/from a target; params: `address`
- `search_all` — broad search across functions, strings, imports; params: `query`
- `search_structs` — structure/type-oriented search expansion; params: `query`
- `context_pack` — compact context pack for an address/query
- `quick` — lightweight one-shot analysis; params: `address`
- `rename_suggestions` — suggest names with evidence-backed confidence. If `address` is provided, target that function; without `address`, runs batch suggestions over unnamed functions. Params: `address` (optional), `limit`, `top_k`, `threshold`, `include_evidence`
- `batch_context` — gather context for multiple addresses in one call; params: `addresses`
- `similar` — find semantically similar functions via cosine similarity on bge-code-v1 embeddings; params: `address`, `limit`
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
- `rename_suggestions` and `funcs(action="suggest_names")` share the same embedding-backed suggestion engine to keep behavior consistent across tools.
- `rename_suggestions` does not auto-rename; it emits suggestions by default and persistence to blackboard/capsule is opt-in (`persist_blackboard=true`, `persist_capsule=true`).
