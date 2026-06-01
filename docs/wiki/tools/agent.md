# agent

AI-assisted analysis combining semantic embeddings, multi-hop search, and batch context gathering for reverse engineering workflows.

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
- `intelligence_status` — summarize local intelligence stack status (embedder/index/classifier readiness)
- `embedder_status` — report embedder backend, model identity, dimensions, and readiness
- `anchor_status` — report anchor/index metadata and compatibility state
- `refresh_anchors` — refresh anchor records for current binary/session
- `classify_text` — behavior classify arbitrary text/code snippet; params: `query`, `top_k`, `threshold`
- `classify_function` — behavior classify a function by address; params: `address`, `top_k`, `threshold`
- `index_function` — add/update one function in embedding index; params: `address`
- `index_batch` — batch index multiple functions; params: `limit`
- `similar_functions` — nearest-neighbor search against indexed functions; params: `address|query`, `top_k`, `threshold`
- `semantic_search` — semantic text query over function embedding index; params: `query`, `top_k`, `threshold`
- `blackboard_search` — behavior-centric semantic retrieval from blackboard memory; params: `query`, `top_k`, `threshold`
- `export_index_summary` — export index metadata/status summary for audits
- `evidence_card` — build behavior/evidence card for a function/query with optional persistence
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
