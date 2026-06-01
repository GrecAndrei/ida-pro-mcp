# intelligence

Intelligence subsystem: embedding-based function classification, indexing, similarity search, and evidence-card production. Extracted from `agent` in the dedup pass so the lifecycle of the embedder/classifier/index lives behind a single coherent tool.

## Actions

- `intelligence_status` — summarize local intelligence stack status (embedder/index/classifier readiness). Returns anchor hash, anchor count, anchor load state, functions indexed, active binaries, and capsule embedding state.
- `embedder_status` — report embedder backend, model identity, dimensions, and readiness.
- `anchor_status` — report anchor metadata, count, and loaded-embeddings state.
- `refresh_anchors` — refresh anchor embeddings for the given behaviors (comma-separated `query`); if no query, refreshes all.
- `classify_text` — behavior classify arbitrary text/code snippet; params: `query`, `top_k`, `threshold`, `block`.
- `classify_function` — behavior classify a function by address; params: `address`, `top_k`, `threshold`, `block`.
- `index_function` — add/update one function in embedding index; params: `address`.
- `index_batch` — batch index multiple functions; params: `limit`.
- `similar_functions` — nearest-neighbor search against indexed functions; params: `address`, `top_k`, `threshold`.
- `semantic_search` — semantic text query over function embedding index; params: `query`, `top_k`, `threshold`.
- `blackboard_search` — behavior-centric semantic retrieval from blackboard memory; params: `query`, `top_k`, `threshold`, `include_resolved`.
- `export_index_summary` — export index metadata/status summary for audits.
- `evidence_card` — build behavior/evidence card for a function/query with optional persistence to the capsule.

## Legacy aliases

The following back-compat aliases route to `intelligence`:
- `embeddings` → `intelligence`
- `ai_classifier` → `intelligence`
- `agent_intelligence` → `intelligence`

## CLI

`ida-pro-mcp-cli intelligence <subcommand>` calls this tool. Supported subcommands: `status`, `embedder_status`, `anchor_status`, `refresh_anchors`, `classify_text`, `classify_function`, `index_function`, `index_batch`, `similar_functions`, `export_index_summary`, `evidence_card`, `doctor` (= `embedder_status` with `probe=True`).
