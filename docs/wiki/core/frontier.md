# Frontier Engine

The FrontierEngine (`host/frontier.py`) is an embedding-driven analysis guidance system. It answers the question: **"What should I analyze next?"**

## The Problem It Solves

Without the frontier engine, the LLM has to choose what to analyze next based on:
- Random function selection
- xref counts (hot functions only)
- Manual blackboard entries

This misses large regions of the binary and creates blind spots.

## How It Works

### 1. Cluster

On first use, FrontierEngine loads all indexed function embeddings and runs k-means clustering (k = √(n/2), clamped 5–100). Functions that look similar in pseudocode end up in the same cluster. This creates a structural map of the binary.

### 2. Label Propagation

When the LLM writes a blackboard entry for a function (confidence ≥ 0.6), FrontierEngine automatically propagates that label to all functions within cosine distance 0.82 in embedding space:

```
confidence_propagated = source_confidence × 0.75 × cosine_similarity
```

The LLM labels one function → the engine labels 10–20 similar functions with decayed confidence. These appear in `blackboard(action='list', source_type='propagated')`.

### 3. Frontier Scoring

Every unvisited function is scored:

```
score = 0.45 × proximity + 0.25 × xref_norm + 0.15 × entropy_norm + 0.15 × cluster_coverage
```

- **proximity**: cosine similarity to nearest labeled function in embedding space
- **xref_norm**: normalized xref count (hot functions score higher)
- **entropy_norm**: byte entropy (high entropy = likely crypto/packed)
- **cluster_coverage**: fraction of the function's cluster that is already labeled

### 4. Contradiction Detection

Functions in the same embedding cluster but with different LLM-assigned categories are flagged as contradiction candidates. If `sub_401000` is labeled "AES key schedule" and `sub_402800` is in the same cluster but labeled "HTTP parser", one label is probably wrong.

---

## Usage

### Get ranked frontier targets

```json
{"name": "blackboard", "arguments": {"action": "frontier", "limit": 10}}
```

Or read the resource:
```
ida://blackboard/frontier
```

Returns items ranked by score with `nearest_label_title` showing what the nearest labeled function is.

### Check coverage

```json
{"name": "blackboard", "arguments": {"action": "coverage"}}
```

Or:
```
ida://blackboard/coverage
```

Returns `coverage_pct`, `analyzed`, `unvisited`, and per-cluster breakdown sorted by least-covered clusters first.

### Manually trigger propagation

```json
{"name": "blackboard", "arguments": {"action": "propagate_labels"}}
```

Returns count of newly propagated entries.

---

## Automatic Operation

The analysis engine runs `_stage_frontier` every 180 seconds:
1. Rebuilds clusters
2. Propagates labels
3. Seeds top-10 frontier entries into the blackboard as `hypothesis` entries
4. Detects contradictions and pushes them as proposals
5. Pushes `notifications/resources/updated` for `ida://blackboard/frontier`
6. Pushes `notifications/message` with `frontier_updated` type when coverage < 50%

The notification includes `required_actions` with the exact `code(smart_decompile)` call for the top target.

---

## The Feedback Loop

```
LLM analyzes sub_401000
  → writes blackboard entry (confidence=0.85)
  → FrontierEngine propagates to 12 similar functions
  → blackboard(action='frontier') returns those 12 as next targets
  → LLM analyzes top target, writes entry
  → propagates to more functions
  → coverage grows systematically
```

The LLM doesn't need to read 2000 functions. It reads 50, labels them, and the embedding model propagates those labels to the other 1950 with confidence scores.

---

## Requirements

- Functions must be indexed in the FunctionEmbeddingIndex (`<idb>.embeddings.db`)
- Indexing happens automatically when `code(action='decompile')` or `code(action='smart_decompile')` is called
- Or run `schemaboot(action='ingest')` to batch-index all functions
- The bge-code-v1 model must be available (configured via `IDA_MCP_EMBEDDER_*` env vars)
