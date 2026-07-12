# Intelligence Layer

IDA Pro MCP uses a real embedding model (bge-code-v1, 1536 dims) for semantic analysis. No keyword lists. No hardcoded rules for classification.

## How it works

**BgeCodeEmbedder** — manages a `llama-server` subprocess running `bge-code-v1-q8_0.gguf`. Auto-detected from common local model locations or `IDA_MCP_EMBED_MODEL`. Falls back to TF-IDF if the model isn't found.

**FunctionEmbeddingIndex** — per-binary SQLite store of 1536-dim embeddings. Written to `<idb_path>.embeddings.db`. Populated automatically when you decompile functions via `code(action="decompile")`.

**BehaviorClassifier** — zero-shot classification via cosine similarity to anchor descriptions. Anchors cover: `crypto_symmetric`, `crypto_hash`, `network_http`, `network_raw`, `process_injection`, `file_operations`, `anti_debug`, `anti_vm`, `persistence`, `evasion`, `string_decrypt`, `c2_communication`, `privilege_escalation`, `memory_manipulation`.

## What uses it

| Tool | How |
|------|-----|
| `classify(action="function")` | BehaviorClassifier on decompiled pseudocode |
| `intelligence(action="similar_functions")` | FunctionEmbeddingIndex cosine search |
| `intelligence(action="index_batch")` | Batch decompile and embed functions for semantic analysis |
| `search(action="fingerprint")` | Generate structural fingerprints for comparison |
| `funcs(action="suggest_names")` | Find nearest named function by cosine similarity |
| `search(action="nl")` | Embed query → search FunctionEmbeddingIndex |
| `security(action="detect")` | Combined packer, entropy, crypto, and obfuscation sweep |
| `gadgets(action="classify_chain")` | BehaviorClassifier with exploit-primitive anchors |
| `blackboard(action="search")` | Cosine search over stored entry vectors |
| Every `code(action="decompile")` | Auto-indexes the function, injects relevant blackboard context |

## Context injection

Every `code(action="decompile")` response includes a `context_pack` with:
- Behavior classifications
- Top-3 semantically similar blackboard entries (prior findings)
- Structural attributes (entropy, xor_count, cyclomatic complexity)
- Suggested next actions

## Rename propagation

After `modify(action="rename")`, a background thread re-embeds the renamed function, finds unnamed callees with high cosine similarity, and writes rename suggestions to `blackboard(category="rename_suggestion")`.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `IDA_MCP_EMBED_MODEL` | auto-detect | Path to bge-code-v1 GGUF |
| `IDA_MCP_EMBED_SERVER_BIN` | auto-detect | Path to llama-server binary |
| `IDA_MCP_EMBED_DISABLED` | `0` | Set to `1` to force TF-IDF fallback |
| `IDA_MCP_EMBED_THREADS` | `cpu_count/2` | CPU threads for llama-server |

## Embedder status / doctor

The embedder exposes a lightweight status view for diagnostics:

- `BgeCodeEmbedder().status(probe=False)` reports backend, discovered model/server paths, readiness, batch state, and lightweight file fingerprints.
- `probe=False` does not start `llama-server`.
- `probe=True` may probe `/health` and can start the local server when configured.
- `deep_hash=True` adds full SHA-256 hashes for model/server files (heavier than head-hash mode).

Use this for local-first setup checks and keep claims cautious: semantic results are behavior hints and triage signals, not proof.
