# Intelligence Layer

IDA Pro MCP can use a local GGUF embedding model for semantic analysis. The
default profile is `bge-code-v1` (1536 dimensions); `zembed-1` is an opt-in
2560-dimension profile. Lexical retrieval remains available, while a missing
embedding model is reported explicitly rather than silently replaced with a
different vector representation.

## How it works

**BgeCodeEmbedder** — compatibility class name for the profile-aware local
embedder. It manages one `llama-server` process, detects the selected GGUF
dimension, and applies profile-specific prompts. Zembed uses separate
`query` and `document` prompts; indexed functions are documents and search
text is a query.

**FunctionEmbeddingIndex** — per-binary SQLite store of model-native
embeddings. Written to `<idb_path>.embeddings.db`. Its metadata records model
identity, dimension, and prompt format so a profile/model change rebuilds the
index rather than mixing incompatible vectors.

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
| `IDA_MCP_EMBED_PROFILE` | `bge-code-v1` | Model profile and prompt contract |
| `IDA_MCP_EMBED_MODEL` | auto-detect | Path to the selected GGUF |
| `IDA_MCP_EMBED_SERVER_BIN` | auto-detect | Path to llama-server binary |
| `IDA_MCP_EMBED_DISABLED` | `0` | Set to `1` to disable semantic embeddings |
| `IDA_MCP_EMBED_THREADS` | adaptive | CPU threads for llama-server |
| `IDA_MCP_EMBED_MAX_REQUESTS` | `512` | Recycle the server after successful requests |
| `IDA_MCP_EMBED_MAX_RSS_MB` | adaptive | Optional server RSS recycle limit |
| `IDA_MCP_EMBED_IDLE_TIMEOUT` | `15` | Retire llama-server after this many idle seconds (`0` disables it) |

The server starts only for an explicit indexing, semantic-search, or anchor
refresh operation; routine tool/context work does not cold-start it. It
accepts one embedding request at a time. A timeout recycles it so abandoned
work cannot block future requests. Full decompilation indexing stops at the
failed batch and returns a cursor for a clean retry.

## Embedder status / doctor

The embedder exposes a lightweight status view for diagnostics:

- `BgeCodeEmbedder().status(probe=False)` reports backend, discovered model/server paths, readiness, batch state, and lightweight file fingerprints.
- `probe=False` does not start `llama-server`.
- `probe=True` may probe `/health` and can start the local server when configured.
- `deep_hash=True` adds full SHA-256 hashes for model/server files (heavier than head-hash mode).

Use this for local-first setup checks and keep claims cautious: semantic results are behavior hints and triage signals, not proof.
