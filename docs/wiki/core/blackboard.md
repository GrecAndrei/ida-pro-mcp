# Blackboard

Persistent, self-maintaining analysis context. Survives context window resets.

## What it does automatically

The blackboard captures findings without you asking:
- `memory(action="pointers/strings/entropy/struct_walk")` → writes pointer/string/entropy entries
- `calc(action="resolve/deref/chain")` → writes resolved addresses and pointer chains
- `code(action="decompile")` → writes behavior classifications and hypotheses
- `modify(action="rename")` → writes rename propagation suggestions for callees
- `agent(action="cluster")` → writes cluster summaries
- `deobfuscate(action="detect")` → writes obfuscation findings
- `gadgets(action="classify_chain")` → writes exploit assessment

## Actions

| Action | Purpose |
|--------|---------|
| `write` | Pin a finding manually |
| `read` | Get entry by ID |
| `list` | List entries (filter by category, addr, tag) |
| `search` | **Semantic search** — embed query, cosine-rank entries |
| `update` | Modify an entry |
| `delete` | Remove an entry |
| `clear` | Remove all (or by category) |
| `stats` | Counts, categories, embedding coverage |
| `prune` | Evict low-quality or old entries |
| `merge` | Deduplicate similar entries |

## Semantic search

```json
{"name":"blackboard","arguments":{"action":"search","query":"AES key schedule crypto","top_k":5}}
```

Uses stored bge-code-v1 vectors (written at entry creation time). Falls back to substring match if embedder unavailable.

## Categories used by auto-capture

`pointer`, `string`, `entropy`, `address`, `pointer_chain`, `deref`, `cluster`, `hypothesis`, `rename_suggestion`, `obfuscation`, `protocol`, `session_diff`

## Manual write example

```json
{"name":"blackboard","arguments":{
  "action":"write",
  "title":"Buffer overflow at 0x401234",
  "content":"Unchecked strcpy into 64-byte stack buffer. Controlled by network input.",
  "category":"vuln",
  "addr":"0x401234",
  "tags":["overflow","strcpy","network"],
  "confidence":0.95
}}
```

## Storage

Per-binary: `<idb_path>.blackboard.db` (SQLite, WAL mode).
Global fallback: `~/.local/state/ida-pro-mcp/blackboard.db`.
