# blackboard

Persistent working memory (SQLite-backed) for storing, searching, and managing analysis findings across sessions.

## Actions
- `write` — store a finding; params: `category`, `content`, `address`, `tags`, `confidence`
- `read` — read a specific entry; params: `id`
- `list` — list entries; params: `category`, `tags`, `offset`, `count`
- `search` — semantic search using bge-code-v1 vectors (falls back to substring); params: `query`, `limit`
- `update` — update an existing entry; params: `id`, `content`, `tags`, `confidence`
- `delete` — delete an entry; params: `id`
- `clear` — clear all entries (or by category); params: `category` (optional)
- `stats` — show entry counts, categories, storage size
- `prune` — remove low-value entries; params: `max_entries`, `min_q_value`, `older_than_days`
- `merge` — merge duplicate/related entries; params: `ids`

## Examples

```json
{"name": "blackboard", "arguments": {"action": "search", "query": "crypto key schedule", "limit": 5}}
```

```json
{"name": "blackboard", "arguments": {"action": "write", "category": "vuln", "content": "Buffer overflow in parse_header", "address": "0x401234", "tags": ["overflow", "input"]}}
```

## Notes
- `search` performs semantic vector search on stored bge-code-v1 embeddings; falls back to substring matching when vectors are unavailable.
- Auto-capture: findings from `memory`, `calc`, `classify`, `deobfuscate`, `gadgets`, and `agent` are automatically written to the blackboard without explicit calls.
- Entries have Q-values (updated by MemRL) that influence context injection ranking — low-value entries are pruned automatically or via `prune`.
