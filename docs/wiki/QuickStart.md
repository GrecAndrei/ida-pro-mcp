# IDA Pro MCP — Quick Start

## 1. Create a session
```json
{"name":"session","arguments":{"action":"create","binary_path":"/path/to/binary"}}
```

## 2. Orient yourself
```json
{"name":"idb","arguments":{"action":"meta"}}
{"name":"data","arguments":{"action":"imports"}}
{"name":"data","arguments":{"action":"strings","count":50}}
```

## 3. Understand the binary at a glance
```json
{"name":"agent","arguments":{"action":"cluster","max_items":8,"func_limit":200}}
```
Returns behavioral clusters (crypto, network, injection, etc.) across all functions using bge-code-v1 embeddings.

## 4. Decompile and classify a function
```json
{"name":"code","arguments":{"action":"decompile","addrs":"0x401000"}}
{"name":"classify","arguments":{"action":"function","addr":"0x401000"}}
```
`classify` uses BehaviorClassifier (zero-shot embedding similarity) — not keyword matching.

## 5. Find similar functions
```json
{"name":"agent","arguments":{"action":"similar","addr":"0x401000"}}
```
Uses FunctionEmbeddingIndex (cosine similarity over 1536-dim bge-code-v1 vectors).

## 6. Natural language search
```json
{"name":"query","arguments":{"action":"nl","q":"find functions that decrypt strings"}}
```

## 7. Get rename suggestions for unnamed functions
```json
{"name":"funcs","arguments":{"action":"suggest_names","limit":20}}
```

## 8. Use the blackboard for persistent context
```json
{"name":"blackboard","arguments":{"action":"search","query":"crypto key schedule AES"}}
{"name":"blackboard","arguments":{"action":"list","category":"hypothesis"}}
```
The blackboard auto-captures findings from `memory`, `calc`, `deobfuscate`, `classify`, and `gadgets` — you don't need to write entries manually for those.

## 9. Generate a full report
```json
{"name":"summarize","arguments":{"action":"report"}}
```

## Key rules
- `session(action="create")` does not accept `idb_path` or `use_existing`.
- `idb` is optional once a session is active.
- Every response includes `context_pack` with relevant prior findings from the blackboard.
- Use `calc` and `memory` for address arithmetic — never compute addresses mentally.
- `batch` reduces round-trips for deterministic multi-step flows.
