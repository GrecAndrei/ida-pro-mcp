# IDA MCP Quick Start

## 1) Create a session
Use `session(action="create")` with a binary path.

```json
{"name":"session","arguments":{"action":"create","binary_path":"/path/to/binary"}}
```

## 2) Inspect metadata
```json
{"name":"idb","arguments":{"action":"meta"}}
```

## 3) Query code/data
```json
{"name":"data","arguments":{"action":"functions","count":50}}
```

## 4) Use wiki for detailed docs
```json
{"name":"wiki","arguments":{"action":"read","topic":"tools/session"}}
```

## Key behavior
- `session(action="create")` does not accept `idb_path` or `use_existing`.
- `idb` argument is optional for most tools once a session is active.
- `tools/list` defaults to full descriptions and full schemas.
- Host normalization now tolerates noisy LLM call forms for `threat_hunt`, `search`, `session`, and `code` (wrapped action names, noisy arg keys, bracketed address/list values) when mapping is unambiguous.
- Every tool response includes `llm_pointer_note` in ALL CAPS, reminding agents to use `calc`/`memory` for pointer/address arithmetic.

---
Doc status: Updated to current host/runtime behavior.
Last reviewed: 2026-03-27
