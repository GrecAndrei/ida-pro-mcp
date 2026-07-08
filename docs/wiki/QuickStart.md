# IDA Pro MCP — Quick Start

Agent-facing surface is **Tier A** (~17 tools). Full tool list exists but is hidden from `tools/list`. See `docs/ROADMAP.md`.

## 1. Create a session

```json
{"name":"session","arguments":{"action":"create","binary_path":"/path/to/binary"}}
```

## 2. Analysis state (every turn)

```json
{"name":"session","arguments":{"action":"state"}}
```

Returns binary metadata, coverage, blackboard summary, and suggested next actions.

> Prefer `session(action='state')` over `ida://state` resources (resources are not auto-injected for the model).

## 3. Wait / kick analysis if needed

```json
{"name":"analysis","arguments":{"action":"wait"}}
{"name":"analysis","arguments":{"action":"analyze","blocking":true}}
```

## 4. Optional: embed index for NL search

```json
{"name":"intelligence","arguments":{"action":"index_fast"}}
```

## 5. Search

```json
{"name":"search","arguments":{"action":"find","pattern":"recv"}}
{"name":"search","arguments":{"action":"nl","query":"function that decrypts strings","mode":"quick"}}
{"name":"search","arguments":{"action":"string","pattern":"password"}}
```

Core search actions: `find`, `nl`, `string`, `bytes`, `api`, `callers`, `callees`, `xrefs_to_string`, `symbol`, `symbol_info`, `decompiled`, `behavior`.

## 6. Decompile

```json
{"name":"code","arguments":{"action":"smart_decompile","addrs":"0x401000"}}
```

## 7. Annotate

```json
{"name":"modify","arguments":{"action":"rename","addr":"0x401000","name":"handle_recv","_risk_ack":true}}
{"name":"modify","arguments":{"action":"comment","addr":"0x401000","comment":"entry for C2 recv","_risk_ack":true}}
```

## 8. Persist findings (blackboard = durable notebook)

```json
{"name":"blackboard","arguments":{"action":"write","addr":"0x401000","category":"finding","title":"recv handler","confidence":0.8}}
{"name":"blackboard","arguments":{"action":"frontier","limit":10}}
```

Do **not** use `wiki` for findings (docs only). Do **not** use `knowledge` for session notes (chip/symbol KB).

## 9. Batch multi-call

```json
{"name":"batch","arguments":{"calls":["idb:meta","data:imports",{"name":"data","action":"strings","count":50}]}}
```

## 10. Save and close

```json
{"name":"idb","arguments":{"action":"save"}}
{"name":"session","arguments":{"action":"close"}}
```

## Key rules

- Write ops (`modify`, `funcs`, …) may require `_risk_ack=true` under policy modes
- Unknown tool kwargs are **rejected** with `INVALID_ARGS` (not silently dropped)
- `search.nl` needs an embedding index (`intelligence.index_fast` / `index_batch`)
- `misc(action='reload')` is **dev-only** (hot-reload IDA tool modules); not in compact enum
- Prefer hex address strings verbatim from search results (`"0x356f8"`)
