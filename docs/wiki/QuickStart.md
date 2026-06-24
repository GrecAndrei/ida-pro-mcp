# IDA Pro MCP — Quick Start

## 1. Create a session
```json
{"name":"session","arguments":{"action":"create","binary_path":"/path/to/binary"}}
```

## 2. Get the analysis state
```json
{"name":"session","arguments":{"action":"state"}}
```
Returns: binary metadata, coverage, blackboard summary, engine status, and suggested next actions.

> `ida://state` and other `ida://` resources exist in the MCP protocol but are **not** auto-injected — the LLM cannot read them autonomously. Use `session(action='state')` instead.

`tools/list` defaults to `ultra` mode — short routing hints plus action enums, ~9.5k tokens. Use `mode="lean"` or `mode="full"` only when you need exact argument shapes.

## 3. Get ranked next targets
```json
{"name":"blackboard","arguments":{"action":"frontier","limit":10}}
```

## 4. Decompile a function
```json
{"name":"code","arguments":{"action":"smart_decompile","addrs":"0x401000"}}
```
`smart_decompile` returns decompiled code + behavior tags + call graph in one call.

## 5. Classify behavior
```json
{"name":"classify","arguments":{"action":"function","addr":"0x401000"}}
```
Uses BehaviorClassifier (zero-shot embedding similarity), not keyword matching.

## 6. Find similar functions
```json
{"name":"agent","arguments":{"action":"similar","addr":"0x401000"}}
```

## 7. Natural language search
```json
{"name":"search","arguments":{"action":"nl","query":"function that decrypts strings"}}
```

## 8. Persist findings
```json
{"name":"blackboard","arguments":{"action":"write","addr":"0x401000","category":"vuln","title":"heap overflow in recv handler","confidence":0.85}}
```

## 9. Batch multiple calls
```json
{"name":"batch","arguments":{"calls":["idb:meta","data:imports",{"name":"data","action":"strings","count":50}]}}
```

## 10. Full report
```json
{"name":"summarize","arguments":{"action":"report"}}
```

## Key rules

- Write ops (`modify`, `funcs`, `data_ops`, etc.) require `_risk_ack=true`
- `idb` is optional once a session is active — the active session is used automatically
- `batch` reduces round-trips for deterministic multi-step flows
- Use `calc` for address arithmetic
- Blackboard auto-captures findings from `classify`, `gadgets`, `deobfuscate`, `memory`, `calc` — no manual write needed for those
