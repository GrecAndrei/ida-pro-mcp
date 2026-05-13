# compare

Compares two functions or binaries across multiple dimensions (code, APIs, strings, structure).

## Actions
- `functions` — diff two functions; params: `addr_a`, `addr_b`
- `blocks` — compare basic blocks; params: `addr_a`, `addr_b`
- `apis` — compare API call sets; params: `addr_a`, `addr_b`
- `strings` — compare referenced strings; params: `addr_a`, `addr_b`
- `constants` — compare numeric constants; params: `addr_a`, `addr_b`
- `structure` — compare structural layout (CFG shape); params: `addr_a`, `addr_b`
- `semantics` — semantic similarity score; params: `addr_a`, `addr_b`
- `batch_compare` — compare multiple pairs; params: `pairs` (list)
- `find_clones` — find code clones of a function; params: `address`, `threshold`

## Examples
```json
{"name": "compare", "arguments": {"action": "functions", "addr_a": "0x401000", "addr_b": "0x402000"}}
```
```json
{"name": "compare", "arguments": {"action": "find_clones", "address": "0x401000", "threshold": 0.8}}
```

## Notes
- `semantics` uses local ML scoring (no external calls).
- `find_clones` scans all functions and returns those above the similarity threshold.
