# microcode

Accesses IDA's intermediate microcode representation for a function.

## Actions
- `get` — get microcode for a function; params: `address`, `maturity` (optional)
- `blocks` — list microcode basic blocks; params: `address`
- `instructions` — list microcode instructions; params: `address`, `block` (optional)
- `def_use_graph` — compute def-use graph from microcode; params: `address`

## Examples
```json
{"name": "microcode", "arguments": {"action": "get", "address": "0x401000", "maturity": "MMAT_GLBOPT1"}}
```
```json
{"name": "microcode", "arguments": {"action": "def_use_graph", "address": "0x401000"}}
```

## Notes
- `maturity` controls optimization level (MMAT_GENERATED through MMAT_LVARS).
- Requires Hex-Rays decompiler.
- `def_use_graph` is useful for tracking data dependencies at IR level.
