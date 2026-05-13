# calc

Evaluate expressions, resolve pointers, dereference chains, and perform address arithmetic safely.

## Actions
- `eval` — evaluate arithmetic/bitwise expression; param `expr` (e.g. `"0x401000 + 0x20"`).
- `offset` — compute offset between two addresses; params `base`, `target`.
- `convert` — convert value between representations; params `value`, `to` (hex/dec/bin/oct).
- `resolve` — resolve symbol or address to concrete value; param `name` or `address`. Auto-captured to blackboard.
- `deref` — dereference pointer at `address`, optional `size`/`depth`. Auto-captured to blackboard.
- `chain` — follow pointer chain from `address`; optional `max_depth`. Auto-captured to blackboard.
- `align` — align `address` to `boundary`.

## Examples
```json
{"name": "calc", "arguments": {"action": "eval", "expr": "0x401000 + 0x48 * 3"}}
```
```json
{"name": "calc", "arguments": {"action": "chain", "address": "0x601020", "max_depth": 4}}
```

## Notes
- Always use `calc` for address math instead of mental arithmetic — this avoids pointer errors.
- `resolve`, `deref`, and `chain` results are auto-captured to the blackboard for later reference.
- Accepts natural language via `intent` param (e.g. `"offset from base to vtable entry 5"`).
