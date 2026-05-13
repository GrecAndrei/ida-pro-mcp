# memory

Read, write, search, and analyze raw memory/binary content with auto-blackboard capture.

## Actions
- `read` — read `size` bytes from `address`; returns raw bytes.
- `write` — write `data` (hex) to `address`. Guardrail-protected.
- `hexdump` — formatted hex dump at `address`, optional `size`.
- `search` — search memory for `pattern` (hex or string); optional `start`, `end`.
- `compare` — compare memory at two addresses; params `addr1`, `addr2`, `size`.
- `pointers` — scan for pointer-like values at `address`; auto-captured to blackboard.
- `entropy` — compute entropy of region at `address`, `size`; auto-captured to blackboard.
- `strings` — extract strings from region at `address`, `size`; auto-captured to blackboard.
- `struct_walk` — walk memory as a structure; params `address`, `struct_name`; auto-captured to blackboard.
- `histogram` — byte frequency histogram at `address`, `size`.

## Examples
```json
{"name": "memory", "arguments": {"action": "hexdump", "address": "0x401000", "size": 64}}
```
```json
{"name": "memory", "arguments": {"action": "entropy", "address": "0x600000", "size": 4096}}
```

## Notes
- `pointers`, `strings`, `entropy`, and `struct_walk` results are automatically written to the blackboard for persistent context.
- Use `calc` tool for address arithmetic instead of computing offsets manually.
- `write` is guardrail-protected; requires `_guardrail_ack=true` in strict mode.
