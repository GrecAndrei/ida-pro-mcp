# memory

Read, write, search, and inspect raw memory contents and typed values at arbitrary addresses.

## Actions

- `read` — reads raw bytes from an address; params: `addr`, `size`
- `write` — writes raw bytes to an address; params: `addr`, `data` (hex string)
- `hexdump` — returns a formatted hex dump; params: `addr`, `size`
- `search` — searches memory for a byte pattern; params: `pattern`, `start`, `end`
- `compare` — compares two memory regions; params: `addr_a`, `addr_b`, `size`
- `pointers` — finds all pointer-sized values in a range; params: `addr`, `size`
- `entropy` — computes entropy of a memory region; params: `addr`, `size`
- `strings` — extracts printable strings from a memory region; params: `addr`, `size`, `min_len`
- `struct_walk` — follows a chain of pointer dereferences (e.g., `obj->next->data`); params: `addr`, `offsets`
- `histogram` — shows byte frequency distribution for a region; params: `addr`, `size`
- `bytes` — reads raw bytes as a hex string; params: `addr`, `size`
- `u8` — reads an unsigned 8-bit value; params: `addr`
- `u16` — reads an unsigned 16-bit value; params: `addr`
- `u32` — reads an unsigned 32-bit value; params: `addr`
- `u64` — reads an unsigned 64-bit value; params: `addr`
- `s8` — reads a signed 8-bit value; params: `addr`
- `s16` — reads a signed 16-bit value; params: `addr`
- `s32` — reads a signed 32-bit value; params: `addr`
- `s64` — reads a signed 64-bit value; params: `addr`
- `f32` — reads a 32-bit float; params: `addr`
- `f64` — reads a 64-bit double; params: `addr`
- `ptr` — reads a pointer-sized value; params: `addr`
- `string` — reads a null-terminated string; params: `addr`, `max_len`

## Examples

```json
{"name": "memory", "arguments": {"action": "hexdump", "addr": "0x401000", "size": 64}}
```

```json
{"name": "memory", "arguments": {"action": "u32", "addr": "0x404010"}}
```

```json
{"name": "memory", "arguments": {"action": "search", "pattern": "4D5A", "start": "0x400000", "end": "0x500000"}}
```

```json
{"name": "memory", "arguments": {"action": "struct_walk", "addr": "0x6040A0", "offsets": [0, 8, 16]}}
```

```json
{"name": "memory", "arguments": {"action": "pointers", "addr": "0x404000", "size": 256}}
```

```json
{"name": "memory", "arguments": {"action": "entropy", "addr": "0x401000", "size": 4096}}
```

## Notes

- Type shortcut actions (`u8`–`u64`, `s8`–`s64`, `f32`, `f64`, `ptr`, `string`) read a single typed value — use these instead of `read` + manual parsing.
- `struct_walk` is essential for traversing linked structures; provide offsets as a list of byte offsets to dereference at each step.
- `histogram` is useful for detecting packed/encrypted regions (high entropy = flat distribution).
- `write` is a guardrailed action — may require `_guardrail_ack=true` in strict write mode.
- Do not compute addresses mentally — use the `calc` tool for pointer arithmetic.
- `search` accepts hex byte patterns; use `??` for wildcard bytes if supported.
