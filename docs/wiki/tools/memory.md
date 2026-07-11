# memory

Read, write, search, and inspect raw memory contents and typed values at arbitrary addresses.

## Actions

- `read` — reads a typed value from `addr`; param `type` controls format (see Types below)
- `write` — writes raw bytes to an address; params: `addr`, `data` (hex string)
- `hexdump` — returns a formatted hex dump; params: `addr`, `size`
- `search` — searches memory for a byte pattern, string, or regex; params: `data`/`pattern`, `end_addr`, `regex`, `literal`, `int_width`
- `compare` — compares two memory regions; params: `addr`, `end_addr` (or `addr1`, `addr2`), `size`
- `pointers` — finds all valid pointers in a range; params: `addr`, `end_addr`
- `entropy` — computes Shannon entropy of a memory region; params: `addr`, `end_addr`
- `strings` — extracts printable ASCII/UTF-16 strings; params: `addr`, `end_addr`
- `struct_walk` — follows pointer dereferences recursively; params: `addr`, `depth`
- `histogram` — byte frequency distribution + entropy sparkline; params: `addr`, `end_addr`

## Types (for `action=read`)

Use the `type` parameter to control what `read` returns:

| type | Description |
|------|-------------|
| `bytes` | Raw hex dump of `size` bytes (default) |
| `u8` / `u16` / `u32` / `u64` | Unsigned integer |
| `s8` / `s16` / `s32` / `s64` | Signed integer |
| `f32` / `f64` | IEEE float |
| `ptr` | Pointer-sized value (32 or 64 bit) |
| `string` | Null-terminated string at address |

## Filesystem (host-side, intercepted before IDA)

- `read_file` — read a file from the host filesystem (sandboxed to IDB dir or `IDA_MCP_MEMORY_ROOT`)
- `write_file` — write a file to the host filesystem

## Examples

```json
{"name": "memory", "arguments": {"action": "read", "addr": "0x404010", "type": "u32"}}
```

```json
{"name": "memory", "arguments": {"action": "hexdump", "addr": "0x401000", "size": 64}}
```

```json
{"name": "memory", "arguments": {"action": "search", "data": "4D5A", "end_addr": "0x500000"}}
```

```json
{"name": "memory", "arguments": {"action": "search", "pattern": "recv", "regex": false, "literal": true}}
```

```json
{"name": "memory", "arguments": {"action": "struct_walk", "addr": "0x6040A0", "depth": 3}}
```

```json
{"name": "memory", "arguments": {"action": "pointers", "addr": "0x404000", "end_addr": "0x405000"}}
```

```json
{"name": "memory", "arguments": {"action": "entropy", "addr": "0x401000", "end_addr": "0x405000"}}
```

## Notes

- **Integer detection trap**: Searching for `"1234"` triggers integer-mode by default (converts to `0x000004D2`). Use `literal=true` to search for the ASCII string instead.
- **Region capping**: search/compare/pointers/entropy/strings cap at 1MB per call. Results include `region_capped=true` when the requested range was larger.
- **Compare distance**: small inputs get true Levenshtein `edit_distance`; large inputs (>4M comparisons) fall back to `hamming_distance` with a note.
- `write` is guardrailed — may require `_guardrail_ack=true` in strict write mode.
- Do not compute addresses mentally — use the `calc` tool for pointer arithmetic.
- `addr` is optional for `search` only — if omitted, auto-fills from IDB minimum address with a 64KB window.
