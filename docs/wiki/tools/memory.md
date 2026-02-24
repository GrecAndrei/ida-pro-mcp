# MEMORY Tool Manual

## What It Does
Reads typed values/byte blocks and patches bytes at addresses, plus formatted hexdump output.

## Actions
- `read`: Read at `addr` using scalar/float/pointer/string/bytes types.
- `write`: Patch bytes from hex string.
- `hexdump`: Return xxd-style formatted dump.

## Key Parameters
- `action`: One of `read|write|hexdump`.
- `addr`: Required target address.
- `type`: For `read`; supports `bytes|u8|u16|u32|u64|s8|s16|s32|s64|f32|f64|ptr|string`.
- `size`: Used by `read(type="bytes")` and `hexdump`.
- `data`: Required for `write`; hex string (spaces allowed).

## Examples
```python
memory(action="read", addr="0x401000", type="u32")
memory(action="read", addr="0x401000", type="bytes", size=32)
memory(action="read", addr="0x500000", type="string")
memory(action="write", addr="0x401234", data="90 90 90")
memory(action="hexdump", addr="0x401000", size=128)
```

## Failure Modes
- Invalid/missing address.
- Read size too large (`>1MB`) for `read` bytes mode.
- Hexdump size exceeds hard cap (`4096`).
- Invalid hex in `write` data.
- Read failures for unmapped/unreadable locations.
