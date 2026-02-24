# FIXUPS Tool Manual

## What It Does
Lists and manipulates relocation/fixup entries stored in the IDA database.

## Actions
- `list`: Enumerate fixups in a range (or whole database).
- `get`: Read fixup details at one address.
- `add`: Create/set fixup at address with optional target.
- `delete`: Remove fixup at address.

## Key Parameters
- `action`: One of `list|get|add|delete`.
- `addr`: Required for `get`, `add`, `delete`.
- `target`: Optional target address for `add`.
- `fixup_type`: Integer fixup type for `add`.
- `start`, `end`: Optional listing bounds.
- `offset`, `count`: Pagination controls (`count=0` means unlimited scan).

## Examples
```python
fixups(action="list", start="0x400000", end="0x500000", offset=0, count=200)
fixups(action="get", addr="0x401234")
fixups(action="add", addr="0x401234", target="0x500000", fixup_type=0)
fixups(action="delete", addr="0x401234")
```

## Failure Modes
- Missing required `addr`.
- Invalid range/address parsing.
- No fixup at requested address for `get`.
- IDA API-level failures when setting/deleting entries.
