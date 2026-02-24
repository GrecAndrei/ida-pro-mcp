# STRUCTS Tool Manual

## What It Does
Supports structure recovery and lifecycle tasks: infer usage, list/create/update structs, apply struct types to addresses, and reconstruct vtable-like layouts.

## Actions
- `recover`: Heuristic struct-candidate extraction from one function.
- `analyze_usage`: Show xref-based usage from an address.
- `list`: List struct/union types with optional filter/pagination.
- `create`: Parse C declaration and create type.
- `add_member`: Append a member to an existing struct.
- `apply`: Apply named struct type at an address.
- `reconstruct_vtable`: Build a vtable struct from pointer table data.

## Key Parameters
- `action`: One of `recover|analyze_usage|list|create|add_member|apply|reconstruct_vtable`.
- `addr`: Required for `recover`, `analyze_usage`, `apply`, `reconstruct_vtable`.
- `name`: Struct name (required for `add_member` and `apply`; optional class/vtable name for `reconstruct_vtable`).
- `decl`: Required C declaration for `create`.
- `member_name`, `member_type`, `member_offset`: Member fields for `add_member`.
- `query`, `offset`, `count`: Listing filters/pagination.

## Examples
```python
structs(action="list", query="net", count=50)
structs(action="create", decl="struct Header { int magic; short ver; };")
structs(action="add_member", name="Header", member_name="flags", member_type="int", member_offset=8)
structs(action="apply", addr="0x404000", name="Header")
structs(action="recover", addr="0x401250")
structs(action="reconstruct_vtable", addr="0x500000", name="ClientVTable")
```

## Failure Modes
- Missing required fields by action.
- Type parse failure (`create`, `add_member`).
- Named struct not found (`add_member`, `apply`).
- `recover` depends on successful Hex-Rays decompilation.
- `reconstruct_vtable` fails if pointer table does not resolve to plausible code pointers.
