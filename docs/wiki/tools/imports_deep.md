# IMPORTS_DEEP Tool Manual

## What It Does
Performs deeper import/thunk inspection beyond basic import listing, including ordinal/API-set views and per-address import resolution.

## Actions
- `thunks`: Scan IAT-like areas for thunk target values.
- `delay`: Heuristic delay-import section scan.
- `forwarded`: Detect dotted-name style forwarded import hints.
- `ordinal`: List ordinal imports (optionally filtered by DLL query).
- `api_sets`: Map `api-ms-*` imports to heuristic backing DLL names.
- `resolve`: Resolve one import address or list all resolved imports.

## Key Parameters
- `action`: One of `thunks|delay|forwarded|ordinal|api_sets|resolve`.
- `query`: Optional filter (`thunks`, `ordinal`).
- `addr`: Optional for `resolve`; if omitted, action returns batch list.
- `offset`, `count`: Pagination controls (`count=0` means no cap).

## Examples
```python
imports_deep(action="thunks", query="kernel32", offset=0, count=100)
imports_deep(action="delay")
imports_deep(action="forwarded")
imports_deep(action="ordinal", query="ntdll")
imports_deep(action="api_sets")
imports_deep(action="resolve", addr="0x180020000")
imports_deep(action="resolve", offset=0, count=200)
```

## Failure Modes
- Invalid `addr` for single-item `resolve`.
- Heuristic section-name logic may miss nonstandard layouts.
- Forwarded/API-set outputs are best-effort, not loader-accurate emulation.
- Unknown action returns invalid-args error.
