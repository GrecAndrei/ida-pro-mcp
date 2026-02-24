# LUMINA Tool Manual

## What It Does
Interfaces with Hex-Rays Lumina integration to inspect availability, trigger pull/push/history UI actions, and query limited metadata for a function.

## Actions
- `status`: Report Lumina action availability and module/init state hints.
- `pull`: Pull metadata for one function (`addr`) or all functions.
- `push`: Push one function (`addr`) or all (`push_all=True`).
- `history`: Open Lumina history for a function.
- `search`: Placeholder; currently returns not-implemented.
- `get_metadata`: Best-effort metadata/name-origin inspection for function.

## Key Parameters
- `action`: One of `pull|push|status|history|search|get_metadata`.
- `addr`: Function address for `pull` (single), `push` (single), `history`, `get_metadata`.
- `query`: Required for `search` (currently unsupported).
- `push_all`: Enables all-function push path.

## Examples
```python
lumina(action="status")
lumina(action="pull", addr="0x401000")
lumina(action="pull")
lumina(action="push", addr="0x401000")
lumina(action="push", push_all=True)
lumina(action="history", addr="0x401000")
lumina(action="get_metadata", addr="0x401000")
```

## Failure Modes
- Missing required `addr` for function-specific actions.
- Missing `addr`/`push_all=True` for `push`.
- Lumina UI actions unavailable in current build/session.
- `search` always returns `NOT_IMPLEMENTED`.
- Metadata API differences across IDA versions.
