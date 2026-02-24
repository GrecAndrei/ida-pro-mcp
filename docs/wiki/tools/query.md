# QUERY Tool Manual

## What It Does
Acts as a unified read-only router that forwards requests to other tools (`data`, `search`, `idb`, `code`, `types`, `imports_deep`, `symbols`, `patterns`).

## Actions
- `data`: Route to `data` tool (`subaction` default: `functions`).
- `search`: Route to `search` tool (`subaction` default: `find`).
- `idb`: Route to `idb` tool (`subaction` default: `summary`).
- `code`: Route to `code` tool (`subaction` default: `disasm`).
- `types`: Route to `types` tool (`subaction` default: `list`).
- `imports_deep`: Route to `imports_deep` tool (`subaction` default: `thunks`).
- `symbols`: Route to `symbols` tool (`subaction` default: `status`).
- `patterns`: Route to `patterns` tool (`subaction` default: `list_sigs`).

## Key Parameters
- `action`: One of `data|search|idb|code|types|imports_deep|symbols|patterns`.
- `subaction`: Action to run on routed tool (optional; defaults per action).
- `args`: Dictionary forwarded as keyword args to routed tool.

## Examples
```python
query(action="data", subaction="functions", args={"count": 20})
query(action="search", subaction="find", args={"pattern": "malloc", "limit": 30})
query(action="idb", subaction="summary")
query(action="code", subaction="decompile", args={"addr": "0x401000"})
query(action="types", subaction="list", args={"count": 50})
query(action="symbols", subaction="status")
```

## Failure Modes
- Unknown top-level `action` returns `ACTION_NOT_FOUND`.
- Invalid `subaction`/`args` failures bubble up from routed tool.
- Tool import/runtime exceptions are returned via common error handler.
