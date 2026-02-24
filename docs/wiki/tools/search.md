# SEARCH Tool Manual

## What It Does
Provides broad binary search capabilities: bytes, strings, names, instruction/text searches, references, smart lookup, callgraph lookups, API usage, vulnerability heuristics, constant hunting, and decompiled-code regex search.

## Actions
- `bytes`, `string`, `immediate`, `name`, `insns`, `text`, `operand`, `comment`
- `data_ref`, `code_ref`, `regex`, `func_by_sig`
- `find`, `callers`, `callees`, `api`
- `vulnerable`, `constants`, `decompiled`

## Key Parameters
- `action`: One of `bytes|string|immediate|name|insns|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled`.
- `pattern`: Primary pattern/value/target for most actions.
- `query`: Alias for `pattern`.
- `limit`: Max returned lines.
- `offset`: Skip first N matches.
- `start`, `end`: Optional bounded range (must be provided together).
- `case_sensitive`: Applies to string/text/regex-like matching flows.
- `include_context`: Adds extra disasm/function context in results.

## Examples
```python
search(action="bytes", pattern="55 8B EC", limit=50)
search(action="string", pattern="license", case_sensitive=False)
search(action="immediate", pattern="0x10001", include_context=True)
search(action="find", pattern="malloc")
search(action="callers", pattern="main")
search(action="api", pattern="*CreateProcess*")
search(action="vulnerable", limit=100, include_context=True)
search(action="constants", start="0x401000", end="0x410000")
search(action="decompiled", pattern="memcpy\\s*\\(", limit=20)
```

## Failure Modes
- Missing `pattern` for actions that require it.
- Invalid range when only one of `start`/`end` is provided.
- Invalid numeric/regex input (`immediate`, `regex`, `decompiled`).
- Target resolution failures for `data_ref`, `code_ref`, `callers`, `callees`, `api`.
- Some actions are heuristic and may produce false positives or truncated results at `limit`.
