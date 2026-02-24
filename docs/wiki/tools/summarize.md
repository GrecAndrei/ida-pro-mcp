# SUMMARIZE Tool Manual

## What It Does
Builds LLM-friendly summaries at binary/function/segment level and provides derived analytics for imports, strings, complexity, call hierarchy, data flow, security posture, and global statistics.

## Actions
- `binary`: High-level binary overview.
- `function`: Function-level behavior summary.
- `segment`: Segment-level summary.
- `imports_by_category`: Functional categorization of imports.
- `strings_by_category`: Pattern-based string categorization.
- `complexity`: CFG/instruction complexity metrics.
- `call_hierarchy`: Recursive call tree from a root function.
- `data_flow`: Input/transform/output heuristic summary.
- `security_posture`: Dangerous API and mitigation signal assessment.
- `statistics`: Aggregate binary metrics.

## Key Parameters
- `action`: One of `binary|function|segment|imports_by_category|strings_by_category|complexity|call_hierarchy|data_flow|security_posture|statistics`.
- `addr`: Required for `function`, `segment`, `complexity`, `call_hierarchy`, `data_flow`.
- `depth`: Traversal depth for `call_hierarchy`.
- `max_items`: Per-list cap in output summaries.

## Examples
```python
summarize(action="binary", max_items=25)
summarize(action="function", addr="0x401000", max_items=20)
summarize(action="segment", addr="0x400000")
summarize(action="complexity", addr="0x401000")
summarize(action="call_hierarchy", addr="0x401000", depth=2, max_items=10)
summarize(action="security_posture", max_items=50)
summarize(action="statistics")
```

## Failure Modes
- Missing required `addr` for function-scoped actions.
- Invalid/non-function addresses on function-only actions.
- Complexity/call/data-flow quality depends on analysis completeness and symbol recovery.
- Decompilation preview may be unavailable when Hex-Rays is not initialized.
