# STACK_ANALYSIS Tool Manual

## What It Does
Performs function-level stack-frame analysis for reverse engineering, including frame layout, buffers, canaries, alignment, spills, usage depth, variable classification, array detection, uninitialized-variable heuristics, and quick summaries.

## Actions
- `frame`: Full frame member layout.
- `buffers`: Potential stack buffers.
- `canary`: Stack canary/cookie detection.
- `alignment`: Frame/member alignment characteristics.
- `spills`: Saved-register spill candidates.
- `usage`: Stack-depth and dynamic-allocation hints.
- `variables`: Typed/classified variable inventory.
- `arrays`: Array-like stack variables.
- `uninitialized`: Variables without detected writes (heuristic).
- `summary`: One-shot stack profile.

## Key Parameters
- `action`: One of `frame|buffers|canary|alignment|spills|usage|variables|arrays|uninitialized|summary`.
- `addr`: Optional function address. If omitted, uses cursor address (fails in headless when unavailable).
- `limit`: Max rows for list-like outputs.

## Examples
```python
stack_analysis(action="frame", addr="0x401000", limit=100)
stack_analysis(action="buffers", addr="0x401000")
stack_analysis(action="canary", addr="0x401000")
stack_analysis(action="usage", addr="0x401000")
stack_analysis(action="uninitialized", addr="0x401000", limit=30)
stack_analysis(action="summary", addr="0x401000")
```

## Failure Modes
- No valid target function at provided/implicit address.
- No frame available for some functions (tool may return empty-note output).
- `uninitialized` is heuristic and can report false positives.
- Register-spill and buffer detection rely on naming/type heuristics.
