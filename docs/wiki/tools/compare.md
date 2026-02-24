# COMPARE Tool Manual

## What It Does
Compare functions for similarity, structural differences, and clone detection.

## Actions
- `functions`: Compare two functions at a high level.
- `blocks`: Compare basic-block structure.
- `apis`: Compare API usage overlap.
- `strings`: Compare referenced strings.
- `constants`: Compare constant/immediate usage.
- `structure`: Compare CFG/shape-level structure.
- `semantics`: Compare semantic signals heuristically.
- `batch_compare`: Run pairwise comparisons for multiple functions.
- `find_clones`: Search for clone-like functions by similarity threshold.
- `changelog`: Summarize notable differences between two functions.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `addr2` (default `None`): Second address for pairwise comparisons.
- `addrs` (default `None`): Comma-separated addresses or address list, action-dependent.
- `threshold` (default `0.7`): Similarity threshold in [0,1].
- `limit` (default `30`): Maximum result count.

## Examples (JSON call snippets)
```json
{
  "tool": "compare",
  "args": {
    "action": "functions",
    "addr": "0x401000",
    "addr2": "0x402000"
  }
}
```
```json
{
  "tool": "compare",
  "args": {
    "action": "find_clones",
    "threshold": 0.85,
    "limit": 20
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `{label} required`
- `INVALID_ARGS`: `addrs (comma-separated) required`
- `INVALID_ARGS`: `Unknown action: {action}`
