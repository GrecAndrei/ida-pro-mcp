# CFG_ANALYSIS Tool Manual

## What It Does
Control flow graph analysis for reverse engineering.

## Actions
- `complexity`: Compute CFG complexity metrics.
- `loops`: Find loop structures in CFG.
- `branches`: Summarize branch behavior.
- `paths`: Enumerate candidate paths with depth bounds.
- `dominators`: Compute dominator relationships.
- `post_dominators`: Compute post-dominator relationships.
- `back_edges`: Detect back edges in control flow.
- `natural_loops`: Find natural loops from back edges.
- `irreducible`: Detect irreducible control flow patterns.
- `flatten_detect`: Heuristically detect control-flow flattening.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.
- `depth` (default `20`): Traversal/path depth bound.

## Examples (JSON call snippets)
```json
{
  "tool": "cfg_analysis",
  "args": {
    "action": "complexity",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "cfg_analysis",
  "args": {
    "action": "paths",
    "addr": "0x401000",
    "depth": 12,
    "limit": 30
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `Unknown action: {action}`
