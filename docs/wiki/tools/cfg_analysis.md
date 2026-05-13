# cfg_analysis

Analyze control-flow graph properties: complexity, loops, dominators, and obfuscation detection.

## Actions
- `complexity` — compute cyclomatic complexity of function at `address`.
- `loops` — detect loops in function at `address`.
- `branches` — enumerate branch points in function at `address`.
- `paths` — enumerate paths through function CFG; params `address`, optional `max_paths`.
- `dominators` — compute dominator tree for function at `address`.
- `post_dominators` — compute post-dominator tree for function at `address`.
- `back_edges` — identify back edges (loop indicators) in function at `address`.
- `natural_loops` — identify natural loops with header/body info at `address`.
- `flattening_detect` — detect control-flow flattening obfuscation at `address`.

## Examples
```json
{"name": "cfg_analysis", "arguments": {"action": "complexity", "address": "0x401000"}}
```
```json
{"name": "cfg_analysis", "arguments": {"action": "flattening_detect", "address": "0x401000"}}
```

## Notes
- High cyclomatic complexity often indicates dispatch functions or obfuscated code.
- `flattening_detect` identifies state-machine-based CFF obfuscation patterns.
- All actions operate on a single function; pass the function start address.
