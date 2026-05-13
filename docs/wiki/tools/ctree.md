# ctree

Queries and traverses the Hex-Rays decompiler ctree (AST) for a function.

## Actions
- `get` — get full ctree for a function; params: `address`
- `traverse` — walk ctree with filter; params: `address`, `node_type`
- `find_calls` — find all call expressions; params: `address`
- `find_vars` — find variable references; params: `address`, `var_name` (optional)
- `find_strings` — find string literals in ctree; params: `address`
- `find_conditions` — extract conditional expressions; params: `address`
- `get_logic_flow` — high-level logic flow summary; params: `address`
- `dominance_map` — compute dominator tree; params: `address`
- `var_dependency_graph` — variable def-use dependency graph; params: `address`

## Examples
```json
{"name": "ctree", "arguments": {"action": "find_calls", "address": "0x401000"}}
```
```json
{"name": "ctree", "arguments": {"action": "var_dependency_graph", "address": "0x401000"}}
```

## Notes
- Requires Hex-Rays decompiler license.
- `get_logic_flow` provides a compact summary suitable for LLM consumption.
- `dominance_map` and `var_dependency_graph` are useful for data-flow analysis.
