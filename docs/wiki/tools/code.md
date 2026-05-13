# code

Decompile, disassemble, and query code structure (xrefs, call graphs, diffs) for functions.

## Actions
- `decompile` — decompile function at `address`. Auto-indexes in FunctionEmbeddingIndex; injects `context_pack` with behavior_tags and relevant blackboard entries.
- `semantic_decompile` — decompile with semantic annotations and enriched context.
- `decomp_dataflow` — dataflow analysis on decompiled output at `address`.
- `disasm` — disassemble instructions at `address`, optional `count`.
- `xrefs_to` — cross-references TO `address`.
- `xrefs_from` — cross-references FROM `address`.
- `callees` — functions called by function at `address`.
- `callers` — functions that call function at `address`.
- `call_chain` — call chain between two addresses; params `source`, `target`, optional `depth`.
- `find_paths` — find execution paths between `source` and `target`.
- `strings_in_func` — string references used within function at `address`.
- `diff_functions` — diff two functions; requires exactly 2 addresses in `addrs` param.

## Examples
```json
{"name": "code", "arguments": {"action": "decompile", "address": "0x401000"}}
```
```json
{"name": "code", "arguments": {"action": "diff_functions", "addrs": ["0x401000", "0x402000"]}}
```

## Notes
- `decompile` automatically populates the embedding index and blackboard context for downstream semantic queries.
- `diff_functions` fails if `addrs` does not contain exactly 2 entries.
- Use `disasm` for raw instruction view; use `decompile` for C pseudocode.
