# code

Decompilation, disassembly, cross-references, and control-flow analysis for functions and addresses.

## Actions

- `decompile` — returns Hex-Rays pseudocode for a function; params: `addr` or `name`
- `disasm` — returns disassembly listing; params: `addr`, `count` (number of instructions), `end` (optional end address), `limit` (alias for `count`), `window` (centered ±N instructions around `addr` instead of function-bounded), `disasm_style` (`csmini` / `classic` / `annotated`), `include_bytes` (bool)
- `smart_decompile` — decompile prioritized targets; results are cached via `ToolResultCache` and tagged with `_cache_hit: true` and `_cache_age_seconds: <n>` on every cached response
- `xrefs_to` — lists all cross-references to an address; params: `addr`
- `xrefs_from` — lists all cross-references from an address; params: `addr`
- `xrefs_to_field` — lists cross-references to a specific struct field; params: `struct_name`, `field_name`
- `callees` — lists functions called by a function; params: `addr` or `name`
- `callers` — lists functions that call a function; params: `addr` or `name`
- `blocks` — returns basic blocks of a function's CFG; params: `addr` or `name`
- `analyze` — performs deeper analysis on a function (type propagation, etc.); params: `addr` or `name`
- `callgraph` — returns the call graph rooted at a function; params: `addr` or `name`, `depth`
- `export` — exports decompilation/disassembly to file; params: `addr`, `format`, `path`
- `find_paths` — finds execution paths between two addresses; params: `src`, `dst`
- `strings_in_func` — lists string references used within a function; params: `addr` or `name`
- `diff_functions` — compares two functions side by side; params: `addr_a`, `addr_b`
- `semantic_decompile` — decompiles with added `behavior_tags` describing function semantics; params: `addr` or `name`
- `decomp_dataflow` — traces variable dataflow through decompiled code; params: `addr` or `name`, `var`
- `decompile_chain` — decompiles a function and all its callees recursively; params: `addr` or `name`, `depth`
- `json` — returns decompilation as structured JSON AST; params: `addr` or `name`
- `c_header` — generates a C header for a function's types; params: `addr` or `name`
- `prototypes` — returns function prototypes for a function and its callees; params: `addr` or `name`

## Examples

```json
{"name": "code", "arguments": {"action": "decompile", "addr": "0x401000"}}
```

```json
{"name": "code", "arguments": {"action": "disasm", "addr": "0x401000", "count": 20}}
```
```json
{"name": "code", "arguments": {"action": "disasm", "addr": "0x4010a0", "window": 20}}
```

```json
{"name": "code", "arguments": {"action": "semantic_decompile", "name": "main"}}
```

```json
{"name": "code", "arguments": {"action": "decompile_chain", "addr": "0x401000", "depth": 2}}
```

```json
{"name": "code", "arguments": {"action": "diff_functions", "addr_a": "0x401000", "addr_b": "0x402000"}}
```

```json
{"name": "code", "arguments": {"action": "decomp_dataflow", "addr": "0x401000", "var": "buf"}}
```

## Notes

- `decompile` requires Hex-Rays decompiler license.
- `semantic_decompile` adds `behavior_tags` (e.g., `allocator`, `crypto`, `network_io`) to the output for classification.
- `decomp_dataflow` traces how a variable is defined, used, and propagated through the decompiled pseudocode.
- `decompile_chain` can produce large output; use `depth` to limit recursion.
- `diff_functions` is useful for patch diffing or comparing similar functions across binaries.
- Use `addr` (hex string) or `name` (symbol name) interchangeably where supported.
- Do not perform mental address arithmetic — use `calc` tool instead.
- `disasm` with `window=N` returns up to N instructions *before* and *after* the input address, with the focus line preserved even when `max_items` clamps the total. Output is ordered oldest→newest. The response record carries an explicit `"window": N` field. `window < 0` or non-int `window` is rejected with `INVALID_ARGS`.
- `smart_decompile` and any other `@idaread`-backed action that lives in `ToolResultCache` returns annotated cached responses: `_cache_hit: true` and `_cache_age_seconds: <int>`. Clients that don't care can ignore the keys; clients that want freshness visibility get it without an extra round-trip.
