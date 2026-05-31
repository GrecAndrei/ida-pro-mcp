# IDA MCP Tool Doc: `code`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `code` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Decompilation, disassembly, and code analysis. smart_decompile: best single call — pseudocode + behavior_tags + api_calls + crypto_hints + dangerous_patterns + var_rename_hints + callers + callees + strings + blackboard_context + suggested_next_actions. decompile: pseudocode with inline api_calls/crypto_hints/complexity. disasm: assembly listing. analyze: comprehensive (decompile+callers+callees+strings+stack). decompile_chain: function with compact caller/callee context (first 8 lines each). semantic_decompile: pseudocode + CFG semantics + variable dependency graph. diff_functions: unified diff of two functions. annotate: add comment to function/address. xrefs_to/from, callees, callers, blocks, callgraph, find_paths, strings_in_func, decomp_dataflow, export.

## Actions
- `decompile` (tool-specific)
- `disasm` (tool-specific)
- `xrefs_to` (tool-specific)
- `xrefs_from` (tool-specific)
- `xrefs_to_field` (tool-specific)
- `callees` (tool-specific)
- `callers` (tool-specific)
- `blocks` (tool-specific)
- `analyze` (analysis)
- `callgraph` (tool-specific)
- `export` (tool-specific)
- `find_paths` (analysis)
- `strings_in_func` (tool-specific)
- `diff_functions` (tool-specific)
- `semantic_decompile` (tool-specific)
- `decomp_dataflow` (tool-specific)
- `decompile_chain` (tool-specific)
- `smart_decompile` (tool-specific)
- `annotate` (tool-specific)
- `explain` (tool-specific)
- `json` (tool-specific)
- `c_header` (tool-specific)
- `prototypes` (tool-specific)
- `csmini` (tool-specific)
- `classic` (tool-specific)
- `annotated` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/code')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed_count: `26`
- `addr`: `string`
- `addrs`: `array|string`
- `disasm_style`: `string` - allowed: `csmini, classic, annotated`
- `end`: `string`
- `field_name`: `string`
- `format`: `string`
- `include_bytes`: `boolean`
- `limit`: `integer`
- `max_depth`: `integer`
- `max_items`: `integer`
- `target`: `string`
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "code",
  "arguments": {
    "action": "decompile"
  }
}
```
```json
{
  "name": "code",
  "arguments": {
    "action": "grep",
    "source_action": "decompile",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
