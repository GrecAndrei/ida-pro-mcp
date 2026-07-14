# funcs

Create, delete, query, and annotate functions with metrics and ML-powered name suggestions.

## Actions
- `create` — create a new function at address; params: `address`, `end` (optional)
- `change` — set the current function's end address, equivalent to IDA's Set function end command; params: `address`, `end`
- `delete` — delete a function; params: `address`
- `set_flags` — set function flags; params: `address`, `flags`
- `set_name` (alias: `rename`) — rename a function; params: `address`, `name`
- `add_comment` — add a comment to a function; params: `address`, `comment`, `repeatable`
- `list` — list functions; params: `offset`, `count`, `filter`, `min_xrefs` (filter to functions with ≥N xrefs before counting)
- `info` — get detailed function info; params: `address`
- `metrics` — get cyclomatic complexity, instruction count, call depth; params: `address`
- `find_similar` — find functions with similar structure; params: `address`, `limit`
- `suggest_names` — suggest names for `sub_XXXX` functions using cosine similarity to nearest named function; params: `limit`, `threshold` (default 0.65)

## Examples

```json
{"name": "funcs", "arguments": {"action": "suggest_names", "limit": 20, "threshold": 0.6}}
```

```json
{"name": "funcs", "arguments": {"action": "metrics", "address": "0x401000"}}
```

## Notes
- `suggest_names` only targets unnamed (`sub_XXXX`) functions and ranks candidates by embedding cosine similarity.
- `set_name` is an alias for `rename` — both work identically.
- `metrics` returns structured data (cyclomatic complexity, instruction count, call depth) useful for prioritizing analysis effort.
- `list` and `data(functions)` share the same pagination envelope: `{ok, items, total, offset, count}`. `min_xrefs` is applied before `total` is incremented so the count reflects the filtered set.
- `metrics`, `suggest_names`, and `find_similar` walk the whole function list — they're in the dispatcher's `LONG_RUNNING_ACTIONS` whitelist and may take minutes on large binaries. The wall-clock cap is `IDA_MCP_RPC_HARD_WALLCLOCK_SEC` (default 900s); past that the IDA process is restarted.
