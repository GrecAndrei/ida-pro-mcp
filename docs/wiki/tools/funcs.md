# funcs

Create, delete, query, and annotate functions with metrics and ML-powered name suggestions.

## Actions
- `create` — create a new function at address; params: `address`, `end` (optional)
- `delete` — delete a function; params: `address`
- `set_flags` — set function flags; params: `address`, `flags`
- `set_name` (alias: `rename`) — rename a function; params: `address`, `name`
- `add_comment` — add a comment to a function; params: `address`, `comment`, `repeatable`
- `list` — list functions; params: `offset`, `count`, `filter`
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
