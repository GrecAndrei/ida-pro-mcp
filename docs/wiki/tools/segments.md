# segments

Manages binary segments: list, create, modify permissions, analyze, and compare.

## Actions
- `list` — list all segments with addresses, sizes, classes
- `add` — create a new segment. Params: `start`, `end`, `name`, `class`
- `delete` — delete a segment. Params: `name` or `start`
- `set_attr` — set segment attribute. Params: `name`, `attr`, `value`
- `set_perms` — set segment permissions. Params: `name`, `perms` (e.g. "rwx")
- `move` — move/rebase a segment. Params: `name`, `new_start`
- `info` — detailed info for one segment. Params: `name` or `address`
- `analyze` — re-analyze a segment. Params: `name`
- `find_code` — find code patterns in segment. Params: `name`, `pattern`
- `find_data` — find data patterns in segment. Params: `name`, `pattern`
- `compare` — compare two segments. Params: `seg_a`, `seg_b`
- `merge` — merge adjacent segments. Params: `seg_a`, `seg_b`

## Examples
```json
{"name": "segments", "arguments": {"action": "list"}}
```
```json
{"name": "segments", "arguments": {"action": "set_perms", "name": ".text", "perms": "r-x"}}
```

## Notes
- `add` and `delete` are write operations; guardrails apply in strict mode.
- Use `info` for detailed segment metadata including alignment and bitness.
