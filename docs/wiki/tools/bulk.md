# bulk

Applies batch edits: renames, comments, types, and stack variable names across multiple addresses.

## Actions
- `rename` — rename multiple symbols. Params: `items` (array of `{address, name}`)
- `comment` — set comments on multiple addresses. Params: `items` (array of `{address, comment}`)
- `apply_type` — apply types to multiple addresses. Params: `items` (array of `{address, type}`)
- `rename_stack` — rename stack variables. Params: `address` (function), `items` (array of `{old_name, new_name}`)
- `import_annotations` — import annotations from JSON. Params: `data` or `path`
- `export_annotations` — export all annotations as JSON. Optional `path`

## Examples
```json
{"name": "bulk", "arguments": {"action": "rename", "items": [
  {"address": "0x401000", "name": "decrypt_config"},
  {"address": "0x401200", "name": "send_beacon"}
]}}
```
```json
{"name": "bulk", "arguments": {"action": "rename_stack", "address": "0x401000", "items": [
  {"old_name": "var_8", "new_name": "buffer_size"}
]}}
```

## Notes
- Bulk operations are atomic per-item; failures on one item don't block others.
- Guardrail strict mode applies; use `_guardrail_ack=true` to acknowledge writes.
- Use `export_annotations` to checkpoint before large bulk edits.
