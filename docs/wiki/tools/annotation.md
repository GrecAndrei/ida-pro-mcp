# annotation

Automated annotation: comments, labels, tags, and documentation for functions and code.

## Actions
- `auto_comment` — generate and apply comments for a function. Params: `address`
- `label_loops` — label loop structures in a function. Params: `address`
- `label_branches` — label branch conditions. Params: `address`
- `mark_dangerous` — mark dangerous API calls/patterns. Params: `address`
- `annotate_constants` — resolve and annotate magic constants. Params: `address`
- `tag_functions` — tag functions by category (crypto, network, etc.). Optional `addresses`
- `document_args` — document function arguments. Params: `address`
- `mark_error_paths` — mark error-handling paths. Params: `address`
- `validate` — pre-flight governance check before writing comments. Params: `address`, `comment`

## Examples
```json
{"name": "annotation", "arguments": {"action": "auto_comment", "address": "0x401000"}}
```
```json
{"name": "annotation", "arguments": {"action": "validate", "address": "0x401000", "comment": "Decrypts config blob"}}
```

## Notes
- Always call `validate` before writing comments to catch PII, contradictions, or misleading claims.
- All write actions respect guardrail strict mode (`_guardrail_ack=true` to override).
- `tag_functions` without `addresses` scans all functions.
