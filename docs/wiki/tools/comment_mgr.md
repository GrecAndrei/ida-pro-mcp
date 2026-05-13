# comment_mgr

Canonical comment management tool with structured comments, bulk operations, and markdown export/import.

## Actions
- `get_context` — get comments and surrounding context at address; params: `address`
- `set_structured` — set a structured comment; params: `address`, `text`, `category`, `confidence`
- `bulk_set` — set multiple comments at once; params: `comments` (list of {address, text, ...})
- `export_md` — export all comments as markdown; params: `path` (optional)
- `import_md` — import comments from markdown; params: `path`
- `summary` — summarize comment coverage and categories

## Examples
```json
{"name": "comment_mgr", "arguments": {"action": "set_structured", "address": "0x401000", "text": "Main decryption loop", "category": "crypto"}}
```
```json
{"name": "comment_mgr", "arguments": {"action": "bulk_set", "comments": [{"address": "0x401000", "text": "entry"}, {"address": "0x401020", "text": "exit"}]}}
```

## Notes
- Alias: `comments_ai` resolves to this tool.
- `set_structured` supports `category` and `confidence` for governance validation.
- Use `export_md`/`import_md` for sharing annotations across sessions.
