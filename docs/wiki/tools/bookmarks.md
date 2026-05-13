# bookmarks

Persistent named bookmarks for addresses and findings that survive context window resets.

## Actions
- `add` — add a bookmark. Params: `address`, `label`, optional `notes`, `tags`
- `list` — list all bookmarks. Optional `tag` filter
- `delete` — delete a bookmark. Params: `id` or `address`
- `update` — update bookmark metadata. Params: `id`, optional `label`, `notes`, `tags`
- `clear` — delete all bookmarks
- `find` — find bookmarks by query. Params: `query`
- `export` — export bookmarks as JSON

## Examples
```json
{"name": "bookmarks", "arguments": {"action": "add", "address": "0x401000", "label": "main_decrypt", "tags": ["crypto"]}}
```
```json
{"name": "bookmarks", "arguments": {"action": "list", "tag": "crypto"}}
```

## Notes
- Bookmarks persist in session metadata and are included in `recent_workset`.
- Use bookmarks to mark milestones and key addresses for resumption after context resets.
