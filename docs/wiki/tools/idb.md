# idb

Retrieves high-level metadata and structural overview of the current IDB (IDA database).

## Actions
- `meta` — binary metadata: architecture, bitness, compiler, file type, entry point
- `summary` — concise analysis summary with key statistics
- `segments` — list all segments with addresses, sizes, permissions
- `entrypoints` — list all entry points
- `bookmarks` — list IDA-native bookmarks (not MCP bookmarks)
- `overview` — combined high-level overview (meta + segments + stats)

## Examples
```json
{"name": "idb", "arguments": {"action": "meta"}}
```
```json
{"name": "idb", "arguments": {"action": "overview"}}
```

## Notes
- Use `idb(action="meta")` as the first call after session create for initial grounding.
- Does not require explicit `idb` param when a session is active.
