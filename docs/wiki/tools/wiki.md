# WIKI Tool Manual

## What It Does
Provides built-in documentation search and reading for `docs/wiki`, with safe topic resolution, section extraction, and paginated reads.

## Actions
- `list_topics`: Returns categories -> page names.
- `read`: Reads full topic or specific `section`; supports `offset`/`limit` chunking.
- `search`: Full-text search across wiki pages (`query` or `topic` alias).
- `sections`: Lists parsed markdown headers with line numbers for one topic.
- `index`: Returns category map plus total page count.

## Key Parameters
- `action`: `list_topics|read|search|sections|index`.
- `topic`: Topic name/path. Valid examples: `trace`, `tools/trace`, `workflows/ForensicProtocol`, `skills/TriageNewBinary`.
- Topic lookup behavior: single-name topics are searched in `tools`, `workflows`, `skills`, `core`, then wiki root; `.md` suffix is optional.
- `query`: Search term (used by `search`; falls back to `topic` when omitted).
- `section`: Header text filter for `read`.
- `offset`, `limit`: Line-based pagination for `read`.
- `include_snippets`, `context_lines`: Controls snippet output in `search`.

## Examples
```json
{"name":"wiki","arguments":{"action":"list_topics"}}
```

```json
{"name":"wiki","arguments":{"action":"read","topic":"trace","section":"Failure Modes","offset":0,"limit":120}}
```

```json
{"name":"wiki","arguments":{"action":"search","query":"truncation token","include_snippets":true,"context_lines":2}}
```

## Failure Modes
- `topic` required for `read` and `sections`.
- Invalid topic paths (`..`, absolute paths, escapes) are rejected.
- Missing topics return file-not-found errors.
- Missing `query`/`topic` for `search` is rejected.
- Unknown action returns invalid-args error.
