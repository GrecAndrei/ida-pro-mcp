# WIKI Tool Manual

## What It Does
Provides built-in documentation search and reading for `docs/wiki`, with ranked search, semantic concept search, fuzzy topic resolution, section extraction, related-topic hints, and paginated reads.

## Actions
- `list_topics`: Returns categories -> page names, plus category/page counts.
- `read`: Reads full topic or specific `section`; supports `offset`/`limit` chunking.
- `search`: Ranked search across wiki pages (`query` or `topic` alias), with optional snippets and fuzzy matching.
- `semantic_search`: Concept-aware search that expands query intent (e.g., runtime/flow/trace) before ranking results.
- `sections`: Lists parsed markdown headers with line numbers for one topic.
- `index`: Returns category map plus index summary.

## Key Parameters
- `action`: `list_topics|read|search|semantic_search|sections|index`.
- `topic`: Topic name/path. Valid examples: `trace`, `tools/trace`, `workflows/ForensicProtocol`, `skills/TriageNewBinary`.
- Topic lookup behavior: single-name topics are searched in `tools`, `workflows`, `skills`, `core`, then wiki root; `.md` suffix is optional.
- `query`: Search term (used by `search`; falls back to `topic` when omitted).
- `semantic_search` accepts the same query knobs as `search` (`query`, `topic`, `max_results`, `category`, `include_snippets`, `context_lines`) and adds concept expansion automatically.
- `max_results`: Cap search result count (default 20, max 200).
- `category`: Optional category filter (`tools`, `workflows`, `skills`, `core`, or comma-separated list).
- `fuzzy`: Enables typo-tolerant ranking for `search` and section/header matching in `read`.
- `strict_topic`: Disables smart topic fallback and requires exact topic match.
- `include_related`: Include related topics in `read` results.
- `section`: Header text filter for `read`.
- `offset`, `limit`: Line-based pagination for `read`.
- `include_snippets`, `context_lines`: Controls snippet output in `search`.
- If markdown docs are missing in install environments, tool docs are auto-generated as fallback.

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

```json
{"name":"wiki","arguments":{"action":"search","query":"trcae","fuzzy":true,"category":"tools","max_results":8}}
```

```json
{"name":"wiki","arguments":{"action":"semantic_search","query":"runtime flow tracing","category":"tools","max_results":8}}
```

## Failure Modes
- `topic` required for `read` and `sections`.
- Invalid topic paths (`..`, absolute paths, escapes) are rejected.
- Missing topics return file-not-found with `details.suggestions` when available.
- Missing `query`/`topic` for `search` is rejected.
- Unknown action returns invalid-args error.
