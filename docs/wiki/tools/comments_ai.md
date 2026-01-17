# COMMENTS_AI Tool Manual

Structured, AI-optimized comment management.

## Actions
### Supported Actions
- get_context
- set_structured
- bulk_set
- export_md
- import_md
- summary


### `import_md`
Import structured annotations from Markdown.

### `summary`
Return a high-level diff summary.

### `get_context`
Get structured annotation context for an address.
Retrieves all comments (regular, repeatable, anterior, posterior) in a range around `addr`.

### `set_structured`
Set a structured annotation at an address.
Sets a formatted, machine-readable comment.

### `bulk_set`
Set multiple structured annotations.
Applies multiple comments at once from a JSON list.

### `export_md` / `import_md`
Export structured annotations to Markdown.
Exports your annotations to a Markdown report, or imports comments from an existing report.

## Strategy
Use `set_structured` to store metadata about vulnerabilities or algorithms that you want to persist across sessions and be easily parsed later.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
