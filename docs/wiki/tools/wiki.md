# WIKI Tool Manual

On-demand documentation and manual for the IDA Pro MCP system.

## Actions
### Supported Actions
- list_topics
- read
- search
- sections
- index


### `list_topics`
List wiki topics grouped by category.
Lists all available categories and specific tool manuals.

### `read`
Read data or content from the specified source.
Reads the full manual for a specific tool or workflow.
*   **Args**: `topic` (e.g. 'code', 'agent', 'strategy'), `section`, `offset`, `limit`.

### `search`
Search for matching content and return matching topics.
Searches all manuals for a keyword.
*   **Args**: `query` (or `topic`), `include_snippets`, `context_lines`.

### `sections`
List headers for a topic with line numbers.
Lists headers for a topic with line numbers.

### `index`
Return a structured wiki index.
Returns a structured index with categories and total page count.

## Strategy
**CRITICAL**: Use the `wiki` tool instead of asking the user for help. This tool provides deep context that is stripped from the standard tool descriptions to save your context window tokens.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
