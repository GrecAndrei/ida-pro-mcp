# PLUGINS Tool Manual

Access and management of IDA Pro third-party plugins.

## Actions
### Supported Actions
- list
- run


### `list`
List available items for this tool with optional paging where supported.
Lists all installed and available plugins.

### `run`
Run an IDA plugin by name.
Executes a specific plugin by name.
*   **Args**: `name` (e.g. 'hexrays', 'binexport').

## Strategy
Use this tool to trigger specialized third-party analysis (e.g. `LazyIDA`, `D810`) if they are installed.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
