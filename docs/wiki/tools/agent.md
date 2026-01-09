# AGENT Tool Manual

High-level triage and exploration "force multipliers".

## Actions
### Supported Actions
- analyze_function
- explore_address
- find_references
- search_all
- search_structs
- context_pack


### `find_references`
Return code and data references to the target address.

### `analyze_function`
Aggregate decompilation, callers/callees, and strings for a function.
A wrapper around `code.analyze`. Provides the most comprehensive single-turn view of a function.

### `explore_address`
Summarize what exists at an address (name, type, xrefs).
Used when you find a random pointer or address and don't know what it is. It checks for functions, data, segments, and xrefs.

### `search_all`
Search names, strings, and functions for a query.
Universal search across names, strings, and functions. Use this for your first "recon" sweep of a binary.

### `search_structs`
Search structure names and fields for a query.
Finds structs by type name or field name. 
*   **Best for**: "Which struct has an 'apikey' field?"

### `context_pack`
Return a one-shot function context pack for LLM grounding.
One-shot function context (pseudocode, callers/callees, xrefs, strings, types).
*   **Best for**: fast per-function grounding for LLMs.
*   **Args**: `addr`, `include_pseudocode`, `max_items`, `use_cache`.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
