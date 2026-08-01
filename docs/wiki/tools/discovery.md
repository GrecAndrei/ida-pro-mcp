# Discovery

Finding your way around the binary: metadata, names, strings, imports, and
functions.

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_overview` | Binary metadata, architecture, entry points, analysis context. | First call after opening. |
| `ida_find(query=...)` | Find names, strings, imports, comments, references matching text. | Best first move for a known name or IOC. |
| `ida_list_functions(query=...)` | List functions, optionally filtered by name. | |
| `ida_list_strings(query=...)` | List strings, optionally filtered by text. | |
| `ida_list_imports` | List imported APIs. | Reveals the module's capabilities. |

`query` filters and `limit` caps results on all list operations. Every
operation takes an optional `idb` argument to target a specific session
instead of the active one.

## Semantic search

For behavior-based lookup — "function that decrypts strings" — see
[Intelligence](../core/intelligence.md): `ida_index_functions` builds the
index, `ida_semantic_search` queries it. These are gated by safe mode.
