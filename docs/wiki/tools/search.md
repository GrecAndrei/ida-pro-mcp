# search

Search the binary for bytes, strings, patterns, names, instructions, xrefs, and semantic/structural queries.

## Actions
- `bytes` — search for byte pattern; param `pattern` (hex string, e.g. `"4889e5"`).
- `string` — search for string literal; param `pattern`.
- `immediate` — search for immediate value; param `value`.
- `name` — search symbols/names matching `pattern`.
- `insns` / `mnemonic` / `instruction` — search for instruction mnemonic; param `mnemonic`.
- `text` — full-text search across disassembly; param `pattern`.
- `comment` — search comments; param `pattern`.
- `api` — search for API/import references; param `pattern`.
- `callers` — find callers of address; param `address`.
- `callees` — find callees of address; param `address`.
- `xrefs_to` — xrefs to `address`.
- `xrefs_from` — xrefs from `address`.
- `data_ref` — data references to/from `address`.
- `code_ref` — code references to/from `address`.
- `find` — generic multi-type search; param `pattern`, optional `type`.
- `semantic` — embedding-based similarity search using FunctionEmbeddingIndex; param `query`.
- `structured` — SQL pre-filter + BM25 reranking via schemaboot; param `constraints` (dict).
- `query_lang` — structured query language expression; param `expr`.
- `vulnerable` — find dangerous API call patterns (e.g. strcpy, sprintf); optional `pattern` filter.

## Examples
```json
{"name": "search", "arguments": {"action": "string", "pattern": "password"}}
```
```json
{"name": "search", "arguments": {"action": "semantic", "query": "function that decrypts network traffic"}}
```

## Notes
- `semantic` requires functions to have been decompiled (indexed) first.
- `structured` combines schema-induced attributes with BM25 text ranking for precise filtering.
- `vulnerable` is a quick triage action for identifying unsafe API usage patterns.
