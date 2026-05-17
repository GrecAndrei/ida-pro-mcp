# search

Search the binary for bytes, strings, patterns, names, instructions, xrefs, and semantic/structural queries.

## Quick Reference

| Action | What it does | When to use |
|--------|-------------|-------------|
| `nl` | Natural language search via bge-code-v1 embeddings | "function that parses HTTP headers" |
| `behavior` | Find functions by behavior tag (BehaviorClassifier) | "find all crypto functions" |
| `find` | Smart unified search (names/strings/imports/instructions) | General purpose |
| `semantic` | NL search with embedding-aware ranking | Faster than nl, less accurate |
| `smart_bundle` | Fused `find` + `semantic` with deduped items | Broad first-pass retrieval |
| `api` | Find all usages of an imported API | "where is recv called?" |
| `decompiled` | Search pseudocode across all functions | "find memcpy with no length check" |
| `callers` / `callees` | Call graph queries | "who calls sub_401000?" |
| `vulnerable` | Scan for dangerous API patterns | Quick vuln triage |
| `func_by_sig` | Filter functions by structural properties | "find leaf functions" |
| `summary` | Count matches across all categories | Planning before expensive search |

---

## Semantic Search Actions

### nl
Natural language search using bge-code-v1 cosine similarity on indexed function embeddings. Most accurate for RE queries.

```json
{"name": "search", "arguments": {"action": "nl", "query": "function that handles AES key schedule", "limit": 10}}
```

Requires functions to be indexed (decompile some first, or run `schemaboot(action='ingest')`). Returns items with similarity scores.
`nl` also does embedding-driven query expansion by classifying the query into likely behavior tags, re-embedding those tags, and merging high-similarity neighbors.

### behavior
Find all functions matching a behavior tag using BehaviorClassifier.

```json
{"name": "search", "arguments": {"action": "behavior", "pattern": "crypto_symmetric", "limit": 20}}
```

Primary: L1 insight index (fast). Secondary: BehaviorClassifier on unnamed functions.

Common tags: `crypto_symmetric`, `network_http`, `network_socket`, `file_io`, `memory_alloc`, `process_exec`, `anti_analysis`, `persistence`, `credential_access`.

### semantic
NL search with lightweight embedding-aware ranking (faster than `nl`, less accurate).

```json
{"name": "search", "arguments": {"action": "semantic", "query": "packet parser", "limit": 20}}
```

### smart_bundle
Runs `find` and `semantic` together, then merges/deduplicates results into one ranked structured list.

```json
{"name":"search","arguments":{"action":"smart_bundle","pattern":"credential decrypt", "limit":20}}
```

### find
Smart unified search — auto-detects names, strings, imports, instructions. Heap-ranked by score.

```json
{"name": "search", "arguments": {"action": "find", "pattern": "recv", "include_breakdown": true}}
```

Returns `blackboard_context` for addresses that already have findings.

---

## Reference Search Actions

### api
Find all usages of an imported API function.

```json
{"name": "search", "arguments": {"action": "api", "pattern": "recv", "include_items": true}}
```

Returns call sites with caller function names. `include_breakdown=true` shows all matched APIs.

### callers / callees
Find functions calling a target, or functions called by a target.

```json
{"name": "search", "arguments": {"action": "callers", "pattern": "sub_401000"}}
{"name": "search", "arguments": {"action": "callees", "pattern": "main"}}
```

Supports semantic name resolution — `pattern` can be a name, address, or fuzzy match.

### data_ref / code_ref
Find data or code references to a target.

```json
{"name": "search", "arguments": {"action": "code_ref", "pattern": "0x401000"}}
```

---

## Code Search Actions

### decompiled
Search pseudocode across all functions with caching. Auto-writes blackboard entries for matches.

```json
{"name": "search", "arguments": {"action": "decompiled", "pattern": "memcpy", "limit": 20, "timeout_ms": 10000}}
```

Params: `addr` (scope to one function), `max_functions` (default 180), `sample` (bool).

### vulnerable
Scan for dangerous API call patterns across all functions.

```json
{"name": "search", "arguments": {"action": "vulnerable", "include_items": true, "include_breakdown": true}}
```

Returns severity-ranked findings. `include_breakdown=true` shows counts by vuln type.

### constants
Find crypto/magic constants in instruction immediates.

```json
{"name": "search", "arguments": {"action": "constants", "limit": 50}}
```

Recognizes MD5/SHA256/AES/ChaCha20/CRC32/TEA/Blowfish init constants.

---

## Structural Search Actions

### func_by_sig
Filter functions by structural properties. Supports natural language filters.

```json
{"name": "search", "arguments": {"action": "func_by_sig", "pattern": "leaf size:>100"}}
{"name": "search", "arguments": {"action": "func_by_sig", "pattern": "no_callers"}}
{"name": "search", "arguments": {"action": "func_by_sig", "pattern": "calls:memcpy args:3+"}}
```

Filters: `leaf` / `no_callees`, `no_callers` / `entry_point`, `size:>N` / `size:<N` / `size:N-M`, `calls:NAME`, `args:N` / `args:N+`.

Results always include `callers=N` count.

### structured
Schema-based pre-filtered semantic retrieval.

```json
{"name": "search", "arguments": {"action": "structured", "constraints": {"behavior_tags": ["crypto"], "tag_mode": "or"}}}
```

---

## Pattern Search Actions

### bytes
Byte pattern search with wildcards.

```json
{"name": "search", "arguments": {"action": "bytes", "pattern": "48 89 e5 ?? ?? 48 83 ec"}}
```

### string
Search string literals. Always includes xref count.

```json
{"name": "search", "arguments": {"action": "string", "pattern": "password", "case_sensitive": false}}
```

### name
Search symbol names. Always includes xref count.

```json
{"name": "search", "arguments": {"action": "name", "pattern": "aes"}}
```

### regex
Regex search in disassembly. ReDoS-protected.

```json
{"name": "search", "arguments": {"action": "regex", "pattern": "mov.*\\[rsp\\+0x[0-9a-f]+\\].*rax"}}
```

### mnemonic / instruction / text / operand / comment / insns
Instruction-level searches.

---

## Meta Actions

### summary
Quick count of matches across all categories. Fast planning aid before expensive searches.

```json
{"name": "search", "arguments": {"action": "summary", "pattern": "AES"}}
```

### type / export
Search type library or exported symbols.

### query_lang
Execute a structured query language expression.

---

## Blackboard Integration

- `find`, `semantic`, `nl`, `behavior` inject `blackboard_context` into results — addresses with existing findings show their entries inline.
- `decompiled` auto-writes `hypothesis` entries to the blackboard for matching functions.
- `resolve_target` (used by `callers`, `callees`, `api`) checks the blackboard for custom names before fuzzy matching.
