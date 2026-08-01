# Intelligence

Semantic indexing lets you find functions by *behavior*, not just by name or
string.

## Indexing

`ida_index_functions(query=...)` builds a scoped semantic function index in
responsive background slices. Scope it to stay fast:

- `query` — filter by function name (glob/regex).
- `ranges=[{start, end}]`, `start`/`end`, or `address` + `radius` — restrict
  to one or more regions.
- `min_size`/`max_size` — filter by function size.
- `quality` — `fast` (metadata + disassembly) or `full` (adds Hex-Rays
  decompilation, better retrieval, slower).
- `background` — defaults to true: the call returns a `task_id`; poll with
  `ida_index_status(task_id=...)` until it reports the result.
- `slice_size` — functions per RPC slice; smaller = more interactive.

Cancel a running job with `ida_cancel_index(task_id=...)`.

## Searching

`ida_semantic_search(query=...)` finds functions by intent — e.g. "function
that decrypts strings". Options: `mode` (`quick` or `expand`, which adds
behavior-driven matches), `min_score`, `limit`, and the same range/radius
filters as indexing to confine results.

Indexing is host-assisted but reads the IDB through the session runtime; it
is gated by safe mode like other whole-binary analysis.
