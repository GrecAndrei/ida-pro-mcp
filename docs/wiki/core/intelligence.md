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

## Embedding backends

By default the embedder runs a local GGUF model through `llama-server`
(`bge-code-v1`, or the opt-in `zembed-1`). It can instead use the **opt-in
cloud Gemini backend** (`gemini-embedding-2`), selected explicitly via
`IDA_MCP_EMBED_BACKEND=gemini` or `embedder.json` `{"backend": "gemini"}`.

> **Privacy:** the cloud backend uploads the *compact behavioral signature* of a
> function (calls, constants, string literals, control-flow profile) — never the
> full decompilation. If you cannot send any code to Google, keep the local
> backend. The backend is never chosen automatically, even when GCP/Gemini
> environment variables are present.

Credentials come from the environment: `GEMINI_API_KEY` / `GOOGLE_API_KEY`
(AI Studio), or `VERTEX_AI_ACCESS_TOKEN` / `GOOGLE_APPLICATION_CREDENTIALS`
plus `GOOGLE_CLOUD_PROJECT` and `VERTEX_AI_LOCATION` (Vertex AI). The installer
(`--embed-backend gemini`) prompts for the backend, writes `embedder.json`, and
can persist an AI Studio key into the MCP client config env block.

Run `python install.py --embedder-doctor --embed-backend gemini` to verify a
setup without opening IDA.
