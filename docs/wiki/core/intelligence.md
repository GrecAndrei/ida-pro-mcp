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
behavior-driven matches), `min_score`, `limit`, `rerank` (default true), and
the same range/radius filters as indexing to confine results.

Indexing is host-assisted but reads the IDB through the session runtime; it
is gated by safe mode like other whole-binary analysis.

## Two-stage retrieval (recall + rerank)

Semantic search is two-stage. Stage 1 is the embedding index — a *bi-encoder*
that embeds the query and each function's pseudocode into vectors and ranks by
cosine. The vectors never see each other, so recall is wide but the *top* of
the list is only "nearby", not "correct". Stage 2 is a **cross-encoder
reranker**: it concatenates the query with each recalled candidate's full
document and scores the pair with cross-attention. It cannot run over the
whole binary (every pair is a fresh forward pass), so it only re-scores the
recalled pool — typically up to `IDA_MCP_RERANK_MAX_CANDIDATES` (default 64) —
and the returned list is ordered by rerank score.

The reranker runs on its own `llama-server --rerank` process with the same
lifecycle guarantees as the embedder (lease, idle shutdown, activation grace,
request lock). It is a **quality boost, never a hard gate**: if no rerank
model is installed, or the model returns non-discriminating scores (equal
scores for every input — e.g. a headless conversion), the recall order is
preserved and the response's `rerank` block reports `applied: false`.

Configuration is per-profile (see `rerank_profiles.py`):

| Profile | Family | Notes |
| --- | --- | --- |
| `qwen3-reranker-0.6b` | Qwen3 | Default; speed tier. |
| `qwen3-reranker-4b` | Qwen3 | Opt-in; precision tier for deep dives. |
| `bge-reranker-v2-gemma` | BGE | Middle tier; the known public GGUF is headless (constant scores) — verify before relying on it. |
| `bge-reranker-v2-m3` | BGE | Opt-in compatibility. |

Select with `IDA_MCP_RERANK_PROFILE` / `IDA_MCP_RERANK_MODEL`, or the
`rerank` key in `embedder.json` (installer: `--rerank-profile`,
`--rerank-model`, `--download-rerank-model`). Disable with
`IDA_MCP_RERANK_DISABLED=1`. `ida_reranker_status(probe=True)` reports the
installed model and readiness.

## Function families

`ida_function_families()` clusters *lookalike* functions — reused logic,
renamed wrappers, compiler-generated variants — by embedding cosine. Each
family reports:

- `representative` — a named member closest to the family centroid (the one
  worth reading).
- `members` — every address with its similarity to the centroid.
- `deltas` — per-member `+token` / `-token` diffs against the representative.
- `summary` — a one-line description of what the family shares.

`min_similarity` (default 0.85) tunes how tight "lookalike" is;
`min_size` (default 2) drops small groups; `address` + `radius` or
`start`/`end` scope the clustering to a region; `query` filters by name.

`mark_examined=true` records every family member as examined in one call —
read the representative, skip the rest, and the workspace reflects it. Use
`verdict="interesting"` if the family warrants a finding.

## Embedding backends

By default the embedder runs a local GGUF model through `llama-server`
(`qwen3-embedding-0.6b`, or the legacy `bge-code-v1` / opt-in `zembed-1`).
It can instead use the **opt-in
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
