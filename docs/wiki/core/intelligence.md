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
behavior-driven matches), `min_score`, `limit`, `rerank`, and the same
range/radius filters as indexing to confine results.

`rerank` is **auto by default**: it applies in `expand` mode and whenever the
caller passes `rerank=true` explicitly; `quick` mode skips it so quick stays
bounded on CPU boxes (pass `rerank=true` to force). The response's `rerank`
block reports `applied` and, when skipped, a `reason`.

Indexing is host-assisted but reads the IDB through the session runtime; it
is gated by safe mode like other whole-binary analysis.

A search never ranks against a stale index generation: when an index rebuild
(``fast`` -> ``full``) rewrites the embeddings DB, the reader notices the
newest mtime across the DB and its WAL/SHM sidecars and reloads vectors at the
next read, and index-mutating operations invalidate cached ``@idaread`` search
responses so a repeated query is re-evaluated instead of served from before
the rebuild.

## Two-stage retrieval (recall + rerank)

Semantic search is two-stage. Stage 1 is the embedding index — a *bi-encoder*
that embeds the query and each function's pseudocode into vectors and ranks by
cosine. The vectors never see each other, so recall is wide but the *top* of
the list is only "nearby", not "correct". Stage 2 is a **cross-encoder
reranker**: it concatenates the query with each recalled candidate's full
document and scores the pair with cross-attention. It cannot run over the
whole binary (every pair is a fresh forward pass), so it only re-scores the
recalled pool — bounded by `IDA_MCP_RERANK_POOL` (default 8) with each
document truncated to `IDA_MCP_RERANK_DOC_BUDGET_CHARS` (default 800 chars,
~250 tokens) — and the returned list is ordered by rerank score.  The caps
exist because the cross-encoder costs seconds per pair on CPU: an unbounded
pool turned a "quick" search into a silent multi-minute CPU burn.  Raise the
env vars for GPU boxes or when precision matters more than latency.

Behavior-anchor classification (`expand` mode) embeds ~60 static anchor texts;
those embeddings are persisted per model (anchor cache under the cache dir)
and cold-start embedding is budgeted to `IDA_MCP_ANCHOR_EMBED_BUDGET_SEC`
(default 20s), so a fresh process never spends minutes warming anchors.

The reranker runs on its own `llama-server --rerank` process with the same
lifecycle guarantees as the embedder (lease, idle shutdown, activation grace,
request lock). It is a **quality boost, never a hard gate**: if no rerank
model is installed, or the model returns non-discriminating scores (equal
scores for every input — e.g. a headless conversion), the recall order is
preserved and the response's `rerank` block reports `applied: false`.

## Find scoring (two-phase, latency-bounded)

`search(action='find')` and name resolution (`resolve_target`-based actions
like `ida_callees`/`ida_decompile` with a fuzzy target) score candidates in
two phases.  Phase 1 ranks the whole matched pool with a deterministic
subword/ngram scorer — identifiers are split on snake_case/camelCase, exact
matches score 120, and substring + edit-distance bonuses cover typos — so
ordinary symbol queries never touch the embedder.  Phase 2 applies only to
phrase-like queries (whitespace or >= 24 chars): the top candidates (24 for
`find`, 64 elsewhere) are embedded in a *single* batched native call and their
scores become embedding-first.  A decisive-winner gate skips phase 2 entirely
when the deterministic top score already dominates, and all vectors are
cached per session, so repeated queries are instant and per-candidate
embedding cost is bounded regardless of pool size.

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

### In-process native backend (`libmcp_llama.so`)

When `libmcp_llama.so` and the matching model are present, the embedder and reranker can run **in
process** via `ctypes` instead of shelling out to two full `llama-server` HTTP
subprocesses.  `BgeCodeEmbedder()` and `Reranker()` transparently resolve to
`NativeEmbedder` / `NativeReranker` when the host bootstrap enables it; each
component independently falls back to HTTP when its model is absent.
`ida_reranker_status`
reports `backend: native-llama` when active.

- **Build** (`scripts/build_native_llama.sh`): a trimmed llama.cpp (server /
  UI / tools / mtmd / SSL off, CPU + OpenMP + llamafile on, `-fPIC`) plus a
  minimal C-ABI driver (`src/ida_pro_mcp/native/mcp_llama.cpp`) → one
  self-contained `libmcp_llama.so`.
- **Selection**: `IDA_MCP_BACKEND=native` pins native; `=http` forces HTTP;
  otherwise the host sets `IDA_MCP_NATIVE=1` at startup when the library and
  at least one matching retrieval model are found.
- **Wins**: no subprocess startup, no HTTP/JSON, no per-request graph
  allocation (RSS plateaus — the 5 GiB floor and recycle machinery are
  bypassed), no chunk-of-8 round trips, all CPU threads during a batch.
  Rerank scores and embed vectors match the HTTP path (verified to float
  noise).
- **Batched decode**: `encode_batched` packs up to `n_seq_max` (4 by default) sequences
  into one `llama_decode` with distinct `seq_id`s (each its own KV stream,
  KV cleared once per batch), so short documents share a ubatch instead of
  streaming the weights once each. Native uses a 512-token physical
  microbatch by default (larger values are available through
  `IDA_MCP_NATIVE_UBATCH` and should be benchmarked per machine). Native
  defaults to F16 KV for parity with llama-server; `IDA_MCP_NATIVE_KV=q8` is
  the lower-memory speed mode. Over-long sequences are truncated
  head-first (query + document prefix preserved).  `IDA_MCP_NATIVE_SEQUENCES=<1..64>` env
  overrides the batch width (`MCP_NSEQ` remains a compatibility alias).  The context passed by the
  Python side (`IDA_MCP_EMBED_CTX` / `IDA_MCP_RERANK_CTX`) is the
  **per-sequence** token budget — the total KV spans `n_ctx_seq × n_seq_max`.
  (An earlier interpretation divided the caller's value by `n_seq_max`,
  silently truncating every prompt to a fraction of its budget.)
- **Q4_K_M models**: `mcp_quantize` (built by the same script) produces
  ~1.6× smaller weights; model discovery prefers `Q4_K_M` over `Q8_0` when
  both are installed (`IDA_MCP_Q4=0` forces Q8; explicit
  `IDA_MCP_EMBED_MODEL`/state paths are always honored).  On the
  bandwidth-bound CPU decode this is the biggest single lever after batching.
- **Install**: `INSTALL_BIN=<install_root>/bin ./scripts/build_native_llama.sh`
  copies the `.so` and `mcp_quantize` into the install layout.
