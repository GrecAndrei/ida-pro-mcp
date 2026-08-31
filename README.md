# IDA Pro MCP

Give an LLM agent a working seat at IDA Pro.

This is an [MCP](https://modelcontextprotocol.io) server that exposes IDA Pro's
analysis to a model as 104 exact-schema operations — decompile, cross-reference,
search, rename, annotate — plus an investigation workspace so the model's
conclusions survive across turns instead of living in a context window.

It runs deterministic IDA SDK calls. There is no LLM service behind it, and
nothing about your binary leaves the machine.

> **Alpha (1.0.0a1).** The agent interface is still moving. Pin a commit if you
> depend on it.

---

## Why this instead of a thin SDK wrapper

**Every operation has an exact schema.** The surface is `ida_decompile(address)`,
not `tool(action="decompile", ...)`. Models don't infer argument shapes, so they
don't burn turns on `INVALID_ARGS`. `ida_help(topic="ida_decompile")` returns the
contract over MCP, so it works in clients with no filesystem access.

**Decompilation comes with structure, not just text.** `ida_decompile` returns
pseudocode *plus* a bounded evidence block: CFG shape, resolved call targets,
ctree control points, and local data-flow. `ida_disassemble` returns the CFG and
call-target portion without starting Hex-Rays. A model reasoning about a function
gets the graph, not only the listing.

**Semantic search runs locally — in process by default — or against an opt-in
cloud model, and it says so when it can't.** Function embeddings and
cross-encoder reranking run inside the server through a native llama.cpp library
(`libmcp_llama.so`, loaded via `ctypes`): no subprocess, no HTTP server, no JSON
round trips. The two `llama-server` subprocesses remain as the fallback when the
library isn't built. When you opt in (`--embed-backend gemini`), a Google
`gemini-embedding-2` cloud backend is used instead — it uploads only the compact
behavioral signature of each function, never the full decompilation. If the
model, library, server, or cloud credentials are unavailable, semantic
operations return an explicit unavailable result — they never fall back to a
different vector space, and never hand back a zero vector dressed as a score.
The index records model, dimension, and prompt format, and rebuilds when any
changes.

**The workspace remembers, and comes back on its own.** `ida_write_finding`
records a claim with confidence and evidence into a per-session SQLite workspace
with an append-only audit trail. You do not have to ask for it back: every
response about an address carries `_recall` — the findings, verdicts, and open
questions already recorded there.

**Dead ends are recorded too.** `ida_mark_examined` costs one line and says "I
read this, it's a CRT wrapper, skip it." Search results come back tagged with
what you already dismissed, so the next session doesn't re-read forty functions
to re-conclude the same nothing.

**Claims notice when they go out of date.** Each finding is anchored to a digest
of the code it was made against. When that code changes, the claim is flagged
stale — including "boring" verdicts, since that too is a claim about code that
just changed. `ida_next_target(strategy="stale")` lists them.

**Disagreement is never merged away.** Recording a rejection over a confirmed
claim keeps both rows and links them as a conflict rather than silently taking
the higher confidence. `ida_next_target(strategy="conflict")` surfaces them.

**Conclusions land in the IDB, not just here.** `ida_publish_findings` writes
confirmed findings into the database as repeatable comments and — where IDA
still auto-named the function — as symbols, so the marked-up IDB is something
you can open in the GUI without this tool. It never overwrites a name someone
else applied. `ida_import_annotations` reads existing names and comments back
as findings, so a session inherits the last analyst's work.

**Next-step suggestions explain themselves.** `ida_next_target` takes a named
strategy — `unresolved`, `stale`, `conflict`, `coverage`, `frontier` — and every
candidate states why it was chosen ("12 callers, never examined"), rather than
emerging from an opaque blended score.

**Mutations are gated, and the gate is yours.** Anything that writes to the IDB
requires an explicit `risk_ack`. Policy strictness comes from the operator, via
`IDA_MCP_POLICY_MODE` or `~/.config/ida-pro-mcp/policy.json`; a session can tighten
it but never relax it. See [the safety model](docs/guide/safety-model.md).

**Concurrent sessions stay separated.** Each MCP connection owns the sessions it
opened. Another client cannot drive, switch to, or kill a session it did not open,
and disconnecting tears down the `idat` processes that connection started.

---

## Install

```bash
python install.py
```

That builds the runtime environment, locates IDA, configures supported MCP
clients, and installs the portable `ida-pro-mcp` skill for Claude Code, Codex,
and OpenCode.

**Requirements:** IDA Pro 9.2+, Python 3.11+. Runtime dependencies are four
packages (`tomli-w`, `yara-python`, `requests`, `numpy`) — no torch, no
transformers.

From source:

```bash
git clone https://github.com/GrecAndrei/ida-pro-mcp.git
cd ida-pro-mcp
pip install -e .
python -u -m ida_pro_mcp.host.server
```

### Build the fast in-process retrieval backend (optional, recommended)

Embedding and reranking work out of the box via `llama-server` subprocesses. To
get the much faster in-process native backend instead, build it once against a
llama.cpp checkout:

```bash
# clone llama.cpp once, wherever you keep external source checkouts
git clone https://github.com/ggml-org/llama.cpp /path/to/llama.cpp

# build the trimmed library + quantizer, then install into the layout
LLAMA_CPP_SRC=/path/to/llama.cpp \
INSTALL_BIN="$HOME/.local/share/ida-pro-mcp/bin" \
  ./scripts/build_native_llama.sh
```

That compiles a minimal llama.cpp (CPU + OpenMP only — no server, UI, tools,
vision, or GPU backends) and the C-ABI driver into one self-contained
`libmcp_llama.so`, plus `mcp_quantize` for producing Q4_K_M models (see below).
The install root is `~/.local/share/ida-pro-mcp` (Linux), `%LOCALAPPDATA%\ida-pro-mcp`
(Windows), or wherever `IDA_PRO_MCP_HOME` points.

The server auto-enables native per retrieval component when the library and
matching model are present; HTTP remains the fallback for anything missing.
`IDA_MCP_BACKEND=native` pins it explicitly.

---

## Quick start

```jsonc
// Open a binary
{"name": "ida_open_binary", "arguments": {"binary_path": "/path/to/binary"}}

// Orient
{"name": "ida_overview",      "arguments": {}}
{"name": "ida_session_state", "arguments": {}}

// Find and read code
{"name": "ida_find",       "arguments": {"query": "recv", "limit": 20}}
{"name": "ida_decompile",  "arguments": {"address": "0x401000"}}
{"name": "ida_xrefs_to",   "arguments": {"address": "0x401000"}}

// Record what you concluded
{"name": "ida_write_finding", "arguments": {
    "title": "packet receive handler",
    "content": "Parses inbound data before dispatching on the command byte.",
    "address": "0x401000",
    "confidence": 0.8}}

// Record what you ruled out, so the next session doesn't re-read it
{"name": "ida_mark_examined", "arguments": {
    "address": "0x401a20", "verdict": "boring",
    "note": "CRT string helper, no input handling."}}

// Leave the conclusions in the IDB itself
{"name": "ida_publish_findings", "arguments": {"dry_run": true}}

// Writes need an acknowledgement
{"name": "ida_rename", "arguments": {
    "address": "0x401000", "name": "handle_recv", "risk_ack": true}}
```

A typical path through the surface:

```text
ida_open_binary → ida_session_state → ida_overview → ida_find
  → ida_decompile / ida_disassemble / ida_xrefs_to → ida_write_finding
```

---

## The operations

| Group | Operations |
|---|---|
| **Session** | `open_binary`, `open_background`, `close_session`, `session_get`, `session_list`, `session_switch`, `session_state`, `session_status`, `session_health` |
| **Discovery** | `overview`, `find`, `list_functions`, `list_imports`, `list_strings`, `semantic_search`, `index_functions`, `index_status`, `cancel_index`, `reranker_status`, `function_families`, `auto_wait`, `events`, `registers`, `search_data_value`, `search_query_lang`, `r2_status`, `r2_bininfo`, `r2_load_hints`, `r2_disassemble_hypothesis`, `r2_vxrefs`, `fw_detect_vector_table`, `fw_detect_load_base`, `fw_detect_mmio`, `fw_rtos_scan`, `fw_carve` |
| **Code** | `decompile`, `disassemble`, `xrefs_to`, `callers`, `callees`, `read_bytes`, `callgraph`, `emulate` |
| **Findings** | `write_finding`, `mark_examined`, `update_finding`, `list_findings`, `search_findings`, `next_target`, `analysis_brief`, `export_findings` |
| **IDB sync** | `publish_findings`, `import_annotations` |
| **Edit** | `rename`, `comment`, `change_function`, `create_function`, `patch_bytes`, `rename_local`, `make_code`, `undefine`, `save_idb`, `create_data`, `create_strlit`, `undo_begin`, `undo_end`, `add_entry`, `idb_snapshot`, `idb_restore_snapshot`, `mark_dangerous` |
| **Types** | `get_type`, `declare_type`, `apply_type`, `list_types`, `struct_member_add`, `struct_member_del`, `struct_member_rename`, `struct_member_set_type`, `enum_member_add`, `enum_member_rename`, `enum_member_revalue`, `til_delete`, `til_export`, `til_import` |
| **Segments** | `list_segments`, `add_segment`, `set_segment_attrs`, `sreg_get`, `sreg_set`, `sreg_list` |
| **Signatures** | `apply_sig`, `list_sigs` |
| **Calculation** | `calc_eval`, `calc_convert`, `calc_deref`, `calc_offset`, `calc_align`, `calc_bitops`, `calc_chain`, `calc_resolve` |
| **Support** | `help`, `continue`, `python` |
| **Workflow** | `batch` |

All prefixed `ida_`. Full contracts in [docs/TOOLS_REFERENCE.md](docs/TOOLS_REFERENCE.md),
or ask the server: `ida_help(query="strings")`.

The earlier broad `tool(action=...)` API still exists for old scripts —
set `IDA_MCP_TOOL_SURFACE=legacy`. It is a compatibility backend, not the
supported contract.

---

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_TOOL_SURFACE` | `agent` | `agent` for the `ida_*` operations, `legacy` for the old catalog |
| `IDA_MCP_RESPONSE_MODE` | `compact` | `full` for unabridged payloads |
| `IDA_MCP_POLICY_MODE` | `assist` | `off`, `permissive`, `assist`, `enforce` — operator baseline |

---

## Local retrieval (embed + rerank)

Semantic search and full indexing are optional. Both stages — the bi-encoder
embedding index and the cross-encoder reranker — run on one of two local
backends with the same public contract:

- **Native (default when built).** A single in-process shared library
  (`libmcp_llama.so`) drives llama.cpp through `ctypes`. No subprocess, no HTTP,
  no JSON, no lease/lock files, no per-request graph allocation — RSS plateaus,
  and the recycle machinery that the HTTP path needs is bypassed. Rerank scores
  and embed vectors match the HTTP path to float noise.
- **HTTP (fallback).** The two full `llama-server` subprocesses
  (`--embedding` and `--rerank`), with the lifecycle, recycling, and chunking
  machinery described under HTTP knobs below.

Selection: the server sets `IDA_MCP_NATIVE=1` at startup when the native
library and at least one matching retrieval model are found and no backend is
pinned. Each embedder/reranker still checks its own model before taking the
native route. `IDA_MCP_BACKEND=native|http` overrides either way.

### Why the native path is faster

- **Batched decode.** Instead of one sequence per `llama_decode` (KV cache
  cleared, weights streamed, per call), `encode_batched` packs up to 4 by
  default into one decode with distinct `seq_id`s, each with its own KV
  stream, clearing the KV once per batch. The decode graph runs over a physical
  512-token microbatch by default, so several documents packed into one decode
  fill the graph — the weights stream once for a full batch instead of once per
  document. That is the dominant cost for a bandwidth-bound 0.6B model.
- **KV cache.** Native uses F16 KV by default to match llama-server vectors;
  `IDA_MCP_NATIVE_KV=q8` halves the ~28 KiB/token footprint when memory is the
  constraint, with a small quality tradeoff. `IDA_MCP_NATIVE_SEQUENCES` tunes
  the width.
- **Q4_K_M weights.** `mcp_quantize` (built alongside the library) converts any
  Q8_0 GGUF to Q4_K_M — ~1.6× fewer weight bytes to stream. Model discovery
  prefers `Q4_K_M` over `Q8_0` when both are installed (`IDA_MCP_Q4=0` forces
  Q8; an explicit `IDA_MCP_EMBED_MODEL` / state path always wins).

```bash
# convert your Q8_0 model to Q4_K_M for the fast path
mcp_quantize /path/to/qwen3-embedding-0.6b-q8_0.gguf /path/to/qwen3-embedding-0.6b-Q4_K_M.gguf Q4_K_M
mcp_quantize /path/to/qwen3-reranker-0.6b-q8_0.gguf  /path/to/qwen3-reranker-0.6b-Q4_K_M.gguf  Q4_K_M
```

### Model profiles

The default recall profile is Qwen3-Embedding-0.6B (last-token pooling, 1024
dims); bge-code-v1 remains as a legacy fallback and Zembed 1 is opt-in and
non-commercial.

| Profile | Dims | Size | License | Notes |
| --- | ---: | --- | --- | --- |
| `qwen3-embedding-0.6b` | 1024 | ~396 MiB Q4 | Apache-2.0 | **Default.** 0.6B, fast on CPU. |
| `bge-code-v1` | 1536 | ~1.6 GB Q8 | Apache-2.0 | Legacy fallback. |
| `zembed-1` | 2560 | ~2.5 GB Q4 | CC-BY-NC-4.0 | Opt-in; slower on CPU. |

Semantic search is two-stage. Stage 1 recalls a wide candidate pool with the
embedding index (bi-encoder); Stage 2 re-scores it with a cross-encoder
reranker so the top of the list is the genuinely most relevant functions. The
reranker is a no-op (recall order preserved, `rerank: {applied: false}`) when no
rerank model is installed.

| Reranker profile | Size | Family | Notes |
| --- | ---: | --- | --- |
| `qwen3-reranker-0.6b` | ~396 MiB Q4 | Qwen3 | **Default.** Speed tier. |
| `qwen3-reranker-4b` | ~2.5 GB Q4 | Qwen3 | Opt-in; precision tier for deep dives. |
| `bge-reranker-v2-gemma` | ~1.6 GB Q4 | BGE | Middle tier; the public conversion is headless (constant scores) — verify before relying on it. |
| `bge-reranker-v2-m3` | ~0.6 GB Q8 | BGE | Opt-in compatibility. |

```bash
# managed download, explicit opt-in (HTTP backend path)
python install.py --embed-profile qwen3-embedding-0.6b --download-embed-model \
  --install-llama-server
python install.py --rerank-profile qwen3-reranker-0.6b --download-rerank-model

# or point at your own GGUF
python install.py --embed-profile qwen3-embedding-0.6b --embed-model /path/to/model.gguf
python install.py --rerank-profile qwen3-reranker-0.6b --rerank-model /path/to/reranker.gguf

# check a configuration without opening IDA
python install.py --embedder-doctor
```

Managed model downloads use immutable Hugging Face revisions and pinned
SHA-256 digests. The llama-server installer selects a compatible GitHub
release asset only when GitHub supplies its digest; an older release without
one is refused. `--allow-unverified-downloads` is available only as an
explicit, unsafe compatibility escape hatch.

The optional threat corpus uses a moving set of upstream sources. Normal
installs record each downloaded source checksum and reject unexpected changes
when reusing the cache. For strict first-download verification, provide one
`IDA_MCP_BRON_CORPUS_SHA256_<SOURCE>` variable per source and run
`python install.py --verify-corpus` (or set `IDA_MCP_BRON_CORPUS_VERIFY=1`).
The source keys are `CWE`, `ATTACK_ENTERPRISE`, `ATTACK_ICS`, `ATTACK_MOBILE`,
`SIGNATURE_BASE`, and `FINDCRYPT`.

The embed model starts only for explicit indexing, semantic search, or anchor
refresh; the reranker starts only for the rerank stage of semantic search.
Ordinary tool calls never spin them up. Indexing is interruptible and resumable:
a background job returns a cursor to pass back to `ida_index_functions`, and a
partial index is preserved if a batch fails.

### Native backend knobs

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_BACKEND` | auto | `native` pins the in-process backend; `http`/`llama` forces the subprocess path |
| `IDA_MCP_NATIVE` | set at startup | `1` when the library and at least one matching model are found and the backend is unpinned |
| `IDA_MCP_NATIVE_LIB` | auto-detect | explicit path to `libmcp_llama.so` |
| `IDA_MCP_NATIVE_CTX` | `2048` | per-sequence context (max tokens a doc can occupy) |
| `IDA_MCP_NATIVE_THREADS` | half available CPUs (capped at 16) | threads for the decode; explicit values override |
| `IDA_MCP_NATIVE_UBATCH` | `512` | physical tokens per native graph execution; benchmark `1024`/`2048` on larger machines |
| `IDA_MCP_NATIVE_KV` | `f16` | native KV precision; set `q8` for lower memory/faster inference with a small quality tradeoff |
| `IDA_MCP_NATIVE_DOC_CHARS` | `6000` | rerank document cap in chars (truncated head-first) |
| `IDA_MCP_NATIVE_SEQUENCES` | `4` | max sequences packed per `llama_decode` batch (`1`–`64`); `MCP_NSEQ` remains an alias |
| `IDA_MCP_NATIVE_RERANK_CACHE` | `128` | bounded exact-query rerank score cache; `0` disables it |
| `IDA_MCP_Q4` | `1` | prefer `Q4_K_M` over `Q8_0` when both are installed; `0` forces Q8 |

### HTTP backend knobs

Used only when the native library is absent or `IDA_MCP_BACKEND=http`. The
embed server starts for indexing / semantic search / anchor refresh; the rerank
server starts for the rerank stage. One request in flight per server; a
timed-out request recycles that server rather than queueing behind it, and the
RSS/recycle machinery bounds memory (embed floor ~3 GiB, rerank ~5 GiB, with
differential growth checks that only recycle on real leaks).

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_EMBED_PROFILE` | `qwen3-embedding-0.6b` | Selects prompts and expected model profile |
| `IDA_MCP_EMBED_MODEL` | auto-detect | Path to the GGUF model |
| `IDA_MCP_EMBED_SERVER_BIN` | auto-detect | Path to `llama-server` |
| `IDA_MCP_EMBED_THREADS` | adaptive | CPU threads, from available affinity |
| `IDA_MCP_EMBED_BATCH` / `_MAX_BATCH` | `1` / adaptive | Indexing batch size; grows on success up to the ceiling |
| `IDA_MCP_EMBED_GPU` | `0` | `1` offloads to a GPU backend (CPU is forced otherwise) |
| `IDA_MCP_EMBED_MAX_RSS_MB` | adaptive | RSS recycle limit; `0` derives one from model size |
| `IDA_MCP_EMBED_IDLE_TIMEOUT` | `15` | Seconds to keep the server after its last request; `0` disables |
| `IDA_MCP_EMBED_CACHE` | `4096` | Bounded exact-text embedding cache; `0` disables |
| `IDA_MCP_RERANK_PROFILE` | `qwen3-reranker-0.6b` | Selects the rerank model profile |
| `IDA_MCP_RERANK_MODEL` | auto-detect | Path to the rerank GGUF |
| `IDA_MCP_RERANK_DOC_CHARS` | `6000` | Document cap per rerank pair |
| `IDA_MCP_RERANK_DOC_BUDGET_CHARS` | `800` | Per-document budget passed to the reranker from search |
| `IDA_MCP_RERANK_POOL` | `8` | Recalled pool capped before cross-encoder re-scoring; benchmarked 12/12 top-1 on the bundled corpus |
| `IDA_MCP_RERANK_CHUNK` | `8` | Documents scored per request, so peak memory tracks the chunk not the pool |
| `IDA_MCP_RERANK_CTX` | `1024` | Per-pair rerank context size (query + document) |
| `IDA_MCP_RERANK_CACHE` | `128` | Bounded exact-chunk score cache; `0` disables it |

The full set of knobs for both backends lives in
[docs/wiki/core/intelligence.md](docs/wiki/core/intelligence.md).

### Benchmarking

Performance and retrieval quality are measured at run time against the selected
corpus, model, backend, and machine. Use the portable pipelines in
[`benchmarks/README.md`](benchmarks/README.md); they emit JSON and Markdown
reports with the inputs and environment recorded, so one workstation's numbers
are not presented as product guarantees.

### Cloud embeddings (Gemini, opt-in)

An alternative backend that calls Google's `gemini-embedding-2` (or
`gemini-embedding-001`) instead of running a local GGUF. **Opt in explicitly** —
selection is never automatic, so a stray `GOOGLE_CLOUD_PROJECT` in your
environment cannot silently switch you to a cloud model.

> **Privacy:** the cloud backend uploads the *compact behavioral signature* of each
> function (calls, constants, string literals, control-flow profile) — never the
> full decompilation. If you cannot send any code to Google, keep the local backend.

```bash
# AI Studio (API key from https://aistudio.google.com/apikey)
export GEMINI_API_KEY="..."

# Vertex AI (GCP) — project + region; ADC via GOOGLE_APPLICATION_CREDENTIALS
export GOOGLE_CLOUD_PROJECT="my-project"
export VERTEX_AI_LOCATION="us-central1"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# pick the cloud backend for a new install (interactive wizard asks too)
python install.py --embed-backend gemini --gemini-access aistudio --gemini-api-key "$GEMINI_API_KEY"
python install.py --embed-backend gemini --gemini-access vertex \
  --gemini-vertex-project "$GOOGLE_CLOUD_PROJECT" --gemini-vertex-location us-central1 --gemini-install-auth

# check your setup without opening IDA
python install.py --embedder-doctor --embed-backend gemini
```

The installer writes `embedder.json` with `{"backend": "gemini", ...}` so the
server picks the cloud backend, and (when you provide it) persists the AI Studio
key into the generated MCP client config env block. The key is **never** written
to `embedder.json`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_EMBED_BACKEND` | `local` | `gemini` selects the cloud backend |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | — | Google AI Studio API key |
| `VERTEX_AI_ACCESS_TOKEN` / `GOOGLE_ACCESS_TOKEN` | — | Already-obtained Vertex bearer token |
| `GOOGLE_APPLICATION_CREDENTIALS` | — | Service-account JSON for Vertex ADC (needs `google-auth`) |
| `GOOGLE_CLOUD_PROJECT` / `VERTEX_AI_PROJECT` | — | Vertex project (from env or `embedder.json`) |
| `VERTEX_AI_LOCATION` / `GOOGLE_CLOUD_REGION` | `us-central1` | Vertex region |
| `IDA_MCP_GEMINI_MODEL` | `gemini-embedding-2` | Embedding model name |
| `IDA_MCP_GEMINI_DIM` | `768` | Output dimensionality (128–3072) |
| `IDA_MCP_GEMINI_TASK_TYPE` | auto | `none` omits `taskType`; else a value like `retrieval_document` |
| `IDA_MCP_GEMINI_BATCH` | `16` | Requests per batch call |
| `IDA_MCP_GEMINI_TIMEOUT` / `_BATCH_TIMEOUT` | `30` / `120` | Seconds per request |

---

## Development

```bash
ruff check .
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
pytest -q
```

`host/agent_operations.py` is the single source of truth: `tools/list`, `ida_help`,
the installed skill, and `docs/TOOLS_REFERENCE.md` are all generated from it. Change
an operation, then regenerate — CI checks for drift.

Live IDA integration tests need a local IDA install and a target binary; they skip
otherwise. See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and
[the architecture guide](docs/guide/architecture.md) for the layout.

---

## Credits

Portions of `ida_mcp/utils.py` and the vendored `ida_mcp/zeromcp` package come from
[ida-pro-mcp by mrexodia](https://github.com/mrexodia/ida-pro-mcp) (MIT), which is
also where the idea of driving IDA over MCP came from. `zeromcp` keeps its own
LICENSE alongside the sources.

FindCrypt signatures and the threat corpus are fetched from their upstream projects
by the installer.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
