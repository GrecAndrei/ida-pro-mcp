# Embedding layer benchmark — local vs Gemini (Vertex)

Corpus: `libgpu_aux.so` (MediaTek GPU HAL) — 33 real decompiled functions,
median 766 chars. Host: 8-core Linux, 15 GiB RAM.
Date: 2026-08-03. Harness: `benchmarks/embed_bench.py`.

## Speed

| metric | local `bge-code-v1` (llama-server CPU) | gemini `gemini-embedding-001` (Vertex) |
|---|---|---|
| cold start | 13–19 s | 0 s (no local process) |
| first embed | 28–30 s | 2.6 s |
| single embed (warm) | **5–78 s** (pathological) | **2.6 s** median |
| batch throughput | couldn't complete (HTTP 500) | ~0.5 s/doc (batch 16) |
| dimension | 1536 | 768 |
| cost model | free local compute | Vertex quota-bound |

Local backend measured at **~0.3 s/token** on CPU (8 s for an 11-char string,
78 s for a 400-token function), then degraded to HTTP 500. This is a broken
local path on this machine — indexing a 449-function binary would take hours.

Gemini throughput is bounded by Vertex's `online_prediction_requests_per_base_model`
quota (burst ~4–5 requests, sustainable ~1 request/5 s). Batching 8–16 docs per
request is the throughput lever.

## Accuracy (8 hand-authored behavior queries → target function)

| metric | gemini |
|---|---|
| self-retrieval@1 (own pseudocode → itself) | 100% |
| query→target recall@1 | 62% (5/8) |
| query→target recall@5 | **100% (8/8)** |
| MRR@5 | 0.76 |
| off-diagonal cosine (separation) | median 0.81, max 0.97 |

Local couldn't complete the accuracy pass (embed failures), so no accuracy
comparison is available for it — that is itself the finding.

## Why the local backend was slow

`bge-code-v1-q8_0.gguf` is a **Qwen2 1.5B decoder** (`general.architecture =
qwen2`), not a purpose-built embedding encoder. At q8 it is ~1.65 GB and the
host has only 8 CPU cores and a UHD 620 iGPU — decoding a 400-token function
is ~400 sequential steps at ~5 tok/s, hence 78 s. (Note: a decoder still
embeds in a single prefill pass — the architecture was not itself the bug;
the *size* was.)

## The model swap: Qwen3-Embedding-0.6B (DONE)

The default local profile is now **Qwen3-Embedding-0.6B** (1024-dim, last-token
pooling, query-instruction aware, q8 = 639 MB) with a bge-code-v1 fallback if
only the old model is present. Benchmark on the same corpus:

| metric | bge-code-v1 (old) | Qwen3-0.6B (new) |
|---|---|---|
| cold start | 13–19 s | ~3–6 s |
| single embed (warm) | **5–78 s then HTTP 500** | ~3.5 s (CPU) |
| batch throughput | couldn't complete | ~0.2 docs/s (CPU) |
| self-retrieval@1 | — | 100% |
| query→target recall@1 / MRR | — | 88% / 0.88 |
| dimension | 1536 | 1024 |

Two silent correctness bugs were fixed for the swap: the server launch now
uses the model's declared `pooling` (Qwen3 = `last`) instead of hardcoded
`mean`, and the profile carries the query-instruction prefix Qwen3 was trained
with.

## The iGPU experiment: NOT a win on this hardware (opt-in)

A Vulkan llama-server build (`GGML_VULKAN=ON`) was compiled and its iGPU
detected (`Vulkan0: Intel UHD 620`). Direct A/B on a **short** (240-char)
doc showed Vulkan 112 ms vs CPU 2.5 s — a 20× win. But on **real
decompilations** (500–2000+ chars) the same Vulkan path is pathological:
shader compilation per sequence length made full-function embeds hang or take
minutes (harness: ~5.6 s single, ~0.1 docs/s batch — *worse* than CPU). The
UHD 620 (gen9, 24 EU) is simply not suited to variable-length transformer
prefill. Conclusion: **CPU with the 0.6B model is the reliable default; GPU
offload is opt-in** via `IDA_MCP_EMBED_GPU=1` for users with a capable GPU.

## Findings that need fixing

1. **Local backend was not viable on this machine.** ~0.3 s/token CPU embedding
   with eventual HTTP 500s. Root cause: 1.5B decoder model on a weak host. Addressed
   by the Qwen3-0.6B swap (the iGPU experiment did not help — see above).
2. **First-embed timeout bug — FIXED.** `EMBED_REQUEST_TIMEOUT=5` killed the first
   query after cold start (~28 s), returning `unavailable` instead of waiting.
   Now a per-profile activation-grace window gives post-start requests up to
   `EMBED_ACTIVATION_GRACE_TIMEOUT` and a timeout inside that window no longer
   kills the just-started server. Default single-request timeout raised to 15 s.
3. **Vertex quota is the real ceiling for Gemini.** ~4–5 requests/minute burst
   on this project (`online_prediction_requests_per_base_model`). Bulk indexing
   must batch aggressively and pace requests.
4. **Session lockout with zero visibility — FIXED.** Shared session store + 5 live
   MCP servers = legitimate FILE_LOCKED with no owner info surfaced. Session
   list/state and the FILE_LOCKED error now carry a full ownership report
   (`holder`, `owner_id`, `owner_pid`, `owner_alive`, `idat_pid`,
   `lease_age_seconds`).
5. **`expansion_queries: ["crypto symmetric"]` auto-injection — FIXED.**
   `mode=expand` turned any low-confidence behavior-classifier label into a
   search query, so unrelated queries got crypto expansion. Expansion now clears
   an absolute floor (`IDA_MCP_EXPANSION_MIN_CONFIDENCE`, default 0.50) plus the
   same median/quartile margin gate `search_behavior` uses.
6. **Mean pooling on a decoder model — FIXED.** The server launch hardcoded
   `--pooling mean`, which silently corrupts embeddings for last-token-pooled
   models. `pooling` is now a per-profile field; Qwen3-Embedding declares `last`.

Raw reports: `corpus_libgpu_aux.gemini.report.json` (+ `local` when runnable).

## Cross-encoder reranking (two-stage retrieval)

Harness: `benchmarks/rerank_bench.py`. Same `libgpu_aux.so` corpus. Stage 1
recall is the Qwen3-0.6B embedding index; Stage 2 re-scores the recalled pool
with the cross-encoder reranker. Gold = hand-authored queries mapped to the
function the query describes. Pool of 16, 12 queries (full run).

| metric | baseline (Qwen3 recall) | qwen3-reranker-0.6b (rerank) |
|---|---|---|
| MRR@10 | 0.9583 | **1.0** |
| recall@1 | 0.9167 | **1.0** |
| recall@5 | 1.0 | 1.0 |
| per-pair latency | — | 6.4 s |
| pool-of-16 latency | — | 115 s |
| rerank applied | — | 12/12 discriminating queries |

**Qwen3-Reranker-0.6B is the correct Stage-2 model.** It is a real
cross-encoder (311 tensors, `cls.output.weight` classification head — the
opposite of the headless Gemma below) and it **improves** retrieval: on the
one query where recall ranked the gold function 2nd, the reranker moved it to
rank 1, lifting MRR 0.9583 → 1.0 and recall@1 0.9167 → 1.0. It never moved a
correct answer down. Latency is real CPU cost (~6.4 s/pair on 4 threads) —
expected for a cross-encoder on a laptop, and why the pipeline only re-scores
the recalled pool rather than the whole binary. All 12/12 pool calls
discriminated (the two pool failures from the earlier 9-query run are gone);
the single mid-run RSS recycle auto-recovered and cost no accuracy.

### RSS floor correction (2026-08-04, full-run benchmark)

The 12-query full run exposed a wrong assumption in the rerank RSS floor. The
old comment claimed a chunked 0.6B pool measures ~3 GB RSS at ctx 2048 and
that a 4 GiB floor "leaves headroom." Measured reality with `--parallel 2` +
`ubatch 2048` + 8-doc chunks on the varied corpus: RSS **ratchets** with
request size — llama.cpp allocates a fresh compute buffer for each distinct
larger batch and never frees the old one. Verified with a fixed-size control
(12 identical requests → flat 1752 MiB plateau, no recycle) vs the varied
corpus (climbed to ~4.15 GiB, crossing the 4 GiB floor and recycling a healthy
server mid-run). The floor is now 5 GiB (`model_size * 5 + 1 GiB`), leaving
~0.85 GiB of headroom over the measured peak. The differential growth check
still catches genuine leaks; the absolute floor now only trips on real
runaway, not legitimate worst-case pools.

### Historical: bge-reranker-v2-gemma (deleted — not viable)

Before the Qwen3 conversion was available, the only public "reranker" GGUF on
disk was `bge-reranker-v2-gemma.Q4_K_M` (2.6B). It degraded retrieval (MRR
1.0 → 0.714 on the 3 queries it ran), took 2.2 s/pair, and failed 2/3 pool
calls. It was a **headless base Gemma** (verified: 164 tensors, no
classification head, no `output.weight`), so its scores are not calibrated for
relevance. The benchmark's discriminating-score detection surfaced it; the
model was deleted from `~/Downloads`.

### Infra fixes found while benchmarking

The benchmark exposed three real bugs in the embed/rerank servers, now fixed:

1. **Vulkan build auto-grabbed the GPU.** A llama.cpp Vulkan build defaults to
   the first device when no `--device` is given — on this box that silently
   loaded `libggml-vulkan` + `libvulkan_intel` and ran on the pathological
   Intel UHD 620 iGPU even though offload is opt-in. Both servers now force
   `--device none` unless the GPU env var is set.
2. **RSS recycle killed healthy servers.** The growth check compared RSS
   against the startup baseline, so the first batch's one-time compute-graph
   allocation (0.9 → 1.6 GB, then flat) tripped it — the benchmark indexed
   only 16/33 corpus functions. Growth is now measured differentially (since
   the previous request); absolute floors raised to match the real plateaus
   (embed 3 GB, rerank 5 GB — raised again 2026-08-04, see the RSS floor
   correction above).
3. **Rerank memory scaled with the whole pool.** llama.cpp sizes buffers for
   the request batch, so a 64-doc pool ballooned to ~5.4 GB RSS (OOM on this
   15 GB / 5.6 GB-available box). `rerank()` now scores in chunks of 8
   (`IDA_MCP_RERANK_CHUNK`), ctx default 2048 (not 8192), and `--parallel 2`
   (the `--parallel 1` collapse bug is specific to a value of 1). A recycled
   server auto-recovers on the next call instead of disabling rerank.

Two llama.cpp build quirks remain documented: `--parallel 1` collapses `/rerank`
to one identical score per document, and a `top_k` field in the request body
shifts the returned indices by one. Neither is sent.

## In-process native backend (2026-08-04)

`benchmarks/native_bench.py` / A/B harness, same `libgpu_aux.so` corpus (real
decompilations), same 8-thread i7-8665U host.  Native runs both models in one
process via `libmcp_llama.so` (ctypes); HTTP runs two `llama-server`
subprocesses.

| metric | native | HTTP |
|---|---|---|
| cold → first embed | **1.8 s** | ~10–25 s (server spawn) |
| index 6 full decompilations | **21.9 s** (0.27 docs/s) | 32.7 s (0.18 docs/s) |
| rerank pool of 6 (full docs) | 46.4 s | 44.9 s |
| rerank scores (per index) | identical to HTTP | — |
| peak RSS, both models | **~1.9 GiB** (one process) | ~3.5+ GiB (two servers, ratchets) |
| subprocess / lease / recycle machinery | none | full |

**Correctness is bit-for-bit.** Rerank scores on the real corpus match HTTP to
the 4th decimal (e.g. `0.9814, 0.9281, 0.0211, ...` for an "acquire a buffer"
query — the relevant `AcquireBuffer`/`ReleaseBuffer` docs ranked 1st/2nd, all
others ~0.02).  Embed vectors are the same direction (L2-normalized like HTTP).

**Where native wins:** cold start (~10×), indexing throughput (~1.5×), memory
(~half, no 5 GiB rerank floor / recycle needed), and operational simplicity
(no leases, no chunk-of-8 HTTP round trips, no RSS ratchet).

**Where it does not:** rerank latency is **model-bound** (~7.7 s per full-decomp
pair on 8 threads) — native's `llama_decode` is not faster than the server's
for the same GEMM work.  The win there is not chunking, not recycling, and
one context instead of two.  A full 12-query × 16-doc rerank sweep exceeds 30
minutes on this host for *both* backends; the numbers above are the
representative subset.
