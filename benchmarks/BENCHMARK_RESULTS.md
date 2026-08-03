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
function the query describes. 3 queries, pool of 8.

| metric | baseline (Qwen3 recall) | bge-reranker-v2-gemma (rerank) |
|---|---|---|
| MRR@10 | **1.0** | 0.714 |
| recall@1 | **1.0** | 0.667 |
| per-pair latency | — | 2.2 s |
| pool-of-8 latency | — | 48.9 s |
| pool reliability | — | failed on 2/3 queries |

**Verdict: the public `bge-reranker-v2-gemma` GGUF is not viable.** The
reranker *degraded* retrieval — the query it did re-score moved the correct
function out of rank 1 — and it is pathologically slow on this CPU (a 2.6B
model on 8 weak cores). The GGUF is a **headless base Gemma** (verified: 164
tensors, no classification head, no `output.weight`), so its scores are not
calibrated for relevance. The benchmark's discriminating-score detection and
early-exit correctly surface this; the pipeline falls back to recall order
rather than trusting it.

**The comparison this setup needs is the Qwen3-Reranker family** (`ggml-org`
conversions, which ship the classification head): `qwen3-reranker-0.6b`
(default, ~130 ms/pair) vs `qwen3-reranker-4b` (opt-in, ~0.5 s/pair). The
harness runs both once the GGUFs are in `~/Downloads`:
`python benchmarks/rerank_bench.py --models qwen3-reranker-0.6b qwen3-reranker-4b`.

Two llama.cpp build quirks were found and worked around in the reranker
manager (verified empirically on build `99111b1`): `--parallel 1` collapses
`/rerank` to one identical score per document, and a `top_k` field in the
request body shifts the returned indices by one. Neither is sent.
