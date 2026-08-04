#!/usr/bin/env python
"""Benchmark the embedding layer: speed and retrieval accuracy per backend.

Usage:
    python benchmarks/embed_bench.py --backend local   [--corpus benchmarks/corpus_libgpu_aux.json]
    python benchmarks/embed_bench.py --backend gemini  [--dim 768]

Backends:
    local   bge-code-v1 via llama-server  (default embedder.json profile)
    gemini  gemini-embedding-001 via Vertex AI (uses gcloud ADC, or
            VERTEX_AI_ACCESS_TOKEN). Opt-in only: set IDA_MCP_GEMINI_VERTEX=1
            and IDA_MCP_GEMINI_MODEL=gemini-embedding-001.

Output: prints a markdown report and writes <corpus>.report.json next to the
corpus file.

Measures:
    speed   cold-start (ensure_ready), single-embed latency, batch throughput
    accuracy leave-one-out self-retrieval@1 (pipeline sanity), hand-authored
            query->target recall@5 + MRR, and the off-diagonal cosine
            distribution (does the model actually separate functions?).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from statistics import median

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── corpus ────────────────────────────────────────────────────────────────

def load_corpus(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    funcs = [fn for fn in data.get("functions", []) if (fn.get("pseudocode") or "").strip()]
    return {"source": data.get("source", ""), "functions": funcs}


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb or 1.0)


# ── embedders ─────────────────────────────────────────────────────────────

def make_embedder(backend: str):
    from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder
    if backend == "local":
        return BgeCodeEmbedder()
    from ida_pro_mcp.host.intelligence.core import _read_embedder_state
    from ida_pro_mcp.host.intelligence.gemini import GeminiEmbedBackend
    return GeminiEmbedBackend(state=_read_embedder_state())


# ── timing helpers ────────────────────────────────────────────────────────

def bench_speed(embedder, docs: list[str], batch_sizes=(1, 8, 16), gap: float = 0.0) -> dict:
    # Cold start (server process + model load) is measured separately from the
    # first inference. The local llama-server's first real embed can take tens
    # of seconds while the model warms; the default 5s interactive timeout
    # kills it. Raise the request timeout for the harness so we measure the
    # backend's true throughput, not the warmup failure.
    import ida_pro_mcp.host.intelligence.core as core
    core.EMBED_REQUEST_TIMEOUT = 120.0
    core.EMBED_BATCH_REQUEST_TIMEOUT = 180.0

    t0 = time.perf_counter()
    embedder.ensure_ready()
    cold_start = time.perf_counter() - t0
    status = embedder.status(probe=False)
    dim = int(status.get("dim") or embedder.dim or 0)

    # First inference warms the model. Measure it, then discard from steady
    # state so per-embed latency reflects warm throughput.
    t0 = time.perf_counter()
    warm = embedder.embed_document(docs[0])
    first_embed = time.perf_counter() - t0
    assert warm.ok, f"warmup embed failed: {warm}"

    single_times: list[float] = []
    n_single = 6
    for i in range(n_single):
        t0 = time.perf_counter()
        r = embedder.embed_document(docs[(i + 1) % len(docs)])
        single_times.append(time.perf_counter() - t0)
        assert r.ok, f"single embed failed: {r}"
        if gap:
            time.sleep(gap)

    batches: dict[str, dict] = {}
    for bs in batch_sizes:
        if bs <= 1:
            continue
        t0 = time.perf_counter()
        results = _chunk_embed(embedder, docs, bs, gap=gap)
        wall = time.perf_counter() - t0
        ok = sum(1 for r in results if getattr(r, "ok", True))
        batches[str(bs)] = {
            "wall_sec": round(wall, 3),
            "docs_per_sec": round(len(results) / wall, 1) if wall else 0,
            "ok": ok,
            "total": len(results),
        }

    return {
        "backend": getattr(embedder, "backend", "unknown"),
        "dim": dim,
        "cold_start_sec": round(cold_start, 3),
        "first_embed_sec": round(first_embed, 3),
        "single_ms_median": round(median(single_times) * 1000, 1),
        "batches": batches,
    }


def _chunk_embed(embedder, docs: list[str], bs: int, gap: float = 0.0):
    out = []
    for i in range(0, len(docs), bs):
        out.extend(embedder.embed_batch(docs[i:i + bs], purpose="document"))
        if gap:
            time.sleep(gap)
    return out


# ── accuracy ──────────────────────────────────────────────────────────────

def bench_accuracy(embedder, corpus: dict, gap: float = 0.0) -> dict:
    funcs = corpus["functions"]
    docs = [fn["pseudocode"] for fn in funcs]

    # Embed corpus once (through the same batch path indexing uses).
    results = _chunk_embed(embedder, docs, 8, gap=gap)
    vectors = [r.vector for r in results]
    assert all(v is not None for v in vectors), "some corpus documents failed to embed"
    assert all(len(v) == len(vectors[0]) for v in vectors), "dimension mismatch"

    def topk(qvec, k=5):
        sims = sorted(
            ((cosine(qvec, v), i) for i, v in enumerate(vectors)), reverse=True
        )
        return sims[:k]

    # 1) leave-one-out self-retrieval: query = own pseudocode, exclude self.
    hit1 = 0
    for i, v in enumerate(vectors):
        ranked = [idx for _, idx in topk(v, k=2)]
        if ranked and ranked[0] == i and len(ranked) > 1 and ranked[1] != i:
            hit1 += 1
    self_recall = hit1 / max(1, len(vectors))

    # 2) hand-authored query -> target.
    qpath = os.path.join(os.path.dirname(__file__), "bench_queries.json")
    queries: dict[str, list[dict]] = {}
    if os.path.exists(qpath):
        with open(qpath, encoding="utf-8") as qfh:
            queries = json.load(qfh)
    qa = queries.get(corpus.get("source") or corpus.get("session") or "", [])
    if not qa:
        # fall back to generic queries keyed by function name
        qa = _auto_queries(funcs)

    # Query text is a short behavioral description; embed as a *query*.
    def embed_query_text(text: str):
        r = embedder.embed_query(text)
        return r.vector if getattr(r, "ok", True) else None

    target_map = {fn["ea"]: i for i, fn in enumerate(funcs)}
    rr_at5 = 0.0
    recall_at1 = 0
    recall_at5 = 0
    rows = []
    for item in qa:
        qvec = embed_query_text(item["query"])
        if gap:
            time.sleep(gap)
        if qvec is None:
            rows.append({"query": item["query"], "error": "embed failed"})
            continue
        ranked = topk(qvec, k=5)
        target_idx = target_map.get(item["target"])
        rank = next((r + 1 for r, (_, idx) in enumerate(ranked) if idx == target_idx), None)
        hit1 = rank == 1
        hit5 = rank is not None
        recall_at1 += int(hit1)
        recall_at5 += int(hit5)
        if rank:
            rr_at5 += 1.0 / rank
        rows.append({
            "query": item["query"],
            "target": item["target"],
            "top1": funcs[ranked[0][1]]["name"] if ranked else None,
            "top1_sim": round(ranked[0][0], 4) if ranked else None,
            "rank": rank,
        })
    nq = len(qa) or 1
    recall1 = recall_at1 / nq
    recall5 = recall_at5 / nq
    mrr = rr_at5 / nq

    # 3) off-diagonal cosine distribution — does the model collapse functions?
    offdiag = []
    for i in range(len(vectors)):
        for j in range(i + 1, len(vectors)):
            offdiag.append(cosine(vectors[i], vectors[j]))
    offdiag.sort()

    return {
        "corpus_size": len(funcs),
        "self_recall_at1": round(self_recall, 4),
        "query_recall_at1": round(recall1, 4),
        "query_recall_at5": round(recall5, 4),
        "query_mrr_at5": round(mrr, 4),
        "num_queries": len(qa),
        "offdiag_cos": {
            "min": round(offdiag[0], 4) if offdiag else None,
            "p10": round(offdiag[max(0, int(len(offdiag) * 0.1))], 4) if offdiag else None,
            "median": round(offdiag[len(offdiag) // 2], 4) if offdiag else None,
            "max": round(offdiag[-1], 4) if offdiag else None,
        },
        "query_rows": rows,
    }


def _auto_queries(funcs: list[dict]) -> list[dict]:
    # Fallback: "function named X that does Y" using the name itself as query.
    out = []
    for fn in funcs[:10]:
        name = fn["name"].replace("::", " ").replace("_", " ")
        out.append({"query": f"{name}", "target": fn["ea"]})
    return out


# ── report ────────────────────────────────────────────────────────────────

def format_report(corpus: dict, speed: dict, acc: dict) -> str:
    L = []
    L.append(f"## Embedding benchmark — {speed['backend']}")
    L.append(f"- corpus: {corpus.get('source')} — {acc.get('corpus_size')} functions")
    L.append("")
    L.append("### Speed")
    L.append(f"- cold start (ensure_ready): **{speed['cold_start_sec']}s**")
    L.append(f"- first embed (cold model): **{speed['first_embed_sec']}s**")
    L.append(f"- single embed (warm): **{speed['single_ms_median']} ms** median")
    L.append(f"- dimension: {speed['dim']}")
    L.append("")
    L.append("| batch size | wall (s) | docs/sec | ok |")
    L.append("|---|---|---|---|")
    for bs, b in speed["batches"].items():
        L.append(f"| {bs} | {b['wall_sec']} | {b['docs_per_sec']} | {b['ok']}/{b['total']} |")
    L.append("")
    L.append("### Accuracy")
    L.append(f"- self-retrieval@1 (own pseudocode → itself): **{acc.get('self_recall_at1'):.0%}**")
    L.append(f"- query→target recall@1: **{acc.get('query_recall_at1'):.0%}**  "
             f"recall@5: **{acc.get('query_recall_at5'):.0%}**  MRR@5: **{acc.get('query_mrr_at5'):.2f}**")
    L.append(f"- {acc.get('num_queries')} queries")
    off = acc.get("offdiag_cos") or {}
    L.append(f"- off-diagonal cosine: min {off.get('min')} · p10 {off.get('p10')} · "
             f"median {off.get('median')} · max {off.get('max')}")
    L.append("")
    L.append("| query | target | top1 | sim | rank |")
    L.append("|---|---|---|---|---|")
    for r in acc.get("query_rows", []):
        L.append(f"| {r.get('query', '')[:48]} | {r.get('target')} | {r.get('top1') or '-'} | "
                 f"{r.get('top1_sim') or '-'} | {r.get('rank') or '-'} |")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["local", "gemini"], default="local")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus_libgpu_aux.json"))
    ap.add_argument("--batch-sizes", default="1,8,16")
    ap.add_argument("--gap", type=float, default=float(os.environ.get("IDA_MCP_BENCH_GAP", "0") or 0),
                    help="seconds to sleep between embed requests (respect cloud quota)")
    args = ap.parse_args()

    corpus = load_corpus(args.corpus)
    if len(corpus["functions"]) < 3:
        print(f"corpus too small: {len(corpus['functions'])} functions")
        return 1

    embedder = make_embedder(args.backend)
    speed = bench_speed(embedder, [fn["pseudocode"] for fn in corpus["functions"]],
                        batch_sizes=[int(x) for x in args.batch_sizes.split(",") if x],
                        gap=args.gap)
    acc = bench_accuracy(embedder, corpus, gap=args.gap)

    report = format_report(corpus, speed, acc)
    print(report)

    out_path = os.path.splitext(args.corpus)[0] + f".{args.backend}.report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"speed": speed, "accuracy": acc}, f, indent=1)
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
