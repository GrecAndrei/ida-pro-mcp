#!/usr/bin/env python3
"""Native in-process llama.cpp backend benchmark (A/B vs HTTP llama-server).

Same corpus and gold queries as ``rerank_bench.py``, but focused on the
native backend's wins:

  - embed throughput (corpus indexing time, docs/s)
  - cold start to first embed / first rerank score
  - rerank pool latency (one native call vs HTTP chunk-of-8 round trips)
  - peak RSS (single process vs two llama-server processes)
  - the standard MRR / recall@1 / recall@5 accuracy, so native vs HTTP
    quality can be compared on equal footing

Usage:
  IDA_MCP_NATIVE=1 python benchmarks/native_bench.py --queries 12   # native
  IDA_MCP_NATIVE=0 python benchmarks/native_bench.py --queries 12   # HTTP
  python benchmarks/native_bench.py --queries 12 --both             # A/B

Reuses the exact corpus, gold queries and metric helpers from rerank_bench.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# Module-level llama.cpp constants read env at import time, so set the knobs
# BEFORE importing the intelligence modules.
os.environ.setdefault("IDA_MCP_RERANK_TIMEOUT", "300")
os.environ.setdefault("IDA_MCP_RERANK_BATCH_TIMEOUT", "600")

from rerank_bench import (  # noqa: E402
    GOLD_QUERIES,
    _metrics,
    _recall,
)

from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder  # noqa: E402
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex  # noqa: E402
from ida_pro_mcp.host.intelligence.rerank import Reranker  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus_libgpu_aux.json"


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


def _phase(name: str, fn, *args):
    start = time.time()
    result = fn(*args)
    return result, time.time() - start


def run_backend(idx: FunctionEmbeddingIndex, funcs: list[dict],
                max_candidates: int, queries: list[tuple[str, str]]) -> dict:
    backend = str(getattr(idx._embedder, "backend", "?"))

    # --- per-query accuracy + latency (reuses rerank_bench logic) ---
    baseline_mrr, baseline_r1, rerank_mrr, rerank_r1 = [], [], [], []
    pool_ms: list[float] = []
    per_pair_ms: list[float] = []
    rr = Reranker()
    rr_ready = bool(getattr(rr, "_use_llama", False)) if rr is not None else False
    ea_to_name = {f["ea"]: f["name"] for f in funcs}
    by_ea = {f["ea"]: f for f in funcs}
    if rr_ready:
        rr.ensure_ready()
    for query, gold in queries:
        recalled = _recall(idx, query, max_candidates)
        names = [ea_to_name.get(str(r["ea"]), str(r["ea"])) for r in recalled]
        b = _metrics(names, gold)
        baseline_mrr.append(b["mrr"])
        baseline_r1.append(b["recall@1"])
        if not recalled or not rr_ready:
            rerank_mrr.append(b["mrr"])
            rerank_r1.append(b["recall@1"])
            continue
        pool = recalled[:max_candidates]
        docs = [by_ea.get(str(r["ea"]), {}).get("pseudocode", "") for r in pool]
        docs = [d or r.get("signature", "") for d, r in zip(docs, pool, strict=False)]
        t0 = time.time()
        rr.rerank(query, [docs[0]])
        per_pair_ms.append((time.time() - t0) * 1000)
        t0 = time.time()
        scored = rr.rerank(query, docs)
        pool_ms.append((time.time() - t0) * 1000)
        if not scored:
            rerank_mrr.append(b["mrr"])
            rerank_r1.append(b["recall@1"])
            continue
        by_index = {int(s["index"]): float(s["score"]) for s in scored}
        reordered = sorted(range(len(pool)), key=lambda i: by_index.get(i, 0.0), reverse=True)
        reranked_names = [ea_to_name.get(str(pool[i]["ea"]), str(pool[i]["ea"])) for i in reordered]
        rb = _metrics(reranked_names, gold)
        rerank_mrr.append(rb["mrr"])
        rerank_r1.append(rb["recall@1"])
    rr.stop()

    return {
        "backend": backend,
        "rerank_used": rr_ready,
        "recall": {"mrr@10": _mean(baseline_mrr), "recall@1": _mean(baseline_r1)},
        "rerank": {"mrr@10": _mean(rerank_mrr), "recall@1": _mean(rerank_r1)},
        "latency_ms": {
            "per_pair": _mean(per_pair_ms),
            f"pool_{max_candidates}": _mean(pool_ms),
        },
        "pool_latency_rows": len(pool_ms),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--max-candidates", type=int, default=16)
    ap.add_argument("--queries", type=int, default=0, help="first N gold queries (0 = all)")
    ap.add_argument("--both", action="store_true", help="A/B native vs HTTP")
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as cfh:
        corpus = json.load(cfh)
    queries = GOLD_QUERIES[: args.queries] if args.queries > 0 else GOLD_QUERIES
    print(f"corpus: {corpus['source']} ({corpus['count']} functions), "
          f"{len(queries)} gold queries, pool={args.max_candidates}")

    runs: list[dict] = []
    for mode in (["native", "http"] if args.both else
                 ["native"] if os.environ.get("IDA_MCP_NATIVE", "").strip().lower() in
                 ("1", "true", "yes") else ["http"]):
        os.environ["IDA_MCP_NATIVE"] = "1" if mode == "native" else "0"
        os.environ["IDA_MCP_BACKEND"] = "native" if mode == "native" else "http"
        from ida_pro_mcp.host.intelligence import native as _native

        _native._NativeLib._instance = None
        _native.NativeEmbedder._instance = None
        _native.NativeReranker._instance = None
        BgeCodeEmbedder._instance = None
        Reranker._instance = None

        print(f"\n=== backend: {mode} ===")
        # Cold start: embed a warmup once and time it.
        t0 = time.time()
        emb = BgeCodeEmbedder()
        cold_ready = time.time() - t0
        warm_start = time.time()
        emb.embed_vector("warmup")
        first_embed_ms = (time.time() - warm_start) * 1000
        print(f"  cold construct: {cold_ready:.1f}s   first embed: {first_embed_ms:.0f}ms")

        # Indexing throughput on the full corpus.
        rss0 = _rss_mb()
        t0 = time.time()
        db_path = os.path.join(tempfile.mkdtemp(prefix=f"native_bench_{mode}_"),
                               "corpus.embeddings.db")
        idx = FunctionEmbeddingIndex(db_path, emb)
        funcs = corpus["functions"]
        for start in range(0, len(funcs), 8):
            idx.index_many([(f["ea"], f["name"], f["pseudocode"], None) for f in funcs[start:start + 8]])
        index_s = time.time() - t0
        rss1 = _rss_mb()
        print(f"  indexed {idx.size}/{len(funcs)} in {index_s:.1f}s "
              f"({idx.size / max(index_s, 0.001):.2f} docs/s)  RSS {rss0:.0f}->{rss1:.0f} MB")

        r = run_backend(idx, funcs, args.max_candidates, queries)
        r["index_seconds"] = round(index_s, 2)
        r["docs_per_s"] = round(idx.size / max(index_s, 0.001), 3)
        r["cold_construct_s"] = round(cold_ready, 2)
        r["first_embed_ms"] = round(first_embed_ms, 1)
        r["peak_rss_mb"] = round(rss1, 1)
        runs.append(r)
        print(f"  recall   mrr={r['recall']['mrr@10']} r@1={r['recall']['recall@1']}")
        if r["rerank_used"]:
            print(f"  rerank   mrr={r['rerank']['mrr@10']} r@1={r['rerank']['recall@1']} "
                  f"pool-{args.max_candidates}={r['latency_ms'][f'pool_{args.max_candidates}']:.0f}ms")
        emb.stop()

    print("\n=== comparison ===")
    pool_key = f"pool_{args.max_candidates}"
    print(f"{'backend':<8}{'index(s)':<10}{'docs/s':<9}{'cold(s)':<9}"
          f"{f'pool-{args.max_candidates}(s)':<11}{'r@1 rec':<9}{'r@1 rer':<9}{'peakRSS(MB)':<12}")
    for r in runs:
        pool_s = r["latency_ms"].get(pool_key, 0) / 1000
        print(f"{r['backend']:<8}{r['index_seconds']:<10.1f}{r['docs_per_s']:<9.3f}"
              f"{r['cold_construct_s']:<9.1f}{pool_s:<11.1f}"
              f"{r['recall']['recall@1']:<9.2f}{r['rerank']['recall@1'] if r['rerank_used'] else '-':<9}"
              f"{r['peak_rss_mb']:<12.0f}")

    out = "native_bench_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
