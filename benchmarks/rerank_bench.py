#!/usr/bin/env python3
"""Cross-encoder reranker benchmark.

Compares the Stage-2 rerankers against the Stage-1 bi-encoder baseline on a
real decompiled corpus: does the cross-encoder put the gold function at the
top of the list, and how fast is it?

Flow per available rerank model:
  1. Embed every corpus function (Qwen3-0.6B) into a temp index.
  2. For each gold query, recall the top-N with the embedding index (baseline).
  3. Re-score that pool with the reranker; re-order.
  4. Measure MRR@10 / recall@1 / recall@5 for baseline vs rerank, plus
     per-pair and full-pool latency.

A model that returns non-discriminating scores (identical for every input —
e.g. a headless GGUF) is reported as FAIL: reranking cannot improve anything
and the pipeline correctly falls back to recall order.

Usage:
  python benchmarks/rerank_bench.py [--models qwen3-reranker-0.6b] [--max-candidates 16]
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
# that must survive a slow run BEFORE importing the intelligence modules.
os.environ.setdefault("IDA_MCP_RERANK_TIMEOUT", "300")
os.environ.setdefault("IDA_MCP_RERANK_BATCH_TIMEOUT", "600")

from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder  # noqa: E402
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex  # noqa: E402
from ida_pro_mcp.host.intelligence.rerank import Reranker  # noqa: E402
from ida_pro_mcp.host.intelligence.rerank_profiles import (  # noqa: E402
    RERANK_MODEL_PROFILES,
    get_rerank_model_profile,
)

CORPUS = Path(__file__).resolve().parent / "corpus_libgpu_aux.json"

# (query, expected name substring) — the function names are the ground truth.
GOLD_QUERIES: list[tuple[str, str]] = [
    ("create and initialize a new gpu aux context", "GpuAuxCreateContext"),
    ("prepare an ANativeWindowBuffer for conversion", "prepare"),
    ("perform the pixel format conversion if needed", "DoConversionIfNeed"),
    ("set the crop size of the source buffer", "SetBufferCropSize"),
    ("get information about the source image buffer", "GetBufferInfo"),
    ("destroy the gpu aux context and free its resources", "DestoryContext"),
    ("check whether the source buffer is dirty and needs reprocessing", "CheckIfSrcDirty"),
    ("prepare the destination region of interest rectangle", "PrepareDstRoi"),
    ("acquire a buffer from the aux buffer queue", "AcquireBuffer"),
    ("release a buffer back to the aux queue", "ReleaseBuffer"),
    ("set the consumer name on the buffer queue", "setConsumerName"),
    ("what angle should the source image be pre-rotated", "GetPreRotationAngle"),
]


def _available_rerank_models() -> list[str]:
    """Return profile keys whose GGUF is present in Downloads/install dirs."""

    from ida_pro_mcp.host.intelligence.rerank import _find_rerank_model

    found = {p: _model_present(p) for p in RERANK_MODEL_PROFILES}
    # Always include the discovered default even if its profile pattern
    # differs slightly from the profile table.
    discovered = _find_rerank_model()
    if discovered and not any(found.values()):
        profile = _profile_key_for_path(discovered)
        found[profile] = True
    return [k for k, v in found.items() if v]


def _model_present(profile_key: str) -> bool:
    import glob


    profile = get_rerank_model_profile(profile_key)
    if profile is None or not profile.filename_patterns:
        return False
    home = str(Path.home())
    bases = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Documents"),
        os.path.join(home, "models"),
    ]
    for base in bases:
        for pattern in profile.filename_patterns:
            if glob.glob(os.path.join(base, pattern)):
                return True
    return False


def _profile_key_for_path(path: str) -> str:
    from ida_pro_mcp.host.intelligence.rerank_profiles import profile_from_rerank_model

    return profile_from_rerank_model(path).key


def _embed_corpus(corpus: dict, max_candidates: int) -> tuple[FunctionEmbeddingIndex, list[dict]]:
    # The cold embed server times out large first batches (known weak spot), so
    # warm it up and chunk.  Batch timeout is raised so a real CPU-bound batch
    # finishes instead of tripping the recycle path.  Idle shutdown is disabled
    # so the embed server stays warm across the whole benchmark (a reranker
    # pool call can take longer than the default 15s idle window, and a warm
    # server must not idle out mid-run).
    os.environ.setdefault("IDA_MCP_EMBED_BATCH_REQUEST_TIMEOUT", "180")
    os.environ.setdefault("IDA_MCP_EMBED_IDLE_TIMEOUT", "0")
    os.environ.setdefault("IDA_MCP_EMBED_DISABLED", "")
    embedder = BgeCodeEmbedder()
    if not embedder.ensure_ready():
        raise RuntimeError("embedding backend unavailable; cannot build recall baseline")
    embedder.embed_vector("warmup")
    db_path = os.path.join(tempfile.mkdtemp(prefix="rerank_bench_"), "corpus.embeddings.db")
    idx = FunctionEmbeddingIndex(db_path, embedder)
    funcs = corpus["functions"]
    indexed = 0
    for start in range(0, len(funcs), 8):
        chunk = funcs[start:start + 8]
        result = idx.index_many([(f["ea"], f["name"], f["pseudocode"], None) for f in chunk])
        indexed += int(result.get("indexed") or 0)
    if indexed < len(funcs):
        print(f"  [warn] indexed {indexed}/{len(funcs)} functions")
    return idx, funcs


def _recall(idx: FunctionEmbeddingIndex, query: str, top_k: int) -> list[dict]:
    vec = idx._embedder.embed_query_vector(query)
    if vec is None:
        # The embed server may have idled out between queries; restart and retry
        # once so a slow rerank between recalls does not collapse the baseline.
        embedder = idx._embedder
        if getattr(embedder, "ensure_ready", None) and embedder.ensure_ready():
            vec = embedder.embed_query_vector(query)
    if vec is None:
        return []
    return idx.similar_vec(vec, top_k=top_k, threshold=0.0)


def _metrics(ordered: list[str], gold_substr: str, k: int = 10) -> dict:
    """MRR@k and recall@k against the gold name substring."""
    rank = None
    for i, name in enumerate(ordered[:k]):
        if gold_substr.lower() in name.lower():
            rank = i + 1
            break
    return {
        "mrr": 1.0 / rank if rank else 0.0,
        "recall@1": 1.0 if rank == 1 else 0.0,
        "recall@5": 1.0 if rank and rank <= 5 else 0.0,
        "gold_rank": rank,
    }


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _run_one_model(profile_key: str, idx: FunctionEmbeddingIndex, funcs: list[dict],
                   max_candidates: int, queries: list[tuple[str, str]]) -> dict:
    path = _model_path_for(profile_key)
    rr = Reranker.reset(path)
    if not getattr(rr, "_use_llama", False):
        return {"profile": profile_key, "ok": False, "error": "no model / disabled"}

    ea_to_name = {f["ea"]: f["name"] for f in funcs}
    by_ea = {f["ea"]: f for f in funcs}

    print(f"\n=== {rr.status().get('profile_name')} ({profile_key}) ===")
    if not rr.ensure_ready():
        return {"profile": profile_key, "ok": False, "error": "server did not start"}

    baseline_mrr, baseline_r1, baseline_r5 = [], [], []
    rerank_mrr, rerank_r1, rerank_r5 = [], [], []
    per_pair_ms: list[float] = []
    pool_ms: list[float] = []
    discriminating_total = 0
    non_discriminating_streak = 0
    rows = []

    for qi, (query, gold) in enumerate(queries, 1):
        # A model that cannot discriminate on the first two queries is broken
        # (constant scores).  Stop early instead of burning minutes confirming
        # the same FAIL on every query.
        if non_discriminating_streak >= 2:
            break
        print(f"  q{qi}/{len(queries)}: {gold[:40]!r} ...", flush=True)
        recalled = _recall(idx, query, max_candidates)
        names = [ea_to_name.get(str(r["ea"]), str(r["ea"])) for r in recalled]
        b = _metrics(names, gold)
        baseline_mrr.append(b["mrr"])
        baseline_r1.append(b["recall@1"])
        baseline_r5.append(b["recall@5"])

        if not recalled:
            rows.append({"query": query, "baseline": b, "rerank": b, "note": "no recall"})
            continue

        pool = recalled[:max_candidates]
        docs = [by_ea.get(str(r["ea"]), {}).get("pseudocode", "") for r in pool]
        docs = [d or r.get("signature", "") for d, r in zip(docs, pool, strict=False)]

        # Per-pair latency on the top candidate only.
        t0 = time.time()
        rr.rerank(query, [docs[0]])
        per_pair_ms.append((time.time() - t0) * 1000)

        t0 = time.time()
        scored = rr.rerank(query, docs)
        pool_ms.append((time.time() - t0) * 1000)

        if not scored:
            non_discriminating_streak += 1
            rows.append({"query": query, "baseline": b, "rerank": b, "note": "rerank failed"})
            rerank_mrr.append(b["mrr"])
            rerank_r1.append(b["recall@1"])
            rerank_r5.append(b["recall@5"])
            continue

        by_index = {int(s["index"]): float(s["score"]) for s in scored}
        distinct = len(set(by_index.values()))
        if distinct < 2:
            non_discriminating_streak += 1
            rows.append({"query": query, "baseline": b, "rerank": b,
                         "note": "non-discriminating (constant scores)"})
            rerank_mrr.append(b["mrr"])
            rerank_r1.append(b["recall@1"])
            rerank_r5.append(b["recall@5"])
            continue
        non_discriminating_streak = 0
        discriminating_total += 1

        # Reorder the pool by rerank score (index == position in `docs`).
        reordered = sorted(range(len(pool)), key=lambda i: by_index.get(i, 0.0), reverse=True)
        reranked_names = [ea_to_name.get(str(pool[i]["ea"]), str(pool[i]["ea"])) for i in reordered]
        rb = _metrics(reranked_names, gold)
        rerank_mrr.append(rb["mrr"])
        rerank_r1.append(rb["recall@1"])
        rerank_r5.append(rb["recall@5"])
        rows.append({"query": query, "baseline": b, "rerank": rb})

    rr.stop()

    summary = {
        "profile": profile_key,
        "profile_name": get_rerank_model_profile(profile_key).display_name if profile_key else "?",
        "ok": True,
        "queries": len(queries),
        "queries_run": len(rows),
        "early_exit_non_discriminating": non_discriminating_streak >= 2,
        "discriminating_queries": discriminating_total,
        "baseline": {
            "mrr@10": _mean(baseline_mrr),
            "recall@1": _mean(baseline_r1),
            "recall@5": _mean(baseline_r5),
        },
        "rerank": {
            "mrr@10": _mean(rerank_mrr),
            "recall@1": _mean(rerank_r1),
            "recall@5": _mean(rerank_r5),
        },
        "latency_ms": {
            "per_pair": _mean(per_pair_ms),
            f"pool_{max_candidates}": _mean(pool_ms),
        },
        "rows": rows,
    }
    print(f"  baseline  mrr={summary['baseline']['mrr@10']} r@1={summary['baseline']['recall@1']} r@5={summary['baseline']['recall@5']}")
    print(f"  rerank    mrr={summary['rerank']['mrr@10']} r@1={summary['rerank']['recall@1']} r@5={summary['rerank']['recall@5']}")
    print(f"  latency   per-pair={summary['latency_ms']['per_pair']:.0f}ms  pool={summary['latency_ms'][f'pool_{max_candidates}']:.0f}ms  discriminating={discriminating_total}/{len(queries)}")
    return summary


def _model_path_for(profile_key: str) -> str:
    import glob

    profile = get_rerank_model_profile(profile_key)
    if profile is None:
        return ""
    home = str(Path.home())
    for base in (os.path.join(home, "Downloads"), os.path.join(home, "Documents"),
                 os.path.join(home, "models")):
        for pattern in profile.filename_patterns:
            hits = glob.glob(os.path.join(base, pattern))
            if hits:
                return hits[0]
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--max-candidates", type=int, default=16,
                    help="recall pool size the reranker re-scores (default 16)")
    ap.add_argument("--models", nargs="*", default=None,
                    help="restrict to specific rerank profiles")
    ap.add_argument("--queries", type=int, default=0,
                    help="limit to the first N gold queries (0 = all)")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as cfh:
        corpus = json.load(cfh)
    models = args.models or _available_rerank_models()
    queries = GOLD_QUERIES[: args.queries] if args.queries > 0 else GOLD_QUERIES
    if not models:
        print("No rerank models found on disk. Download one, e.g.:")
        print("  https://huggingface.co/ggml-org/Qwen3-Reranker-0.6B-Q8_0-GGUF")
        return

    print(f"corpus: {corpus['source']} ({corpus['count']} functions)")
    print(f"rerank models present: {models}")
    print("building recall baseline (embedding corpus)...")
    idx, funcs = _embed_corpus(corpus, args.max_candidates)

    results = []
    for profile_key in models:
        r = _run_one_model(profile_key, idx, funcs, args.max_candidates, queries)
        results.append(r)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nwrote {args.out}")
    return results


if __name__ == "__main__":
    main()
