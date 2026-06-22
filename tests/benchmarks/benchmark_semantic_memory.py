#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder, BehaviorClassifier
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex, SemanticObject, SemanticObjectIndex


FIX_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "semantic"


def _fixture(name: str) -> str:
    return (FIX_DIR / name).read_text(encoding="utf-8")


def _ms(start: float, end: float) -> float:
    return round((end - start) * 1000.0, 3)


def main() -> int:
    emb = BgeCodeEmbedder()
    clf = BehaviorClassifier.instance(emb)

    fixtures = [
        _fixture("crypto_aes.c.txt"),
        _fixture("http_client.c.txt"),
        _fixture("buffer_overflow.c.txt"),
        _fixture("benign_file_io.c.txt"),
        _fixture("string_decrypt.c.txt"),
    ]

    t0 = time.perf_counter()
    _ = emb.embed(fixtures[0])
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    _ = emb.embed_batch(fixtures)
    t3 = time.perf_counter()

    t4 = time.perf_counter()
    _ = clf.classify(fixtures[1], threshold=0.2, top_k=4, block=False)
    t5 = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="sideband-benchmark-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        idx = FunctionEmbeddingIndex(str(tmp_path / "embeddings.db"), emb)
        t6 = time.perf_counter()
        for i, text in enumerate(fixtures):
            idx.index(f"0x40{i:04x}", f"sub_{i}", text)
        t7 = time.perf_counter()

        t8 = time.perf_counter()
        _ = idx.similar(fixtures[0], top_k=3, threshold=0.0)
        t9 = time.perf_counter()

        sem_idx = SemanticObjectIndex(str(tmp_path / "semantic-objects.db"), emb)
        for i, text in enumerate(fixtures):
            sem_idx.upsert_object(
                SemanticObject(
                    kind="function",
                    stable_ref=f"fx_{i}",
                    title=f"fixture_{i}",
                    text=text,
                    metadata={"fixture": i},
                )
            )
        t10 = time.perf_counter()
        _ = sem_idx.semantic_search("http recv parser", kind="function", top_k=3, threshold=0.0)
        t11 = time.perf_counter()

    payload = {
        "backend": emb.backend,
        "embed_single_ms": _ms(t0, t1),
        "embed_batch_ms": _ms(t2, t3),
        "classify_ms": _ms(t4, t5),
        "index_fixtures_ms": _ms(t6, t7),
        "similarity_search_ms": _ms(t8, t9),
        "semantic_object_search_ms": _ms(t10, t11),
        "fixtures_indexed": len(fixtures),
        "function_index_size": idx.size,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
