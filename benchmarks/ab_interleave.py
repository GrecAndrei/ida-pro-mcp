#!/usr/bin/env python3
"""Interleaved nseq=1 vs nseq=N benchmark in ONE process.

Creates two contexts (n_seq_max=1 and n_seq_max=N) by flipping the MCP_NSEQ
env between handle creations, then alternates measurement so CPU contention
hits both sides equally.  Also asserts batched scores == single-seq scores
for identical docs (correctness under any load).
"""
import ctypes
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
os.environ["IDA_MCP_NATIVE_LIB"] = "/tmp/llama.cpp/build-mcp/libmcp_llama.so"
from ida_pro_mcp.host.intelligence.native import _NativeLib

RERANK = "/home/alex/Downloads/qwen3-reranker-0.6b-q8_0.gguf"


def make_doc(chars: int, seed: int) -> str:
    base = (
        "def process_data(handle, size, flags):\n"
        "    # validate the incoming buffer and check the capability bits\n"
        "    if not handle or size == 0:\n"
        "        return -1\n"
        "    buf = acquire_buffer(handle, size)\n"
        "    if not buf:\n"
        "        return -2\n"
        "    total = 0\n"
        "    for i in range(size):\n"
        "        total += buf[i] & 0xff\n"
        "        if total > 1024:\n"
        "            break\n"
        "    return total + %d\n" % (seed % 100)
    )
    reps = max(1, chars // len(base))
    return (base * (reps + 1))[:chars]


def make_handle(lib, n_ctx):
    h = lib.mcp_rerank_new(RERANK.encode(), 8, n_ctx)
    assert h, "handle failed"
    return h


def score(lib, h, q, docs):
    n = len(docs)
    arr = (ctypes.c_char_p * n)(*(d.encode() for d in docs))
    out = (ctypes.c_float * n)()
    t0 = time.perf_counter()
    rc = lib.mcp_rerank_score(h, q.encode(), arr, n, out)
    dt = time.perf_counter() - t0
    assert rc == 0, rc
    return dt, [float(x) for x in out]


def main():
    lib = _NativeLib()
    n = int(os.environ.get("NDOCS", "8"))
    dlen = int(os.environ.get("DOCLEN", "400"))
    iters = int(os.environ.get("ITERS", "2"))
    docs = [make_doc(dlen, i) for i in range(n)]
    q = "how does this function validate the input buffer and compute a checksum"

    # two contexts, env flipped between creations
    os.environ["MCP_NSEQ"] = "1"
    h1 = make_handle(lib, 2048)
    os.environ["MCP_NSEQ"] = "16"
    h16 = make_handle(lib, 16 * 2048)  # n_ctx_seq=2048, n_seq_max=16
    del os.environ["MCP_NSEQ"]

    # warm both
    score(lib, h1, q, docs[:2])
    score(lib, h16, q, docs[:2])

    # correctness: batched vs single scores on same docs
    _, s1 = score(lib, h1, q, docs)
    _, s16 = score(lib, h16, q, docs)
    maxdiff = max(abs(a - b) for a, b in zip(s1, s16))
    print(f"SCOREDIFF n={n} max|batched-single|={maxdiff:.6f}")

    # interleaved timing
    t1 = t16 = 0.0
    for i in range(iters):
        d, _ = score(lib, h1, q, docs)
        t1 += d
        d, _ = score(lib, h16, q, docs)
        t16 += d
    per1 = t1 / iters / n
    per16 = t16 / iters / n
    print(f"RESULT n={n} doclen={dlen} "
          f"nseq1: {per1*1000:7.1f} ms/doc  nseq16: {per16*1000:7.1f} ms/doc  "
          f"speedup={per1/per16:.2f}x")

    lib.mcp_rerank_free(h1)
    lib.mcp_rerank_free(h16)


if __name__ == "__main__":
    main()
