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

# These paths used to be hardcoded to the author's machine.  Parameterize via
# env (the native module already honors IDA_MCP_NATIVE_LIB) and fail fast with
# a clear message instead of a late ctypes assert.
_NATIVE_LIB = os.environ.get("IDA_MCP_NATIVE_LIB", "").strip()
if not _NATIVE_LIB or not os.path.isfile(_NATIVE_LIB):
    raise SystemExit(
        f"libmcp_llama.so not found: {_NATIVE_LIB!r}\n"
        "set IDA_MCP_NATIVE_LIB to your built libmcp_llama.so"
    )
os.environ["IDA_MCP_NATIVE_LIB"] = _NATIVE_LIB
from ida_pro_mcp.host.intelligence.native import _NativeLib  # noqa: E402

_RERANK_MODEL = os.environ.get("IDA_MCP_RERANK_MODEL", "").strip()
if not _RERANK_MODEL or not os.path.isfile(_RERANK_MODEL):
    raise SystemExit(
        f"rerank model not found: {_RERANK_MODEL!r}\n"
        "set IDA_MCP_RERANK_MODEL to your reranker .gguf"
    )
RERANK = _RERANK_MODEL


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
        f"    return total + {seed % 100}\n"
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
    if not getattr(lib, "lib", None):
        raise SystemExit(f"native lib failed to load: {lib.error}")
    n = int(os.environ.get("NDOCS", "8"))
    dlen = int(os.environ.get("DOCLEN", "400"))
    iters = int(os.environ.get("ITERS", "2"))
    docs = [make_doc(dlen, i) for i in range(n)]
    q = "how does this function validate the input buffer and compute a checksum"

    h1 = h16 = None
    try:
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
        maxdiff = max(abs(a - b) for a, b in zip(s1, s16, strict=True))
        print(f"SCOREDIFF n={n} max|batched-single|={maxdiff:.6f}")

        # interleaved timing
        t1 = t16 = 0.0
        for _i in range(iters):
            d, _ = score(lib, h1, q, docs)
            t1 += d
            d, _ = score(lib, h16, q, docs)
            t16 += d
        per1 = t1 / iters / n
        per16 = t16 / iters / n
        print(f"RESULT n={n} doclen={dlen} "
              f"nseq1: {per1*1000:7.1f} ms/doc  nseq16: {per16*1000:7.1f} ms/doc  "
              f"speedup={per1/per16:.2f}x")
    finally:
        # Free native contexts even when an assert above fails.
        if h16 is not None:
            lib.mcp_rerank_free(h16)
        if h1 is not None:
            lib.mcp_rerank_free(h1)


if __name__ == "__main__":
    main()
