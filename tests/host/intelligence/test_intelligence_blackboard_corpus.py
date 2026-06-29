"""Tests for the blackboard-driven rewire of FunctionEmbeddingIndex.

The legacy per-function path (decide every function in the IDB) was
killed because the synchronous decompile+embed loop blocked IDA.  The
new path indexes curated blackboard entries (hypotheses, IOCs, vulns,
evidence tuples) which is bounded, in-process, and never touches
Hex-Rays.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeEmbedder:
    """Deterministic, content-sensitive embedder.  Hash of text → unit vector."""

    backend = "tfidf-fallback"
    dim = 16

    def __init__(self):
        self.calls: list[str] = []

    def embed(self, text: str):
        self.calls.append(text)
        if not text:
            return [0.0] * self.dim
        # Mix a couple of buckets so cosine actually differentiates inputs.
        v = [0.0] * self.dim
        for i, ch in enumerate(text):
            v[(ord(ch) + i) % self.dim] += 1.0
        norm = sum(x * x for x in v) ** 0.5 or 1.0
        return [x / norm for x in v]

    def status(self, probe: bool = False):
        return {"model_path": "", "server_bin": ""}


def _entry(**kw) -> dict:
    base = {
        "id": kw.get("id", "e0001"),
        "title": kw.get("title", "strcpy buffer overflow"),
        "content": kw.get("content", "calls strcpy with attacker-controlled src"),
        "category": kw.get("category", "vuln"),
        "addr": kw.get("addr", "0x401000"),
        "tags": kw.get("tags", ["overflow", "memcpy"]),
        "confidence": kw.get("confidence", 0.9),
        "evidence": kw.get("evidence", [
            {"type": "import", "value": "strcpy", "weight": 1.0},
            {"type": "string", "value": "GET /api", "weight": 0.5},
        ]),
    }
    base.update(kw)
    return base


def test_entry_doc_includes_addr_title_evidence_and_tags():
    from ida_pro_mcp.host.intelligence.embeddings import _build_entry_doc
    e = _entry(
        title="recv handler",
        content="parses incoming requests",
        tags=["network", "recv"],
        evidence=[{"type": "import", "value": "recv"}],
    )
    doc = _build_entry_doc(e)
    # Ordering: category, addr, title, content, tags, ioc, evidence.
    assert "category vuln" in doc
    assert "addr 0x401000" in doc
    assert "title recv handler" in doc
    assert "parses incoming requests" in doc
    assert "tags network recv" in doc
    assert "import recv" in doc


def test_entry_doc_handles_string_tags_and_decimal_addr():
    from ida_pro_mcp.host.intelligence.embeddings import _build_entry_doc, _entry_addrs
    e = _entry(
        id="e2",
        addr=4198400,  # 0x401000 in decimal
        tags='network,recv',  # string instead of list
        evidence=[{"type": "xref", "value": "0x401200"}],
    )
    addrs = _entry_addrs(e)
    assert "0x401000" in addrs
    assert "0x401200" in addrs
    doc = _build_entry_doc(e)
    assert "addr 0x401000" in doc
    assert "tags network recv" in doc


def test_index_entry_persists_and_dedupes(tmp_path):
    from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
    db = tmp_path / "bb.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())
    assert idx.entry_size() == 0

    res1 = idx.index_entry(_entry(id="e1", title="recv handler"))
    assert res1["ok"], res1
    assert idx.entry_size() == 1

    # Re-index with identical doc: no-op, no extra embed call.
    embedder = idx._embedder
    calls_before = len(embedder.calls)
    res2 = idx.index_entry(_entry(id="e1", title="recv handler"))
    assert res2["ok"] and res2.get("skipped") is True
    assert len(embedder.calls) == calls_before

    # Re-index with a different title: actually re-embeds.
    res3 = idx.index_entry(_entry(id="e1", title="recv handler v2"))
    assert res3["ok"] and res3.get("skipped") is None
    assert len(embedder.calls) == calls_before + 1


def test_index_entries_respects_corpus_gate(tmp_path):
    from ida_pro_mcp.host.intelligence.embeddings import (
        ENTRY_CORPUS_GATE_DEFAULT,
        FunctionEmbeddingIndex,
    )
    db = tmp_path / "bb-gate.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())

    # Default gate is 2000 — pass 3 entries, no force needed.
    small = [_entry(id=f"e{i}", title=f"entry {i}") for i in range(3)]
    res = idx.index_entries(small)
    assert res["ok"], res
    assert res["indexed"] == 3
    assert res["gate"] == ENTRY_CORPUS_GATE_DEFAULT

    # Trip the gate by setting it low.
    try:
        os.environ["IDA_MCP_EMBED_CORPUS_GATE"] = "2"
        big = [_entry(id=f"b{i}", title=f"big {i}") for i in range(5)]
        tripped = idx.index_entries(big)
        assert tripped["ok"] is False
        assert "corpus gate tripped" in tripped["error"]
        assert tripped["would_index"] == 5
        # And force=True bypasses it.
        forced = idx.index_entries(big, force=True)
        assert forced["ok"] is True
        assert forced["indexed"] == 5
    finally:
        os.environ.pop("IDA_MCP_EMBED_CORPUS_GATE", None)


def test_similar_for_address_pulls_context_and_ranks(tmp_path):
    from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
    db = tmp_path / "bb-similar.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())

    # Index a few entries that all mention 0x401000 or related addrs.
    a = idx.index_entry(_entry(id="a", addr="0x401000", title="recv handler", content="parses requests"))
    b = idx.index_entry(_entry(id="b", addr="0x401000", title="packet dispatcher", content="dispatches recv"))
    c = idx.index_entry(_entry(id="c", addr="0x402000", title="aes decrypt", content="crypto round"))
    d = idx.index_entry(_entry(id="d", addr="0x403000", title="logger", content="writes log file"))
    assert all(x["ok"] for x in (a, b, c, d))

    # The first two entries share content with 0x401000, so they should
    # come back as the top hits.
    hits = idx.similar_for_address(
        "0x401000",
        top_k=3,
        threshold=0.0,
        context_entries=[
            _entry(id="ctx", addr="0x401000", title="recv handler", content="parses requests"),
        ],
    )
    assert hits, "expected at least one hit"
    ids = [h["entry_id"] for h in hits]
    # a and b are exact-addr matches so they get the +0.05 bonus; one of
    # them must be in the top-K.
    assert ("a" in ids) or ("b" in ids)
    # The +0.05 addr_match bonus must be set on the exact-addr entries.
    for h in hits:
        if h["entry_id"] in {"a", "b"}:
            assert h["addr_match"] is True
        else:
            assert h["addr_match"] is False


def test_similar_to_entry_round_trip(tmp_path):
    from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
    db = tmp_path / "bb-self.i64.embeddings.db"
    idx = FunctionEmbeddingIndex(str(db), _FakeEmbedder())

    idx.index_entry(_entry(id="x", addr="0x401000", title="recv packet parser"))
    idx.index_entry(_entry(id="y", addr="0x401200", title="recv packet dispatcher"))
    idx.index_entry(_entry(id="z", addr="0x500000", title="aes encrypt round"))

    neighbours = idx.similar_to_entry("x", top_k=2, threshold=0.0)
    assert neighbours
    # "y" shares more text content with "x" than "z" does.
    ids = [n["entry_id"] for n in neighbours]
    assert "y" in ids
    assert "x" not in ids  # exclude_self
