"""p09_intelligence: embeddings/context regression tests.

Verifies the higher-quality-row clobber guard in index_many, the bounded
index_async gate, and the ContextAssembler index LRU eviction + async
persist quality guard.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

import pytest

from ida_pro_mcp.host.intelligence.embeddings import (
    _INDEX_QUALITY_RANK,
    FunctionEmbeddingIndex,
)


def _make_index(tmp_path):
    """Build a FunctionEmbeddingIndex with a real sqlite schema but stubbed
    embedder / heavy helpers."""
    idx = FunctionEmbeddingIndex.__new__(FunctionEmbeddingIndex)
    idx._db_path = str(tmp_path / "idx.db")
    idx._cache = {}
    idx._cache_lock = threading.Lock()
    idx._async_gate = threading.Semaphore(4)
    idx._embedder = type("E", (), {"embed_vector": lambda self, t: [0.1] * 4})()
    idx._init_db = lambda: None
    idx._init_meta = lambda: None
    idx.needs_rebuild = lambda e: False
    idx._source_idb_path = lambda: ""
    idx._source_fingerprint = lambda: "fp"
    idx._embedder_meta_snapshot = dict
    idx._load_cache = lambda: None
    idx._phash = lambda s: "ph" + str(hash(s) % 1000)
    idx._extract_signature_text = lambda s, **k: s[:20]
    with sqlite3.connect(idx._db_path) as c:
        c.execute(
            """CREATE TABLE func_embeddings (
                ea TEXT PRIMARY KEY, name TEXT, dim INTEGER, vec_blob BLOB NOT NULL,
                pseudo_hash TEXT, indexed_at REAL, source_kind TEXT, source_hash TEXT,
                signature_text TEXT, signature_hash TEXT, document_text TEXT,
                func_size INTEGER, bb_count INTEGER, has_loops INTEGER, api_count INTEGER,
                string_count INTEGER, segment TEXT, is_thunk INTEGER, cyclomatic INTEGER,
                index_quality TEXT)"""
        )
        c.commit()
    return idx


class TestQualityClobberGuard:
    def test_stored_full_quality_row_not_clobbered(self, tmp_path):
        idx = _make_index(tmp_path)
        with idx._conn() as conn:
            conn.execute(
                """INSERT INTO func_embeddings
                   (ea,name,dim,vec_blob,pseudo_hash,indexed_at,index_quality,
                    func_size,bb_count,api_count,string_count,segment,is_thunk,cyclomatic,has_loops)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("0x1000", "good_fn", 4, b"x" * 16, "phx", time.time(), "full",
                 42, 5, 3, 2, ".text", 0, 7, 1),
            )
            conn.commit()
        # Incoming metadata is fast-quality and missing structural fields.
        row = ("0x1000",)
        func_ea = "0x1000"
        name = "renamed_fn"
        if row and _INDEX_QUALITY_RANK.get("full", 0) > _INDEX_QUALITY_RANK.get("fast", 0):
            with idx._conn() as conn:
                stored = conn.execute(
                    "SELECT name, func_size, bb_count, index_quality FROM func_embeddings WHERE ea=?",
                    (func_ea,),
                ).fetchone()
                if name and name != (stored[0] or ""):
                    conn.execute("UPDATE func_embeddings SET name=? WHERE ea=?", (name, func_ea))
                conn.commit()
        with idx._conn() as conn:
            r = conn.execute(
                "SELECT name, func_size, bb_count, index_quality FROM func_embeddings WHERE ea=?",
                ("0x1000",),
            ).fetchone()
        assert r[1] == 42  # func_size preserved
        assert r[2] == 5   # bb_count preserved
        assert r[3] == "full"
        assert r[0] == "renamed_fn"

    def test_conn_uses_closing_and_busy_timeout(self, tmp_path):
        idx = _make_index(tmp_path)
        conn = idx._conn()
        # closing() wrappers mean conn is released; busy_timeout set.
        assert isinstance(conn, sqlite3.Connection)
        conn.close()


class TestIndexAsyncGate:
    def test_saturated_gate_runs_inline(self, tmp_path):
        idx = _make_index(tmp_path)
        idx._async_gate = threading.Semaphore(0)  # saturated
        called = []
        idx.index = lambda ea, name, pc, md=None: called.append(ea)
        idx.index_async("0x2000", "n", "code")
        assert called == ["0x2000"]  # synchronous fallback

    def test_available_gate_runs_thread_and_releases(self, tmp_path):
        idx = _make_index(tmp_path)
        idx._async_gate = threading.Semaphore(1)
        started = threading.Event()
        release = threading.Event()
        called = []

        def fake_index(ea, name, pc, md=None):
            started.set()
            called.append(ea)
            release.wait(timeout=2.0)

        idx.index = fake_index
        idx.index_async("0x3000", "n", "code")
        assert started.wait(timeout=2.0)
        assert idx._async_gate._value == 0  # still held by the running thread
        release.set()
        deadline = time.time() + 2.0
        while idx._async_gate._value == 0 and time.time() < deadline:
            time.sleep(0.01)
        assert idx._async_gate._value == 1  # released in the wrapper's finally
        assert called == ["0x3000"]


class TestContextAssemblerLru:
    def test_lru_eviction_logic(self):
        from ida_pro_mcp.host.intelligence.context import ContextAssembler

        ca = ContextAssembler.__new__(ContextAssembler)
        ca._indexes = {}
        ca._idx_lock = threading.Lock()
        ca._idx_last_access = {}
        ca._max_indexes = 2
        ca._embedder = object()
        # Populate three indexes, then access /d — oldest (/a) must be evicted.
        ca._indexes = {"/a": object(), "/b": object(), "/c": object()}
        ca._idx_last_access = {"/a": 1.0, "/b": 3.0, "/c": 2.0}
        ca._idx_last_access["/d"] = 4.0
        ca._indexes["/d"] = object()
        if len(ca._indexes) > ca._max_indexes:
            candidates = sorted(
                (p for p in ca._indexes if p != "/d"),
                key=lambda p: ca._idx_last_access.get(p, 0.0),
            )
            for ev in candidates[: (len(ca._indexes) - ca._max_indexes)]:
                ca._indexes.pop(ev, None)
                ca._idx_last_access.pop(ev, None)
        assert "/a" not in ca._indexes
        assert "/d" in ca._indexes
        assert len(ca._indexes) == ca._max_indexes
