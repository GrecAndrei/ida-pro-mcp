"""Regression tests for the f12 intelligence/embedding wave.

Covers:
  - rerank start-timeout path kills the orphaned llama-server subprocess
    instead of leaking one hung process per failed attempt (rerank.py).
  - the cross-process startup lock timeout clears the whole health-poll
    critical section so a concurrent cold start does not spuriously fail.
  - ``FunctionEmbeddingIndex._load_cache`` survives a single corrupt row
    instead of silently dropping the whole in-RAM index (embeddings.py).
  - ``index_many`` preserves the real ``indexed`` count when its first DB
    block fails, and stamps the freshness marker after its own writes so the
    next search does not pay a full O(N) reload.
  - ``read_gguf_metadata`` degrades to ``{}`` on pathologically nested GGUF
    array metadata instead of leaking a RecursionError out of embedder init.

Mocks stay at the process/network boundary (``subprocess.Popen``,
``urllib.request.urlopen``, sqlite rows), per project test rules.  No live
IDA session is required.
"""

from __future__ import annotations

import logging
import sqlite3
import struct
import sys
import threading
import time

import pytest

from ida_pro_mcp.host.intelligence import model_profiles, rerank as rerank_mod, rerank_profiles
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex

# ---------------------------------------------------------------------------
# shared stubs
# ---------------------------------------------------------------------------

class _FixedEmbedder:
    backend = "test"
    dim = 3

    def embed_vector(self, text: str):
        return [0.0, 0.6, 0.8]


class _FakeProc:
    def __init__(self, pid=12345, poll_result=None):
        self.pid = pid
        self._poll = poll_result
        self.terminated = False
        self.killed = False
        self.waited: list[float | None] = []

    def poll(self):
        return self._poll

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return 0


def _stub_reranker(**attrs) -> rerank_mod.Reranker:
    """Minimal Reranker without ``_init()`` (no discovery, no singleton)."""
    obj = object.__new__(rerank_mod.Reranker)
    obj._server_bin = ""
    obj._model_path = ""
    obj._profile = rerank_profiles.QWEN3_RERANKER_0_6B
    obj._port = None
    obj._proc = None
    obj._ready = False
    obj._start_lock = threading.Lock()
    obj._use_llama = False
    obj._owns_proc = False
    obj._stop_registered = True
    obj._consecutive_rpc_failures = 0
    obj._max_rpc_failures = 2
    obj._last_batch_timeout = False
    obj._last_recycle_reason = ""
    obj._identity_cache = None
    obj._server_started_at = time.monotonic() - 3600.0
    obj._idle_lock = threading.Lock()
    obj._idle_timer = None
    obj._idle_generation = 0
    obj._ctx = 1024
    for key, value in attrs.items():
        setattr(obj, key if key.startswith("_") else f"_{key}", value)
    return obj


# ---------------------------------------------------------------------------
# finding 1 (medium): rerank start-timeout leaks the spawned llama-server
# ---------------------------------------------------------------------------

class TestStartTimeoutReapsOrphanedProc:
    def test_health_timeout_kills_spawned_proc_and_clears_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(tmp_path / "lease.json"))
        # Shrink the wall-clock health-poll deadline so the loop exits
        # immediately instead of spinning for 60 real seconds.
        monkeypatch.setattr(rerank_mod, "RERANK_START_DEADLINE", 0.05)
        obj = _stub_reranker(
            server_bin="/bin/echo",
            model_path=str(tmp_path / "m.gguf"),
            use_llama=True,
        )
        monkeypatch.setattr(obj, "_read_lease", dict)
        monkeypatch.setattr(obj, "_pick_port", lambda: 9999)
        monkeypatch.setattr(rerank_mod.time, "sleep", lambda _s: None)

        proc = _FakeProc(pid=888)
        monkeypatch.setattr(rerank_mod.subprocess, "Popen", lambda cmd, **kwargs: proc)

        def _never_healthy(req, timeout=2.0):
            raise TimeoutError("server never answers /health")

        monkeypatch.setattr(rerank_mod.urllib.request, "urlopen", _never_healthy)

        assert obj._start_server_locked() is False
        assert obj._ready is False
        # The proc we spawned for the failed attempt must be reaped, not
        # orphaned, and the next cold start must spawn fresh.
        assert proc.terminated is True
        assert obj._proc is None
        assert obj._owns_proc is False
        assert obj._last_recycle_reason == "health poll timed out"

    def test_retry_after_timeout_spawns_fresh_proc(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(tmp_path / "lease.json"))
        monkeypatch.setattr(rerank_mod, "RERANK_START_DEADLINE", 0.05)
        model = tmp_path / "m.gguf"
        model.write_bytes(b"m" * 64)
        obj = _stub_reranker(
            server_bin="/bin/echo",
            model_path=str(model),
            use_llama=True,
        )
        monkeypatch.setattr(obj, "_read_lease", dict)
        monkeypatch.setattr(obj, "_pick_port", lambda: 9999)
        monkeypatch.setattr(rerank_mod.time, "sleep", lambda _s: None)

        spawned: list[_FakeProc] = []

        def _popen(cmd, **kwargs):
            proc = _FakeProc(pid=900 + len(spawned))
            spawned.append(proc)
            return proc

        monkeypatch.setattr(rerank_mod.subprocess, "Popen", _popen)
        attempt = {"n": 0}

        def _urlopen(req, timeout=2.0):
            # First _start_server_locked attempt: never healthy.  Second: ok.
            if attempt["n"] < 1:
                raise TimeoutError("still starting")
            return _FakeResp(b'{"status":"ok"}')

        monkeypatch.setattr(rerank_mod.urllib.request, "urlopen", _urlopen)

        assert obj._start_server_locked() is False
        assert spawned[0].terminated is True
        assert obj._proc is None
        attempt["n"] += 1
        assert obj._start_server_locked() is True
        assert spawned[1].terminated is False
        assert obj._ready is True


class _FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


# ---------------------------------------------------------------------------
# finding 6 (low): startup lock timeout vs health-poll critical section
# ---------------------------------------------------------------------------

class TestStartLockTimeout:
    def test_start_lock_timeout_covers_start_deadline(self):
        # Structurally the lock is held across the whole health poll, so the
        # waiter's budget must clear that window or a healthy concurrent cold
        # start spuriously fails with RerankQueueTimeout.
        assert rerank_mod.RERANK_START_LOCK_TIMEOUT >= rerank_mod.RERANK_START_DEADLINE

    def test_start_server_uses_start_lock_timeout(self, monkeypatch):
        captured: dict = {}

        class _RecLock:
            def __init__(self, path, timeout):
                captured["timeout"] = timeout

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(rerank_mod, "_RerankInterProcessLock", _RecLock)
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_start_server_locked", lambda: True)
        assert obj._start_server() is True
        assert captured["timeout"] == rerank_mod.RERANK_START_LOCK_TIMEOUT


# ---------------------------------------------------------------------------
# finding 2 (medium): _load_cache swallows a corrupt row into total search loss
# ---------------------------------------------------------------------------

class TestLoadCacheCorruptRow:
    def test_corrupt_row_is_skipped_not_fatal(self, tmp_path, caplog):
        db_path = str(tmp_path / "corrupt.embeddings.db")
        writer = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
        assert writer.index("0x1000", "good", "def good(): return 1") is True

        # A row whose vec_blob is not a float32 blob (as a different host /
        # generation could produce) makes _unpack_floats raise.
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO func_embeddings(ea, name, dim, vec_blob) VALUES (?, ?, ?, ?)",
                ("0x2000", "bad", 3, "not-a-blob"),
            )

        with caplog.at_level(logging.WARNING, logger="ida_pro_mcp.host.intelligence.embeddings"):
            reader = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
        # The good row survives; the corrupt one is dropped without nuking the
        # whole in-RAM index, and the corruption is surfaced, not silent.
        assert reader.size == 1
        assert any("skipping unreadable embedding row" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# finding 3 (low): index_many first DB-block exception misreports accounting
# ---------------------------------------------------------------------------

class TestIndexManyFirstBlockAccounting:
    def test_db_block_exception_preserves_indexed(self, tmp_path):
        db_path = str(tmp_path / "sample.embeddings.db")
        index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
        assert index.index("0x1000", "f", "def f(): return 1") is True

        real_meta_set = index._meta_set

        def _boom(conn, key, value):
            if key == "updated_at":
                raise sqlite3.OperationalError("simulated DB failure")
            return real_meta_set(conn, key, value)

        index._meta_set = _boom
        out = index.index_many([("0x1000", "f", "def f(): return 1", None)])
        # The unchanged row was counted as indexed before the failure; the
        # handler must not claim every input failed.
        assert out["indexed"] == 1
        assert out["failed"] == 0
        assert out["resume_after_ea"] is None


# ---------------------------------------------------------------------------
# finding 4 (low): own writes poison the freshness stamp -> full reload
# ---------------------------------------------------------------------------

class TestFreshnessStamp:
    def test_embed_write_does_not_poison_freshness(self, tmp_path):
        db_path = str(tmp_path / "sample.embeddings.db")
        index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
        assert index.index("0x1000", "f", "def f(): return 1") is True
        # The writer updated the in-RAM cache, so its own commit must not mark
        # the DB changed and force a full reload on the next search.
        assert index.db_changed_since_load() is False

        reloads: list[int] = []
        index.refresh_from_disk = lambda: reloads.append(1)
        index._similarity_candidates(None, None)
        assert reloads == []

    def test_metadata_refresh_does_not_poison_freshness(self, tmp_path):
        db_path = str(tmp_path / "sample.embeddings.db")
        index = FunctionEmbeddingIndex(db_path, _FixedEmbedder())
        assert index.index("0x1000", "f", "def f(): return 1") is True
        # Re-indexing an unchanged row goes down the metadata-refresh path;
        # that commit must not poison the freshness stamp either.
        out = index.index_many([("0x1000", "f", "def f(): return 1", None)])
        assert out["indexed"] == 1
        assert index.db_changed_since_load() is False


# ---------------------------------------------------------------------------
# finding 5 (low): read_gguf_metadata lets RecursionError escape
# ---------------------------------------------------------------------------

def _write_deep_nested_gguf(path: str, depth: int) -> None:
    """Write a GGUF with one metadata value that is ``depth`` arrays deep."""
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<QQ", 0, 1))  # 0 tensors, 1 metadata entry
        key = b"general.architecture"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 9))  # value_type: array
        for _ in range(depth):
            f.write(struct.pack("<I", 9))  # element_type: array
            f.write(struct.pack("<Q", 1))  # count: 1
        f.write(struct.pack("<I", 0))  # innermost element_type: u8
        f.write(struct.pack("<Q", 1))  # innermost count: 1
        f.write(struct.pack("<B", 42))  # one u8 element


class TestReadGgufMetadataRecursion:
    def test_deeply_nested_array_degrades_to_empty(self, tmp_path):
        gguf = tmp_path / "deep-nested.gguf"
        _write_deep_nested_gguf(str(gguf), depth=500)
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(300)
        try:
            # A pathologically nested GGUF array must degrade to {} (fall back
            # to the default profile), not blow out of embedder/reranker init.
            assert model_profiles.read_gguf_metadata(str(gguf)) == {}
        finally:
            sys.setrecursionlimit(old_limit)

    def test_flat_gguf_still_reads(self, tmp_path):
        gguf = tmp_path / "flat.gguf"
        _write_deep_nested_gguf(str(gguf), depth=0)
        metadata = model_profiles.read_gguf_metadata(str(gguf))
        assert metadata.get("gguf.version") == 3
        assert "general.architecture" in metadata
        assert metadata["general.architecture"] == [42]
