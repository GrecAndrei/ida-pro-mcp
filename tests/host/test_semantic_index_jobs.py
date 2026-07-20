from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.batch_manager import BatchManager
from ida_pro_mcp.host.server.server_batch import BackgroundMixin


class _SessionManager:
    def __init__(self, sessions):
        self.sessions = list(sessions)

    def discover_sessions(self):
        return list(self.sessions)


class _IndexHarness(BackgroundMixin):
    def __init__(self, sessions, responses=None):
        self.session_mgr = _SessionManager(sessions)
        self._batch_mgr = BatchManager(max_workers=2)
        self.responses = list(responses or [])
        self.calls = []
        self.metadata = []

    def _resolve_session_from_idb_ref(self, ref):
        return next(
            (
                session
                for session in self.session_mgr.sessions
                if ref in {session.session_id, session.idb_path, session.binary_path}
            ),
            None,
        )

    def call_tool(self, tool, idb_path, **args):
        self.calls.append((tool, idb_path, args))
        return self.responses.pop(0)

    def _update_session_indexing_metadata(self, session_id, **updates):
        self.metadata.append((session_id, updates))


def _session(tmp_path: Path, sid: str, binary_name: str = "sample.bin"):
    binary = tmp_path / f"{sid}-{binary_name}"
    binary.write_bytes(b"same binary content")
    idb = tmp_path / f"SID_{sid}_{binary_name}.i64"
    idb.write_bytes(b"idb")
    return SimpleNamespace(
        session_id=sid,
        binary_path=str(binary),
        idb_path=str(idb),
        analysis_options={},
    )


def test_background_index_runs_every_slice_without_blocking_submission(tmp_path):
    session = _session(tmp_path, "AAAAAAAA")
    responses = [
        {
            "ok": True,
            "indexed": 2,
            "attempted": 2,
            "failed": 0,
            "eligible": 5,
            "complete": False,
            "next_cursor": "0x20",
            "index": {"size": 2},
        },
        {
            "ok": True,
            "indexed": 2,
            "attempted": 2,
            "failed": 0,
            "eligible": 5,
            "complete": False,
            "next_cursor": "0x40",
            "index": {"size": 4},
        },
        {
            "ok": True,
            "indexed": 1,
            "attempted": 1,
            "failed": 0,
            "eligible": 5,
            "complete": True,
            "next_cursor": None,
            "index": {"size": 5},
        },
    ]
    harness = _IndexHarness([session], responses)
    submitted = harness._submit_semantic_index(
        {
            "action": "index_fast",
            "mode": "full",
            "_background": True,
            "_index_slice_size": 2,
            "start": "0x1000",
            "end": "0x5000",
        },
        session.session_id,
    )

    assert submitted["background"] is True
    assert submitted["slice_size"] == 2
    result = harness._batch_manager.wait(submitted["task_id"], timeout=5)
    harness._batch_manager.shutdown()

    assert result["state"] == "done"
    assert result["result"]["complete"] is True
    assert result["result"]["indexed"] == 5
    assert len(harness.calls) == 3
    assert [call[2].get("start_after") for call in harness.calls] == [None, "0x20", "0x40"]
    assert all(call[2]["index_limit"] == 2 for call in harness.calls)
    assert all(call[2]["start"] == "0x1000" and call[2]["end"] == "0x5000" for call in harness.calls)


def test_matching_binary_seeds_an_independent_session_index(tmp_path):
    source = _session(tmp_path, "AAAAAAAA")
    target = _session(tmp_path, "BBBBBBBB")
    Path(target.binary_path).write_bytes(Path(source.binary_path).read_bytes())
    source_db = f"{source.idb_path}.embeddings.db"
    with sqlite3.connect(source_db) as conn:
        conn.execute("CREATE TABLE embedding_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE func_embeddings(ea TEXT PRIMARY KEY, name TEXT, vec_blob BLOB, index_quality TEXT)"
        )
        conn.execute(
            "INSERT INTO func_embeddings(ea, name, vec_blob, index_quality) VALUES(?, ?, ?, ?)",
            ("0x1000", "decode", b"vector", "full"),
        )
        conn.execute("INSERT INTO embedding_meta(key, value) VALUES('source_idb_path', ?)", (source.idb_path,))
        conn.commit()

    harness = _IndexHarness([source, target])
    reused = harness._seed_index_from_matching_binary(target)
    harness._batch_manager.shutdown()

    assert reused["reused"] is True
    assert reused["from_session"] == source.session_id
    target_db = f"{target.idb_path}.embeddings.db"
    assert target_db != source_db
    with sqlite3.connect(target_db) as conn:
        assert conn.execute("SELECT ea, name FROM func_embeddings").fetchall() == [("0x1000", "decode")]
        metadata = dict(conn.execute("SELECT key, value FROM embedding_meta"))
    assert metadata["source_idb_path"] == target.idb_path
    assert metadata["source_binary_sha256"] == reused["binary_sha256"]


def test_matching_binary_rejects_conflicting_load_addresses(tmp_path):
    source = _session(tmp_path, "AAAAAAAA")
    target = _session(tmp_path, "BBBBBBBB")
    source.analysis_options = {"base_address": "0x1000"}
    target.analysis_options = {"base_address": "0x8000"}
    source_db = f"{source.idb_path}.embeddings.db"
    with sqlite3.connect(source_db) as conn:
        conn.execute("CREATE TABLE embedding_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE func_embeddings(ea TEXT PRIMARY KEY, vec_blob BLOB)")
        conn.execute("INSERT INTO func_embeddings(ea, vec_blob) VALUES('0x1000', X'00')")
        conn.commit()

    harness = _IndexHarness([source, target])
    reused = harness._seed_index_from_matching_binary(target)
    harness._batch_manager.shutdown()

    assert reused["reused"] is False
    assert reused["reason"] == "no_compatible_index"
