"""Composed offline coverage for semantic gadget indexing boundaries."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_semantic as semantic
from ida_pro_mcp.host.server.server_semantic import ServerSemanticMixin


class _Host(ServerSemanticMixin):
    def __init__(self, tmp_path):
        self._semantic_index_lock = threading.RLock()
        (tmp_path / "artifacts").mkdir()
        self.session_mgr = SimpleNamespace(
            get_session_artifact_dir=lambda _sid, create=True: str(tmp_path / "artifacts")
        )
        self.current_session = None
        self.sessions = {}


def _session(tmp_path, sid="ABC12345"):
    binary = tmp_path / f"{sid}.bin"
    idb = tmp_path / f"{sid}.i64"
    binary.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    return SimpleNamespace(
        session_id=sid,
        binary_path=str(binary),
        idb_path=str(idb),
        analysis_options={"processor": "x86", "bitness": 64},
    )


def test_semantic_helpers_validate_vectors_payloads_and_fingerprints(tmp_path):
    host = _Host(tmp_path)
    assert semantic._pack_vector([]) is None
    assert semantic._pack_vector(["not-a-number"]) is None
    packed = semantic._pack_vector([1, 2.5])
    assert semantic._unpack_vector(packed) == pytest.approx([1, 2.5])
    assert semantic._unpack_vector(b"x") is None
    assert semantic._unpack_vector(b"") is None
    assert host._semantic_extract_gadget_rows(None) == []
    assert host._semantic_extract_gadget_rows({"gadgets": "bad"}) == []
    rows = host._semantic_extract_gadget_rows(
        {"gadgets": [None, {}, {"addr": "", "gadget": "ret"},
                     {"addr": "0x1", "gadget": " pop rax ; ret ", "insns": "bad"}]}
    )
    assert rows == [("0x1", 0, "pop rax ; ret")]
    session = _session(tmp_path)
    first = host._semantic_index_fingerprint(session)
    session.binary_path = str(tmp_path / "missing.bin")
    second = host._semantic_index_fingerprint(session)
    assert first != second


def test_semantic_schema_meta_and_rebuild_mixed_source_modes(tmp_path):
    host = _Host(tmp_path)
    session = _session(tmp_path)
    valid = {"ok": True, "gadgets": [{"addr": "0x10", "insns": 2, "gadget": "pop rdi ; ret"}]}
    calls = []

    def call_tool(_tool, _idb, *, action, **_kwargs):
        calls.append(action)
        if action == "bad_source":
            return make_error(MCPError.INTERNAL, "source failed")
        if action == "empty_source":
            return {"ok": True}
        return valid

    host.call_tool = call_tool
    result = host._semantic_index_rebuild(
        session, ["rop", "bad_source", "empty_source"], source_limit=50, max_insns=4
    )
    assert result["ok"] is True
    assert result["rows_indexed"] == 1
    assert calls == ["rop", "bad_source", "empty_source"]
    db = sqlite3.connect(result["db_path"])
    try:
        assert host._semantic_index_meta(db)["source_actions"] == "rop,bad_source,empty_source"
        host._semantic_index_put_meta(db, {"version": 1})
        db.commit()
    finally:
        db.close()

    host.call_tool = lambda *_args, **_kwargs: make_error(MCPError.INTERNAL, "all failed")
    failed = host._semantic_index_rebuild(session, ["rop"], source_limit=50, max_insns=4)
    assert failed["error"] is True and failed["code"] == MCPError.INTERNAL


def test_semantic_find_validation_session_and_embedding_fallback_modes(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    assert host._handle_gadgets_semantic_find({})["code"] == MCPError.INVALID_ARGS
    assert host._handle_gadgets_semantic_find({"query": "x", "source_actions": ["unsupported"]})["code"] == MCPError.INVALID_ARGS
    host._resolve_session_from_idb_ref = lambda _ref: None
    assert host._handle_gadgets_semantic_find({"query": "x"})["code"] == MCPError.SESSION_REQUIRED

    session = _session(tmp_path)
    host.current_session = session
    host._resolve_session_from_idb_ref = lambda _ref: session
    host._ensure_client_owns_session = lambda _session: make_error(MCPError.FILE_LOCKED, "owned elsewhere")
    locked = host._handle_gadgets_semantic_find({"query": "x", "idb": session.session_id})
    assert locked["code"] == MCPError.FILE_LOCKED

    host._ensure_client_owns_session = lambda _session: None
    host.call_tool = lambda *_args, **_kwargs: {"gadgets": []}
    monkeypatch.setattr(semantic, "EMBEDDING_FIRST_MODE", False)
    result = host._handle_gadgets_semantic_find(
        {"query": "ret", "idb": session.session_id, "source_actions": "rop,rop", "limit": "1"}
    )
    assert result["ok"] is True and result["count"] == 0


def test_semantic_legacy_schema_is_readable(tmp_path):
    host = _Host(tmp_path)
    path = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute(
        "CREATE TABLE gadgets (source_action TEXT NOT NULL, addr TEXT NOT NULL, "
        "insns INTEGER NOT NULL, gadget TEXT NOT NULL, norm_text TEXT NOT NULL, "
        "tokens TEXT NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(source_action, addr, digest))"
    )
    conn.commit()
    host._semantic_index_ensure_schema(conn)
    assert "vector" in {row[1] for row in conn.execute("PRAGMA table_info(gadgets)")}
    conn.close()
    assert Path(path).exists()
