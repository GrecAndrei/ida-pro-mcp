"""Deep offline coverage for semantic-index retrieval modes."""

from __future__ import annotations

import sqlite3
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.intelligence import core
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


def _session(tmp_path):
    binary = tmp_path / "sample.bin"
    idb = tmp_path / "sample.i64"
    binary.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    return SimpleNamespace(
        session_id="SEMANTIC99",
        binary_path=str(binary),
        idb_path=str(idb),
    )


GADGETS = {
    "gadgets": [
        {"addr": "0x10", "insns": 2, "gadget": "pop rdi ; ret"},
        {"addr": "0x20", "insns": 3, "gadget": "mov rax, rbx ; ret"},
    ]
}


def _ready_host(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    session = _session(tmp_path)
    host.current_session = session
    host._resolve_session_from_idb_ref = lambda _ref: session
    host._ensure_client_owns_session = lambda _session: None
    host.call_tool = lambda *_args, **_kwargs: GADGETS
    monkeypatch.setattr(semantic, "EMBEDDING_FIRST_MODE", True)
    semantic._GADGET_VEC_CACHE.clear()
    return host, session


def test_embedding_first_warms_persisted_vectors_and_embeds_only_cold_rows(
    tmp_path, monkeypatch
):
    host, session = _ready_host(tmp_path, monkeypatch)
    cached_text = "pop rdi ; ret"
    semantic._GADGET_VEC_CACHE[cached_text] = [1.0, 0.0]

    class Embedder:
        calls: list[str] = []

        def __init__(self):
            self.calls = []

        def embed_vector(self, text):
            self.calls.append(text)
            return [1.0, 0.0] if text == "query" else [0.0, 1.0]

        @staticmethod
        def cosine(left, right):
            return 1.0 if left == right else 0.0

    embedder = Embedder()
    monkeypatch.setattr(core, "BgeCodeEmbedder", lambda: embedder)

    # Build while one vector is already cached, then simulate a process
    # restart. The retrieval call must restore that vector from SQLite and
    # embed only the cold row.
    host._semantic_index_rebuild(session, ["rop"], source_limit=50, max_insns=6)
    semantic._GADGET_VEC_CACHE.clear()

    result = host._handle_gadgets_semantic_find(
        {
            "query": "query",
            "source_actions": ["rop"],
            "source_limit": 50,
            "min_score": 1,
        }
    )

    assert result["ok"] is True
    assert [match["addr"] for match in result["matches"]] == ["0x10"]
    assert embedder.calls == ["query", "mov rax, rbx ; ret"]
    assert semantic._GADGET_VEC_CACHE["mov rax, rbx ; ret"] == [0.0, 1.0]
    db = sqlite3.connect(result["index"]["db_path"])
    try:
        vectors = db.execute("SELECT vector FROM gadgets ORDER BY addr").fetchall()
    finally:
        db.close()
    # Rebuild persists vectors already present in the module cache. The cold
    # row is cached for the running process, but is intentionally not written
    # back synchronously during retrieval.
    assert vectors[0][0]
    assert vectors[1][0] is None


def test_embedding_first_uses_malformed_persisted_vector_as_a_cold_row(
    tmp_path, monkeypatch
):
    host, session = _ready_host(tmp_path, monkeypatch)
    host._semantic_index_rebuild(session, ["rop"], source_limit=50, max_insns=6)
    db_path = host._semantic_index_db_path(session.session_id)
    db = sqlite3.connect(db_path)
    try:
        db.execute("UPDATE gadgets SET vector = ? WHERE addr = ?", (b"bad", "0x10"))
        db.commit()
    finally:
        db.close()

    class Embedder:
        def __init__(self):
            self.calls = []

        def embed_vector(self, text):
            self.calls.append(text)
            return [1.0, 0.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.75

    embedder = Embedder()
    monkeypatch.setattr(core, "BgeCodeEmbedder", lambda: embedder)
    result = host._handle_gadgets_semantic_find(
        {
            "query": "query",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "source_limit": 50,
        }
    )

    assert result["ok"] is True
    assert embedder.calls == ["query", "pop rdi ; ret", "mov rax, rbx ; ret"]
    assert all(match["score"] == 750 for match in result["matches"])


def test_embedding_constructor_failure_falls_back_to_lexical_scoring(tmp_path, monkeypatch):
    host, session = _ready_host(tmp_path, monkeypatch)
    monkeypatch.setattr(
        core,
        "BgeCodeEmbedder",
        lambda: (_ for _ in ()).throw(RuntimeError("model unavailable")),
    )

    result = host._handle_gadgets_semantic_find(
        {
            "query": "pop rdi",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "min_score": 1000,
        }
    )

    assert result["ok"] is True
    assert result["count"] == 0


def test_row_embedding_failure_isolated_from_other_matches(tmp_path, monkeypatch):
    host, session = _ready_host(tmp_path, monkeypatch)

    class Embedder:
        def __init__(self):
            self.calls = []

        def embed_vector(self, text):
            self.calls.append(text)
            if text == "pop rdi ; ret":
                return None
            return [1.0, 0.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.9

    embedder = Embedder()
    monkeypatch.setattr(core, "BgeCodeEmbedder", lambda: embedder)
    result = host._handle_gadgets_semantic_find(
        {"query": "query", "idb": session.session_id, "source_actions": ["rop"]}
    )

    assert result["ok"] is True
    assert [match["addr"] for match in result["matches"]] == ["0x20"]
    assert embedder.calls == ["query", "pop rdi ; ret", "mov rax, rbx ; ret"]


def test_embedding_query_none_uses_lexical_fallback_with_rows(tmp_path, monkeypatch):
    host, session = _ready_host(tmp_path, monkeypatch)

    class Embedder:
        def embed_vector(self, _text):
            return None

    monkeypatch.setattr(core, "BgeCodeEmbedder", Embedder)
    result = host._handle_gadgets_semantic_find(
        {
            "query": "pop rdi",
            "idb": session.session_id,
            "source_actions": ["rop"],
            "min_score": 1000,
        }
    )

    assert result["ok"] is True
    assert result["count"] == 0


def test_embedding_first_handles_an_empty_index(tmp_path, monkeypatch):
    host, session = _ready_host(tmp_path, monkeypatch)
    host.call_tool = lambda *_args, **_kwargs: {"gadgets": []}

    class Embedder:
        def __init__(self):
            self.calls = []

        def embed_vector(self, text):
            self.calls.append(text)
            return [1.0]

        @staticmethod
        def cosine(_left, _right):
            return 1.0

    embedder = Embedder()
    monkeypatch.setattr(core, "BgeCodeEmbedder", lambda: embedder)
    result = host._handle_gadgets_semantic_find(
        {"query": "query", "idb": session.session_id, "source_actions": ["rop"]}
    )

    assert result["ok"] is True
    assert result["count"] == 0
    assert embedder.calls == ["query"]


def test_semantic_find_uses_current_session_when_idb_is_omitted(tmp_path, monkeypatch):
    host, session = _ready_host(tmp_path, monkeypatch)
    monkeypatch.setattr(semantic, "EMBEDDING_FIRST_MODE", False)

    result = host._handle_gadgets_semantic_find(
        {"query": "pop", "source_actions": ["rop"]}
    )

    assert result["ok"] is True
    assert result["count"] == 1
    assert result["matches"][0]["addr"] == "0x10"


def test_unpacked_vector_rejects_non_buffer_objects():
    assert semantic._unpack_vector([1, 2, 3, 4]) is None


@pytest.mark.parametrize("bad_result", [None, {"gadgets": "not-a-list"}])
def test_semantic_rebuild_reports_unusable_source_payload(tmp_path, bad_result):
    host = _Host(tmp_path)
    session = _session(tmp_path)
    host.call_tool = lambda *_args, **_kwargs: bad_result

    result = host._semantic_index_rebuild(session, ["rop"], 50, 6)

    assert result["error"] is True
    assert result["code"] == MCPError.INTERNAL
    assert result["details"]["errors"][0]["action"] == "rop"
