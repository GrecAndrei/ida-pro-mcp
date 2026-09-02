"""Cross-mode coverage for the durable blackboard storage core."""

from __future__ import annotations

import builtins
import json
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.stores import blackboard_store as module
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def test_path_and_scalar_helpers_cover_host_and_ida_resolution(monkeypatch, tmp_path):
    assert module._resolve_db_path("  /tmp/blackboard.db  ") == "/tmp/blackboard.db"
    with pytest.raises(ValueError, match="db_path is required"):
        module._resolve_db_path("  ")

    monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(get_idb_path=lambda: "/tmp/sample.i64"))
    assert module._resolve_db_path() == "/tmp/sample.i64.blackboard.db"

    monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(get_idb_path=lambda: ""))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("IDA_MCP_CACHE_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_DATA_DIR", raising=False)
    resolved = module._resolve_db_path()
    assert resolved == str(tmp_path / "state" / "ida-pro-mcp" / "blackboard.db")

    def no_directories(*_args, **_kwargs):
        raise OSError("read-only state")

    monkeypatch.setattr(module.os, "makedirs", no_directories)
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "unwritable"))
    assert module._resolve_db_path() == str(tmp_path / "unwritable" / "blackboard.db")

    assert module.normalize_addr(None) == ""
    assert module.normalize_addr(0x401000) == "0x401000"
    assert module.normalize_addr(" 0X0000401000 ") == "0x401000"
    assert module.normalize_addr("plain") == "plain"
    assert module.normalize_addr(" ") == ""
    assert module.code_digest("") == ""
    assert module._jaccard("", "words") == 0.0
    assert module._clamp01("bad", default=0.7) == 0.7


def test_embedder_import_fallbacks_and_protocols(monkeypatch, tmp_path):
    original_import = builtins.__import__

    def fallback_import(name, *args, **kwargs):
        if name == "ida_pro_mcp.host.intelligence.core":
            raise ImportError("host package unavailable")
        if name == "host.intelligence.core":
            return SimpleNamespace(BgeCodeEmbedder=lambda: "fallback")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fallback_import)
    assert module._get_embedder() == "fallback"

    def no_embedder_import(name, *args, **kwargs):
        if name in {"ida_pro_mcp.host.intelligence.core", "host.intelligence.core"}:
            raise ImportError("no embedder")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_embedder_import)
    assert module._get_embedder() is None

    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")

    class CallableIdentity:
        backend = staticmethod(lambda: "local")
        embedding_format = staticmethod(lambda: "document-v2")
        _model_path = model

    identity = BlackboardStore._embedding_identity(CallableIdentity(), 2)
    assert identity.startswith("local|document-v2|model:") and identity.endswith("|2")
    assert BlackboardStore._embedding_identity(SimpleNamespace(model_path=tmp_path / "missing")) == "unknown|model:" + str(tmp_path / "missing")
    assert BlackboardStore._embedding_text("title", "body", tags="bad", evidence=[{"source": "ida"}]).endswith("evidence: ida")

    store = BlackboardStore(str(tmp_path / "workspace.db"))
    store._get_embedder = lambda: None
    assert store._embed_text("none") is None

    class VectorEmbedder:
        def embed_document_vector(self, _text):
            return [1.0, 0.0]

    store._get_embedder = VectorEmbedder
    assert module.unpack_floats(store._embed_text("vector")) == [1.0, 0.0]

    class DocumentEmbedder:
        def embed_document(self, text):
            return SimpleNamespace(vector=[float(len(text)), 1.0])

    store._get_embedder = DocumentEmbedder
    assert module.unpack_floats(store._embed_text("document"))[1] == 1.0

    class RawDocumentEmbedder:
        def embed_document(self, _text):
            return [0.25, 0.75]

    store._get_embedder = RawDocumentEmbedder
    assert module.unpack_floats(store._embed_text("raw")) == [0.25, 0.75]

    class PurposeEmbedder:
        def embed_vector(self, _text, *, purpose):
            assert purpose == "document"
            return [0.5, 0.5]

    store._get_embedder = PurposeEmbedder
    assert module.unpack_floats(store._embed_text("purpose")) == [0.5, 0.5]

    class LegacyEmbedder:
        def embed_vector(self, _text):
            return [0.4, 0.6]

    store._get_embedder = LegacyEmbedder
    assert module.unpack_floats(store._embed_text("legacy")) == pytest.approx([0.4, 0.6])

    class BrokenEmbedder:
        def embed_vector(self, *_args, **_kwargs):
            raise RuntimeError("model stopped")

    store._get_embedder = BrokenEmbedder
    assert store._embed_text("broken") is None
    store.embed_enqueue = lambda *_args: (_ for _ in ()).throw(RuntimeError("queue stopped"))
    store._enqueue_embedding("entry", "text")


def _legacy_connection():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    module._migrate_0001_initial_schema(conn)
    conn.execute(
        """
        CREATE TABLE blackboard (
            id TEXT, kind TEXT, status TEXT, category TEXT, title TEXT, content TEXT,
            addr TEXT, addr_end TEXT, tags, confidence REAL, priority REAL, q_value REAL,
            source TEXT, source_type TEXT, evidence, fingerprint TEXT, ioc_type TEXT,
            ioc_value TEXT, depends_on TEXT, blocks_addr TEXT, register TEXT, reg_type TEXT,
            entropy REAL, xref_count INTEGER, calibrated INTEGER, verdict TEXT,
            anchor_kind TEXT, anchor_digest TEXT, stale INTEGER, stale_reason TEXT,
            contradiction_reason TEXT, version INTEGER, created_at REAL, updated_at REAL,
            decayed_at REAL, published_at REAL, published_symbol TEXT, resolved INTEGER,
            contradicted INTEGER, conflicts_with TEXT, vector BLOB
        )
        """
    )
    return conn


def test_legacy_rows_migrate_all_compatibility_shapes():
    conn = _legacy_connection()
    conn.execute("INSERT INTO blackboard (id) VALUES ('')")
    conn.execute(
        """
        INSERT INTO blackboard
            (id, kind, status, category, title, content, addr, tags, confidence,
             source, evidence, contradiction_reason, resolved, conflicts_with, vector,
             created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("legacy-a", "unknown", "invalid", "general", "A", "body", "0x1", 7, 0.8,
         "legacy", 3, "old reason", 1, "not-json", b"abcd", 1.0, 2.0),
    )
    conn.execute(
        """
        INSERT INTO blackboard
            (id, kind, status, category, title, content, addr, tags, evidence,
             confidence, source, contradicted, conflicts_with, vector, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("legacy-b", "finding", "open", "general", "B", "body", "0x2", '["tag"]', '[{"x": 1}]',
         0.4, "legacy", 1, '["legacy-a", "", "legacy-b"]', b"efgh", 1.0, 2.0),
    )
    module._migrate_legacy_blackboard(conn)
    first = dict(conn.execute("SELECT * FROM findings WHERE id='legacy-a'").fetchone())
    second = dict(conn.execute("SELECT * FROM findings WHERE id='legacy-b'").fetchone())
    assert first["status"] == "resolved" and first["kind"] == "finding"
    assert second["status"] == "rejected"
    assert conn.execute("SELECT COUNT(*) FROM links WHERE entry_a='legacy-b'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM findings_embeddings").fetchone()[0] == 2

    empty = _legacy_connection()
    module._migrate_legacy_blackboard(empty)
    assert empty.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_old_embedding_schema_and_failed_migration_are_retriable(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE findings_embeddings (entry_id TEXT PRIMARY KEY, vector BLOB NOT NULL, model TEXT, created_at REAL, updated_at REAL)"
    )
    conn.execute("INSERT INTO findings_embeddings VALUES ('e', ?, '', 1, 1)", (b"12345678",))
    module._migrate_0003_embedding_metadata(conn)
    assert conn.execute("SELECT embedding_dim FROM findings_embeddings WHERE entry_id='e'").fetchone()[0] == 2
    module._migrate_0003_embedding_metadata(conn)

    failing = sqlite3.connect(":memory:")
    failing.isolation_level = None
    original = module._MIGRATIONS

    def fail(_conn):
        raise RuntimeError("migration interrupted")

    monkeypatch.setattr(module, "_MIGRATIONS", {1: fail})
    with pytest.raises(RuntimeError, match="interrupted"):
        module._migrate(failing)
    assert failing.execute("PRAGMA user_version").fetchone()[0] == 0
    monkeypatch.setattr(module, "_MIGRATIONS", original)


def test_store_fallback_connection_and_staleness_lifecycle(monkeypatch, tmp_path):
    calls = []
    real_init = BlackboardStore._init_db

    def fail_once(self):
        if not calls:
            calls.append("failed")
            raise OSError("primary unavailable")
        calls.append("fallback")

    monkeypatch.setattr(BlackboardStore, "_init_db", fail_once)
    fallback_root = tmp_path / "fallback"
    monkeypatch.setattr("ida_pro_mcp.host.config.CACHE_DIR", str(fallback_root))
    store = BlackboardStore(str(tmp_path / "primary" / "workspace.db"))
    assert calls == ["failed", "fallback"]
    assert store.db_path.startswith(str(fallback_root / "fallback_indexes"))

    monkeypatch.setattr(BlackboardStore, "_init_db", real_init)
    real = BlackboardStore(str(tmp_path / "real.db"))
    assert real.current_anchor("") is None
    assert real.observe_code("", "decompile", "body")["ok"] is False
    assert real.observe_code("0x1", "other", "body")["ok"] is False
    assert real.observe_code("0x1", "decompile", "")["ok"] is False
    first = real.observe_code("0X0001", "decompile", "int f() { return 1; }")
    assert first["changed"] is False
    assert real.observe_code("0x1", "decompile", "int f() { return 1; }")["changed"] is False
    entry = real.write("anchored", addr="0x1")
    changed = real.observe_code("0x1", "decompile", "int f() { return 2; }")
    assert changed["stale_marked"] == 1
    assert real.stale_entries()[0]["id"] == entry
    assert real.clear_stale("missing") is False
    assert real.clear_stale(entry) is True
    assert real.read(entry)["stale"] == 0


def test_blackboard_brief_and_maintenance_modes(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    assert "Workspace is empty" in store.workspace_brief()["brief"]
    store.record_examination("0x1000", verdict="boring", note="library wrapper")
    question = store.write("Blocked question", category="analysis", addr="0x1001", kind="question")
    store.update(question, depends_on="0x1002")
    confirmed = store.write("Confirmed IOC", category="ioc", addr="0x1003", status="confirmed", ioc_type="domain", ioc_value="example.test")
    store.write("Open vulnerability", category="vuln", addr="0x1004", ioc_type="", status="open")
    store.update(confirmed, stale=1, stale_reason="changed")
    brief = store.workspace_brief(limit=3)
    assert brief["counts"]["examined"] == 1
    assert "blocked on 0x1002" in brief["brief"]
    summary = store.campaign_summary()
    assert summary["iocs"][0]["ioc_value"] == "example.test"
    assert summary["vulns"][0]["title"] == "Open vulnerability"
    assert store.recall([])["addresses"] == []
    recalled = store.recall(["0X1001", "0x1001", "0x1000"], include_open_threads=False, limit=1)
    assert recalled["addresses"] == ["0x1001", "0x1000"]
    assert recalled["open_threads"] == []
    assert any("already examined" in line for line in store.recall_lines(["0x1000"]))

    assert store.list(addr="0x1003", include_contradicted=True)
    assert store.list(stale_only=True)[0]["id"] == confirmed
    assert store.delete(confirmed) is True
    assert store.clear("vuln") == 1
    assert store.clear() == 2
