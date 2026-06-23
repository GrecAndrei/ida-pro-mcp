from __future__ import annotations

import json
import sqlite3

import pytest

from ida_pro_mcp.capsule import CapsuleStore, CapsuleVerificationError


def _make_embedding_db(path, rows):
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE func_embeddings (
            ea TEXT PRIMARY KEY,
            name TEXT,
            dim INTEGER,
            vec_blob BLOB NOT NULL,
            pseudo_hash TEXT,
            indexed_at REAL,
            source_kind TEXT,
            source_hash TEXT,
            signature_text TEXT,
            signature_hash TEXT
        )
        """
    )
    conn.execute("CREATE TABLE embedding_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.executemany(
        "INSERT INTO embedding_meta(key, value) VALUES(?, ?)",
        [
            ("embedding_backend", "bge-code-v1"),
            ("embedding_dim", "1536"),
            ("model_path", "/tmp/model.gguf"),
            ("source_fingerprint", "srcfp1"),
        ],
    )
    conn.executemany(
        """
        INSERT INTO func_embeddings(ea, name, dim, vec_blob, pseudo_hash, indexed_at, source_kind, source_hash, signature_text, signature_hash)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()


def test_capsule_init_creates_valid_manifest(tmp_path):
    capsule_path = tmp_path / "project.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="firmware-audit", created_by="ida-pro-mcp")
        manifest = c.get_manifest()
    assert manifest["format"] == "sideband-capsule"
    assert manifest["format_version"] == 0
    assert manifest["schema_version"] == 3
    assert manifest["project_name"] == "firmware-audit"
    assert manifest["trust"]["contains_executable_payloads"] is False


def test_capsule_inspect_json(tmp_path):
    capsule_path = tmp_path / "inspect.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="inspect-test")
        summary = c.inspect_summary()
    assert summary["project_name"] == "inspect-test"
    assert summary["format"] == "sideband-capsule/v0"


def test_capsule_verify_passes_for_new_capsule(tmp_path):
    capsule_path = tmp_path / "verify.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="verify-test")
        result = c.verify()
    assert result["ok"] is True


def test_capsule_add_install_report(tmp_path):
    capsule_path = tmp_path / "report.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="report-test")
        rid = c.add_install_report({"status": "ok", "started_at": "2026-01-01T00:00:00+00:00"})
        row = c.conn.execute("SELECT id, status FROM install_reports WHERE id=?", (rid,)).fetchone()
    assert row is not None
    assert row["status"] == "ok"


def test_capsule_add_audit_event(tmp_path):
    capsule_path = tmp_path / "audit.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="audit-test")
        eid = c.add_audit_event("policy_decision", {"decision": "allow"}, session_id="SID_1")
        row = c.conn.execute("SELECT event_type, session_id FROM audit_events WHERE id=?", (eid,)).fetchone()
    assert row is not None
    assert row["event_type"] == "policy_decision"
    assert row["session_id"] == "SID_1"


def test_capsule_add_note(tmp_path):
    capsule_path = tmp_path / "note.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="note-test")
        nid = c.add_note(kind="finding", title="Packet parser", body="Bounds check missing")
        row = c.conn.execute("SELECT kind, title, body FROM notes WHERE id=?", (nid,)).fetchone()
    assert row is not None
    assert row["kind"] == "finding"
    assert row["title"] == "Packet parser"


def test_capsule_rejects_invalid_manifest_format(tmp_path):
    capsule_path = tmp_path / "invalid.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="invalid-test")
        manifest = c.get_manifest()
        manifest["format"] = "wrong-format"
        c.update_manifest(manifest)
        with pytest.raises(CapsuleVerificationError):
            c.verify()


def test_capsule_blob_hash_roundtrip(tmp_path):
    capsule_path = tmp_path / "blob.sideband"
    payload = b"capsule-blob-payload"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="blob-test")
        sha = c.store_blob(payload, kind="artifact", media_type="application/octet-stream")
        restored = c.get_blob(sha)
    assert restored == payload


def test_capsule_verify_sets_last_verified_timestamp(tmp_path):
    capsule_path = tmp_path / "verified.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="verified-test")
        c.verify()
        manifest = c.get_manifest()
    assert manifest["trust"]["last_verified_at"] is not None


def test_capsule_rejects_invalid_trust_state(tmp_path):
    capsule_path = tmp_path / "invalid-trust.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="invalid-trust")
        manifest = c.get_manifest()
        manifest["trust"]["state"] = "definitely-not-valid"
        c.update_manifest(manifest)
        with pytest.raises(CapsuleVerificationError):
            c.verify()


def test_capsule_upsert_session_updates_existing_state(tmp_path):
    capsule_path = tmp_path / "sessions.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="sessions")
        c.upsert_session("SID_1", {"phase": "triage"})
        c.upsert_session("SID_1", {"phase": "deep-dive"})
        row = c.conn.execute("SELECT state_json FROM sessions WHERE session_id=?", ("SID_1",)).fetchone()
    assert row is not None
    assert json.loads(row["state_json"]) == {"phase": "deep-dive"}


def test_capsule_upsert_profiles_roundtrip(tmp_path):
    capsule_path = tmp_path / "profiles.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="profiles")
        c.upsert_backend_profile("ida-primary", "ida", {"status": "primary"})
        c.upsert_client_profile("OpenCode", "mcp-client", {"configured": True})
        backend = c.conn.execute("SELECT kind, config_json FROM backend_profiles WHERE name='ida-primary'").fetchone()
        client = c.conn.execute("SELECT kind, config_json FROM client_profiles WHERE name='OpenCode'").fetchone()
    assert backend is not None
    assert backend["kind"] == "ida"
    assert json.loads(backend["config_json"]) == {"status": "primary"}
    assert client is not None
    assert client["kind"] == "mcp-client"
    assert json.loads(client["config_json"]) == {"configured": True}


def test_capsule_add_install_report_accepts_custom_id(tmp_path):
    capsule_path = tmp_path / "report-id.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="report-id")
        rid = c.add_install_report({"status": "ok"}, report_id="REPORT_1")
        row = c.conn.execute("SELECT id FROM install_reports WHERE id='REPORT_1'").fetchone()
    assert rid == "REPORT_1"
    assert row is not None


def test_capsule_summary_counts_reflect_written_rows(tmp_path):
    capsule_path = tmp_path / "counts.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="counts")
        c.upsert_session("SID_A", {"x": 1})
        c.add_audit_event("installer_completed", {"ok": True})
        c.store_blob(b"abc", kind="artifact")
        summary = c.inspect_summary()
    assert summary["sessions"] == 1
    assert summary["audit_events"] == 1
    assert summary["objects"] == 1
    assert summary["semantic_indexes"] == 0


def test_capsule_add_embedding_state_roundtrip(tmp_path):
    capsule_path = tmp_path / "embedder.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="embedder")
        sid = c.add_embedding_state(
            {
                "backend": "bge-code-v1",
                "model_path": "/tmp/model.gguf",
                "model_hash": "abc123",
                "embedding_dim": 1536,
                "index_metadata": {"db_path_pattern": "<idb_path>.embeddings.db"},
                "anchor_metadata": {"anchor_hash_sha256": "deadbeef"},
                "last_indexed_functions": [],
                "thresholds": {"classification_default": 0.25},
            }
        )
        row = c.conn.execute(
            "SELECT id, backend, embedding_dim, model_hash FROM embedding_states WHERE id=?",
            (sid,),
        ).fetchone()
    assert row is not None
    assert row["backend"] == "bge-code-v1"
    assert row["embedding_dim"] == 1536
    assert row["model_hash"] == "abc123"


def test_capsule_verify_detects_blob_hash_mismatch(tmp_path):
    capsule_path = tmp_path / "tampered-blob.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="tampered")
        sha = c.store_blob(b"good", kind="artifact")
        c.conn.execute("UPDATE blobs SET data=? WHERE sha256=?", (b"evil", sha))
        c.conn.commit()
        with pytest.raises(CapsuleVerificationError):
            c.verify()


def test_capsule_semantic_tables_roundtrip_and_verify(tmp_path):
    capsule_path = tmp_path / "semantic.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="semantic")
        idx = c.add_semantic_index(kind="function", backend="bge-code-v1", dim=1536)
        vec = c.store_semantic_vector(b"abc123", dim=1536)
        item = c.upsert_semantic_item(
            index_id=idx,
            kind="function",
            stable_ref="0x401000",
            title="sub_401000",
            text_hash="thash",
            vector_sha256=vec,
            metadata={"name": "sub_401000"},
        )
        c.add_behavior_hit(item_id=item, behavior="network_http", confidence=0.42, explain=["recv/send"])
        c.add_evidence_card(
            claim="candidate http parser",
            claim_type="behavior_triage",
            confidence=0.42,
            evidence=[{"type": "behavior", "value": "network_http"}],
        )
        sem = c.semantic_summary()
        assert sem["semantic_indexes"] == 1
        assert sem["semantic_items"] == 1
        assert sem["semantic_vectors"] == 1
        assert sem["behavior_hits"] == 1
        assert sem["evidence_cards"] == 1
        assert len(c.list_semantic_indexes()) == 1
        c.verify()


def test_capsule_auto_upgrades_schema_to_v3(tmp_path):
    capsule_path = tmp_path / "migrate.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="migrate")
        c.conn.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
        row = c.conn.execute("SELECT json FROM manifest WHERE id=1").fetchone()
        assert row is not None
        manifest = json.loads(row["json"])
        manifest["schema_version"] = 1
        c.conn.execute("UPDATE manifest SET json=? WHERE id=1", (json.dumps(manifest),))
        c.conn.commit()
        assert int(c.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"]) == 1
        c.inspect_summary()
        assert int(c._get_meta("schema_version") or 0) == 3



def test_capsule_import_export_function_index_metadata_only(tmp_path):
    src_db = tmp_path / "src.embeddings.db"
    _make_embedding_db(
        src_db,
        [
            ("0x401000", "sub_401000", 1536, b"abc", "ph1", 1.0, "function", "sh1", None, "sg1"),
            ("0x402000", "sub_402000", 1536, b"def", "ph2", 2.0, "function", "sh2", None, "sg2"),
        ],
    )
    capsule_path = tmp_path / "cap.sideband"
    out_db = tmp_path / "out.embeddings.db"

    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="idx")
        imp = c.import_function_embedding_index(src_db, mode="metadata-only", index_id="IDX_META", max_items=1)
        assert imp["imported_items"] == 1
        assert imp["imported_vectors"] == 0
        sem = c.semantic_summary()
        assert sem["semantic_indexes"] == 1
        assert sem["semantic_items"] == 1
        assert sem["semantic_vectors"] == 0
        exp = c.export_function_embedding_index(index_id="IDX_META", out_path=out_db, mode="metadata-only")
        assert exp["exported_items"] == 1
        assert exp["exported_vectors"] == 0

    conn = sqlite3.connect(str(out_db))
    row = conn.execute("SELECT COUNT(*) FROM func_embeddings").fetchone()
    assert row[0] == 1
    meta = dict(conn.execute("SELECT key, value FROM embedding_meta").fetchall())
    assert meta["export_mode"] == "metadata-only"
    conn.close()


def test_capsule_import_export_function_index_with_vectors(tmp_path):
    src_db = tmp_path / "src2.embeddings.db"
    _make_embedding_db(
        src_db,
        [
            ("0x500000", "sub_500000", 4, b"\x00\x00\x80?\x00\x00\x00@", "phx", 3.0, "function", "shx", None, "sgx"),
        ],
    )
    capsule_path = tmp_path / "cap2.sideband"
    out_db = tmp_path / "out2.embeddings.db"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="idx2")
        imp = c.import_function_embedding_index(src_db, mode="with-vectors", index_id="IDX_VEC")
        assert imp["imported_items"] == 1
        assert imp["imported_vectors"] == 1
        sem = c.semantic_summary()
        assert sem["semantic_vectors"] == 1
        c.verify()
        exp = c.export_function_embedding_index(index_id="IDX_VEC", out_path=out_db, mode="with-vectors")
        assert exp["exported_items"] == 1
        assert exp["exported_vectors"] == 1
    conn = sqlite3.connect(str(out_db))
    row = conn.execute("SELECT dim, vec_blob FROM func_embeddings WHERE ea='0x500000'").fetchone()
    assert row is not None
    assert row[0] == 4
    assert bytes(row[1]) == b"\x00\x00\x80?\x00\x00\x00@"
    conn.close()


def test_capsule_export_analysis_capsule_metadata_only_excludes_blobs(tmp_path):
    src = tmp_path / "src.sideband"
    out = tmp_path / "analysis-only.sideband"
    with CapsuleStore.open(src) as c:
        c.init(project_name="analysis-export")
        c.upsert_session("SID_1", {"phase": "triage"})
        c.add_note(kind="finding", title="HTTP parser", body="candidate")
        c.add_audit_event("session_create", {"ok": True}, session_id="SID_1")
        c.store_blob(b"raw-bytes", kind="binary_blob")
        idx = c.add_semantic_index(kind="function", backend="bge-code-v1", dim=4, index_id="IDX_EXP")
        vec = c.store_semantic_vector(b"\x00\x00\x80?\x00\x00\x00@", dim=2)
        item = c.upsert_semantic_item(
            index_id=idx,
            kind="function",
            stable_ref="0x401000",
            title="sub_401000",
            text_hash="h1",
            vector_sha256=vec,
            metadata={"name": "sub_401000"},
        )
        c.add_behavior_hit(item_id=item, behavior="network_http", confidence=0.6)
        c.add_evidence_card(claim="http parser candidate", claim_type="behavior_triage", confidence=0.6)

        payload = c.export_analysis_capsule(out_path=out, include_vectors=False, include_notes=True, include_audit=False)
        assert payload["ok"] is True

    with CapsuleStore.open(out) as dst:
        summary = dst.inspect_summary()
        assert summary["objects"] == 0
        assert summary["semantic_indexes"] == 1
        assert summary["semantic_items"] == 1
        assert summary["semantic_vectors"] == 0
        assert summary["audit_events"] == 0
        assert summary["sessions"] == 1
        assert summary["evidence_cards"] == 1
        manifest = dst.get_manifest()
        assert manifest.get("analysis_export", {}).get("mode", {}).get("include_vectors") is False


def test_capsule_export_analysis_capsule_with_vectors_and_audit(tmp_path):
    src = tmp_path / "src2.sideband"
    out = tmp_path / "analysis-with-vectors.sideband"
    with CapsuleStore.open(src) as c:
        c.init(project_name="analysis-export-2")
        c.add_audit_event("session_update", {"ok": True}, session_id="SID_2")
        idx = c.add_semantic_index(kind="function", backend="tfidf-fallback", dim=2, index_id="IDX2")
        vec = c.store_semantic_vector(b"\x00\x00\x80?\x00\x00\x00@", dim=2)
        _ = c.upsert_semantic_item(
            index_id=idx,
            kind="function",
            stable_ref="0x500000",
            title="sub_500000",
            text_hash="h2",
            vector_sha256=vec,
            metadata={"name": "sub_500000"},
        )
        payload = c.export_analysis_capsule(out_path=out, include_vectors=True, include_notes=False, include_audit=True)
        assert payload["ok"] is True

    with CapsuleStore.open(out) as dst:
        summary = dst.inspect_summary()
        assert summary["semantic_vectors"] == 1
        assert summary["audit_events"] == 1


def test_capsule_evidence_source_refs_normalized_backend_neutral(tmp_path):
    capsule_path = tmp_path / "src-ref.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="src-ref")
        cid = c.add_evidence_card(
            claim="candidate parser",
            claim_type="behavior_triage",
            source_refs=[{"kind": "function", "addr": "0x401000", "name": "sub_401000"}],
        )
        row = c.conn.execute("SELECT source_refs_json FROM evidence_cards WHERE id=?", (cid,)).fetchone()
    refs = json.loads(str(row["source_refs_json"]))
    assert refs and refs[0]["backend"] == "ida"
    assert refs[0]["object_kind"] == "function"
    assert refs[0]["stable_ref"] == "0x401000"


def test_capsule_evidence_source_refs_preserve_non_ida_backend(tmp_path):
    capsule_path = tmp_path / "src-ref2.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="src-ref2")
        cid = c.add_evidence_card(
            claim="ghidra object",
            claim_type="behavior_triage",
            source_refs=[
                {
                    "backend": "ghidra",
                    "binary_id": "prog-1",
                    "object_kind": "function",
                    "stable_ref": "FUN_401000",
                    "name": "FUN_401000",
                }
            ],
        )
        row = c.conn.execute("SELECT source_refs_json FROM evidence_cards WHERE id=?", (cid,)).fetchone()
    refs = json.loads(str(row["source_refs_json"]))
    assert refs and refs[0]["backend"] == "ghidra"
    assert refs[0]["binary_id"] == "prog-1"
    assert refs[0]["stable_ref"] == "FUN_401000"


def test_capsule_list_evidence_cards_roundtrip(tmp_path):
    capsule_path = tmp_path / "evidence.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="evidence")
        c.add_evidence_card(claim="http parser", claim_type="behavior_triage", confidence=0.6)
        c.add_evidence_card(claim="crypto", claim_type="behavior_triage", confidence=0.7)
        c.add_evidence_card(claim="flow", claim_type="control_flow", confidence=0.8)
        rows = c.list_evidence_cards(limit=2, claim_type="behavior_triage")
    assert len(rows) == 2
    assert all(r["claim_type"] == "behavior_triage" for r in rows)


def test_capsule_session_auto_resolution(tmp_path):
    import os
    from unittest.mock import MagicMock
    from ida_pro_mcp.services import ServerSessionMixin

    mixin = ServerSessionMixin()
    mixin._session_capsules = {}
    mixin.current_session = MagicMock()
    mixin.current_session.session_id = "ABC12345"
    mixin.current_session.idb_path = str(tmp_path / "firmware.i64")
    mixin.current_session.binary_path = str(tmp_path / "firmware.bin")

    old_env = os.environ.pop("IDA_MCP_CAPSULE", None)

    try:
        resolved = mixin._resolve_session_capsule("ABC12345")
        expected = os.path.abspath(str(tmp_path / "firmware.sideband"))
        assert resolved == expected
        assert os.environ.get("IDA_MCP_CAPSULE") == expected
    finally:
        if old_env is not None:
            os.environ["IDA_MCP_CAPSULE"] = old_env
        else:
            os.environ.pop("IDA_MCP_CAPSULE", None)



