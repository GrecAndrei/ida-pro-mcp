from __future__ import annotations

import json

import pytest

from ida_pro_mcp.capsule import CapsuleStore, CapsuleVerificationError


def test_capsule_init_creates_valid_manifest(tmp_path):
    capsule_path = tmp_path / "project.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="firmware-audit", created_by="ida-pro-mcp")
        manifest = c.get_manifest()
    assert manifest["format"] == "sideband-capsule"
    assert manifest["format_version"] == 0
    assert manifest["schema_version"] == 2
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


def test_capsule_auto_upgrades_schema_v1_to_v2(tmp_path):
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
        assert int(c._get_meta("schema_version") or 0) == 2
