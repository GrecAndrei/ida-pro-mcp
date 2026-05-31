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
    assert manifest["schema_version"] == 1
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
