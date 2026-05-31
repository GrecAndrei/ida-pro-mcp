from __future__ import annotations

import json
import sqlite3

from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.capsule.cli import main


def _write_idx(path):
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE func_embeddings (
            ea TEXT PRIMARY KEY,
            name TEXT,
            dim INTEGER,
            vec_blob BLOB NOT NULL,
            pseudo_hash TEXT,
            indexed_at REAL
        )
        """
    )
    conn.execute("CREATE TABLE embedding_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO embedding_meta(key, value) VALUES('embedding_backend', 'tfidf-fallback')")
    conn.execute("INSERT INTO embedding_meta(key, value) VALUES('embedding_dim', '1536')")
    conn.execute(
        "INSERT INTO func_embeddings(ea, name, dim, vec_blob, pseudo_hash, indexed_at) VALUES(?,?,?,?,?,?)",
        ("0x401000", "sub_401000", 1536, b"xyz", "ph1", 1.0),
    )
    conn.commit()
    conn.close()


def test_capsule_cli_init_inspect_verify(tmp_path, capsys):
    capsule = tmp_path / "cli.sideband"

    rc = main(["init", str(capsule), "--project-name", "firmware-audit"])
    assert rc == 0
    capsys.readouterr()

    rc = main(["inspect", str(capsule), "--json"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary.get("project_name") == "firmware-audit"

    rc = main(["verify", str(capsule)])
    assert rc == 0


def test_capsule_cli_add_report_and_note_and_export_manifest(tmp_path, capsys):
    capsule = tmp_path / "report.sideband"
    report = tmp_path / "install-report.json"
    report.write_text(json.dumps({"status": "ok", "started_at": "2026-05-31T00:00:00+00:00"}), encoding="utf-8")

    assert main(["init", str(capsule), "--project-name", "capsule-cli"]) == 0
    capsys.readouterr()
    assert main(["add-report", str(capsule), str(report)]) == 0
    capsys.readouterr()
    assert main(["add-note", str(capsule), "--kind", "finding", "--title", "Packet parser", "--body", "bounds issue"]) == 0
    capsys.readouterr()
    assert main(["export-manifest", str(capsule)]) == 0

    manifest = json.loads(capsys.readouterr().out)
    assert manifest.get("format") == "sideband-capsule"


def test_capsule_cli_init_existing_without_force_fails(tmp_path, capsys):
    capsule = tmp_path / "existing.sideband"
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    assert main(["init", str(capsule), "--project-name", "x"]) == 1
    output = capsys.readouterr().out
    assert "already exists" in output


def test_capsule_cli_verify_json_output(tmp_path, capsys):
    capsule = tmp_path / "verify-json.sideband"
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    assert main(["verify", str(capsule), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["checks"]["integrity_check"] == "ok"


def test_capsule_cli_inspect_human_readable(tmp_path, capsys):
    capsule = tmp_path / "human.sideband"
    assert main(["init", str(capsule), "--project-name", "human-project"]) == 0
    capsys.readouterr()
    assert main(["inspect", str(capsule)]) == 0
    output = capsys.readouterr().out
    assert "Capsule:" in output
    assert "Format: sideband-capsule/v0" in output
    assert "Project: human-project" in output


def test_capsule_cli_add_report_invalid_json_fails(tmp_path, capsys):
    capsule = tmp_path / "invalid-report.sideband"
    report = tmp_path / "bad.json"
    report.write_text("not-json", encoding="utf-8")
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    assert main(["add-report", str(capsule), str(report)]) == 1
    output = capsys.readouterr().out
    assert "Error:" in output


def test_capsule_cli_add_note_persists_content(tmp_path, capsys):
    capsule = tmp_path / "note-persist.sideband"
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "add-note",
                str(capsule),
                "--kind",
                "finding",
                "--title",
                "Parser",
                "--body",
                "off-by-one",
            ]
        )
        == 0
    )
    capsys.readouterr()
    with CapsuleStore.open(capsule) as store:
        row = store.conn.execute("SELECT kind, title, body FROM notes").fetchone()
    assert row is not None
    assert row["kind"] == "finding"
    assert row["title"] == "Parser"
    assert row["body"] == "off-by-one"


def test_capsule_cli_semantic_commands(tmp_path, capsys):
    capsule = tmp_path / "semantic-cli.sideband"
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    with CapsuleStore.open(capsule) as store:
        store.add_semantic_index(kind="function", backend="bge-code-v1", dim=1536, index_id="IDX1")
    assert main(["semantic-summary", str(capsule), "--json"]) == 0
    sem = json.loads(capsys.readouterr().out)
    assert sem["semantic_indexes"] == 1
    assert main(["list-indexes", str(capsule), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["id"] == "IDX1"
    assert main(["export-semantic-manifest", str(capsule)]) == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["semantic_summary"]["semantic_indexes"] == 1


def test_capsule_cli_import_export_function_index(tmp_path, capsys):
    capsule = tmp_path / "imp.sideband"
    idx = tmp_path / "sample.embeddings.db"
    out = tmp_path / "out.embeddings.db"
    _write_idx(idx)
    assert main(["init", str(capsule), "--project-name", "x"]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "import-function-index",
                str(capsule),
                str(idx),
                "--mode",
                "with-vectors",
                "--index-id",
                "IDX1",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["imported_items"] == 1
    assert payload["imported_vectors"] == 1
    assert main(["export-function-index", str(capsule), "--index-id", "IDX1", "--out", str(out), "--mode", "with-vectors"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exported_items"] == 1
    conn = sqlite3.connect(str(out))
    row = conn.execute("SELECT COUNT(*) FROM func_embeddings").fetchone()
    assert row is not None and row[0] == 1
    conn.close()


def test_capsule_cli_export_analysis(tmp_path, capsys):
    capsule = tmp_path / "analysis-src.sideband"
    out = tmp_path / "analysis-only.sideband"

    assert main(["init", str(capsule), "--project-name", "analysis-cli"]) == 0
    capsys.readouterr()

    with CapsuleStore.open(capsule) as c:
        idx = c.add_semantic_index(kind="function", backend="tfidf-fallback", dim=2, index_id="IDXA")
        vec = c.store_semantic_vector(b"\x00\x00\x80?\x00\x00\x00@", dim=2)
        c.upsert_semantic_item(
            index_id=idx,
            kind="function",
            stable_ref="0x401000",
            title="sub_401000",
            text_hash="h",
            vector_sha256=vec,
            metadata={"name": "sub_401000"},
        )
        c.store_blob(b"raw-binary", kind="binary")

    assert (
        main(
            [
                "export-analysis",
                str(capsule),
                "--out",
                str(out),
                "--metadata-only",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True

    with CapsuleStore.open(out) as dst:
        summary = dst.inspect_summary()
        assert summary["objects"] == 0
        assert summary["semantic_vectors"] == 0
