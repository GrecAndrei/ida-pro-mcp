from __future__ import annotations

import json

from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.capsule.cli import main


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
