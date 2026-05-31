from __future__ import annotations

import json

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
