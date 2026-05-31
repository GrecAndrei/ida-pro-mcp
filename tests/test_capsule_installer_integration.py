from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.installer.main import UI, parse_args, run_install


def test_installer_capsule_success_writes_records(tmp_path, monkeypatch):
    install_root = tmp_path / "install-root"
    capsule_path = tmp_path / "install.sideband"

    monkeypatch.setattr(
        "ida_pro_mcp.installer.main.setup_runtime_environment",
        lambda **kwargs: install_root / ".venv" / "bin" / "python",
    )
    monkeypatch.setattr(
        "ida_pro_mcp.installer.main.configure_clients",
        lambda **kwargs: ["OpenCode", "Gemini CLI"],
    )
    monkeypatch.setattr("ida_pro_mcp.installer.main.install_ida_plugin", lambda **kwargs: None)
    monkeypatch.setattr("ida_pro_mcp.installer.main.install_codex_skills", lambda *a, **k: None)
    monkeypatch.setattr("ida_pro_mcp.installer.main.detect_ida_install_dir", lambda: Path("/opt/ida"))

    opts = parse_args(
        [
            "--yes",
            "--no-interactive",
            "--capsule",
            str(capsule_path),
            "--install-root",
            str(install_root),
        ]
    )
    rc = run_install(opts, UI())
    assert rc == 0
    assert capsule_path.exists()

    with CapsuleStore.open(capsule_path) as capsule:
        summary = capsule.inspect_summary()
        reports = capsule.conn.execute("SELECT COUNT(*) AS c FROM install_reports").fetchone()["c"]
        backends = capsule.conn.execute("SELECT COUNT(*) AS c FROM backend_profiles").fetchone()["c"]
        clients = capsule.conn.execute("SELECT COUNT(*) AS c FROM client_profiles").fetchone()["c"]
        events = capsule.conn.execute(
            "SELECT COUNT(*) AS c FROM audit_events WHERE event_type='installer_completed'"
        ).fetchone()["c"]

    assert summary["project_name"] == "install-root"
    assert reports == 1
    assert backends == 1
    assert clients == 2
    assert events == 1


def test_installer_capsule_dry_run_does_not_write_capsule(tmp_path, monkeypatch):
    install_root = tmp_path / "install-root"
    capsule_path = tmp_path / "dryrun.sideband"

    monkeypatch.setattr(
        "ida_pro_mcp.installer.main.setup_runtime_environment",
        lambda **kwargs: install_root / ".venv" / "bin" / "python",
    )
    monkeypatch.setattr(
        "ida_pro_mcp.installer.main.configure_clients",
        lambda **kwargs: ["OpenCode"],
    )
    monkeypatch.setattr("ida_pro_mcp.installer.main.install_ida_plugin", lambda **kwargs: None)
    monkeypatch.setattr("ida_pro_mcp.installer.main.install_codex_skills", lambda *a, **k: None)

    opts = parse_args(
        [
            "--yes",
            "--no-interactive",
            "--dry-run",
            "--capsule",
            str(capsule_path),
            "--install-root",
            str(install_root),
        ]
    )
    rc = run_install(opts, UI())
    assert rc == 0
    assert not capsule_path.exists()


def test_installer_capsule_failure_writes_failed_audit_event(tmp_path, monkeypatch):
    install_root = tmp_path / "install-root"
    capsule_path = tmp_path / "failed.sideband"

    def _boom(**kwargs):
        raise RuntimeError("runtime setup failed")

    monkeypatch.setattr("ida_pro_mcp.installer.main.setup_runtime_environment", _boom)

    opts = parse_args(
        [
            "--yes",
            "--no-interactive",
            "--capsule",
            str(capsule_path),
            "--install-root",
            str(install_root),
        ]
    )
    rc = run_install(opts, UI())
    assert rc == 1
    assert capsule_path.exists()

    with CapsuleStore.open(capsule_path) as capsule:
        events = capsule.conn.execute(
            "SELECT COUNT(*) AS c FROM audit_events WHERE event_type='installer_failed'"
        ).fetchone()["c"]
    assert events == 1
