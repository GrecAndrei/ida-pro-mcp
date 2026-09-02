"""Installer behavior coverage for dry-run, selection, and failure modes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ida_pro_mcp.installer import main as installer
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall


def _install(tmp_path, version=(9, 3), *, idat=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    idat_path = tmp_path / "idat64" if idat else None
    if idat_path is not None:
        idat_path.write_text("#!/bin/sh\n", encoding="utf-8")
        idat_path.chmod(0o755)
    return IdaInstall(
        path=tmp_path,
        version=version,
        build="build",
        idat_binary=idat_path,
        arch="x64",
        flavor="pro",
        source="test",
    )


def test_path_hash_and_prompt_edges(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"hello")
    assert installer._absolute_path("$TEST_INSTALLER_PATH").is_absolute() is True
    monkeypatch.setenv("TEST_INSTALLER_PATH", str(source))
    assert installer._absolute_path("$TEST_INSTALLER_PATH") == source
    assert len(installer._sha256_file(str(source))) == 64

    with patch("builtins.input", side_effect=["maybe", "yes"]):
        assert installer._prompt_yes_no("Continue", default=False) is True
    with patch("builtins.input", side_effect=["bad", "2"]):
        assert installer._prompt_choice("Mode", ["one", "two"], "one") == "two"
    with patch("builtins.input", return_value="quoted"):
        assert installer._prompt_text("Name", "default") == "quoted"

    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    with patch("builtins.input", side_effect=[str(tmp_path / "missing"), str(model)]):
        assert installer._prompt_model_path("embedding") == str(model)
    with patch("builtins.input", return_value=""):
        assert installer._prompt_model_path("embedding") == ""


def test_ida_selection_explicit_single_multi_and_missing(tmp_path, monkeypatch):
    ui = installer.UI()
    install_a = _install(tmp_path / "ida-a", (9, 2))
    install_b = _install(tmp_path / "ida-b", (9, 3))
    monkeypatch.setattr(installer, "detect_ida_installs", lambda: [install_a, install_b])
    monkeypatch.setattr(installer, "read_install_state", lambda *_a: install_a)
    assert installer._resolve_ida_install(InstallerOptions(ida_dir=str(install_b.path)), ui).path == install_b.path
    assert installer._resolve_ida_install(InstallerOptions(yes=True), ui) is install_a
    assert installer._resolve_ida_install(InstallerOptions(interactive=False), ui) is install_a
    monkeypatch.setattr(installer, "_is_interactive_terminal", lambda: False)
    assert installer._resolve_ida_install(InstallerOptions(), ui) is install_a

    monkeypatch.setattr(installer, "detect_ida_installs", lambda: [install_b])
    assert installer._resolve_ida_install(InstallerOptions(), ui) is install_b
    monkeypatch.setattr(installer, "detect_ida_installs", list)
    with pytest.raises(RuntimeError, match="no IDA Pro install found"):
        installer._resolve_ida_install(InstallerOptions(), ui)


def test_install_codex_skill_modes_and_safe_link_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    report = InstallReport()
    installer.install_codex_skills(tmp_path, "none", report, dry_run=True)
    assert report.steps[-1]["status"] == "skipped"
    report = InstallReport()
    installer.install_codex_skills(tmp_path, "agent", report, dry_run=True)
    assert report.steps[-1]["status"] == "dry-run"

    source = tmp_path / ".agents" / "skills" / "ida-pro-mcp"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    report = InstallReport()
    installer.install_codex_skills(tmp_path, "agent", report, dry_run=True)
    assert report.steps[-1]["status"] == "dry-run"


def test_bashrc_shim_is_idempotent_and_dry_run(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    report = InstallReport()
    installer.install_bashrc_cli(tmp_path / "install", dry_run=False, report=report)
    first = (home / ".bashrc").read_text(encoding="utf-8")
    installer.install_bashrc_cli(tmp_path / "install", dry_run=False, report=report)
    assert (home / ".bashrc").read_text(encoding="utf-8") == first
    report2 = InstallReport()
    installer.install_bashrc_cli(tmp_path / "other", dry_run=True, report=report2)
    assert report2.modified_files == []


def test_run_install_dry_run_phases_without_ida(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    calls = []
    monkeypatch.setattr(installer, "setup_runtime_environment", lambda **kwargs: calls.append("runtime") or tmp_path / "python")
    monkeypatch.setattr(installer, "resolve_r2_binary", lambda: ("/usr/bin/rz", "rz 1"))
    monkeypatch.setattr(installer, "install_codex_skills", lambda *args: calls.append("skills"))
    monkeypatch.setattr(installer, "install_bashrc_cli", lambda *args, **kwargs: calls.append("shell"))
    opts = InstallerOptions(
        dry_run=True,
        yes=True,
        install_root=tmp_path / "install",
        source_root=source,
        only={"runtime", "skills", "shell"},
        with_r2=False,
        install_cli_shim=True,
        install_claude_skills=False,
    )
    assert installer.run_install(opts, installer.UI()) == 0
    assert calls == ["runtime", "skills", "shell"]
    assert (tmp_path / "install" / "install-report.json").is_file()


def test_run_install_client_gemini_and_sigs_dry_run(tmp_path, monkeypatch):
    ida = _install(tmp_path / "ida")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(installer, "_resolve_ida_install", lambda *_a: ida)
    monkeypatch.setattr(installer, "build_stdio_config", lambda *args, **kwargs: {"command": "python"})
    monkeypatch.setattr(installer, "configure_clients", lambda **kwargs: ["client"])
    monkeypatch.setattr(
        installer,
        "stage_sigs",
        lambda *args, **kwargs: SimpleNamespace(
            count=1, skipped=[], to_dict=lambda: {"count": 1}
        ),
    )
    opts = InstallerOptions(
        dry_run=True,
        yes=True,
        install_root=tmp_path / "install",
        source_root=source,
        only={"clients", "sigs"},
        embed_backend="gemini",
        gemini_access="vertex",
        sigs_dir=str(tmp_path / "sig-source"),
    )
    assert installer.run_install(opts, installer.UI()) == 0


def test_run_install_failure_writes_report_and_rolls_back(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(installer, "setup_runtime_environment", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    rolled_back = []
    monkeypatch.setattr(installer, "rollback_from_backups", lambda report: rolled_back.append(True))
    opts = InstallerOptions(
        install_root=tmp_path / "install",
        source_root=source,
        only={"runtime"},
        rollback_on_fail=True,
    )
    assert installer.run_install(opts, installer.UI()) == 1
    assert rolled_back == [True]
    assert (tmp_path / "install" / "install-report.json").is_file()
    assert (tmp_path / "install" / "install-error.log").is_file()


def test_installer_path_client_and_symlink_helpers_cover_failure_contracts(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    assert installer._normalise_runtime_path(str(model), "model") == str(model.resolve())
    assert installer._normalise_runtime_path(
        "planned.gguf", "model", allow_missing=True
    ).endswith("planned.gguf")
    with pytest.raises(RuntimeError, match="regular file"):
        installer._normalise_runtime_path(str(tmp_path / "missing"), "model")

    binary = tmp_path / "server"
    binary.write_bytes(b"server")
    with pytest.raises(RuntimeError, match="not executable"):
        installer._normalise_runtime_path(str(binary), "server", executable=True)
    monkeypatch.setattr(installer.sys, "platform", "win32")
    with pytest.raises(RuntimeError, match="Windows suffix"):
        installer._normalise_runtime_path(str(model), "server", executable=True)
    monkeypatch.setattr(installer.sys, "platform", "linux")

    monkeypatch.setattr(installer, "get_config_paths", lambda _root: ["one", "two"])
    complete = InstallReport()
    installer._report_client_configuration(
        tmp_path, ["one", "two"], complete, installer.UI(), dry_run=True
    )
    assert complete.steps[-1]["status"] == "dry-run"
    partial = InstallReport()
    installer._report_client_configuration(tmp_path, ["one"], partial, installer.UI())
    assert partial.warnings
    failed = InstallReport()
    failed.metadata["client_update_failures"] = ["one"]
    with pytest.raises(RuntimeError, match="no supported client"):
        installer._report_client_configuration(tmp_path, [], failed, installer.UI())

    source = tmp_path / "source.txt"
    source.write_text("content", encoding="utf-8")
    destination = tmp_path / "destination" / "source.txt"
    mode = installer._replace_with_symlink_or_copy(source, destination)
    assert mode in {"linked", "copied"} and destination.read_text(encoding="utf-8") == "content"
    destination.unlink()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    destination.symlink_to(outside)
    with pytest.raises(RuntimeError, match="symlink"):
        installer._replace_with_symlink_or_copy(source, destination)


def test_installer_reranker_and_idalib_resolution_modes(tmp_path, monkeypatch):
    opts = InstallerOptions(rerank_disabled=True)
    assert installer._resolve_reranker_for_install(
        opts, tmp_path, InstallReport(), installer.UI(), semantic_enabled=True
    ) == ""
    opts = InstallerOptions()
    assert installer._resolve_reranker_for_install(
        opts, tmp_path, InstallReport(), installer.UI(), semantic_enabled=False
    ) == ""

    rerank = tmp_path / "rerank.gguf"
    rerank.write_bytes(b"rerank")
    opts = InstallerOptions(rerank_model_path=str(rerank))
    report = InstallReport()
    assert installer._resolve_reranker_for_install(
        opts, tmp_path, report, installer.UI(), semantic_enabled=True
    ) == str(rerank)
    assert report.metadata["rerank_model"] == str(rerank)

    opts = InstallerOptions(
        dry_run=True,
        download_rerank_model=True,
        accept_model_license=True,
        rerank_profile="qwen3-reranker-0.6b",
    )
    # Keep the dry-run branch deterministic even when the developer machine
    # already has a matching model in a standard download directory.
    monkeypatch.setattr(installer, "find_rerank_model", lambda *_args: "")
    report = InstallReport()
    assert installer._resolve_reranker_for_install(
        opts, tmp_path, report, installer.UI(), semantic_enabled=True
    ) == ""
    assert report.steps[-1]["status"] == "dry-run"

    dry = InstallerOptions(dry_run=True, ida_runtime="idalib")
    report = InstallReport()
    installer._activate_idalib_after_install(dry, None, report, installer.UI())
    assert report.steps[-1]["status"] == "dry-run"
    real = InstallerOptions(ida_runtime="idalib")
    with pytest.raises(RuntimeError, match="no idapro package"):
        installer._activate_idalib_after_install(real, _install(tmp_path / "ida"), InstallReport(), installer.UI())
    monkeypatch.setattr(installer, "find_idalib_python_dir", lambda _path: "/tmp/idalib")
    monkeypatch.setattr(installer, "activate_idalib", lambda _path: (False, "failed"))
    with pytest.raises(RuntimeError, match="activation failed"):
        installer._activate_idalib_after_install(real, _install(tmp_path / "ida2"), InstallReport(), installer.UI())
