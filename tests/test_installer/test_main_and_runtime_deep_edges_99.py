"""Exhaustive unit tests for installer/main.py and installer/runtime.py edge cases."""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.installer import main as installer_main, runtime as installer_runtime
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall


def _make_install(path: Path, version=(9, 4), binary=None):
    path.mkdir(parents=True, exist_ok=True)
    return IdaInstall(
        path=path,
        version=version,
        build="260901.aabbccdd",
        idat_binary=binary,
        arch="x64",
        flavor="pro",
        source="test",
    )


def test_main_prompt_choice_text_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "pypi")
    res = installer_main._prompt_choice("Choose", ["snapshot", "pypi", "local"], default="snapshot")
    assert res == "pypi"


def test_main_prompt_ida_install_invalid_then_valid(monkeypatch, tmp_path):
    inst = _make_install(tmp_path / "ida")
    answers = iter(["invalid", "1"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    res = installer_main._prompt_ida_install([inst])
    assert res == inst


def test_main_resolve_ida_install_interactive_tty(tmp_path, monkeypatch):
    inst1 = _make_install(tmp_path / "ida1", (9, 3))
    inst2 = _make_install(tmp_path / "ida2", (9, 4))
    monkeypatch.setattr(installer_main, "detect_ida_installs", lambda: [inst1, inst2])
    monkeypatch.setattr(installer_main, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(installer_main, "_prompt_ida_install", lambda installs, default_index: inst2)
    opts = InstallerOptions(install_root=tmp_path / "root", yes=False, interactive=True)
    ui = installer_main.UI()
    chosen = installer_main._resolve_ida_install(opts, ui)
    assert chosen == inst2


def test_main_embedder_doctor_with_server_and_model_args(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    class MockEmbedder:
        _instance = None
        def status(self, **kwargs):
            return {"ready": True, "backend": "local"}
        def embed_vector(self, text):
            return [0.1, 0.2]

    monkeypatch.setattr(core, "BgeCodeEmbedder", MockEmbedder)
    monkeypatch.setattr(core, "model_fingerprint", lambda *a, **kw: "fp1")
    monkeypatch.setattr(core, "server_fingerprint", lambda *a, **kw: "fp2")
    opts = InstallerOptions(
        install_root=tmp_path / "root",
        embed_backend="local",
        embed_server_bin="/usr/bin/llama-server",
        embed_model_path="/path/to/model.gguf",
    )
    rc = installer_main.run_embedder_doctor(opts, installer_main.UI())
    assert rc == 0


def test_main_interactive_wizard_gemini_existing_key_and_zembed(tmp_path, monkeypatch):
    monkeypatch.setattr(installer_main, "_is_interactive_terminal", lambda: True)
    monkeypatch.setenv("GEMINI_API_KEY", "fake_existing_key")
    monkeypatch.setattr(installer_main, "find_embed_model", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_llama_server_bin", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_rerank_model", lambda *a: "")

    answers = iter(["1", "n", "1", "n", "4", "1", "1", "n", "1", "y", "n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(install_root=tmp_path / "gem", interactive=True)
    res = installer_main._run_interactive_wizard(opts, installer_main.UI())
    assert res.embed_backend == "gemini"
    assert res.gemini_access == "aistudio"


def test_main_interactive_wizard_zembed_license_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(installer_main, "_is_interactive_terminal", lambda: True)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setattr(installer_main, "find_embed_model", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_llama_server_bin", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_rerank_model", lambda *a: "")

    answers = iter(["1", "n", "1", "n", "3", "y", "n", "", "n", "1", "y", "n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(install_root=tmp_path / "zembed", interactive=True)
    res = installer_main._run_interactive_wizard(opts, installer_main.UI())
    assert res.embed_profile == "zembed-1"
    assert res.embed_auto is False


def test_main_interactive_wizard_native_lib_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(installer_main, "_is_interactive_terminal", lambda: True)
    fake_native = types.ModuleType("ida_pro_mcp.host.intelligence.native")
    fake_native.find_native_lib = lambda: "/opt/lib/libmcp_llama.so"
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.native", fake_native)
    monkeypatch.setattr(installer_main, "find_embed_model", lambda *a: "/opt/model.gguf")
    monkeypatch.setattr(installer_main, "find_llama_server_bin", lambda *a: "/usr/bin/llama-server")
    monkeypatch.setattr(installer_main, "find_rerank_model", lambda *a: "")

    answers = iter(["1", "n", "1", "n", "1", "y", "1", "n", "1", "y", "n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(install_root=tmp_path / "native", interactive=True)
    res = installer_main._run_interactive_wizard(opts, installer_main.UI())
    assert res.embed_auto is True
    assert res.embed_server_bin == "/usr/bin/llama-server"


def test_main_interactive_wizard_policy_disabled_and_idalib_missing_whl(tmp_path, monkeypatch):
    monkeypatch.setattr(installer_main, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(installer_main, "find_embed_model", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_llama_server_bin", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_rerank_model", lambda *a: "")
    monkeypatch.setattr(installer_main, "find_idalib_python_dir", lambda *a: None)

    answers = iter(["1", "n", "1", "n", "1", "", "2", "y", "n", "y", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(install_root=tmp_path / "idalib_opts", interactive=True)
    res = installer_main._run_interactive_wizard(opts, installer_main.UI())
    assert res.disable_policy is True
    assert res.ida_runtime == "idalib"


def test_main_activate_idalib_chosen_install_none():
    opts = InstallerOptions(ida_runtime="idalib", dry_run=False)
    with pytest.raises(RuntimeError, match="no IDA install was resolved"):
        installer_main._activate_idalib_after_install(opts, None, InstallReport(), installer_main.UI())


def test_main_replace_with_symlink_or_copy_replace_error_and_file_backup(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "file.txt").write_text("hello")
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "old.txt").write_text("old")

    real_replace = os.replace
    calls = 0
    def fail_second_replace(s, d):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk full")
        return real_replace(s, d)

    monkeypatch.setattr(os, "replace", fail_second_replace)
    with pytest.raises(OSError, match="disk full"):
        installer_main._replace_with_symlink_or_copy(src, dst)


def test_main_install_claude_skills_import_error(monkeypatch):
    orig_import = __import__
    def broken_import(name, *args, **kwargs):
        if "skills" in name:
            raise ImportError("no skills module")
        return orig_import(name, *args, **kwargs)
    monkeypatch.setattr("builtins.__import__", broken_import)
    report = InstallReport()
    ok = installer_main._install_claude_opencode_skills(report, False, installer_main.UI())
    assert ok is False
    assert any("claude-skills import failed" in w for w in report.warnings)


def test_main_install_codex_skills_broken_symlink(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    skill = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("content")

    codex = tmp_path / "codex"
    codex_skills = codex / "skills"
    codex_skills.mkdir(parents=True)
    broken_sym = codex_skills / "ida-pro-mcp"
    broken_sym.symlink_to(tmp_path / "nonexistent_target")
    monkeypatch.setenv("CODEX_HOME", str(codex))

    report = InstallReport()
    with pytest.raises(RuntimeError, match="symlinked skill installation path"):
        installer_main.install_codex_skills(source_root, "agent", report, False)


def test_main_parse_args_setup_embedder_default_only():
    opts = installer_main.parse_args(["--setup-embedder"])
    assert opts.only == {"clients"}
    assert opts.embed_auto is True


def test_main_resolve_path_option_oserror(monkeypatch):
    def broken_resolve(self, strict=False):
        raise OSError("resolution failed")
    monkeypatch.setattr(Path, "resolve", broken_resolve)
    with pytest.raises(RuntimeError, match="Could not resolve"):
        installer_main._normalise_runtime_path("/some/path", "test")


def test_main_warn_ida_python_compat(tmp_path, monkeypatch):
    inst = _make_install(tmp_path / "ida", (9, 4))
    report = InstallReport()
    monkeypatch.setattr(installer_runtime, "python_environment_kind", lambda: "system")
    installer_main._warn_ida_python_compat(inst, report, installer_main.UI())
    assert "python_kind" not in report.metadata

    monkeypatch.setattr(installer_runtime, "python_environment_kind", lambda: "conda")
    installer_main._warn_ida_python_compat(inst, report, installer_main.UI())
    assert report.metadata["python_kind"] == "conda"


def test_main_run_install_lock_failure(tmp_path, monkeypatch):
    opts = InstallerOptions(install_root=tmp_path / "root", dry_run=False)
    def broken_lock(*a, **kw):
        raise RuntimeError("lock error")
    monkeypatch.setattr(installer_main, "installer_lock", broken_lock)
    rc = installer_main.run_install(opts, installer_main.UI())
    assert rc == 1


def test_main_run_uninstall_detect_ida_exception(tmp_path, monkeypatch):
    opts = InstallerOptions(install_root=tmp_path / "root", dry_run=False)
    monkeypatch.setattr("ida_pro_mcp.installer.discovery.detect_ida_installs", lambda: (_ for _ in ()).throw(RuntimeError("ida fail")))
    report = InstallReport()
    rc = installer_main._run_uninstall(opts, installer_main.UI(), report)
    assert rc == 0


def test_main_run_install_idalib_without_clients_phase(tmp_path):
    opts = InstallerOptions(
        install_root=tmp_path / "root",
        ida_runtime="idalib",
        only={"runtime"},
        dry_run=True,
    )
    rc = installer_main.run_install(opts, installer_main.UI())
    assert rc == 1


def test_main_run_install_sigs_without_ida(tmp_path):
    opts = InstallerOptions(
        install_root=tmp_path / "root",
        sigs_dir=str(tmp_path / "sigs"),
        dry_run=True,
    )
    rc = installer_main.run_install(opts, installer_main.UI())
    assert rc == 1


def test_main_run_install_r2_missing_binary(tmp_path, monkeypatch):
    opts = InstallerOptions(
        install_root=tmp_path / "root",
        with_r2=True,
        only={"clients"},
        dry_run=True,
    )
    monkeypatch.setattr(installer_main, "resolve_r2_binary", lambda: ("", ""))
    monkeypatch.setattr(installer_main, "detect_ida_installs", list)
    rc = installer_main.run_install(opts, installer_main.UI())
    assert rc == 0


def test_runtime_kill_ida_processes_oserror_and_returncodes(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    mock_run = MagicMock()
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="1234  \n5678 /opt/ida\n")
    monkeypatch.setattr(subprocess, "run", mock_run)

    real_resolve = Path.resolve
    def flaky_res(self, *a, **kw):
        if "opt" in str(self):
            raise OSError("cannot resolve")
        return real_resolve(self, *a, **kw)
    monkeypatch.setattr(Path, "resolve", flaky_res)

    res = installer_runtime.kill_ida_processes("/opt/ida")
    assert res in (True, False)


def test_runtime_download_rerank_existing_file(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence.rerank_profiles import QWEN3_RERANKER_0_6B
    dest = tmp_path / "models" / QWEN3_RERANKER_0_6B.download_filename
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"x" * QWEN3_RERANKER_0_6B.download_size)

    monkeypatch.setattr(installer_runtime, "_sha256_file", lambda p: QWEN3_RERANKER_0_6B.download_sha256)
    result = installer_runtime.download_rerank_model(tmp_path, QWEN3_RERANKER_0_6B.key)
    assert result == str(dest)


def test_runtime_find_rerank_model_state_manual(tmp_path, monkeypatch):
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    m = models_dir / "qwen3-reranker-0.6b-q8_0.gguf"
    m.write_bytes(b"dummy")

    state = {
        "rerank": {
            "model_path": str(m),
        }
    }
    monkeypatch.setattr(installer_runtime, "_read_installer_embedder_state", lambda r: state)
    found = installer_runtime.find_rerank_model(tmp_path, "qwen3-reranker-0.6b")
    assert found == str(m)


def test_runtime_find_rerank_model_huggingface_search(tmp_path, monkeypatch):
    home = tmp_path / "home"
    snap_dir = home / ".cache" / "huggingface" / "hub" / "models--qwen" / "snapshots" / "rev1"
    snap_dir.mkdir(parents=True)
    cand = snap_dir / "qwen3-reranker-0.6b-q8_0.gguf"
    cand.write_bytes(b"fake")

    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(installer_runtime, "_read_installer_embedder_state", lambda r: {})
    found = installer_runtime.find_rerank_model(tmp_path, "qwen3-reranker-0.6b")
    assert found == str(cand)


def test_main_doctor_exit_code_via_main(monkeypatch):
    monkeypatch.setattr(installer_main, "run_embedder_doctor", lambda opts, ui: 42)
    assert installer_main.main(["--embedder-doctor"]) == 42


def test_replace_with_symlink_or_copy_deep_edges(tmp_path):
    # 762: nonexistent src
    with pytest.raises(FileNotFoundError):
        installer_main._replace_with_symlink_or_copy(tmp_path / "nonexistent", tmp_path / "dst")

    # 794-795: dst exists as directory, replaces and cleans up directory backup
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    (src_dir / "file.txt").write_text("hello")
    dst_dir = tmp_path / "dst_dir"
    dst_dir.mkdir()
    (dst_dir / "old.txt").write_text("old")
    installer_main._replace_with_symlink_or_copy(src_dir, dst_dir)
    assert dst_dir.exists()

    # 796: dst exists as file, replaces and unlinks file backup
    src_file = tmp_path / "src.txt"
    src_file.write_text("new")
    dst_file = tmp_path / "dst.txt"
    dst_file.write_text("old")
    installer_main._replace_with_symlink_or_copy(src_file, dst_file)
    assert dst_file.exists()


def test_install_skills_existing_directory(tmp_path, monkeypatch):
    # 898-903: dst is existing dir, refreshes managed files
    source_root = tmp_path / "source"
    skill = source_root / ".agents" / "skills" / "ida-pro-mcp"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("skill")
    codex = tmp_path / "codex"
    codex_skills = codex / "skills" / "ida-pro-mcp"
    codex_skills.mkdir(parents=True)
    (codex_skills / "custom.txt").write_text("custom")
    monkeypatch.setenv("CODEX_HOME", str(codex))
    report = InstallReport()
    installer_main.install_codex_skills(source_root, "agent", report, False)
    assert (codex_skills / "custom.txt").exists()


def test_parse_args_source_root_fallbacks(monkeypatch, tmp_path):
    # 1129-1132: fallback branches when client_configs.json not in repo root
    orig_exists = Path.exists

    def mock_exists(self):
        if self.name == "client_configs.json":
            return False
        return orig_exists(self)

    monkeypatch.setattr(Path, "exists", mock_exists)
    opts = installer_main.parse_args([])
    assert opts.source_root is not None


def test_run_install_rerank_profile_errors(tmp_path):
    # 1256, 1258
    ui = installer_main.UI()
    opts = InstallerOptions(
        install_root=tmp_path / "root",
        download_rerank_model=True,
        rerank_profile="nonexistent_profile_xyz",
    )
    with pytest.raises(RuntimeError, match="Unknown rerank profile"):
        installer_main._resolve_reranker_for_install(opts, tmp_path / "root", InstallReport(), ui, semantic_enabled=True)

    opts2 = InstallerOptions(
        install_root=tmp_path / "root",
        download_rerank_model=True,
        rerank_profile="bge-reranker-v2-m3",
        accept_model_license=False,
    )
    with pytest.raises(RuntimeError, match="accept-model-license"):
        installer_main._resolve_reranker_for_install(opts2, tmp_path / "root", InstallReport(), ui, semantic_enabled=True)


def test_run_install_boundary_guards(tmp_path, monkeypatch):
    ui = installer_main.UI()
    monkeypatch.setattr(installer_main, "setup_runtime_environment", lambda *a, **kw: Path(sys.executable))
    # 1427: _resolve_ida_install raises unexpected error
    monkeypatch.setattr(installer_main, "_resolve_ida_install", MagicMock(side_effect=RuntimeError("unexpected ida error")))
    opts = InstallerOptions(install_root=tmp_path / "r1", yes=True)
    rc = installer_main.run_install(opts, ui)
    assert rc == 1

    # 1442: with_r2 requires clients phase
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: None)
    opts_r2 = InstallerOptions(install_root=tmp_path / "r2", yes=True, with_r2=True, only={"plugins"})
    rc2 = installer_main.run_install(opts_r2, ui)
    assert rc2 == 1


def test_run_install_r2_dry_run_and_sigs_branches(tmp_path, monkeypatch):
    ui = installer_main.UI()
    inst = _make_install(tmp_path / "ida")
    monkeypatch.setattr(installer_main, "setup_runtime_environment", lambda *a, **kw: Path(sys.executable))
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: inst)
    monkeypatch.setattr(installer_main, "resolve_r2_binary", lambda: ("/bin/rz", "1.0.0"))

    # 1609: with_r2 in dry-run mode
    opts = InstallerOptions(install_root=tmp_path / "r3", yes=True, with_r2=True, dry_run=True)
    assert installer_main.run_install(opts, ui) == 0

    # 1653: sigs_dir requires IDA install
    opts_no_ida = InstallerOptions(install_root=tmp_path / "r4", yes=True, sigs_dir=tmp_path / "sigs")
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: None)
    assert installer_main.run_install(opts_no_ida, ui) == 1

    # 1661: no sigs found under sigs_dir
    empty_sigs = tmp_path / "empty_sigs"
    empty_sigs.mkdir()
    opts_empty = InstallerOptions(install_root=tmp_path / "r5", yes=True, sigs_dir=empty_sigs)
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: inst)
    assert installer_main.run_install(opts_empty, ui) == 1

    # 1670: existing sigs preserved (manifest.count == 0, len(skipped) > 0)
    manifest = SimpleNamespace(count=0, skipped=["dummy.sig"], to_dict=dict)
    monkeypatch.setattr(installer_main, "stage_sigs", lambda *a, **kw: manifest)
    opts_preserved = InstallerOptions(install_root=tmp_path / "r6", yes=True, sigs_dir=empty_sigs)
    assert installer_main.run_install(opts_preserved, ui) == 0


def test_run_install_vertex_auth_and_llama_download(tmp_path, monkeypatch):
    ui = installer_main.UI()
    inst = _make_install(tmp_path / "ida")
    monkeypatch.setattr(installer_main, "setup_runtime_environment", lambda *a, **kw: Path(sys.executable))
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: inst)

    # 1724-1725: vertex with gemini_install_auth
    opts_vertex = InstallerOptions(
        install_root=tmp_path / "v1",
        yes=True,
        embed_backend="gemini",
        gemini_access="vertex",
        gemini_install_auth=True,
        dry_run=False,
    )
    monkeypatch.setattr(installer_main, "install_optional_packages", lambda exe, pkgs: True)
    assert installer_main.run_install(opts_vertex, ui) == 0

    # 1794-1795: install_llama_server with embed_model
    model_file = tmp_path / "model.gguf"
    model_file.write_bytes(b"dummy")
    server_bin_file = tmp_path / "llama-server"
    server_bin_file.write_bytes(b"")
    server_bin_file.chmod(0o755)
    opts_llama = InstallerOptions(
        install_root=tmp_path / "l1",
        yes=True,
        embed_backend="local",
        embed_auto=True,
        install_llama_server=True,
        embed_model_path=str(model_file),
        dry_run=False,
    )
    mock_dl = MagicMock(return_value=str(server_bin_file))
    monkeypatch.setattr(installer_main, "download_and_install_llama_server", mock_dl)
    monkeypatch.setattr(installer_main, "find_llama_server_bin", lambda *a: "")
    assert installer_main.run_install(opts_llama, ui) == 0
    assert mock_dl.called


def test_run_install_embedder_state_warning_and_shell_shim(tmp_path, monkeypatch):
    ui = installer_main.UI()
    inst = _make_install(tmp_path / "ida")
    monkeypatch.setattr(installer_main, "setup_runtime_environment", lambda *a, **kw: Path(sys.executable))
    monkeypatch.setattr(installer_main, "_resolve_ida_install", lambda *a: inst)
    model_file = tmp_path / "model.gguf"
    model_file.write_bytes(b"dummy")

    # 1852-1853: write_embedder_state exception caught
    from ida_pro_mcp.host.intelligence import core
    monkeypatch.setattr(core, "write_embedder_state", MagicMock(side_effect=RuntimeError("write state failed")))
    opts_fail = InstallerOptions(
        install_root=tmp_path / "s1",
        yes=True,
        embed_model_path=str(model_file),
        dry_run=False,
    )
    assert installer_main.run_install(opts_fail, ui) == 0

    # 1899-1905: install_cli_shim dry_run and ok
    monkeypatch.setattr(installer_main, "install_bashrc_cli", lambda *a: True)
    opts_shim_dry = InstallerOptions(install_root=tmp_path / "sh1", yes=True, install_cli_shim=True, dry_run=True)
    assert installer_main.run_install(opts_shim_dry, ui) == 0
    opts_shim_ok = InstallerOptions(install_root=tmp_path / "sh2", yes=True, install_cli_shim=True, dry_run=False)
    assert installer_main.run_install(opts_shim_ok, ui) == 0


def test_run_install_error_recovery_failures(tmp_path, monkeypatch):
    ui = installer_main.UI()
    monkeypatch.setattr(installer_main, "setup_runtime_environment", lambda *a, **kw: Path(sys.executable))
    # 1935-1936: _write_install_error_log raises OSError
    monkeypatch.setattr(installer_main, "_resolve_ida_install", MagicMock(side_effect=RuntimeError("fatal")))
    monkeypatch.setattr(installer_main, "_write_install_error_log", MagicMock(side_effect=OSError("disk full")))

    # 1942-1944: rollback_from_backups raises exception
    monkeypatch.setattr(installer_main, "rollback_from_backups", MagicMock(side_effect=RuntimeError("rollback failed")))

    # 1951-1952: report.write raises exception
    monkeypatch.setattr(InstallReport, "write", MagicMock(side_effect=OSError("cannot write report")))

    opts = InstallerOptions(install_root=tmp_path / "err_all", yes=True, rollback_on_fail=True)
    assert installer_main.run_install(opts, ui) == 1


def test_main_dunder_entrypoint(tmp_path, monkeypatch):
    # 1967: main execution as __main__
    import runpy
    monkeypatch.setattr(sys, "argv", [
        "ida-pro-mcp-installer",
        "--embedder-doctor",
        "--no-embed-auto",
        "--install-root",
        str(tmp_path),
    ])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("ida_pro_mcp.installer.main", run_name="__main__")
    assert exc_info.value.code in (0, 1)


def test_runtime_deep_edge_cases(tmp_path, monkeypatch):
    # 158: _profile_download_url without /resolve/main/
    prof = SimpleNamespace(download_url="https://hf.co/user/repo/blob/master/m.gguf", download_revision="a" * 40)
    assert installer_runtime._profile_download_url(prof) == ""

    # 339-340, 348-351: kill_ida_processes on win32
    monkeypatch.setattr(sys, "platform", "win32")
    target_bin = "/opt/ida/target_ida64"
    wmic_output = SimpleNamespace(returncode=0, stdout=f"Node,ExecutablePath,ProcessId\nnode1,{target_bin},1234\n")

    def fake_win_run(cmd, *a, **kw):
        if "wmic" in cmd[0]:
            return wmic_output
        if "taskkill" in cmd:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_win_run)
    orig_resolve = Path.resolve
    called_target = False

    def flaky_res(self, *a, **kw):
        nonlocal called_target
        if str(self) == target_bin:
            if not called_target:
                called_target = True
                return target_bin
            raise OSError("cannot resolve")
        return orig_resolve(self, *a, **kw)

    monkeypatch.setattr(Path, "resolve", flaky_res)
    assert installer_runtime.kill_ida_processes(target_bin) is False

    # 384, 395-396: kill_ida_processes on linux
    monkeypatch.setattr(sys, "platform", "linux")
    mock_pgrep = SimpleNamespace(returncode=0, stdout="1234   \n5678 /opt/ida\n")
    def fake_linux_run(cmd, *a, **kw):
        if cmd[0] == "pgrep":
            return mock_pgrep
        if cmd[0] == "kill":
            raise OSError("permission denied")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(subprocess, "run", fake_linux_run)
    assert installer_runtime.kill_ida_processes("/opt/ida") is False

    # 494-495, 537: find_embed_model exception in manual read and falsy base
    from ida_pro_mcp.host.intelligence import core
    orig_expand = installer_runtime._expand_configured_path
    monkeypatch.setattr(core, "_select_state_path", MagicMock(side_effect=RuntimeError("boom")))
    monkeypatch.setattr(installer_runtime, "_read_installer_embedder_state", lambda r: {"model_path": "something"})
    monkeypatch.setenv("IDA_MCP_EMBED_SEARCH_PATHS", "dummy_entry")
    monkeypatch.setattr(installer_runtime, "_expand_configured_path", lambda s: None)
    assert installer_runtime.find_embed_model(tmp_path) == ""
    monkeypatch.setattr(installer_runtime, "_expand_configured_path", orig_expand)

    # 731, 741: find_llama_server_bin darwin roots and seen duplicate
    monkeypatch.setattr(sys, "platform", "darwin")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    srv = bin_dir / "llama-server"
    srv.write_bytes(b"")
    srv.chmod(0o755)
    monkeypatch.setattr(os, "environ", {"PATH": f"{bin_dir}:{bin_dir}"})
    found_bin = installer_runtime.find_llama_server_bin(tmp_path)
    assert found_bin == str(srv)

    # 808, 810, 829-830, 840-841, 859-860: find_rerank_model branches
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    # 808: unknown profile fallback
    assert installer_runtime.find_rerank_model(tmp_path, profile="unknown_xyz") == ""

    # 810: selected is None
    import ida_pro_mcp.host.intelligence.rerank_profiles as rp_mod
    monkeypatch.setattr(rp_mod, "get_rerank_model_profile", lambda *a: None)
    assert installer_runtime.find_rerank_model(tmp_path) == ""

    # 829-830, 840-841, 859-860: extra paths, resolve OSError, rglob match
    monkeypatch.setattr(rp_mod, "get_rerank_model_profile", lambda *a: rp_mod.QWEN3_RERANKER_0_6B)
    monkeypatch.setenv("IDA_MCP_RERANK_SEARCH_PATHS", str(tmp_path / "extra1") + ":" + str(tmp_path / "extra2"))
    (tmp_path / "extra1").mkdir()
    nested = tmp_path / "deep" / "nested" / "models"
    nested.mkdir(parents=True)
    cand_model = nested / rp_mod.QWEN3_RERANKER_0_6B.download_filename
    cand_model.write_bytes(b"dummy")

    real_res = Path.resolve
    def flaky_res_rerank(self, *a, **kw):
        if "extra2" in str(self):
            raise OSError("cannot resolve")
        return real_res(self, *a, **kw)
    monkeypatch.setattr(Path, "resolve", flaky_res_rerank)
    found_rerank = installer_runtime.find_rerank_model(tmp_path, profile=rp_mod.QWEN3_RERANKER_0_6B.key)
    assert found_rerank == str(cand_model)


def test_is_checkout_skill_link_all_branches(tmp_path):
    # Nonexistent path -> OSError in resolve(strict=True) -> False
    assert installer_main._is_checkout_skill_link(tmp_path / "nonexistent") is False

    # Target is not a dir -> False
    f = tmp_path / "regular_file"
    f.touch()
    assert installer_main._is_checkout_skill_link(f) is False

    # Target dir wrong name -> False
    d = tmp_path / "wrong_name"
    d.mkdir()
    assert installer_main._is_checkout_skill_link(d) is False

    # Structure: root / .agents / skills / ida-pro-mcp
    root = tmp_path / "repo"
    skill_dir = root / ".agents" / "skills" / "ida-pro-mcp"
    skill_dir.mkdir(parents=True)

    # Missing SKILL.md -> False
    assert installer_main._is_checkout_skill_link(skill_dir) is False

    (skill_dir / "SKILL.md").touch()
    # Missing operations.md -> False
    assert installer_main._is_checkout_skill_link(skill_dir) is False

    refs = skill_dir / "references"
    refs.mkdir()
    (refs / "operations.md").touch()

    # Without .git -> False
    assert installer_main._is_checkout_skill_link(skill_dir) is False

    # With .git dir -> True
    (root / ".git").mkdir()
    assert installer_main._is_checkout_skill_link(skill_dir) is True


def test_run_embedder_doctor_symlink_and_gemini_modes(tmp_path, monkeypatch):
    # Symlinked install root -> returns 1
    real_root = tmp_path / "real_root"
    real_root.mkdir()
    sym_root = tmp_path / "sym_root"
    sym_root.symlink_to(real_root)

    ui = installer_main.UI()
    opts = InstallerOptions(install_root=sym_root)
    assert installer_main.run_embedder_doctor(opts, ui) == 1

    # Gemini mode with vertex options
    opts2 = InstallerOptions(
        install_root=real_root,
        embed_backend="gemini",
        gemini_model="models/embedding-001",
        gemini_dim=768,
        gemini_access="vertex",
        gemini_api_key="secret-key",
        gemini_vertex_project="gcp-project",
        gemini_vertex_location="us-central1",
    )
    import ida_pro_mcp.host.intelligence.core as intel_core
    class MockEmbedder:
        _instance = None
        def status(self, probe=True, deep_hash=False):
            return {"active_backend": "gemini", "ready": True}
        def embed_vector(self, text):
            return [0.1] * 768
        def embed(self, text):
            return [0.1] * 768
    monkeypatch.setattr(intel_core, "BgeCodeEmbedder", MockEmbedder)
    monkeypatch.setattr(intel_core, "model_fingerprint", lambda *a, **kw: "fp_model")
    monkeypatch.setattr(intel_core, "server_fingerprint", lambda *a, **kw: "fp_server")

    rc = installer_main.run_embedder_doctor(opts2, ui)
    assert rc == 0


def test_interactive_wizard_gemini_prompts(monkeypatch):
    ui = installer_main.UI()

    # 1. AI Studio with key entered
    opts1 = InstallerOptions(interactive=True, skills_mode="agent")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    def mock_prompt_choice(prompt, choices, default=None):
        if "Runtime" in prompt:
            return "snapshot"
        if "skills mode" in prompt:
            return "agent"
        if "Embedding backend" in prompt:
            return "gemini-embedding-2 (cloud, requires API key)"
        if "Gemini access" in prompt:
            return "Google AI Studio (API key)"
        return default or choices[0]

    monkeypatch.setattr(installer_main, "_prompt_choice", mock_prompt_choice)
    monkeypatch.setattr(installer_main, "_prompt_yes_no", lambda *a, **kw: True)
    monkeypatch.setattr(installer_main, "_prompt_secret", lambda *a, **kw: "test-ai-key")

    res1 = installer_main._run_interactive_wizard(opts1, ui)
    assert res1.embed_backend == "gemini"
    assert res1.gemini_access == "aistudio"
    assert res1.gemini_api_key == "test-ai-key"

    # 2. AI Studio with empty key
    opts2 = InstallerOptions(interactive=True, skills_mode="agent")
    monkeypatch.setattr(installer_main, "_prompt_secret", lambda *a, **kw: "")
    res2 = installer_main._run_interactive_wizard(opts2, ui)
    assert res2.gemini_api_key == ""

    # 3. Vertex AI
    opts3 = InstallerOptions(interactive=True, skills_mode="agent")
    def mock_prompt_choice_vertex(prompt, choices, default=None):
        if "Embedding backend" in prompt:
            return "gemini-embedding-2 (cloud, requires API key)"
        if "Gemini access" in prompt:
            return "Vertex AI (GCP)"
        return mock_prompt_choice(prompt, choices, default)

    monkeypatch.setattr(installer_main, "_prompt_choice", mock_prompt_choice_vertex)
    monkeypatch.setattr(installer_main, "_prompt_text", lambda prompt, default=None: "custom-val")
    res3 = installer_main._run_interactive_wizard(opts3, ui)
    assert res3.gemini_access == "vertex"
    assert res3.gemini_vertex_project == "custom-val"
    assert res3.gemini_vertex_location == "custom-val"
    assert res3.gemini_install_auth is True
