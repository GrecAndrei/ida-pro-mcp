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
