"""Exercise installer wizard and phase orchestration across backend modes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.installer import main as installer
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall


def _ida(tmp_path, version=(9, 4)):
    path = tmp_path / "ida"
    path.mkdir(parents=True, exist_ok=True)
    binary = path / "idat64"
    binary.write_text("idat", encoding="ascii")
    binary.chmod(0o755)
    return IdaInstall(
        path=path,
        version=version,
        build="build",
        idat_binary=binary,
        arch="x64",
        flavor="pro",
        source="test",
    )


def _wizard_prompts(monkeypatch, *, backend, access="aistudio", runtime="idat", rerank_enable=True):
    def choice(question, choices, default):
        if "Embedding backend" in question:
            return next(item for item in choices if backend in item)
        if "Gemini access" in question:
            return next(item for item in choices if access in item.lower().replace(" ", "")) if access == "vertex" else choices[0]
        if "Reranker model" in question:
            return choices[0]
        if "runtime backend" in question:
            return next(item for item in choices if runtime in item)
        return default

    def yes_no(question, default):
        if "Enable reranker" in question:
            return rerank_enable
        if "Download the managed" in question or "accept the CC-BY-NC" in question:
            return True
        if "Install google-auth" in question:
            return True
        if "Proceed" in question:
            return True
        if "Disable ALL policy" in question:
            return False
        return default

    monkeypatch.setattr(installer, "_prompt_choice", choice)
    monkeypatch.setattr(installer, "_prompt_yes_no", yes_no)
    monkeypatch.setattr(installer, "_prompt_text", lambda question, default="": "demo-project" if "project" in question.lower() else default)
    monkeypatch.setattr(installer, "_prompt_secret", lambda _question: "key-from-prompt")


def test_interactive_wizard_covers_gemini_vertex_and_idalib(monkeypatch, tmp_path):
    ida = _ida(tmp_path)
    opts = InstallerOptions(
        interactive=True,
        install_root=tmp_path / "install",
        embed_backend="gemini",
        gemini_access="vertex",
        ida_runtime="idalib",
    )
    opts._ida_install = ida
    _wizard_prompts(monkeypatch, backend="gemini", access="vertex", runtime="idalib")
    monkeypatch.setattr(installer, "choose_runtime_source", lambda *_a: "snapshot")
    monkeypatch.setattr(installer, "find_embed_model", lambda *_a: "")
    monkeypatch.setattr(installer, "find_llama_server_bin", lambda *_a: "")
    monkeypatch.setattr(installer, "find_idalib_python_dir", lambda _path: str(tmp_path / "idalib-python"))
    monkeypatch.setattr(installer, "activate_idalib", lambda _path: (True, "activated"))
    monkeypatch.setattr(installer, "get_install_root", lambda: tmp_path / "install")
    result = installer._run_interactive_wizard(opts, installer.UI())
    assert result.embed_backend == "gemini"
    assert result.gemini_access == "vertex"
    assert result.gemini_vertex_project == "demo-project"
    assert result.ida_runtime == "idalib"
    assert result.gemini_install_auth is True


def test_interactive_wizard_covers_opt_in_local_model_and_reranker_decline(monkeypatch, tmp_path):
    opts = InstallerOptions(
        interactive=True,
        install_root=tmp_path / "install",
        embed_backend="zembed-1",
        embed_profile="zembed-1",
    )
    _wizard_prompts(monkeypatch, backend="zembed-1", rerank_enable=False)
    monkeypatch.setattr(installer, "choose_runtime_source", lambda *_a: "local")
    monkeypatch.setattr(installer, "find_embed_model", lambda *_a: "")
    monkeypatch.setattr(installer, "find_llama_server_bin", lambda *_a: "")
    monkeypatch.setattr(installer, "find_rerank_model", lambda *_a: str(tmp_path / "rerank.gguf"))
    monkeypatch.setattr(installer, "get_install_root", lambda: tmp_path / "install")
    result = installer._run_interactive_wizard(opts, installer.UI())
    assert result.download_embed_model is True
    assert result.accept_model_license is True
    assert result.embed_auto is True
    assert result.rerank_disabled is True
    assert result.rerank_model_path == ""


def test_python_compat_warning_only_applies_to_managed_ida_94(monkeypatch, tmp_path):
    report = InstallReport()
    ui = installer.UI()
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.python_environment_kind",
        lambda: "conda",
    )
    installer._warn_ida_python_compat(_ida(tmp_path, (9, 4)), report, ui)
    assert report.metadata["python_kind"] == "conda"
    old_report = InstallReport()
    installer._warn_ida_python_compat(_ida(tmp_path / "old", (9, 3)), old_report, ui)
    assert "python_kind" not in old_report.metadata


def test_run_install_composes_runtime_corpus_r2_sigs_clients_and_skills(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    install_root = tmp_path / "install"
    ida = _ida(tmp_path)
    sig_dir = tmp_path / "sig"
    configured = []
    monkeypatch.setattr(installer, "_resolve_ida_install", lambda *_a: ida)
    monkeypatch.setattr(installer, "_run_interactive_wizard", lambda opts, _ui: opts)
    monkeypatch.setattr(installer, "setup_runtime_environment", lambda **_k: install_root / ".venv" / "bin" / "python")
    monkeypatch.setattr(installer, "backup_file", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "write_install_state", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "kill_ida_processes", lambda **_k: None)
    monkeypatch.setattr(installer, "resolve_r2_binary", lambda: ("/usr/bin/rz", "rz 0.9"))
    monkeypatch.setattr(installer, "find_ida_sig_dir", lambda _path: sig_dir)
    monkeypatch.setattr(
        installer,
        "stage_sigs",
        lambda *_a, **_k: SimpleNamespace(count=1, to_dict=lambda: {"count": 1}),
    )
    monkeypatch.setattr(installer, "build_stdio_config", lambda *_a, **_k: {"command": "python"})
    monkeypatch.setattr(installer, "configure_clients", lambda **_k: configured.append("client") or configured)
    monkeypatch.setattr(installer, "install_codex_skills", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "_install_claude_opencode_skills", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "install_bashrc_cli", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "resolve_r2_binary", lambda: ("/usr/bin/rz", "rz 0.9"))
    monkeypatch.setattr(
        "ida_pro_mcp.installer.bron_corpus.download_bron_corpus",
        lambda **_k: {"built": True, "counts": {"cwe": 2}, "downloads": {"one": {}}},
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.write_embedder_state",
        lambda *_a, **_k: install_root / "embedder.json",
    )
    opts = InstallerOptions(
        install_root=install_root,
        source_root=source,
        yes=True,
        kill_ida=True,
        with_r2=True,
        with_corpus=True,
        sigs_dir=str(tmp_path / "sig-source"),
        embed_model_path=str(tmp_path / "model.gguf"),
        embed_server_bin=str(tmp_path / "llama-server"),
        rerank_model_path=str(tmp_path / "rerank.gguf"),
        install_cli_shim=True,
    )
    assert installer.run_install(opts, installer.UI()) == 0
    assert configured == ["client"]
    report = (install_root / "install-report.json").read_text(encoding="utf-8")
    assert '"corpus"' in report and '"sigs"' in report and '"clients"' in report


def test_run_install_gemini_vertex_handles_optional_auth_and_state_failure(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    install_root = tmp_path / "install"
    ida = _ida(tmp_path)
    monkeypatch.setattr(installer, "_resolve_ida_install", lambda *_a: ida)
    monkeypatch.setattr(installer, "_run_interactive_wizard", lambda opts, _ui: opts)
    monkeypatch.setattr(installer, "backup_file", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "write_install_state", lambda *_a, **_k: None)
    monkeypatch.setattr(installer, "install_optional_packages", lambda *_a, **_k: False)
    monkeypatch.setattr(installer, "build_stdio_config", lambda *_a, **_k: {"backend": "gemini"})
    monkeypatch.setattr(installer, "configure_clients", lambda **_k: ["gemini-client"])
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.write_embedder_state",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("state path unavailable")),
    )
    opts = InstallerOptions(
        install_root=install_root,
        source_root=source,
        yes=True,
        only={"clients"},
        embed_backend="gemini",
        gemini_access="vertex",
        gemini_install_auth=True,
        gemini_vertex_project="project",
        gemini_vertex_location="europe-west1",
    )
    assert installer.run_install(opts, installer.UI()) == 0
    report = (install_root / "install-report.json").read_text(encoding="utf-8")
    assert '"gemini-auth"' in report
