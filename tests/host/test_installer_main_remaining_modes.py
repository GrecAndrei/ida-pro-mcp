"""Exercise installer CLI, wizard, and reporting branches offline."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from ida_pro_mcp.installer import main as installer
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport
from ida_pro_mcp.installer.discovery import IdaInstall


def _install(path: Path, version: tuple[int, int] = (9, 3)) -> IdaInstall:
    path.mkdir(parents=True, exist_ok=True)
    return IdaInstall(
        path=path,
        version=version,
        build="test",
        idat_binary=None,
        arch="x64",
        flavor="pro",
        source="test",
    )


def test_prompt_helpers_accept_defaults_labels_versions_and_secrets(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    assert installer._prompt_choice("mode", ["one", "two"], "two") == "two"
    first = _install(Path("/tmp/ida-main-first"), (9, 2))
    second = _install(Path("/tmp/ida-main-second"), (9, 3))
    assert installer._prompt_ida_install([first, second], default_index=1) is second

    answers = iter(["2"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert installer._prompt_ida_install([first, second]) is second
    monkeypatch.setattr("builtins.input", lambda _prompt: "9.2")
    assert installer._prompt_ida_install([first, second]) is first

    monkeypatch.setattr(installer.getpass, "getpass", lambda _prompt: " secret ")
    assert installer._prompt_secret("token") == "secret"


def test_embedder_doctor_reports_ready_failed_and_gemini_error_modes(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    class FakeEmbedder:
        _instance = None
        vector = [0.1, 0.2]

        def status(self, **_kwargs):
            return {"ready": bool(self.vector), "backend": "fake", "error": "cloud unavailable"}

        def embed_vector(self, _text):
            return self.vector

    monkeypatch.setattr(core, "BgeCodeEmbedder", FakeEmbedder)
    monkeypatch.setattr(core, "model_fingerprint", lambda *_args, **_kwargs: "model-fp")
    monkeypatch.setattr(core, "server_fingerprint", lambda *_args, **_kwargs: "server-fp")
    monkeypatch.setattr(installer, "find_embed_model", lambda *_args: "")
    monkeypatch.setattr(installer, "find_llama_server_bin", lambda *_args: "")
    ui = installer.UI()
    FakeEmbedder.vector = None
    opts = InstallerOptions(install_root=tmp_path / "install", interactive=False)
    assert installer.run_embedder_doctor(opts, ui) == 1

    FakeEmbedder.vector = [1.0]
    opts = InstallerOptions(
        install_root=tmp_path / "gemini",
        embed_backend="gemini",
        gemini_api_key="key",
        interactive=False,
    )
    assert installer.run_embedder_doctor(opts, ui) == 0

    FakeEmbedder.vector = None
    opts = InstallerOptions(install_root=tmp_path / "failed", embed_backend="gemini")
    assert installer.run_embedder_doctor(opts, ui) == 1


def test_interactive_wizard_local_missing_model_and_gemini_access_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(installer, "find_embed_model", lambda *_args: "")
    monkeypatch.setattr(installer, "find_llama_server_bin", lambda *_args: "")
    monkeypatch.setattr(installer, "find_rerank_model", lambda *_args: "")

    # local backend, no model path, then the final safety prompts
    answers = iter(["1", "n", "1", "n", "1", "", "1", "y", "n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(
        install_root=tmp_path / "local",
        source_root=tmp_path / "source",
        interactive=True,
    )
    result = installer._run_interactive_wizard(opts, installer.UI())
    assert result.embed_backend == "qwen3-embedding-0.6b"
    assert result.embed_auto is False

    # Gemini + Vertex takes the cloud credential branch; patch the secret
    # prompt so the test never reads from a real terminal.
    monkeypatch.setattr(installer, "_prompt_secret", lambda _question: "")
    answers = iter(["1", "n", "1", "n", "4", "2", "project", "europe", "n", "1", "y", "n", "1", "y", "n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    opts = InstallerOptions(
        install_root=tmp_path / "gemini",
        source_root=tmp_path / "source",
        interactive=True,
    )
    result = installer._run_interactive_wizard(opts, installer.UI())
    assert result.embed_backend == "gemini"
    assert result.gemini_access == "vertex"
    assert result.gemini_vertex_project == "project"


def test_parse_args_covers_setup_embedder_and_all_explicit_options(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "get_install_root", lambda: tmp_path / "default")
    opts = installer.parse_args(
        [
            "--setup-embedder",
            "--no-interactive",
            "--no-rollback-on-fail",
            "--runtime-source",
            "pypi",
            "--embed-backend",
            "gemini",
            "--gemini-access",
            "vertex",
            "--gemini-api-key",
            "key",
            "--gemini-vertex-project",
            "project",
            "--gemini-vertex-location",
            "europe",
            "--gemini-model",
            "model",
            "--gemini-dim",
            "1024",
            "--gemini-install-auth",
            "--download-embed-model",
            "--accept-model-license",
            "--rerank-model",
            "rerank.gguf",
            "--rerank-profile",
            "qwen3-reranker-4b",
            "--download-rerank-model",
            "--embed-server-bin",
            "llama-server",
            "--embedder-doctor",
            "--install-llama-server",
            "--allow-unverified-downloads",
            "--with-corpus",
            "--verify-corpus",
            "--no-embed-auto",
            "--skills-mode",
            "none",
            "--no-install-skills",
            "--with-r2",
            "--sigs",
            "signatures",
            "--only",
            "clients",
            "--install-root",
            str(tmp_path / "install"),
            "--ida-runtime",
            "idalib",
            "--ida-dir",
            str(tmp_path / "ida"),
            "--ida-version",
            "9.3",
            "--no-ida-prompt",
            "--disable-policy",
            "--ida-binary-path",
            "idat64",
        ]
    )
    assert opts.setup_embedder is True
    assert opts.only == {"clients"}
    assert opts.embed_auto is True
    assert opts.install_llama_server is True
    assert opts.rollback_on_fail is False
    assert opts.with_bron_corpus and opts.verify_bron_corpus
    assert opts.ida_runtime == "idalib"
    assert opts.no_ida_prompt is True
    assert opts.source_root is not None


def test_skill_install_helpers_cover_copy_and_failure_paths(tmp_path, monkeypatch):
    source = tmp_path / "source"
    skill = source / ".agents" / "skills" / "ida-pro-mcp"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("skill", encoding="utf-8")
    (skill / "extra.txt").write_text("extra", encoding="utf-8")
    codex = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex))

    report = InstallReport()
    monkeypatch.setattr(installer.os, "symlink", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("links disabled")))
    installer.install_codex_skills(source, "agent", report, False)
    assert (codex / "skills" / "ida-pro-mcp" / "SKILL.md").read_text(encoding="utf-8") == "skill"

    report = InstallReport()
    skills_module = __import__("ida_pro_mcp.installer.skills", fromlist=["install_skills"])
    monkeypatch.setattr(skills_module, "default_skill_dirs", lambda: [tmp_path / "claude"])
    monkeypatch.setattr(skills_module, "install_skills", lambda *_args, **_kwargs: {"claude": [tmp_path / "claude" / "SKILL.md"]})
    assert installer._install_claude_opencode_skills(report, False, installer.UI()) is True
    assert report.modified_files

    monkeypatch.setattr(skills_module, "install_skills", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("write failed")))
    assert installer._install_claude_opencode_skills(InstallReport(), False, installer.UI()) is False


def test_idalib_activation_and_bashrc_platform_boundaries(tmp_path, monkeypatch):
    install = _install(tmp_path / "ida")
    report = InstallReport()
    opts = InstallerOptions(ida_runtime="idalib", dry_run=True)
    installer._activate_idalib_after_install(opts, install, report, installer.UI())
    assert report.steps[-1]["status"] == "dry-run"

    monkeypatch.setattr(installer.sys, "platform", "win32")
    report = InstallReport()
    assert installer.install_bashrc_cli(tmp_path / "install", False, report) is False
    assert report.warnings
