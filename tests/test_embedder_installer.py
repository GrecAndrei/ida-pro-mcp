from __future__ import annotations

import io
from types import SimpleNamespace

from ida_pro_mcp.installer.common import InstallReport
from ida_pro_mcp.installer.main import parse_args
from ida_pro_mcp.installer.runtime import (
    build_stdio_config,
    choose_runtime_source,
    download_embed_model,
    setup_runtime_environment,
)


def test_zembed_download_is_an_explicit_profile_and_license_choice():
    opts = parse_args(
        [
            "--embed-profile", "zembed-1",
            "--download-embed-model",
            "--accept-model-license",
            "--no-interactive",
        ]
    )
    assert opts.embed_profile == "zembed-1"
    assert opts.download_embed_model is True
    assert opts.accept_model_license is True


def test_managed_zembed_download_is_bounded_and_written_to_the_install_root(monkeypatch, tmp_path):
    class Response(io.BytesIO):
        headers = {"Content-Length": "11"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda _request, timeout: Response(b"GGUF-model!"),
    )

    downloaded = download_embed_model(tmp_path, "zembed-1")
    assert downloaded.endswith("zembed-1-Q4_K_M.gguf")
    assert (tmp_path / "models" / "zembed-1-Q4_K_M.gguf").read_bytes() == b"GGUF-model!"


def test_client_config_carries_the_selected_embedding_profile(tmp_path):
    config = build_stdio_config(
        tmp_path / "python",
        tmp_path,
        embed_model="/models/zembed-1-Q4_K_M.gguf",
        embed_server_bin="/bin/llama-server",
        embed_profile="zembed-1",
    )
    assert config["env"]["IDA_MCP_EMBED_PROFILE"] == "zembed-1"
    assert config["env"]["IDA_MCP_EMBED_MODEL"].endswith("zembed-1-Q4_K_M.gguf")


def test_gemini_backend_cli_args_parse():
    opts = parse_args(
        [
            "--embed-backend", "gemini",
            "--gemini-access", "vertex",
            "--gemini-vertex-project", "proj-x",
            "--gemini-vertex-location", "europe-west1",
            "--gemini-install-auth",
            "--no-interactive",
        ]
    )
    assert opts.embed_backend == "gemini"
    assert opts.gemini_access == "vertex"
    assert opts.gemini_vertex_project == "proj-x"
    assert opts.gemini_vertex_location == "europe-west1"
    assert opts.gemini_install_auth is True
    assert opts.gemini_model == "gemini-embedding-2"
    assert opts.gemini_dim == 768


def test_client_config_carries_gemini_backend_env(tmp_path):
    config = build_stdio_config(
        tmp_path / "python",
        tmp_path,
        embed_backend="gemini",
        gemini_api_key="sekrit-key",
        gemini_vertex_project="proj-x",
        gemini_vertex_location="us-central1",
    )
    env = config["env"]
    assert env["IDA_MCP_EMBED_BACKEND"] == "gemini"
    assert env["GEMINI_API_KEY"] == "sekrit-key"
    assert env["GOOGLE_CLOUD_PROJECT"] == "proj-x"
    assert env["VERTEX_AI_LOCATION"] == "us-central1"


def test_client_config_gemini_vertex_without_key_omits_it(tmp_path):
    config = build_stdio_config(
        tmp_path / "python",
        tmp_path,
        embed_backend="gemini",
        gemini_vertex_project="proj-x",
    )
    assert config["env"]["IDA_MCP_EMBED_BACKEND"] == "gemini"
    assert "GEMINI_API_KEY" not in config["env"]


def test_normal_runtime_install_removes_an_old_live_source_pointer(monkeypatch, tmp_path):
    install_root = tmp_path / "install"
    venv_python = install_root / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    live_pointer = site_packages / "ida_pro_mcp_dev.pth"
    live_pointer.write_text("/working/tree/src\n", encoding="utf-8")
    commands = []

    def fake_run_checked(command, **_kwargs):
        commands.append(command)
        if command[-1] == "import site; print(site.getsitepackages()[0])":
            return SimpleNamespace(stdout=f"{site_packages}\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr("ida_pro_mcp.installer.runtime._probe_venv", lambda _python: True)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.run_checked", fake_run_checked)

    setup_runtime_environment(
        install_root=install_root,
        source_root=tmp_path / "missing-source",
        runtime_source="pypi",
        dry_run=False,
        report=InstallReport(),
    )

    assert not live_pointer.exists()
    assert any(command[-2:] == ["install", "ida-pro-mcp"] for command in commands)


def test_auto_runtime_source_resolves_to_snapshot_for_a_checkout(tmp_path):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    assert choose_runtime_source("auto", checkout) == "snapshot"
    assert choose_runtime_source("local", checkout) == "local"
    assert choose_runtime_source("snapshot", checkout) == "snapshot"


def test_snapshot_install_copies_the_checkout_and_installs_from_it(monkeypatch, tmp_path):
    install_root = tmp_path / "install"
    venv_python = install_root / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    commands = []

    source = tmp_path / "repo"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (source / "src").mkdir()
    (source / "src" / "ida_pro_mcp").mkdir()
    (source / "src" / "ida_pro_mcp" / "__init__.py").write_text("# pkg\n", encoding="utf-8")
    (source / ".git").mkdir()

    def fake_run_checked(command, **_kwargs):
        commands.append(command)
        if command[-1] == "import site; print(site.getsitepackages()[0])":
            return SimpleNamespace(stdout=f"{site_packages}\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr("ida_pro_mcp.installer.runtime._probe_venv", lambda _python: True)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.run_checked", fake_run_checked)

    setup_runtime_environment(
        install_root=install_root,
        source_root=source,
        runtime_source="snapshot",
        dry_run=False,
        report=InstallReport(),
    )

    snapshots = list(install_root.glob("runtime-src-*"))
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert (snapshot / "pyproject.toml").is_file()
    assert (snapshot / "src" / "ida_pro_mcp" / "__init__.py").read_text() == "# pkg\n"
    assert not (snapshot / ".git").exists()
    assert any(command[-2:] == ["install", str(snapshot)] for command in commands)


def test_snapshot_install_prunes_older_snapshots(monkeypatch, tmp_path):
    install_root = tmp_path / "install"
    install_root.mkdir(parents=True)
    old = install_root / "runtime-src-20260713-1706"
    old.mkdir()
    (old / "ida_pro_mcp").mkdir()
    venv_python = install_root / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    source = tmp_path / "repo"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (source / "src").mkdir()

    def fake_run_checked(command, **_kwargs):
        if command[-1] == "import site; print(site.getsitepackages()[0])":
            return SimpleNamespace(stdout=f"{site_packages}\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr("ida_pro_mcp.installer.runtime._probe_venv", lambda _python: True)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.run_checked", fake_run_checked)

    setup_runtime_environment(
        install_root=install_root,
        source_root=source,
        runtime_source="snapshot",
        dry_run=False,
        report=InstallReport(),
    )

    snapshots = sorted(p.name for p in install_root.glob("runtime-src-*"))
    assert len(snapshots) == 1
    assert snapshots[0] != "runtime-src-20260713-1706"
    assert not old.exists()
