from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import ida_pro_mcp.installer.main as main_mod
from ida_pro_mcp.installer import runtime as runtime_mod
from ida_pro_mcp.installer.common import InstallerOptions
from ida_pro_mcp.installer.main import UI, parse_args, run_install


def test_parse_args_install_llama_server_flag():
    opts = parse_args(["--install-llama-server", "--no-interactive", "--yes"])
    assert opts.install_llama_server is True
    assert opts.yes is True
    assert opts.interactive is False


def test_parse_args_setup_embedder_enables_client_setup():
    opts = parse_args(["--setup-embedder", "--no-interactive", "--yes"])
    assert opts.setup_embedder is True
    assert opts.install_llama_server is True
    assert opts.embed_auto is True
    assert opts.only == {"clients"}


def test_find_embed_model_finds_model_in_user_downloads(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "home"
        downloads = home / "Downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        ida_dir = downloads / "ida-pro-mcp"
        ida_dir.mkdir(parents=True, exist_ok=True)
        (ida_dir / "bge-code-v1-q8_0.gguf").write_text("x", encoding="utf-8")
        install_root = Path(td) / "install"
        install_root.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
        monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._read_embedder_state", dict)
        result = runtime_mod.find_embed_model(install_root)
        assert result
        assert Path(result).name == "bge-code-v1-q8_0.gguf"
        assert Path(result).parent.name == "ida-pro-mcp"


def test_find_embed_model_finds_model_in_user_models_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "home"
        models = home / "models"
        models.mkdir(parents=True, exist_ok=True)
        (models / "bge-code-v1.gguf").write_text("x", encoding="utf-8")
        install_root = Path(td) / "install"
        install_root.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
        monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._read_embedder_state", dict)
        result = runtime_mod.find_embed_model(install_root)
        assert result
        assert Path(result).name == "bge-code-v1.gguf"
        assert Path(result).parent.name == "models"


def test_find_embed_model_returns_empty_when_nothing_present(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "home"
        home.mkdir(parents=True, exist_ok=True)
        install_root = Path(td) / "install"
        install_root.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
        monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._read_embedder_state", dict)
        assert runtime_mod.find_embed_model(install_root) == ""


def test_run_install_downloads_llama_server_when_enabled_and_embed_model_found(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        install_root = Path(td) / "install-root"
        install_root.mkdir(parents=True, exist_ok=True)
        fake_model = str(install_root / "models" / "bge-code-v1-q8_0.gguf")
        fake_server = str(install_root / "bin" / ("llama-server.exe" if main_mod.sys.platform == "win32" else "llama-server"))
        captured = {}

        monkeypatch.setattr(main_mod, "_run_interactive_wizard", lambda opts, ui: opts)
        monkeypatch.setattr(main_mod, "find_embed_model", lambda _root: fake_model)
        monkeypatch.setattr(main_mod, "find_llama_server_bin", lambda _root: "")
        monkeypatch.setattr(
            main_mod,
            "download_and_install_llama_server",
            lambda install_root, dry_run, report: fake_server,
        )

        def _configure_clients(source_root, server_cfg, report, dry_run):
            captured["cfg"] = server_cfg
            return ["Codex"]

        monkeypatch.setattr(main_mod, "configure_clients", _configure_clients)

        opts = InstallerOptions(
            dry_run=True,
            yes=True,
            interactive=False,
            embed_auto=True,
            install_llama_server=True,
            only={"clients"},
            install_root=install_root,
            source_root=Path(".").resolve(),
        )
        rc = run_install(opts, UI())
        assert rc == 0
        env = captured["cfg"]["env"]
        assert env.get("IDA_MCP_EMBED_MODEL") == fake_model
        assert env.get("IDA_MCP_EMBED_SERVER_BIN") == fake_server


def test_main_embedder_doctor_bypasses_install(monkeypatch):
    called = {"doctor": 0, "install": 0}

    monkeypatch.setattr(main_mod, "run_embedder_doctor", lambda opts, ui: called.__setitem__("doctor", called["doctor"] + 1) or 0)
    monkeypatch.setattr(main_mod, "run_install", lambda opts, ui: called.__setitem__("install", called["install"] + 1) or 1)

    rc = main_mod.main(["--embedder-doctor", "--no-interactive", "--yes"])
    assert rc == 0
    assert called["doctor"] == 1
    assert called["install"] == 0


# ─── venv reuse / stale-venv recovery ───────────────────────────────────────


def _fake_python_exe(path: Path, body: str = "#!fake\n") -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def test_probe_venv_accepts_working_python(monkeypatch, tmp_path: Path):
    venv = tmp_path / ".venv"
    scripts = venv / ("Scripts" if main_mod.sys.platform == "win32" else "bin")
    scripts.mkdir(parents=True)
    py = scripts / ("python.exe" if main_mod.sys.platform == "win32" else "python")
    _fake_python_exe(py)
    # Stub subprocess.run so the probe uses our fake binary's output.
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        from subprocess import CompletedProcess
        return CompletedProcess(cmd, 0, stdout=str(py) + "\n", stderr="")

    monkeypatch.setattr(runtime_mod.subprocess, "run", fake_run)
    assert runtime_mod._probe_venv(py) is True
    assert captured["cmd"][0] == str(py)


def test_probe_venv_rejects_missing_python(tmp_path: Path):
    py = tmp_path / "nope.exe"
    assert runtime_mod._probe_venv(py) is False


def test_probe_venv_rejects_non_zero_exit(monkeypatch, tmp_path: Path):
    py = tmp_path / "python.exe"
    py.write_text("x", encoding="utf-8")
    from subprocess import CompletedProcess

    monkeypatch.setattr(
        runtime_mod.subprocess, "run",
        lambda cmd, **kwargs: CompletedProcess(cmd, 1, stdout="", stderr="bad"),
    )
    assert runtime_mod._probe_venv(py) is False


def test_wipe_venv_removes_directory(tmp_path: Path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "file").write_text("x", encoding="utf-8")
    runtime_mod._wipe_venv(venv)
    assert not venv.exists()


def test_wipe_venv_is_noop_when_missing(tmp_path: Path):
    venv = tmp_path / ".venv"
    runtime_mod._wipe_venv(venv)  # must not raise


def test_wipe_venv_renames_when_rmtree_fails(monkeypatch, tmp_path: Path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "file").write_text("x", encoding="utf-8")
    calls = {"n": 0}

    def flaky_rmtree(*args, **kwargs):
        calls["n"] += 1
        raise OSError("locked")

    monkeypatch.setattr(runtime_mod.shutil, "rmtree", flaky_rmtree)
    monkeypatch.setattr(runtime_mod.time, "sleep", lambda s: None)
    _t = [0.0]
    monkeypatch.setattr(runtime_mod.time, "time", lambda: (_t.__setitem__(0, _t[0] + 100.0) or _t[0]))
    runtime_mod._wipe_venv(venv)
    assert not venv.exists()
    backups = list(tmp_path.glob(".venv.stale.*"))
    assert len(backups) == 1


def test_setup_runtime_environment_reuses_healthy_venv(monkeypatch, tmp_path: Path):
    install_root = tmp_path / "install"
    install_root.mkdir()
    venv_dir = install_root / ".venv"
    scripts = venv_dir / ("Scripts" if main_mod.sys.platform == "win32" else "bin")
    scripts.mkdir(parents=True)
    py = scripts / ("python.exe" if main_mod.sys.platform == "win32" else "python")
    _fake_python_exe(py)

    from ida_pro_mcp.installer.common import InstallReport

    calls = {"venv": 0, "wipe": 0, "probe": 0}
    _fake_site = str(tmp_path / "fake_site")

    monkeypatch.setattr(runtime_mod, "_probe_venv", lambda p: (calls.__setitem__("probe", calls["probe"] + 1) or True))
    monkeypatch.setattr(
        runtime_mod,
        "run_checked",
        lambda cmd, **kwargs: calls.__setitem__("venv", calls["venv"] + 1)
        or subprocess.CompletedProcess(cmd, 0, stdout=_fake_site),
    )
    monkeypatch.setattr(runtime_mod, "_wipe_venv", lambda d: calls.__setitem__("wipe", calls["wipe"] + 1))

    py_path = runtime_mod.setup_runtime_environment(
        install_root=install_root,
        source_root=tmp_path,
        runtime_source="local",
        dry_run=False,
        report=InstallReport(),
    )
    assert py_path == py
    assert calls["probe"] == 2
    # Healthy venv: must NOT have wiped or re-created.
    assert calls["wipe"] == 0
    # We still ran pip / package install / smoke test.
    assert calls["venv"] >= 3


def test_setup_runtime_environment_wipes_stale_venv(monkeypatch, tmp_path: Path):
    install_root = tmp_path / "install"
    install_root.mkdir()
    venv_dir = install_root / ".venv"
    venv_dir.mkdir()  # exists but no python.exe inside — stale

    from ida_pro_mcp.installer.common import InstallReport

    calls = {"wipe": 0, "venv": 0}
    probe_calls = [False, True]

    monkeypatch.setattr(runtime_mod, "_probe_venv", lambda p: probe_calls.pop(0))
    monkeypatch.setattr(runtime_mod, "_wipe_venv", lambda d: calls.__setitem__("wipe", calls["wipe"] + 1) or (d.rmdir() if d.exists() else None))
    _fake_site = str(tmp_path / "fake_site")
    monkeypatch.setattr(
        runtime_mod,
        "run_checked",
        lambda cmd, **kwargs: calls.__setitem__("venv", calls["venv"] + 1)
        or subprocess.CompletedProcess(cmd, 0, stdout=_fake_site),
    )

    py = runtime_mod.setup_runtime_environment(
        install_root=install_root,
        source_root=tmp_path,
        dry_run=False,
        report=InstallReport(),
        runtime_source="local",
    )
    # Probe was called, venv was wiped, then re-created.
    assert calls["wipe"] == 1
    assert calls["venv"] >= 3
    assert py == venv_dir / ("Scripts/python.exe" if main_mod.sys.platform == "win32" else "bin/python")


def test_setup_runtime_environment_creates_missing_venv(monkeypatch, tmp_path: Path):
    install_root = tmp_path / "install"
    install_root.mkdir()

    from ida_pro_mcp.installer.common import InstallReport

    calls = {"venv": 0, "wipe": 0}

    _fake_site = str(tmp_path / "fake_site")
    monkeypatch.setattr(runtime_mod, "_probe_venv", lambda p: True)
    monkeypatch.setattr(runtime_mod, "_wipe_venv", lambda d: calls.__setitem__("wipe", calls["wipe"] + 1))
    monkeypatch.setattr(
        runtime_mod,
        "run_checked",
        lambda cmd, **kwargs: calls.__setitem__("venv", calls["venv"] + 1)
        or subprocess.CompletedProcess(cmd, 0, stdout=_fake_site),
    )

    runtime_mod.setup_runtime_environment(
        install_root=install_root,
        source_root=tmp_path,
        runtime_source="local",
        dry_run=False,
        report=InstallReport(),
    )
    assert calls["wipe"] == 0  # no stale venv to wipe
    assert calls["venv"] >= 3


def test_setup_runtime_environment_dry_run_short_circuits(tmp_path: Path):
    from ida_pro_mcp.installer.common import InstallReport

    install_root = tmp_path / "install"
    py = runtime_mod.setup_runtime_environment(
        install_root=install_root,
        source_root=tmp_path,
        runtime_source="local",
        dry_run=True,
        report=InstallReport(),
    )
    assert not (install_root / ".venv").exists()
    assert py.name in ("python.exe", "python")


def test_build_stdio_config_injects_policy_mode_off():
    from ida_pro_mcp.installer.runtime import build_stdio_config
    py = build_stdio_config(
        Path("/tmp/fake"),
        Path("/tmp/root"),
        disable_policy=True,
    )
    assert py["env"]["IDA_MCP_POLICY_MODE"] == "off"


def test_build_stdio_config_omits_policy_mode_by_default():
    from ida_pro_mcp.installer.runtime import build_stdio_config
    py = build_stdio_config(
        Path("/tmp/fake"),
        Path("/tmp/root"),
    )
    assert "IDA_MCP_POLICY_MODE" not in py["env"]


def test_parse_args_disable_policy_flag():
    from ida_pro_mcp.installer.main import parse_args
    opts = parse_args(["--disable-policy"])
    assert opts.disable_policy is True
    opts_default = parse_args([])
    assert opts_default.disable_policy is False
