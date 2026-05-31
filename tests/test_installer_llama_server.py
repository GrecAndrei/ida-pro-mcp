from __future__ import annotations

import tempfile
from pathlib import Path

from ida_pro_mcp.installer.common import InstallerOptions
from ida_pro_mcp.installer.main import parse_args, run_install, UI
from ida_pro_mcp.installer import runtime as runtime_mod
import ida_pro_mcp.installer.main as main_mod


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


def test_find_embed_model_no_home_fallback(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "home"
        downloads = home / "Downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        (downloads / "bge-code-v1-q8_0.gguf").write_text("x", encoding="utf-8")
        install_root = Path(td) / "install"
        install_root.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
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
