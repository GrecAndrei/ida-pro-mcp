"""Regression tests for p17_installer audit fixes.

Each test pins one behavior that the agent-blitz audit found broken and that
this package's fixer pass intentionally changed.  Files under test:

* installer/clients.py  — VS Code / Copilot CLI "servers" top-level key
* installer/runtime.py  — IDA_PRO_MCP_HOME, rerank opt-out, disable-policy env, IDA_MCP_R2_BIN
* installer/discovery.py — in-process binary version scan (no ``strings``)
* installer/main.py     — --disable-policy flag, wizard defaults, rerank decline, --with-r2/--sigs
* cli.py                — intelligence whitelist, background dispatch, timeouts
* server_script.py      — sys.modules restore, non-string tool, auth, error codes

WO-INST additions (paper §8.2 item 11 / §10.2 item 5e): ``--with-r2`` records
an rz/r2 binary as ``IDA_MCP_R2_BIN``; ``--sigs <dir>`` stages a FLIRT sig pack
into ``<IDADIR>/sig``.  Full coverage lives in
``tests/host/test_swarm_p10_installer.py``; the two tests here pin the CLI
contract so a regression cannot silently drop the flags.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import textwrap
import types as _stdlib_types
from pathlib import Path

import pytest

SRC_SERVER_SCRIPT = (
    Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "server_script.py"
)


_FAKE_SERVER = textwrap.dedent(
    """\
    import json
    import sys

    for line in sys.stdin:
        req = json.loads(line)
        method = req.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": req["params"].get("protocolVersion"),
                "capabilities": {},
                "serverInfo": {"name": "fake-mcp", "version": "0"},
            }
        elif method == "tools/call":
            params = req.get("params", {})
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "ok": True,
                                "tool": params.get("name"),
                                "arguments": params.get("arguments"),
                            }
                        ),
                    }
                ],
                "isError": False,
            }
        else:
            result = {"echoed_method": method, "echoed_params": req.get("params")}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\\n")
        sys.stdout.flush()
    """
)


@pytest.fixture
def fake_server_cmd(tmp_path, monkeypatch):
    """Point the CLI at a fake MCP server process (process boundary)."""
    from ida_pro_mcp import cli

    script = tmp_path / "fake_mcp_server.py"
    script.write_text(_FAKE_SERVER, encoding="utf-8")
    monkeypatch.setattr(cli, "_server_cmd", lambda: [sys.executable, "-u", str(script)])
    return str(script)


# ---------------------------------------------------------------------------
# installer.clients: Copilot-family configs use "servers" + type: stdio
# ---------------------------------------------------------------------------


def test_update_json_config_writes_under_servers_key(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    cfg_path = tmp_path / "mcp.json"
    cfg_path.write_text("{}", encoding="utf-8")
    ok = clients.update_json_config(
        cfg_path,
        "ida-pro-mcp",
        {"command": "/x/python", "args": ["-u"]},
        InstallReport(),
        dry_run=False,
        top_level_key="servers",
        server_type="stdio",
    )
    assert ok
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert "servers" in data
    assert "mcpServers" not in data
    entry = data["servers"]["ida-pro-mcp"]
    assert entry["type"] == "stdio"
    assert entry["command"] == "/x/python"


def test_update_json_config_default_still_uses_mcpservers(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    cfg_path = tmp_path / "mcp.json"
    cfg_path.write_text("{}", encoding="utf-8")
    ok = clients.update_json_config(
        cfg_path,
        "ida-pro-mcp",
        {"command": "/x/python", "args": ["-u"]},
        InstallReport(),
        dry_run=False,
    )
    assert ok
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "servers" not in data
    assert "type" not in data["mcpServers"]["ida-pro-mcp"]


def test_dry_run_client_config_does_not_create_parent_directories(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    path = tmp_path / "not-created" / "mcp.json"
    report = InstallReport()
    assert clients.update_json_config(
        path,
        "ida-pro-mcp",
        {"command": "/x/python"},
        report,
        dry_run=True,
    )
    assert not path.parent.exists()
    assert not path.exists()
    assert str(path) in report.modified_files


def test_legacy_copilot_wrapper_preserves_unparseable_config(tmp_path):
    import install

    path = tmp_path / "copilot" / "mcp.json"
    path.parent.mkdir()
    original = '{"keep": [}\n'
    path.write_text(original, encoding="utf-8")

    assert install._update_copilot_config(
        path,
        "ida-pro-mcp",
        {"command": "/x/python", "args": [], "env": {}},
    ) is False
    assert path.read_text(encoding="utf-8") == original


def test_legacy_antigravity_wrapper_does_not_leave_plugin_on_config_failure(tmp_path):
    import install

    path = tmp_path / "antigravity" / "mcp.json"
    path.parent.mkdir()
    original = '{"keep": [}\n'
    path.write_text(original, encoding="utf-8")

    assert install._write_antigravity_plugin(
        path,
        "ida-pro-mcp",
        {"command": "/x/python", "args": [], "env": {}},
    ) is False
    assert path.read_text(encoding="utf-8") == original
    assert not (path.parent / "plugin.json").exists()


def test_configure_clients_writes_vscode_copilot_under_servers(tmp_path, monkeypatch):
    """VS Code Copilot and Copilot CLI must be configured under top-level
    "servers" (their schema), not "mcpServers".  The client ida-pro-mcp is
    also tagged "type": "stdio", which those clients require."""
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    xdg = tmp_path / "config"
    xdg.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    # Isolate every {home}/{appdata} path so configure_clients never touches
    # the real user config.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    source_root = Path(clients.__file__).resolve().parent
    server_cfg = {"command": "/x/python", "args": ["-u"], "env": {}}
    configured = clients.configure_clients(
        source_root, server_cfg, InstallReport(), dry_run=False
    )

    assert "VS Code" in configured
    vscode_path = xdg / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json"
    vscode_data = json.loads(vscode_path.read_text(encoding="utf-8"))
    assert "servers" in vscode_data
    assert vscode_data["servers"]["ida-pro-mcp"]["type"] == "stdio"
    assert vscode_data["servers"]["ida-pro-mcp"]["command"] == "/x/python"

    assert "Copilot CLI" in configured
    copilot_path = xdg / "copilot" / "mcp-config.json"
    copilot_data = json.loads(copilot_path.read_text(encoding="utf-8"))
    assert "servers" in copilot_data
    assert copilot_data["servers"]["ida-pro-mcp"]["type"] == "stdio"


def test_client_configuration_summary_reports_partial_setup(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallReport

    monkeypatch.setattr(
        main_mod,
        "get_config_paths",
        lambda _source_root: {"first": tmp_path / "first", "second": tmp_path / "second"},
    )
    report = InstallReport()

    main_mod._report_client_configuration(
        tmp_path, ["first"], report, main_mod.UI()
    )

    assert report.steps[-1] == {
        "name": "clients",
        "status": "warn",
        "detail": "configured 1/2 clients",
    }
    assert "configured 1/2 clients" in report.warnings[-1]


# ---------------------------------------------------------------------------
# installer.runtime: env the spawned server inherits
# ---------------------------------------------------------------------------


def test_build_stdio_config_emits_install_root(tmp_path):
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(tmp_path / "python", tmp_path)
    assert cfg["env"]["IDA_PRO_MCP_HOME"] == str(tmp_path)


def test_build_stdio_config_rerank_disabled_wins_over_profile(tmp_path):
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(
        tmp_path / "python",
        tmp_path,
        rerank_profile="qwen3-reranker-0.6b",
        rerank_disabled=True,
    )
    assert cfg["env"].get("IDA_MCP_RERANK_DISABLED") == "1"
    assert "IDA_MCP_RERANK_PROFILE" not in cfg["env"]

    cfg2 = build_stdio_config(tmp_path / "python", tmp_path, rerank_profile="qwen3-reranker-4b")
    assert cfg2["env"].get("IDA_MCP_RERANK_PROFILE") == "qwen3-reranker-4b"
    assert "IDA_MCP_RERANK_DISABLED" not in cfg2["env"]


def test_build_stdio_config_disable_policy_env(tmp_path):
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(tmp_path / "python", tmp_path, disable_policy=True)
    assert cfg["env"].get("IDA_MCP_POLICY_MODE") == "off"

    cfg2 = build_stdio_config(tmp_path / "python", tmp_path)
    assert "IDA_MCP_POLICY_MODE" not in cfg2["env"]


# ---------------------------------------------------------------------------
# installer.discovery: version detection without the external `strings` tool
# ---------------------------------------------------------------------------


def test_detect_version_finds_build_string_without_strings_binary(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import discovery

    binary = tmp_path / "ida"
    payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 16
    payload += b"9.3.260421.be7de18d" + b"\x00" * 512
    binary.write_bytes(payload)

    def _no_strings(*args, **kwargs):
        raise OSError("strings tool unavailable on this platform")

    monkeypatch.setattr(discovery.subprocess, "run", _no_strings)
    assert discovery._detect_version(binary) == ((9, 3), "260421.be7de18d")


def test_detect_version_returns_none_for_unrelated_binary(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import discovery

    binary = tmp_path / "ida"
    binary.write_bytes(b"not an ida build at all" + b"\x00" * 64)

    def _no_strings(*args, **kwargs):
        raise OSError("strings tool unavailable")

    monkeypatch.setattr(discovery.subprocess, "run", _no_strings)
    assert discovery._detect_version(binary) is None


# ---------------------------------------------------------------------------
# installer.main: CLI flags and wizard defaults
# ---------------------------------------------------------------------------


def test_parse_args_disable_policy_flag():
    from ida_pro_mcp.installer.main import parse_args

    assert parse_args(["--yes", "--disable-policy"]).disable_policy is True
    assert parse_args(["--yes"]).disable_policy is False


def test_parse_args_no_embed_auto_flag():
    from ida_pro_mcp.installer.main import parse_args

    assert parse_args(["--no-embed-auto"]).embed_auto is False
    assert parse_args([]).embed_auto is True


def test_parse_args_with_r2_and_sigs_flags():
    """WO-INST: --with-r2 and --sigs <dir> must parse onto InstallerOptions."""
    from ida_pro_mcp.installer.main import parse_args

    opts = parse_args(["--with-r2", "--sigs", "/tmp/riscv64-sigpack"])
    assert opts.with_r2 is True
    assert opts.sigs_dir == "/tmp/riscv64-sigpack"
    assert parse_args([]).with_r2 is False
    assert parse_args([]).sigs_dir == ""


def test_parse_args_preserves_kill_scope_and_unverified_download_opt_in():
    from ida_pro_mcp.installer.main import parse_args

    opts = parse_args(
        [
            "--kill-ida",
            "--ida-binary-path",
            "/opt/ida/idat64",
            "--allow-unverified-downloads",
        ]
    )
    assert opts.ida_binary_path == "/opt/ida/idat64"
    assert opts.allow_unverified_downloads is True
    assert parse_args(["--verify-corpus"]).verify_bron_corpus is True


def test_prompt_secret_uses_hidden_terminal_input(monkeypatch):
    from ida_pro_mcp.installer import main as main_mod

    captured: dict[str, str] = {}

    def _getpass(prompt):
        captured["prompt"] = prompt
        return " secret-value "

    monkeypatch.setattr(main_mod.getpass, "getpass", _getpass)

    assert main_mod._prompt_secret("Gemini API key") == "secret-value"
    assert captured == {"prompt": "Gemini API key: "}


def test_build_stdio_config_records_r2_bin(tmp_path):
    """WO-INST: --with-r2 records the resolved engine as IDA_MCP_R2_BIN."""
    from ida_pro_mcp.installer.runtime import build_stdio_config

    cfg = build_stdio_config(tmp_path / "python", tmp_path, r2_bin="/usr/bin/rz")
    assert cfg["env"].get("IDA_MCP_R2_BIN") == "/usr/bin/rz"
    cfg2 = build_stdio_config(tmp_path / "python", tmp_path)
    assert "IDA_MCP_R2_BIN" not in cfg2["env"]


def test_wizard_embed_prompt_default_honors_no_embed_auto(tmp_path, monkeypatch):
    """A bare Enter on the embed-enable prompt must not silently flip an
    explicit --no-embed-auto opt-out back on."""
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "embed.gguf"
    model.write_bytes(b"x")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(model))
    opts = InstallerOptions(interactive=True, embed_auto=False, no_ida_prompt=True)
    monkeypatch.setattr(main_mod, "find_embed_model", lambda *a, **k: str(model))
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: "")
    monkeypatch.setattr(main_mod, "_prompt_yes_no", lambda q, default: default)
    monkeypatch.setattr(main_mod, "_prompt_choice", lambda q, choices, default: default)
    monkeypatch.setattr(main_mod, "_prompt_text", lambda q, default="": default)
    monkeypatch.setattr(main_mod, "_prompt_secret", lambda q: "")
    monkeypatch.setattr(main_mod, "_prompt_model_path", lambda profile: "")

    out = main_mod._run_interactive_wizard(opts, main_mod.UI())
    assert out.embed_auto is False


def test_wizard_gemini_still_requires_a_local_reranker_choice(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    opts = InstallerOptions(interactive=True, embed_backend="gemini")
    monkeypatch.setattr(main_mod, "find_embed_model", lambda *a, **k: "")
    monkeypatch.setattr(main_mod, "find_llama_server_bin", lambda *a, **k: "")
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: "")

    def _choice(question, choices, default):
        if question == "Embedding backend":
            return "gemini-embedding-2 (cloud, requires API key)"
        return default

    monkeypatch.setattr(main_mod, "_prompt_choice", _choice)
    monkeypatch.setattr(
        main_mod,
        "_prompt_yes_no",
        lambda question, default: False if "reranker" in question.lower() else default,
    )
    monkeypatch.setattr(main_mod, "_prompt_secret", lambda _question: "")
    monkeypatch.setattr(main_mod, "_prompt_text", lambda _question, default="": default)

    out = main_mod._run_interactive_wizard(opts, main_mod.UI())

    assert out.embed_backend == "gemini"
    assert out.rerank_disabled is True


def test_wizard_preserves_explicit_runtime_paths_over_discovery(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    explicit_model = tmp_path / "explicit-model.gguf"
    explicit_model.write_bytes(b"explicit")
    explicit_server = tmp_path / "explicit-server"
    explicit_server.write_bytes(b"explicit")
    explicit_reranker = tmp_path / "explicit-reranker.gguf"
    explicit_reranker.write_bytes(b"explicit")
    opts = InstallerOptions(
        interactive=True,
        embed_auto=True,
        embed_model_path=str(explicit_model),
        embed_server_bin=str(explicit_server),
        rerank_model_path=str(explicit_reranker),
    )
    monkeypatch.setattr(main_mod, "find_embed_model", lambda *a, **k: str(tmp_path / "auto-model.gguf"))
    monkeypatch.setattr(main_mod, "find_llama_server_bin", lambda *a, **k: str(tmp_path / "auto-server"))
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: str(tmp_path / "auto-reranker.gguf"))
    monkeypatch.setattr(main_mod, "_prompt_yes_no", lambda _question, default: default)
    monkeypatch.setattr(main_mod, "_prompt_choice", lambda _question, _choices, default: default)
    monkeypatch.setattr(main_mod, "_prompt_text", lambda _question, default="": default)
    monkeypatch.setattr(main_mod, "_prompt_secret", lambda _question: "")

    out = main_mod._run_interactive_wizard(opts, main_mod.UI())

    assert out.embed_model_path == str(explicit_model)
    assert out.embed_server_bin == str(explicit_server)
    assert out.rerank_model_path == str(explicit_reranker)


def test_noninteractive_gemini_install_persists_detected_reranker(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core as intel_core
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    install_root = tmp_path / "install"
    rerank_model = tmp_path / "reranker.gguf"
    rerank_model.write_bytes(b"reranker")
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=install_root,
        embed_backend="gemini",
        rerank_profile="qwen3-reranker-0.6b",
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: str(rerank_model))
    monkeypatch.setattr(main_mod, "get_config_paths", lambda _root: {"fake": tmp_path / "fake.json"})
    captured: dict = {}

    def _configure(**kwargs):
        captured["server_cfg"] = kwargs["server_cfg"]
        return ["fake"]

    monkeypatch.setattr(main_mod, "configure_clients", _configure)

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert captured["server_cfg"]["env"]["IDA_MCP_RERANK_MODEL"] == str(rerank_model)
    state = json.loads((install_root / "embedder.json").read_text(encoding="utf-8"))
    assert state["rerank"] == {
        "profile": "qwen3-reranker-0.6b",
        "model_path": str(rerank_model.resolve()),
    }


def test_noninteractive_gemini_install_disables_missing_reranker(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=tmp_path / "install",
        embed_backend="gemini",
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: "")
    monkeypatch.setattr(main_mod, "get_config_paths", lambda _root: {"fake": tmp_path / "fake.json"})
    captured: dict = {}

    def _configure(**kwargs):
        captured["server_cfg"] = kwargs["server_cfg"]
        return ["fake"]

    monkeypatch.setattr(main_mod, "configure_clients", _configure)

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    env = captured["server_cfg"]["env"]
    assert env["IDA_MCP_RERANK_DISABLED"] == "1"
    assert "IDA_MCP_RERANK_PROFILE" not in env


def test_noninteractive_rerank_download_is_honored_without_local_embedding(
    tmp_path, monkeypatch
):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    rerank_model = tmp_path / "downloaded-reranker.gguf"
    rerank_model.write_bytes(b"reranker")
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=tmp_path / "install",
        embed_auto=False,
        download_rerank_model=True,
        accept_model_license=True,
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: "")
    downloaded: dict[str, str] = {}

    def _download(root, profile):
        downloaded["root"] = str(root)
        downloaded["profile"] = profile
        return str(rerank_model)

    monkeypatch.setattr(main_mod, "download_rerank_model", _download)
    monkeypatch.setattr(main_mod, "get_config_paths", lambda _root: {})

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert downloaded == {
        "root": str(tmp_path / "install"),
        "profile": "qwen3-reranker-0.6b",
    }


@pytest.mark.parametrize("option_name", [
    "embed_model_path",
    "embed_server_bin",
    "rerank_model_path",
])
def test_noninteractive_install_rejects_missing_explicit_runtime_paths(
    tmp_path, monkeypatch, option_name
):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=tmp_path / "install",
        embed_auto=False,
    )
    setattr(opts, option_name, str(tmp_path / f"missing-{option_name}"))
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    monkeypatch.setattr(
        main_mod,
        "configure_clients",
        lambda **_kwargs: pytest.fail("invalid runtime path reached client configuration"),
    )

    assert main_mod.run_install(opts, main_mod.UI()) == 1


def test_noninteractive_install_persists_absolute_runtime_paths(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "model.gguf"
    model.write_bytes(b"embedding")
    reranker = tmp_path / "reranker.gguf"
    reranker.write_bytes(b"reranker")
    server = tmp_path / "llama-server"
    server.write_bytes(b"#!/bin/sh\n")
    server.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=tmp_path / "install",
        embed_auto=False,
        embed_model_path="model.gguf",
        embed_server_bin="llama-server",
        rerank_model_path="reranker.gguf",
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    captured: dict = {}

    def _configure(**kwargs):
        captured["env"] = kwargs["server_cfg"]["env"]
        return []

    monkeypatch.setattr(main_mod, "configure_clients", _configure)

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert captured["env"]["IDA_MCP_EMBED_MODEL"] == str(model)
    assert captured["env"]["IDA_MCP_EMBED_SERVER_BIN"] == str(server)
    assert captured["env"]["IDA_MCP_RERANK_MODEL"] == str(reranker)


def test_noninteractive_install_normalizes_relative_install_root(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    monkeypatch.chdir(tmp_path)
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=Path("install"),
        embed_auto=False,
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    captured: dict = {}

    def _configure(**kwargs):
        captured["env"] = kwargs["server_cfg"]["env"]
        return []

    monkeypatch.setattr(main_mod, "configure_clients", _configure)

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert opts.install_root == tmp_path / "install"
    assert captured["env"]["IDA_PRO_MCP_HOME"] == str(tmp_path / "install")


def test_embedder_doctor_honors_custom_root_and_gemini_overrides(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core as intel_core
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    observed: dict[str, str] = {}

    class _FakeEmbedder:
        _instance = object()

        def __init__(self):
            for name in (
                "IDA_PRO_MCP_HOME",
                "IDA_MCP_EMBED_BACKEND",
                "IDA_MCP_GEMINI_MODEL",
                "IDA_MCP_GEMINI_DIM",
                "IDA_MCP_GEMINI_VERTEX",
                "GEMINI_API_KEY",
                "GOOGLE_CLOUD_PROJECT",
                "VERTEX_AI_LOCATION",
            ):
                observed[name] = os.environ.get(name, "")

        def status(self, *, probe, deep_hash):
            assert probe is True
            assert deep_hash is False
            return {"ready": True, "backend": "gemini"}

        def embed_vector(self, _text):
            return [0.1, 0.2]

    monkeypatch.setattr(intel_core, "BgeCodeEmbedder", _FakeEmbedder)
    opts = InstallerOptions(
        embedder_doctor=True,
        install_root=tmp_path / "custom-install",
        embed_backend="gemini",
        gemini_access="vertex",
        gemini_api_key="doctor-key",
        gemini_model="gemini-test",
        gemini_dim=321,
        gemini_vertex_project="doctor-project",
        gemini_vertex_location="europe-west4",
    )

    assert main_mod.run_embedder_doctor(opts, main_mod.UI()) == 0
    assert observed == {
        "IDA_PRO_MCP_HOME": str(tmp_path / "custom-install"),
        "IDA_MCP_EMBED_BACKEND": "gemini",
        "IDA_MCP_GEMINI_MODEL": "gemini-test",
        "IDA_MCP_GEMINI_DIM": "321",
        "IDA_MCP_GEMINI_VERTEX": "1",
        "GEMINI_API_KEY": "doctor-key",
        "GOOGLE_CLOUD_PROJECT": "doctor-project",
        "VERTEX_AI_LOCATION": "europe-west4",
    }


def test_wizard_rerank_decline_persists_rerank_disabled(tmp_path, monkeypatch):
    """Declining the reranker in the wizard must set rerank_disabled so the
    default profile cannot leak into state / client env."""
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "embed.gguf"
    model.write_bytes(b"x")
    rerank_model = tmp_path / "rerank.gguf"
    rerank_model.write_bytes(b"y")
    opts = InstallerOptions(interactive=True, embed_auto=True)
    monkeypatch.setattr(main_mod, "find_embed_model", lambda *a, **k: str(model))
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: str(rerank_model))

    def _yn(question, default):
        if "Enable reranker" in question:
            return False
        return default

    monkeypatch.setattr(main_mod, "_prompt_yes_no", _yn)
    monkeypatch.setattr(main_mod, "_prompt_choice", lambda q, choices, default: default)
    monkeypatch.setattr(main_mod, "_prompt_text", lambda q, default="": default)
    monkeypatch.setattr(main_mod, "_prompt_secret", lambda q: "")
    monkeypatch.setattr(main_mod, "_prompt_model_path", lambda profile: "")

    out = main_mod._run_interactive_wizard(opts, main_mod.UI())
    assert out.rerank_disabled is True
    assert out.rerank_model_path == ""


def test_wizard_rerank_enable_pins_model_path(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "embed.gguf"
    model.write_bytes(b"x")
    rerank_model = tmp_path / "rerank.gguf"
    rerank_model.write_bytes(b"y")
    opts = InstallerOptions(interactive=True, embed_auto=True)
    monkeypatch.setattr(main_mod, "find_embed_model", lambda *a, **k: str(model))
    monkeypatch.setattr(main_mod, "find_rerank_model", lambda *a, **k: str(rerank_model))
    monkeypatch.setattr(main_mod, "_prompt_yes_no", lambda q, default: default)
    monkeypatch.setattr(main_mod, "_prompt_choice", lambda q, choices, default: default)
    monkeypatch.setattr(main_mod, "_prompt_text", lambda q, default="": default)
    monkeypatch.setattr(main_mod, "_prompt_secret", lambda q: "")
    monkeypatch.setattr(main_mod, "_prompt_model_path", lambda profile: "")

    out = main_mod._run_interactive_wizard(opts, main_mod.UI())
    assert out.rerank_disabled is False
    assert out.rerank_model_path == str(rerank_model)


def test_run_install_rerank_decline_persists_no_rerank_state(tmp_path, monkeypatch):
    """A declined reranker must yield rerank=None in embedder.json (no
    profile pin) instead of silently defaulting the profile."""
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "embed.gguf"
    model.write_bytes(b"x")
    install_root = tmp_path / "install"
    install_root.mkdir()
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=install_root,
        embed_auto=True,
        embed_model_path=str(model),
        rerank_disabled=True,
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    recorded: dict = {}

    def _fake_wes(install_root, **kwargs):
        recorded.update(kwargs)
        return str(tmp_path / "embedder.json")

    # Import the module explicitly so the patch targets the module object that
    # run_install's local `from ... import write_embedder_state` will see.  The
    # autouse _isolate_sys_modules fixture drops core from sys.modules between
    # tests, which would otherwise leave monkeypatch patching a stale copy.
    import ida_pro_mcp.host.intelligence.core as intel_core

    monkeypatch.setattr(intel_core, "write_embedder_state", _fake_wes)
    monkeypatch.setattr(main_mod, "configure_clients", lambda *a, **k: [])

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert recorded["rerank"] is None


def test_run_install_rerank_enabled_persists_state(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallerOptions

    model = tmp_path / "embed.gguf"
    model.write_bytes(b"x")
    rerank_model = tmp_path / "rerank.gguf"
    rerank_model.write_bytes(b"y")
    install_root = tmp_path / "install"
    install_root.mkdir()
    opts = InstallerOptions(
        interactive=False,
        only={"clients"},
        install_root=install_root,
        embed_auto=True,
        embed_model_path=str(model),
        rerank_disabled=False,
        rerank_model_path=str(rerank_model),
        rerank_profile="qwen3-reranker-0.6b",
    )
    monkeypatch.setattr(main_mod, "detect_ida_installs", list)
    recorded: dict = {}

    def _fake_wes(install_root, **kwargs):
        recorded.update(kwargs)
        return str(tmp_path / "embedder.json")

    import ida_pro_mcp.host.intelligence.core as intel_core

    monkeypatch.setattr(intel_core, "write_embedder_state", _fake_wes)
    monkeypatch.setattr(main_mod, "configure_clients", lambda *a, **k: [])

    assert main_mod.run_install(opts, main_mod.UI()) == 0
    assert recorded["rerank"] == {
        "profile": "qwen3-reranker-0.6b",
        "model_path": str(rerank_model),
    }


# ---------------------------------------------------------------------------
# cli.py: intelligence whitelist, background dispatch, wait timeout
# ---------------------------------------------------------------------------


def test_intelligence_semantic_search_is_allowed(fake_server_cmd, capsys):
    from ida_pro_mcp import cli

    assert cli.main(["intelligence", "semantic_search", '{"query":"decrypt"}']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["arguments"]["action"] == "semantic_search"


def test_intelligence_reranker_status_is_allowed(fake_server_cmd, capsys):
    from ida_pro_mcp import cli

    assert cli.main(["intelligence", "reranker_status"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["arguments"]["action"] == "reranker_status"


def test_intelligence_evidence_card_rejected(fake_server_cmd):
    from ida_pro_mcp import cli

    with pytest.raises(SystemExit, match="unsupported intelligence action"):
        cli.main(["intelligence", "evidence_card", "{}"])


def test_background_mode_does_not_spawn_stdio_server(monkeypatch, capsys):
    """background mode must only talk to the daemon socket — booting the whole
    host stdio server per call is wasteful and can fail where the daemon
    would work."""
    from ida_pro_mcp import cli

    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    calls = []
    monkeypatch.setattr(
        cli,
        "_daemon_call",
        lambda tool_name, args, *, timeout=30.0: (
            calls.append((tool_name, args, timeout)),
            {"result": {"content": [], "isError": False}},
        )[1],
    )

    def _boom_server_cmd():
        raise AssertionError("background mode must not build the stdio server cmd")

    monkeypatch.setattr(cli, "_server_cmd", _boom_server_cmd)
    assert cli.main(["background", "status"]) == 0
    assert calls[0][0] == "background"
    assert calls[0][1]["action"] == "status"


def test_background_wait_uses_longer_socket_timeout(monkeypatch, capsys):
    from ida_pro_mcp import cli

    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    captured: dict = {}
    monkeypatch.setattr(
        cli,
        "_daemon_call",
        lambda tool_name, args, *, timeout=30.0: (
            captured.update(timeout=timeout),
            {"result": {"content": [], "isError": False}},
        )[1],
    )
    assert cli.main(["background", "wait", '{"task_id":"t1","timeout":120}']) == 0
    # user timeout 120s + grace => the socket recv window must outlive the daemon
    assert captured["timeout"] == 150.0


def test_background_wait_without_timeout_blocks(monkeypatch, capsys):
    from ida_pro_mcp import cli

    monkeypatch.setattr(cli, "_daemon_is_running", lambda: True)
    captured: dict = {}
    monkeypatch.setattr(
        cli,
        "_daemon_call",
        lambda tool_name, args, *, timeout=30.0: (
            captured.update(timeout=timeout),
            {"result": {"content": [], "isError": False}},
        )[1],
    )
    assert cli.main(["background", "wait", '{"task_id":"t1"}']) == 0
    assert captured["timeout"] is None  # block until the task finishes


# ---------------------------------------------------------------------------
# server_script.py: sys.modules restore, request validation, auth, error codes
# ---------------------------------------------------------------------------


@pytest.fixture
def server_script_module(tmp_path, monkeypatch):
    """Load server_script.py with fake IDA modules so it imports outside IDA."""
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SESSION_TOKEN", raising=False)
    for name in ("ida_segment", "idautils", "idc"):
        monkeypatch.setitem(sys.modules, name, _stdlib_types.ModuleType(name))
    spec = importlib.util.spec_from_file_location(
        "ida_pro_mcp_server_script_under_test", str(SRC_SERVER_SCRIPT)
    )
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


def test_server_script_env_values_fall_back_to_safe_listener_and_analysis_defaults(
    server_script_module, monkeypatch
):
    mod = server_script_module

    for raw in ("not-a-port", "-1", "65536"):
        monkeypatch.setenv("IDA_MCP_PORT", raw)
        assert mod._resolve_port() == 13337
    monkeypatch.setenv("IDA_MCP_PORT", "0")
    assert mod._resolve_port() == 0

    for raw in ("not-a-timeout", "nan", "inf", "-inf"):
        monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", raw)
        assert mod._startup_analysis_timeout() == 120.0
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "2")
    assert mod._startup_analysis_timeout() == 5.0
    monkeypatch.setenv("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "900")
    assert mod._startup_analysis_timeout() == 600.0


def test_load_tools_restores_stdlib_types(server_script_module, tmp_path, monkeypatch):
    mod = server_script_module
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "__init__.py").write_text("", encoding="utf-8")
    (tools_dir / "types.py").write_text(
        "def types():\n    return 'shadow'\n", encoding="utf-8"
    )
    before = sys.modules.get("types")
    monkeypatch.setattr(mod, "_mcp_root", str(tmp_path))
    mod.load_tools()
    # The flat load of tools/types.py must not leave stdlib 'types' shadowed;
    # the later `from types import UnionType` (zeromcp) depends on it.
    assert sys.modules["types"] is before


def test_process_single_non_string_tool_returns_error(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_SESSION_TOKEN", "secret")
    res = mod.process_single({"tool": {"bad": "dict"}, "session_token": "secret"})
    assert res["error"] is True
    assert res["code"] == "INVALID_REQUEST"


def test_process_single_unhashable_tool_does_not_crash(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_SESSION_TOKEN", "secret")
    res = mod.process_single({"tool": ["a", "b"], "session_token": "secret"})
    assert res["error"] is True
    assert res["code"] == "INVALID_REQUEST"


def test_mandatory_auth_refuses_tool_calls_without_token(server_script_module):
    mod = server_script_module
    assert mod._SESSION_TOKEN == ""
    res = mod.process_single({"tool": "analysis", "args": {"action": "status"}})
    assert res["error"] is True
    assert res["code"] == "UNAUTHORIZED"


def test_mandatory_auth_rejects_bad_token(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_SESSION_TOKEN", "secret")
    res = mod.process_single({"tool": "analysis", "session_token": "wrong"})
    assert res["error"] is True
    assert res["code"] == "UNAUTHORIZED"


def test_ping_always_allowed(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_BOUND_PORT", 4321)
    res = mod.process_single({"type": "ping"})
    assert res.get("pong") is True
    assert res.get("port") == 4321


def test_process_single_internal_failure_is_not_invalid_args(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_SESSION_TOKEN", "secret")

    def _boom(**args):
        raise RuntimeError("decompiler exploded")

    monkeypatch.setattr(mod, "TOOLS", {"analysis": _boom})
    res = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert res["error"] is True
    assert res["code"] == "UNKNOWN_ERROR"
    assert "request arguments" in res.get("hint", "")


def test_process_single_arg_error_still_invalid_args(server_script_module, monkeypatch):
    mod = server_script_module
    monkeypatch.setattr(mod, "_SESSION_TOKEN", "secret")

    def _boom(**args):
        raise TypeError("foo() got an unexpected keyword argument 'bogus'")

    monkeypatch.setattr(mod, "TOOLS", {"analysis": _boom})
    res = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert res["error"] is True
    assert res["code"] == "INVALID_ARGS"


def test_snapshot_source_ignores_sockets_and_temp_dirs(tmp_path):
    import socket

    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import _snapshot_source

    source_root = tmp_path / "src_root"
    source_root.mkdir()
    (source_root / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")

    tmp_audit = source_root / ".tmp-audit" / "sub"
    tmp_audit.mkdir(parents=True)
    sock_path = tmp_audit / "daemon.sock"

    normal_dir = source_root / "normal_dir"
    normal_dir.mkdir()
    (normal_dir / "file.txt").write_text("hello", encoding="utf-8")
    unnamed_sock = normal_dir / "ipc_endpoint"

    try:
        s1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s1.bind(str(sock_path))
        s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s2.bind(str(unnamed_sock))
    except Exception:
        pytest.skip("AF_UNIX sockets not supported on this platform")

    install_root = tmp_path / "install_root"
    report = InstallReport()

    target = _snapshot_source(source_root, install_root, dry_run=False, report=report)

    assert target.exists()
    assert (target / "pyproject.toml").exists()
    assert (target / "normal_dir" / "file.txt").exists()
    assert not (target / ".tmp-audit").exists()
    assert not (target / "normal_dir" / "ipc_endpoint").exists()

    s1.close()
    s2.close()


def test_snapshot_source_does_not_follow_checkout_symlinks(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import _snapshot_source

    source_root = tmp_path / "src_root"
    source_root.mkdir()
    (source_root / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("do not copy", encoding="utf-8")
    (source_root / "linked-secrets").symlink_to(outside, target_is_directory=True)

    target = _snapshot_source(
        source_root,
        tmp_path / "install_root",
        dry_run=False,
        report=InstallReport(),
    )

    assert not (target / "linked-secrets").exists()
