"""Regression tests for p17_installer audit fixes.

Each test pins one behavior that the agent-blitz audit found broken and that
this package's fixer pass intentionally changed.  Files under test:

* installer/clients.py  — VS Code / Copilot CLI "servers" top-level key
* installer/runtime.py  — IDA_PRO_MCP_HOME, rerank opt-out, disable-policy env
* installer/discovery.py — in-process binary version scan (no ``strings``)
* installer/main.py     — --disable-policy flag, wizard defaults, rerank decline, --sigs
* cli.py                — intelligence whitelist, background dispatch, timeouts
* server_script.py      — sys.modules restore, non-string tool, auth, error codes

The ``--sigs <dir>`` installer option stages a FLIRT signature pack into
``<IDADIR>/sig``; focused staging coverage lives in the installer test suite.
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


def test_checkout_client_map_preserves_copilot_servers_schema():
    from ida_pro_mcp.installer.clients import load_client_map

    repo_root = Path(__file__).resolve().parents[1]
    client_map = load_client_map(repo_root)

    for client in ("Copilot CLI", "VS Code"):
        assert client_map[client]["json"] == {
            "top_level_key": "servers",
            "type": "stdio",
        }


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
    # A dry-run describes planned steps without claiming that a file was
    # modified; the target does not exist and no write occurred.
    assert str(path) not in report.modified_files


def test_empty_client_path_environment_overrides_use_platform_defaults(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import clients

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("APPDATA", "")

    paths = clients.get_config_paths(Path(__file__).resolve().parents[1])

    assert paths["VS Code"] == home / ".config" / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json"
    assert paths["Claude Desktop"] == home / ".config" / "Claude" / "claude_desktop_config.json"


def test_blank_client_path_environment_overrides_use_platform_defaults(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import clients

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("OPENCODE_CONFIG", "   ")
    monkeypatch.setenv("XDG_CONFIG_HOME", "")

    paths = clients.get_config_paths(Path(__file__).resolve().parents[1])

    assert paths["OpenCode"] == home / ".config" / "opencode" / "opencode.json"


def test_client_path_environment_overrides_expand_environment_paths(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import clients

    monkeypatch.setenv("CLIENT_CONFIG_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENCODE_CONFIG", "$CLIENT_CONFIG_ROOT/opencode.json")

    paths = clients.get_config_paths(Path(__file__).resolve().parents[1])

    assert paths["OpenCode"] == tmp_path / "opencode.json"


def test_client_path_selection_skips_non_file_placeholder_for_fallback(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import clients

    home = tmp_path / "home"
    xdg = tmp_path / "config"
    home.mkdir()
    xdg.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))

    preferred = xdg / "copilot" / "mcp-config.json"
    preferred.mkdir(parents=True)
    fallback = home / ".copilot" / "mcp-config.json"
    fallback.parent.mkdir(parents=True)
    fallback.write_text("{}", encoding="utf-8")

    paths = clients.get_config_paths(Path(__file__).resolve().parents[1])

    assert paths["Copilot CLI"] == fallback


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


def test_legacy_server_config_selects_disabled_intelligence_explicitly(tmp_path):
    import install

    config = install.get_mcp_server_config(tmp_path)

    assert config["env"]["IDA_MCP_INTELLIGENCE_MODE"] == "disabled"


def test_legacy_server_config_normalizes_relative_install_path(tmp_path, monkeypatch):
    import install

    monkeypatch.chdir(tmp_path)
    config = install.get_mcp_server_config(Path("install"))

    assert config["command"] == str(tmp_path / "install" / ".venv" / "bin" / "python")
    assert config["env"]["IDA_PRO_MCP_HOME"] == str(tmp_path / "install")


def test_legacy_server_config_expands_environment_install_path(tmp_path, monkeypatch):
    import install

    monkeypatch.setenv("LEGACY_INSTALL_ROOT", str(tmp_path / "install"))

    config = install.get_mcp_server_config(Path("$LEGACY_INSTALL_ROOT"))

    assert config["command"] == str(
        tmp_path / "install" / ".venv" / "bin" / "python"
    )
    assert config["env"]["IDA_PRO_MCP_HOME"] == str(tmp_path / "install")


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


def test_client_configuration_summary_marks_dry_run_as_planned(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallReport

    monkeypatch.setattr(
        main_mod,
        "get_config_paths",
        lambda _source_root: {"first": tmp_path / "first"},
    )
    report = InstallReport()

    main_mod._report_client_configuration(
        tmp_path, ["first"], report, main_mod.UI(), dry_run=True
    )

    assert report.steps[-1] == {
        "name": "clients",
        "status": "dry-run",
        "detail": "would configure 1 clients",
    }
    assert report.warnings == []


def test_client_configuration_summary_fails_when_all_updates_fail(tmp_path):
    from ida_pro_mcp.installer import main as main_mod
    from ida_pro_mcp.installer.common import InstallReport

    report = InstallReport()
    report.add_warning("client update failed")
    report.metadata["client_update_failures"] = ["fake-client"]

    with pytest.raises(RuntimeError, match="no supported client was configured"):
        main_mod._report_client_configuration(tmp_path, [], report, main_mod.UI())


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
        "ida_pro_mcp.server_script", str(SRC_SERVER_SCRIPT)
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


def test_snapshot_source_ignores_pytest_tmp(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import _snapshot_source

    source_root = tmp_path / "src_root"
    source_root.mkdir()
    (source_root / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    junk = source_root / ".pytest_tmp" / "test_something0"
    junk.mkdir(parents=True)
    (junk / "fake-model.gguf").write_text("junk", encoding="utf-8")

    target = _snapshot_source(
        source_root, tmp_path / "install_root", dry_run=False, report=InstallReport()
    )

    assert target.exists()
    assert (target / "pyproject.toml").exists()
    assert not (target / ".pytest_tmp").exists()
