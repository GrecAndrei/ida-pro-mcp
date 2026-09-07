"""Offline lifecycle matrix for the IDA plugin wrapper."""

from __future__ import annotations

import runpy
import sys
import types
from pathlib import Path


def _load_plugin(monkeypatch, server):
    idaapi = types.ModuleType("idaapi")
    idaapi.PLUGIN_KEEP = 1
    idaapi.PLUGIN_HIDE = 2
    idaapi.PLUGIN_FIX = 4
    idaapi.plugin_t = type("plugin_t", (), {})
    package = types.ModuleType("ida_mcp")
    package.MCP_SERVER = server
    package.IdaMcpHttpRequestHandler = object
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_mcp", package)
    import importlib.util

    plugin_path = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"
    spec = importlib.util.spec_from_file_location("ida_pro_mcp.ida_mcp", str(plugin_path))
    loader = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp", loader)
    spec.loader.exec_module(loader)
    real_unload = loader.unload_package
    loader.unload_package = lambda _name: None
    ns = vars(loader).copy()
    ns["_real_unload_package"] = real_unload
    return ns


class _Server:
    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.stopped = 0

    def serve(self, host, port, request_handler):
        self.calls.append((host, port, request_handler))
        if self.error:
            raise OSError(self.error, "bind failed")

    def stop(self):
        self.stopped += 1


def test_plugin_init_restart_and_term_cover_platform_and_existing_server(monkeypatch):
    server = _Server()
    namespace = _load_plugin(monkeypatch, server)
    monkeypatch.setattr(sys, "platform", "darwin")
    plugin = namespace["PLUGIN_ENTRY"]()
    assert plugin.init() == 1
    plugin.mcp = server
    plugin.run(0)
    assert server.stopped == 1
    assert plugin.mcp is server
    plugin.term()
    assert server.stopped == 2
    plugin.mcp = None
    plugin.term()


def test_plugin_reports_port_exhaustion_without_leaking_a_server(monkeypatch, capsys):
    server = _Server(error=98)
    namespace = _load_plugin(monkeypatch, server)
    plugin = namespace["MCP"]()
    plugin.init()
    plugin.MAX_PORT_TRIES = 2
    plugin.run(0)
    assert plugin.mcp is None
    assert [call[1] for call in server.calls] == [13337, 13338]
    assert "Could not find available port" in capsys.readouterr().out


def test_plugin_with_no_port_attempts_is_a_noop(monkeypatch):
    server = _Server()
    namespace = _load_plugin(monkeypatch, server)
    plugin = namespace["MCP"]()
    plugin.init()
    plugin.MAX_PORT_TRIES = 0
    plugin.run(0)
    assert server.calls == []
    assert plugin.mcp is None


def test_plugin_unload_package(monkeypatch):
    server = _Server()
    namespace = _load_plugin(monkeypatch, server)
    unload_package = namespace["_real_unload_package"]
    monkeypatch.setitem(sys.modules, "dummy_pkg", types.ModuleType("dummy_pkg"))
    monkeypatch.setitem(sys.modules, "dummy_pkg.sub", types.ModuleType("dummy_pkg.sub"))
    monkeypatch.setitem(sys.modules, "other_pkg", types.ModuleType("other_pkg"))
    unload_package("dummy_pkg")
    assert "dummy_pkg" not in sys.modules
    assert "dummy_pkg.sub" not in sys.modules
    assert "other_pkg" in sys.modules


def test_plugin_run_raises_unexpected_oserror(monkeypatch):
    import pytest
    server = _Server(error=13)
    namespace = _load_plugin(monkeypatch, server)
    plugin = namespace["MCP"]()
    plugin.init()
    with pytest.raises(OSError):
        plugin.run(0)
