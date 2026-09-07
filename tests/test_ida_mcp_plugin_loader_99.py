"""Tests for src/ida_pro_mcp/ida_mcp.py plugin loader."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_ida_mcp_plugin_lifecycle(monkeypatch):
    fake_idaapi = types.ModuleType("idaapi")
    fake_idaapi.PLUGIN_KEEP = 1
    fake_idaapi.PLUGIN_HIDE = 2
    fake_idaapi.PLUGIN_FIX = 4

    class FakePluginT:
        pass

    fake_idaapi.plugin_t = FakePluginT
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)

    fake_pkg = types.ModuleType("ida_mcp")
    mock_server = MagicMock()
    fake_pkg.MCP_SERVER = mock_server
    fake_pkg.IdaMcpHttpRequestHandler = object
    monkeypatch.setitem(sys.modules, "ida_mcp", fake_pkg)

    plugin_path = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"
    spec = importlib.util.spec_from_file_location("ida_pro_mcp.ida_mcp", str(plugin_path))
    assert spec is not None and spec.loader is not None
    loader = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp", loader)
    spec.loader.exec_module(loader)

    # Test unload_package directly
    child_name = "ida_mcp.child"
    monkeypatch.setitem(sys.modules, child_name, types.ModuleType(child_name))
    loader.unload_package("ida_mcp")
    assert child_name not in sys.modules

    # Restore fake_pkg and stub unload_package during run
    monkeypatch.setitem(sys.modules, "ida_mcp", fake_pkg)
    monkeypatch.setattr(loader, "unload_package", lambda _name: None)

    plugin = loader.PLUGIN_ENTRY()
    assert isinstance(plugin, loader.MCP)

    monkeypatch.setattr(sys, "platform", "linux")
    assert plugin.init() == fake_idaapi.PLUGIN_KEEP
    monkeypatch.setattr(sys, "platform", "darwin")
    assert plugin.init() == fake_idaapi.PLUGIN_KEEP

    plugin.run(0)
    assert plugin.mcp is mock_server
    assert mock_server.serve.called

    old_server = mock_server
    new_server = MagicMock()
    fake_pkg.MCP_SERVER = new_server
    plugin.run(0)
    assert old_server.stop.called
    assert plugin.mcp is new_server

    plugin.term()
    assert new_server.stop.called

    failing_server = MagicMock()
    def fail_port(*args, **kwargs):
        err = OSError("in use")
        err.errno = 98
        raise err
    failing_server.serve.side_effect = fail_port
    fake_pkg.MCP_SERVER = failing_server
    plugin.run(0)
    assert plugin.mcp is None

    unexp_server = MagicMock()
    def fail_unexp(*args, **kwargs):
        err = OSError("fatal")
        err.errno = 13
        raise err
    unexp_server.serve.side_effect = fail_unexp
    fake_pkg.MCP_SERVER = unexp_server
    with pytest.raises(OSError, match="fatal"):
        plugin.run(0)
