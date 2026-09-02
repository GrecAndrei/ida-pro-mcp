"""Exercise lazy package exports without importing every optional backend."""

from __future__ import annotations

import importlib
import sys
import types

import pytest

from tests.fakes.ida_fake import FakeDatabase, install_fake_idb

install_fake_idb(FakeDatabase())


def test_ida_tools_package_lazy_mapping_and_errors(monkeypatch):
    package = importlib.import_module("ida_pro_mcp.ida_mcp.tools")
    loaded = []

    def fake_import(path, package_name):
        loaded.append((path, package_name))
        return types.SimpleNamespace(governance="governance-value", idb="idb-value")

    monkeypatch.setattr(package, "import_module", fake_import)
    monkeypatch.delitem(package.__dict__, "governance", raising=False)
    monkeypatch.delitem(package.__dict__, "idb", raising=False)
    assert package.__getattr__("governance") == "governance-value"
    assert package.__getattr__("idb") == "idb-value"
    assert loaded == [
        (".governance_engine", "ida_pro_mcp.ida_mcp.tools"),
        (".idb", "ida_pro_mcp.ida_mcp.tools"),
    ]
    assert "governance" in package.__dir__()
    with pytest.raises(AttributeError, match="not_a_tool"):
        package.__getattr__("not_a_tool")


def test_host_server_package_resolves_main_lazily(monkeypatch):
    package = importlib.import_module("ida_pro_mcp.host.server")
    package.__dict__.pop("main", None)
    sentinel = object()
    fake_server = types.ModuleType("ida_pro_mcp.host.server.server")
    fake_server.main = sentinel
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.server.server", fake_server)
    assert package.__getattr__("main") is sentinel
    assert "main" in package.__dir__()
    with pytest.raises(AttributeError, match="missing"):
        package.__getattr__("missing")
