"""Boundary coverage for the optional idalib worker entry point."""

from __future__ import annotations

import importlib
import sys
import types

import pytest


def _worker():
    sys.modules.pop("ida_pro_mcp.idalib_worker", None)
    return importlib.import_module("ida_pro_mcp.idalib_worker")


def _exit_capture(monkeypatch, mod):
    calls = []

    def fail(code, message):
        calls.append((code, message))
        raise SystemExit(code)

    monkeypatch.setattr(mod, "_exit", fail)
    return calls


def test_missing_idapro_is_actionable(monkeypatch):
    mod = _worker()
    calls = []

    def fail(code, message):
        calls.append((code, message))
        raise SystemExit(code)

    monkeypatch.setattr(mod, "_exit", fail)
    monkeypatch.delitem(sys.modules, "idapro", raising=False)
    # The worker uses a direct import statement, so make the import fail by
    # installing a module finder that raises only for idapro.
    class _NoIdapro:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "idapro":
                raise ImportError("no idalib")

    monkeypatch.setattr(sys, "meta_path", [_NoIdapro(), *sys.meta_path])
    with pytest.raises(SystemExit):
        mod.main()
    assert calls and calls[0][0] == 3
    assert "idapro unavailable" in calls[0][1]


def test_invalid_open_spec_is_rejected(monkeypatch):
    mod = _worker()
    monkeypatch.setitem(sys.modules, "idapro", types.ModuleType("idapro"))
    monkeypatch.setenv("IDA_MCP_IDALIB_OPEN", "{")
    calls = _exit_capture(monkeypatch, mod)
    with pytest.raises(SystemExit):
        mod.main()
    assert calls[0][0] == 3
    assert "invalid IDA_MCP_IDALIB_OPEN" in calls[0][1]


def test_missing_database_is_rejected(monkeypatch):
    mod = _worker()
    monkeypatch.setitem(sys.modules, "idapro", types.ModuleType("idapro"))
    monkeypatch.setenv("IDA_MCP_IDALIB_OPEN", "{}")
    monkeypatch.delenv("IDA_MCP_IDB_PATH", raising=False)
    calls = _exit_capture(monkeypatch, mod)
    with pytest.raises(SystemExit):
        mod.main()
    assert "no database file" in calls[0][1]


@pytest.mark.parametrize(
    ("rc", "needle"),
    [(2, "output .i64 exists"), (1, "open_database failed with rc=1")],
)
def test_open_database_return_codes_include_context(monkeypatch, rc, needle):
    mod = _worker()
    ida = types.ModuleType("idapro")
    ida.open_database = lambda *args, **kwargs: rc
    monkeypatch.setitem(sys.modules, "idapro", ida)
    monkeypatch.setenv(
        "IDA_MCP_IDALIB_OPEN",
        '{"file": "sample.bin", "args": "-o sample.i64"}',
    )
    calls = _exit_capture(monkeypatch, mod)
    with pytest.raises(SystemExit):
        mod.main()
    assert calls[0][0] == 3
    assert needle in calls[0][1]


def test_open_exception_and_missing_server_script(monkeypatch):
    mod = _worker()
    ida = types.ModuleType("idapro")
    ida.open_database = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("open boom"))
    monkeypatch.setitem(sys.modules, "idapro", ida)
    monkeypatch.setenv("IDA_MCP_IDALIB_OPEN", '{"file": "sample.bin"}')
    calls = _exit_capture(monkeypatch, mod)
    with pytest.raises(SystemExit):
        mod.main()
    assert "open_database raised" in calls[0][1]

    ida.open_database = lambda *args, **kwargs: 0
    calls.clear()
    monkeypatch.delenv("IDA_MCP_SERVER_SCRIPT", raising=False)
    monkeypatch.setenv("IDA_MCP_IDALIB_OPEN", '{"file": "sample.bin"}')
    with pytest.raises(SystemExit):
        mod.main()
    assert "no server_script" in calls[0][1]


def test_script_lifecycle_closes_database_even_on_script_failure(monkeypatch, tmp_path, capsys):
    mod = _worker()
    script = tmp_path / "server_script.py"
    script.write_text("raise RuntimeError('script boom')\n", encoding="utf-8")
    calls = []
    ida = types.ModuleType("idapro")
    ida.open_database = lambda *args, **kwargs: calls.append(("open", args, kwargs)) or 0
    ida.close_database = lambda **kwargs: calls.append(("close", kwargs))
    monkeypatch.setitem(sys.modules, "idapro", ida)
    monkeypatch.setenv(
        "IDA_MCP_IDALIB_OPEN",
        '{"file": "sample.bin", "skip_analysis": true}',
    )
    monkeypatch.setenv("IDA_MCP_SERVER_SCRIPT", str(script))
    with pytest.raises(SystemExit) as exc:
        mod.main()
    assert exc.value.code == 0
    assert calls[0][0] == "open"
    assert calls[0][1][1] is False
    assert calls[-1] == ("close", {"save": True})
    assert "script exited with error" in capsys.readouterr().err
