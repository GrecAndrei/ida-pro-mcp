"""Exercise r2 host resolution and argument modes without an IDA runtime."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError, is_error_result
from ida_pro_mcp.host.server.server_r2 import ServerR2Mixin


class _Server(ServerR2Mixin):
    current_session = None


def test_r2_target_resolution_covers_standalone_and_session_guards(monkeypatch, tmp_path):
    srv = _Server()
    assert is_error_result(srv._resolve_r2_target({})[2]) is True
    assert srv._resolve_r2_target({})[2]["code"] == MCPError.INVALID_ARGS

    monkeypatch.setattr(srv, "_resolve_session_from_idb_ref", lambda _ref: None, raising=False)
    missing = srv._resolve_r2_target({"idb": "SID_missing"})[2]
    assert missing["code"] == MCPError.FILE_NOT_FOUND

    session = SimpleNamespace(session_id="SID_1", binary_path="", analysis_options={})
    monkeypatch.setattr(srv, "_resolve_session_from_idb_ref", lambda _ref: session)
    monkeypatch.setattr(srv, "_ensure_client_owns_session", lambda _session: {"error": True, "code": "owned"}, raising=False)
    assert srv._resolve_r2_target({"idb": "SID_1"})[2]["code"] == "owned"

    monkeypatch.setattr(srv, "_ensure_client_owns_session", lambda _session: None, raising=False)
    missing_binary = srv._resolve_r2_target({"idb": "SID_1"})[2]
    assert missing_binary["code"] == MCPError.R2_BINARY_NOT_FOUND

    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00")
    session.binary_path = str(target)
    session.analysis_options = {"processor": "riscv", "bitness": 32, "endian": "little", "load_base": 0x1000}
    path, context, err = srv._resolve_r2_target({"idb": "SID_1"})
    assert err is None and path == str(target)
    assert context == {"processor": "riscv", "bitness": 32, "endian": "little", "baseaddr": 0x1000}

    standalone, opts, err = srv._resolve_r2_target({"binary_path": str(target), "processor": "arm", "bitness": 64, "baseaddr": "0x2000"})
    assert err is None and standalone == str(target)
    assert opts["processor"] == "arm" and opts["baseaddr"] == "0x2000"


def test_r2_handler_dispatches_operations_and_normalizes_arguments(monkeypatch, tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00")
    calls = []

    class Engine:
        def __init__(self):
            self.allowed_root = None

        def status(self):
            calls.append(("status",))
            return {"ok": True, "available": False}

        def bininfo(self, path):
            calls.append(("bininfo", path))
            return {"ok": True, "path": path}

        def load_hints(self, path, context):
            calls.append(("hints", path, context))
            return {"ok": True}

        def disassemble_hypothesis(self, path, **kwargs):
            calls.append(("disasm", path, kwargs))
            return {"ok": True, "kwargs": kwargs}

        def vxrefs(self, path, **kwargs):
            calls.append(("vxrefs", path, kwargs))
            return {"ok": True, "kwargs": kwargs}

    monkeypatch.setattr("ida_pro_mcp.host.server.server_r2.R2Engine", Engine)
    srv = _Server()
    srv._r2_allowed_root_for = lambda _path: "/tmp"
    srv._resolve_r2_target = lambda args: (str(target), {"processor": "x"}, None)

    assert srv._handle_r2({"action": "status"})["available"] is False
    assert srv._handle_r2({"action": "bininfo", "binary_path": str(target)})["path"] == str(target)
    assert srv._handle_r2({"action": "load_hints", "binary_path": str(target)})["ok"] is True
    invalid = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "addr": "not-an-address"})
    assert invalid["code"] == MCPError.ADDRESS_INVALID

    disasm = srv._handle_r2({
        "action": "disassemble_hypothesis", "binary_path": str(target), "offset": "0x10",
        "size": 999999, "base": -1, "hypotheses": "x86, thumb",
    })
    assert disasm["kwargs"]["offset"] == 16
    assert disasm["kwargs"]["size"] == 4096
    assert disasm["kwargs"]["base"] == 0
    assert disasm["kwargs"]["hypotheses"] == ["x86", "thumb"]

    by_count = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "count": 3})
    assert by_count["kwargs"]["size"] == 12
    refs = srv._handle_r2({"action": "vxrefs", "binary_path": str(target), "target": "0x40", "limit": -5})
    assert refs["kwargs"]["target"] == "0x40" and refs["kwargs"]["limit"] == 0
    assert calls[0] == ("status",)


def test_r2_handler_propagates_target_error_and_rejects_writes(monkeypatch):
    srv = _Server()
    assert srv._handle_r2({"action": "write_idb"})["code"] == MCPError.ACTION_NOT_FOUND
    target_error = {"error": True, "code": MCPError.FILE_NOT_FOUND}
    monkeypatch.setattr(srv, "_resolve_r2_target", lambda _args: (None, None, target_error))
    result = srv._handle_r2({"action": "bininfo"})
    assert result is target_error
