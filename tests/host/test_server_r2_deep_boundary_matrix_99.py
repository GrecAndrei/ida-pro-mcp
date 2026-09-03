"""Deep offline coverage for the r2 host mixin's remaining safety branches."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_r2
from ida_pro_mcp.host.server.server_r2 import ServerR2Mixin


class _Server(ServerR2Mixin):
    current_session = None


def test_r2_root_resolution_and_current_session_fallback(monkeypatch, tmp_path):
    srv = _Server()
    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", "~/r2-root")
    assert srv._r2_allowed_root_for("/tmp/sample.bin").endswith("/r2-root")

    original_realpath = server_r2.os.path.realpath

    def fail_realpath(_path):
        raise OSError("path unavailable")

    monkeypatch.setattr(server_r2.os.path, "realpath", fail_realpath)
    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", "/broken")
    assert srv._r2_allowed_root_for(str(tmp_path / "sample.bin")) is None
    monkeypatch.setattr(server_r2.os.path, "realpath", original_realpath)
    monkeypatch.delenv("IDA_MCP_MEMORY_ROOT")
    assert srv._r2_allowed_root_for("") is None

    srv.current_session = SimpleNamespace(session_id="SID_current")
    monkeypatch.setattr(srv, "_resolve_session_from_idb_ref", lambda ref: None, raising=False)
    result = srv._resolve_r2_target({})[2]
    assert result["code"] == MCPError.FILE_NOT_FOUND


def test_r2_disassembly_defaults_and_nonlist_hypotheses(monkeypatch, tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00")
    calls = []

    class Engine:
        def __init__(self):
            self.allowed_root = None

        def disassemble_hypothesis(self, path, **kwargs):
            calls.append((path, kwargs))
            return {"ok": True, **kwargs}

    monkeypatch.setattr(server_r2, "R2Engine", Engine)
    srv = _Server()
    srv._resolve_r2_target = lambda _args: (str(target), {"processor": "x"}, None)
    srv._r2_allowed_root_for = lambda _path: str(tmp_path)
    result = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "hypotheses": 7})
    assert result["size"] == 64
    assert result["hypotheses"] is None
    assert calls[0][1]["base"] == 0
    result = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "hypotheses": ["x86"]})
    assert result["hypotheses"] == ["x86"]
