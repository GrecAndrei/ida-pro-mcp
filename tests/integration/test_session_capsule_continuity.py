from __future__ import annotations

from ida_pro_mcp.capsule import CapsuleStore


def _make_server(tmp_path, monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "cache"))
    return IDAMCPServer()


def _make_binary(path):
    path.write_bytes(b"\x7fELF\x02\x01\x01")

