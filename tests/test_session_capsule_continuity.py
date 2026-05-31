from __future__ import annotations

from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.host.server import IDAMCPServer


def _make_server(tmp_path, monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "cache"))
    return IDAMCPServer()


def _make_binary(path):
    path.write_bytes(b"\x7fELF\x02\x01\x01")


def test_session_create_writes_capsule_session_and_audit(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    capsule = tmp_path / "project.sideband"
    monkeypatch.setenv("IDA_MCP_CAPSULE", str(capsule))

    binary = tmp_path / "sample.bin"
    _make_binary(binary)

    out = server._execute_tool("session", {"action": "create", "binary_path": str(binary), "_risk_ack": True})
    assert out.get("ok") is True
    sid = out["session"]["session_id"]
    cap_info = out.get("capsule") or {}
    assert cap_info.get("persisted") is True

    with CapsuleStore.open(capsule) as cap:
        sess_row = cap.conn.execute("SELECT session_id FROM sessions WHERE session_id=?", (sid,)).fetchone()
        event_row = cap.conn.execute(
            "SELECT event_type FROM audit_events WHERE session_id=? ORDER BY id DESC LIMIT 1",
            (sid,),
        ).fetchone()
    assert sess_row is not None
    assert event_row is not None
    assert event_row["event_type"] == "session_create"


def test_session_update_and_close_emit_capsule_events(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    capsule = tmp_path / "attached.sideband"

    binary = tmp_path / "close.bin"
    _make_binary(binary)

    out = server._execute_tool(
        "session",
        {
            "action": "create",
            "binary_path": str(binary),
            "capsule": str(capsule),
            "_risk_ack": True,
        },
    )
    assert out.get("ok") is True
    sid = out["session"]["session_id"]

    upd = server._execute_tool(
        "session",
        {
            "action": "update",
            "session_id": sid,
            "notes": "capsule continuity",
            "_risk_ack": True,
        },
    )
    assert upd.get("ok") is True
    assert (upd.get("capsule") or {}).get("persisted") is True

    closed = server._execute_tool("session", {"action": "close", "session_id": sid, "_risk_ack": True})
    assert closed.get("ok") is True
    assert (closed.get("capsule") or {}).get("persisted") is True

    with CapsuleStore.open(capsule) as cap:
        events = [
            row["event_type"]
            for row in cap.conn.execute(
                "SELECT event_type FROM audit_events WHERE session_id=? ORDER BY id ASC",
                (sid,),
            ).fetchall()
        ]
    assert "session_create" in events
    assert "session_update" in events
    assert "session_close" in events
