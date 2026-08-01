from __future__ import annotations

import json
import os
from types import SimpleNamespace

from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def _server_with_workspace(tmp_path) -> tuple[ServerBlackboardMixin, BlackboardStore]:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"export-me")
    server = object.__new__(ServerBlackboardMixin)
    if not hasattr(ServerBlackboardMixin, "_blackboard_module"):
        ServerBlackboardMixin._blackboard_module = None
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "a.i64"),
        session_id="sess-export",
    )
    server.current_session = session
    workspace = server._session_blackboard_path(session_obj=session)
    store = BlackboardStore(workspace)
    store.write(
        title="recv handler parses framed input",
        content="Length is read before dispatch.",
        category="parsing",
        addr="0x401000",
        kind="finding",
        status="confirmed",
        confidence=0.8,
        priority=0.7,
        tags=["parsing", "recv"],
        evidence=[{"type": "call", "value": "recv", "address": "0x401024", "weight": 1.0}],
    )
    store.write(
        title="Is the frame length bounded?",
        content="No upper bound found yet.",
        category="parsing",
        addr="0x401000",
        kind="question",
        status="open",
        confidence=0.4,
        priority=0.9,
        tags=["parsing"],
    )
    store.write(
        title="Rejected dead end",
        content="Not the dispatch table.",
        category="recon",
        addr="0x403000",
        kind="finding",
        status="rejected",
        confidence=0.2,
        priority=0.1,
        tags=["dead_end"],
    )
    return server, store


def test_export_json_round_trips_full_fidelity(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "json"})

    assert result["ok"] is True
    assert result["format"] == "json"
    assert result["entries"] == 3
    snapshot = json.loads(result["content"])
    assert snapshot["format"] == "ida-findings-v1"
    assert snapshot["exported_at"]
    assert snapshot["stats"]["total_entries"] == 3
    assert len(snapshot["entries"]) == 3

    confirmed = [e for e in snapshot["entries"] if e["title"] == "recv handler parses framed input"][0]
    assert confirmed["kind"] == "finding"
    assert confirmed["status"] == "confirmed"
    assert confirmed["addr"] == "0x401000"
    assert confirmed["confidence"] == 0.8
    assert confirmed["priority"] == 0.7
    assert confirmed["tags"] == ["parsing", "recv"]
    assert confirmed["evidence"] == [
        {"type": "call", "value": "recv", "address": "0x401024", "weight": 1.0}
    ]
    assert confirmed["entry_id"] == confirmed["id"]
    assert "content" in confirmed
    assert "fingerprint" not in confirmed
    assert "vector" not in confirmed
    assert "norm" not in confirmed


def test_export_markdown_groups_by_kind_and_status(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "markdown"})

    assert result["ok"] is True
    content = result["content"]
    assert content.startswith("# IDA Findings Export")
    assert "## finding (2)" in content
    assert "## question (1)" in content
    assert "### confirmed" in content
    assert "### open" in content
    assert "### rejected" in content
    assert "[0x401000] recv handler parses framed input" in content
    assert "conf=0.80" in content
    assert "priority=0.70" in content
    assert "tags=parsing, recv" in content
    assert "Length is read before dispatch." in content
    assert "evidence: [call] recv @ 0x401024" in content


def test_export_to_path_writes_file(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    out = str(tmp_path / "reports" / "findings.json")
    result = server._handle_blackboard({"action": "export", "format": "json", "path": out})

    assert result["ok"] is True
    assert result["path"] == out
    assert "content" not in result
    assert result["entries"] == 3
    assert os.path.isfile(out)
    snapshot = json.loads(open(out, encoding="utf-8").read())
    assert snapshot["format"] == "ida-findings-v1"
    assert len(snapshot["entries"]) == 3


def test_export_kind_filter(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "json", "kind": "finding"})

    snapshot = json.loads(result["content"])
    assert len(snapshot["entries"]) == 2
    assert all(e["kind"] == "finding" for e in snapshot["entries"])


def test_export_status_filter(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "json", "status": "rejected"})

    snapshot = json.loads(result["content"])
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["title"] == "Rejected dead end"


def test_export_addr_and_confidence_filters(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    by_addr = server._handle_blackboard({"action": "export", "format": "json", "addr": "0x401000"})
    snapshot = json.loads(by_addr["content"])
    assert len(snapshot["entries"]) == 2

    by_conf = server._handle_blackboard({"action": "export", "format": "json", "min_confidence": 0.7})
    snapshot = json.loads(by_conf["content"])
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["title"] == "recv handler parses framed input"


def test_export_include_contradicted_flag(tmp_path):
    server, store = _server_with_workspace(tmp_path)
    target = store.list(kind="finding", limit=10)[0]["id"]
    assert store.contradict(target, "recheck") is True

    full = server._handle_blackboard({"action": "export", "format": "json"})
    assert json.loads(full["content"])["stats"]["contradicted"] == 2

    clean = server._handle_blackboard(
        {"action": "export", "format": "json", "include_contradicted": False}
    )
    snapshot = json.loads(clean["content"])
    assert snapshot["stats"]["contradicted"] == 2
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["kind"] == "question"


def test_export_limit_caps_entries(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "json", "limit": 1})

    snapshot = json.loads(result["content"])
    assert len(snapshot["entries"]) == 1
    assert snapshot["stats"]["total_entries"] == 3


def test_export_empty_workspace(tmp_path):
    binary = tmp_path / "empty.bin"
    binary.write_bytes(b"empty")
    server = object.__new__(ServerBlackboardMixin)
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    server._blackboard_path_cache = {}
    session = SimpleNamespace(
        binary_path=str(binary),
        idb_path=str(tmp_path / "e.i64"),
        session_id="sess-empty",
    )
    server.current_session = session

    result = server._handle_blackboard({"action": "export", "format": "json"})
    assert result["ok"] is True
    snapshot = json.loads(result["content"])
    assert snapshot["entries"] == []
    assert snapshot["stats"]["total_entries"] == 0


def test_export_rejects_unknown_format(tmp_path):
    server, _ = _server_with_workspace(tmp_path)
    result = server._handle_blackboard({"action": "export", "format": "yaml"})
    assert result.get("error") is True
    assert "format" in result.get("message", "")
