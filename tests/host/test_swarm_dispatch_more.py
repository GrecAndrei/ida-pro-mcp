"""Cross-mode offline coverage for dispatch boundary handlers."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_dispatch as dispatch_mod
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _MemoryHost(ServerDispatchMixin):
    def __init__(self, root=None, session=True):
        self.root = root
        self.current_session = (
            SimpleNamespace(session_id="SID12345", idb_path=str(root / "db.i64"))
            if session and root
            else None
        )

    def _memory_allow_root(self):
        return str(self.root) if self.root else None


def test_memory_handler_reads_and_writes_text_binary_and_rejects_boundaries(tmp_path):
    host = _MemoryHost(tmp_path)
    text = host._handle_memory_filesystem({"action": "write_file", "path": "a/b.txt", "content": "hello"})
    assert text["ok"] is True
    assert host._handle_memory_filesystem({"action": "read_file", "path": "a/b.txt"})["content"] == "hello"
    binary = host._handle_memory_filesystem({"action": "write_file", "path": "bytes.bin", "content": "00ff", "encoding": "binary"})
    assert binary["size"] == 2
    assert host._handle_memory_filesystem({"action": "read_file", "path": "bytes.bin", "encoding": "binary"})["content"] == "00ff"
    assert host._handle_memory_filesystem({"action": "write_file", "path": "bad.bin", "content": "xyz", "encoding": "binary"})["code"] == "INVALID_ARGS"
    assert host._handle_memory_filesystem({"action": "read_file", "path": "missing"})["code"] == "FILE_NOT_FOUND"
    (tmp_path / "folder").mkdir()
    assert host._handle_memory_filesystem({"action": "read_file", "path": "folder"})["code"] == "INVALID_ARGS"
    assert host._handle_memory_filesystem({"action": "write_file", "path": "empty"})["code"] == "INVALID_ARGS"
    assert host._handle_memory_filesystem({"action": "what", "path": "x"})["code"] == "ACTION_NOT_FOUND"
    assert host._handle_memory_filesystem({"action": "read_file", "path": "../escape"})["code"] == "INVALID_ARGS"
    assert host._handle_memory_filesystem({"action": "read_file", "path": ""})["code"] == "INVALID_ARGS"
    assert _MemoryHost(session=False)._handle_memory_filesystem({"action": "read_file", "path": "x"})["code"] == "INVALID_ARGS"


def test_memory_handler_rejects_symlink_components(tmp_path):
    host = _MemoryHost(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "ok").write_text("x", encoding="utf-8")
    (tmp_path / "alias").symlink_to(target, target_is_directory=True)
    result = host._handle_memory_filesystem({"action": "read_file", "path": "alias/ok"})
    assert result["code"] == "INVALID_ARGS"
    assert host._memory_path_has_symlink("", str(tmp_path)) is True
    assert host._memory_path_has_symlink(str(tmp_path / "../other"), str(tmp_path)) is True


class _BookmarkManager:
    def __init__(self):
        self.calls = []

    def _result(self, name, *args):
        self.calls.append((name, args))
        return {"ok": True, "action": name}

    def add(self, *args): return self._result("add", *args)
    def list(self, *args): return self._result("list", *args)
    def delete(self, *args): return self._result("delete", *args)
    def update(self, *args): return self._result("update", *args)
    def clear(self, *args): return self._result("clear", *args)
    def find(self, *args): return self._result("find", *args)
    def export(self, *args): return self._result("export", *args)


def test_bookmark_handler_dispatches_every_action_and_errors(tmp_path):
    host = _MemoryHost(tmp_path)
    host.bookmark_mgr = _BookmarkManager()
    for action in ("add", "list", "delete", "update", "clear", "find", "export"):
        args = {"action": action, "query": "needle", "category": "crypto", "tag": "hot", "priority": 2}
        assert host._handle_bookmarks(args)["action"] == action
    assert host._handle_bookmarks({"action": "find"})["code"] == "INVALID_ARGS"
    assert host._handle_bookmarks({"action": "unknown"})["code"] == "ACTION_NOT_FOUND"
    del host.bookmark_mgr
    assert host._handle_bookmarks({"action": "list"})["code"] == "INVALID_ARGS"
    assert _MemoryHost(session=False)._handle_bookmarks({"action": "list"})["code"] == "SESSION_REQUIRED"


def test_truncation_handler_covers_all_store_modes_and_scope(monkeypatch):
    class _Host(ServerDispatchMixin):
        def __init__(self):
            self.current_session = SimpleNamespace(session_id="ACTIVE")

        def _truncation_owner_id(self):
            return "owner"

        def _resolve_session_from_idb_ref(self, value):
            if value == "other":
                return SimpleNamespace(session_id="OTHER")
            raise RuntimeError("bad ref")

    host = _Host()
    import ida_pro_mcp.host.stores.truncation as store
    seen = {}

    def result(name, value):
        def call(*_args, **kwargs):
            seen[name] = kwargs
            return value
        return call

    monkeypatch.setattr(store, "continue_truncated", result("continue", {"ok": True}))
    monkeypatch.setattr(store, "peek_truncated", result("peek", {"ok": True}))
    monkeypatch.setattr(store, "search_truncated", result("search", {"ok": True}))
    monkeypatch.setattr(store, "summary_truncated", result("summary", {"ok": True}))
    assert host._handle_truncation({"action": "continue", "token": "tok", "idb": "other", "offset": "bad", "count": "bad"})["ok"]
    assert seen["continue"]["session_id"] == "OTHER"
    assert host._handle_truncation({"action": "peek", "next_token": "tok"})["ok"]
    assert host._handle_truncation({"action": "search", "token": "tok", "query": "needle", "is_regex": "true", "case_sensitive": "1"})["ok"]
    assert seen["search"]["is_regex"] is True
    assert host._handle_truncation({"action": "summary", "token": "tok", "limit": "3"})["ok"]
    assert host._handle_truncation({"action": "nope", "token": "tok"})["code"] == "ACTION_NOT_FOUND"
    assert host._handle_truncation({"action": "peek"})["code"] == "TRUNCATION_TOKEN_INVALID"
    monkeypatch.setattr(store, "peek_truncated", lambda *_args, **_kwargs: {"error": True, "message": "expired"})
    assert host._handle_truncation({"action": "peek", "token": "tok"})["code"] == "TRUNCATION_TOKEN_INVALID"


class _PluginHost(ServerDispatchMixin):
    def __init__(self, target=True, alive=True):
        self.current_session = SimpleNamespace(session_id="SID12345", idb_path="/tmp/db.i64") if target else None
        self.session_runtimes = {"SID12345": {"process": object(), "port": 3333}} if alive else {}

    @staticmethod
    def _runtime_alive(runtime):
        return bool(runtime)

    def _runtime_record(self, _sid):
        return self.session_runtimes.get(_sid)

    def _send_rpc_raw(self, payload, port):
        self.sent = (payload, port)
        return {"ok": True, "value": "done"}

    def _get_session_imagebase(self, _sid):
        raise RuntimeError("unknown image base")

    def _ensure_client_owns_session(self, _session):
        return None

    def _resolve_session_from_idb_ref(self, value):
        return self.current_session if value == "known" else None


def test_plugin_handler_validates_target_and_stamps_execution_scope():
    host = _PluginHost()
    assert host._handle_analysis_plugin_run({"name": "plugin", "arg": "2"})["_executed_in"]["session_id"] == "SID12345"
    assert host.sent[0]["args"]["arg"] == 2
    assert host._handle_analysis_plugin_run({"name": "plugin", "arg": "bad"})["code"] == "INVALID_ARGS"
    assert host._handle_analysis_plugin_run({"name": ""})["code"] == "INVALID_ARGS"
    assert host._handle_analysis_plugin_run({"name": "plugin", "idb": "missing"})["code"] == "FILE_NOT_FOUND"
    assert _PluginHost(target=False)._handle_analysis_plugin_run({"name": "plugin"})["code"] == "IDA_CRASHED"
    assert _PluginHost(alive=False)._handle_analysis_plugin_run({"name": "plugin"})["code"] == "IDA_CRASHED"


def test_long_running_timeout_modes_and_runtime_liveness(monkeypatch):
    monkeypatch.setenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "bad")
    monkeypatch.setenv("IDA_MCP_RPC_TIMEOUT", "bad")
    assert dispatch_mod._long_running_sock_timeout("search", {"action": "nl"}) >= 120
    assert dispatch_mod._long_running_sock_timeout("idb", {"action": "state"}) == -1
    monkeypatch.setenv("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "150")
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_RPC_TIMEOUT", "300")
    assert dispatch_mod._long_running_sock_timeout("intelligence", {"action": "index_batch"}) == 150
    assert ServerDispatchMixin._runtime_alive({"process": SimpleNamespace(poll=lambda: None)}) is True
    assert ServerDispatchMixin._runtime_alive({"process": SimpleNamespace(poll=lambda: 1)}) is False
    assert ServerDispatchMixin._runtime_alive({}) is False
    assert ServerDispatchMixin._runtime_alive(None) is False
