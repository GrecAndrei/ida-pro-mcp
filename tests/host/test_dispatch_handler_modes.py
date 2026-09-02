"""Cross-mode behavior coverage for host-only dispatch handlers.

These tests deliberately exercise the handlers through their stable mixin
interfaces.  They do not pretend to prove IDA behavior; the IDA boundary is
represented by small process/RPC doubles where the host contract requires it.
"""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError, is_error_result
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
from ida_pro_mcp.host.stores.truncation import truncate_response


class _Proc:
    def __init__(self, alive: bool):
        self.alive = alive

    def poll(self):
        return None if self.alive else 1


class _Health(ServerDispatchMixin):
    def __init__(self, cache_dir):
        self._runtime_lock = threading.Lock()
        self.session_runtimes = {
            "live": {"process": _Proc(True), "port": 1111},
            "dead": {"process": _Proc(False), "port": 2222},
            "invalid": {"process": object()},
        }
        self._session_inflight_calls = {"live": 2, "dead": 1}
        self.cache_dir = str(cache_dir)
        self.ida_dir = str(cache_dir / "ida")
        self.idat_exe = str(cache_dir / "idat")
        self.current_session = SimpleNamespace(session_id="live")
        self.session_mgr = SimpleNamespace(discover_sessions=lambda: [1, 2])

    def _resolve_wiki_root(self):
        return self.cache_dir


def test_session_health_verbose_reports_runtime_and_tool_surface(tmp_path):
    (tmp_path / "idat").write_text("", encoding="utf-8")
    health = _Health(tmp_path)
    payload = health._handle_session_health({"verbose": True})

    assert payload["ok"] is True
    assert payload["sessions"]["runtime_processes"] == {
        "tracked": 3,
        "running": 1,
        "stale": 2,
    }
    assert payload["sessions"]["rpc_queued_calls"] == 3
    assert {row["session_id"] for row in payload["sessions"]["runtimes"]} == {
        "live", "dead", "invalid"
    }
    assert payload["ida"]["idat_found"] is True
    assert payload["wiki"]["available"] is True
    assert "action_counts_by_tool" in payload["tools"]


def test_runtime_alive_handles_bad_records_and_poll_errors():
    assert ServerDispatchMixin._runtime_alive({"process": _Proc(True)}) is True
    assert ServerDispatchMixin._runtime_alive({"process": _Proc(False)}) is False
    assert ServerDispatchMixin._runtime_alive(None) is False

    class Broken:
        def poll(self):
            raise OSError("gone")

    assert ServerDispatchMixin._runtime_alive({"process": Broken()}) is False


class _Memory(ServerDispatchMixin):
    def __init__(self, root, session=True):
        self.root = root
        self.current_session = (
            SimpleNamespace(idb_path=str(root / "sample.idb")) if session else None
        )

    def _memory_allow_root(self):
        return str(self.root)


def test_memory_filesystem_text_binary_and_nested_paths(tmp_path):
    memory = _Memory(tmp_path)
    written = memory._handle_memory_filesystem(
        {"action": "write_file", "path": "nested/note.txt", "content": "héllo"}
    )
    assert written["ok"] is True
    read = memory._handle_memory_filesystem(
        {"action": "read_file", "path": "nested/note.txt"}
    )
    assert read["content"] == "héllo"

    binary = memory._handle_memory_filesystem(
        {"action": "write_file", "path": "blob.bin", "content": "00ff", "encoding": "binary"}
    )
    assert binary["size"] == 2
    assert memory._handle_memory_filesystem(
        {"action": "read_file", "path": "blob.bin", "encoding": "binary"}
    )["content"] == "00ff"


@pytest.mark.parametrize(
    "args, code",
    [
        ({"action": "read_file", "path": "missing"}, MCPError.FILE_NOT_FOUND),
        ({"action": "read_file", "path": "."}, MCPError.INVALID_ARGS),
        ({"action": "write_file", "path": "bad.bin", "content": "xyz", "encoding": "binary"}, MCPError.INVALID_ARGS),
        ({"action": "write_file", "path": "missing-content"}, MCPError.INVALID_ARGS),
        ({"action": "what", "path": "x"}, MCPError.ACTION_NOT_FOUND),
        ({"action": "read_file", "path": "../outside"}, MCPError.INVALID_ARGS),
        ({"action": "read_file"}, MCPError.INVALID_ARGS),
    ],
)
def test_memory_filesystem_rejects_invalid_requests(tmp_path, args, code):
    result = _Memory(tmp_path)._handle_memory_filesystem(args)
    assert is_error_result(result)
    assert result["code"] == code


def test_memory_filesystem_rejects_symlink_components(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        ServerDispatchMixin,
        "_memory_path_has_symlink",
        staticmethod(lambda _path, _root: True),
    )
    result = _Memory(tmp_path)._handle_memory_filesystem(
        {"action": "read_file", "path": "link/file.txt"}
    )
    assert is_error_result(result)
    assert "symbolic" in result["message"]


def test_memory_filesystem_requires_root_when_no_session(monkeypatch, tmp_path):
    class NoRoot(_Memory):
        def _memory_allow_root(self):
            return None

    memory = NoRoot(tmp_path, session=False)
    monkeypatch.delenv("IDA_MCP_MEMORY_ROOT", raising=False)
    result = memory._handle_memory_filesystem({"action": "read_file", "path": "x"})
    assert is_error_result(result)
    assert "allowed root" in result["message"]

    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", str(tmp_path))
    assert _Memory(tmp_path, session=False)._memory_allow_root() == os.path.realpath(tmp_path)


class _Bookmarks(ServerDispatchMixin):
    def __init__(self, active=True, manager=True):
        self.current_session = SimpleNamespace(session_id="sid") if active else None
        self.calls = []
        self.bookmark_mgr = _BookmarkManager(self.calls) if manager else None


class _BookmarkManager:
    def __init__(self, calls):
        self.calls = calls

    def _result(self, name, *args):
        self.calls.append((name, args))
        return {"ok": True, "method": name, "args": args}

    def add(self, *args): return self._result("add", *args)
    def list(self, *args): return self._result("list", *args)
    def delete(self, *args): return self._result("delete", *args)
    def update(self, *args): return self._result("update", *args)
    def clear(self, *args): return self._result("clear", *args)
    def find(self, *args): return self._result("find", *args)
    def export(self, *args): return self._result("export", *args)


@pytest.mark.parametrize("action", ["add", "delete", "update", "clear", "export"])
def test_bookmark_mutation_and_export_routes(action):
    host = _Bookmarks()
    result = host._handle_bookmarks({"action": action, "label": "x"})
    assert result["ok"] is True
    assert host.calls[-1][0] == action


def test_bookmark_list_filters_and_find_alias():
    host = _Bookmarks()
    host._handle_bookmarks({"action": "list", "category": "todo", "tag": "hot", "priority": 2, "query": "api"})
    assert host.calls[-1] == ("list", ("sid", {"category": "todo", "tag": "hot", "priority": 2, "query": "api"}))
    assert host._handle_bookmarks({"action": "find", "q": "memcpy"})["method"] == "find"


@pytest.mark.parametrize(
    "host, args, code",
    [
        (_Bookmarks(active=False), {"action": "list"}, MCPError.SESSION_REQUIRED),
        (_Bookmarks(manager=False), {"action": "list"}, MCPError.INVALID_ARGS),
        (_Bookmarks(), {"action": "find"}, MCPError.INVALID_ARGS),
        (_Bookmarks(), {"action": "unknown"}, MCPError.ACTION_NOT_FOUND),
    ],
)
def test_bookmarks_reject_missing_context_and_actions(host, args, code):
    result = host._handle_bookmarks(args)
    assert is_error_result(result)
    assert result["code"] == code


class _Truncation(ServerArgsMixin, ServerDispatchMixin):
    def __init__(self):
        self.current_session = SimpleNamespace(session_id="sid", idb_path="/tmp/a.idb")
        self._next_cache = {}
        self._next_cache_ttl_seconds = 1800

    def _truncation_owner_id(self):
        return "owner"


def test_truncation_handler_runs_continue_peek_search_summary():
    original = {"items": [{"category": "api", "addr": "0x1000", "padding": "x" * 30}] * 200, "text": "needle\nline2\n"}
    result = truncate_response(original, max_tokens=500, session_id="sid", owner_id="owner")
    token = result["_continue"]["token"]
    host = _Truncation()

    assert host._handle_truncation({"action": "peek", "token": token})["ok"] is True
    continued = host._handle_truncation({"action": "continue", "token": token, "field": "items", "count": 2})
    assert continued["ok"] is True
    searched = host._handle_truncation({"action": "search", "token": token, "pattern": "api", "field": "items"})
    assert searched["match_count"] >= 1
    summary = host._handle_truncation({"action": "summary", "token": token, "field": "items"})
    assert summary["type"] == "list"


@pytest.mark.parametrize(
    "args, code",
    [
        ({"action": "continue"}, MCPError.TRUNCATION_TOKEN_INVALID),
        ({"action": "continue", "token": "nope"}, MCPError.TRUNCATION_TOKEN_INVALID),
        ({"action": "unknown", "token": "x"}, MCPError.ACTION_NOT_FOUND),
    ],
)
def test_truncation_handler_rejects_missing_or_invalid_tokens(args, code):
    result = _Truncation()._handle_truncation(args)
    assert is_error_result(result)
    assert result["code"] == code
