"""Exercise the dispatcher routes as they are composed in one host."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _InnerHost(ServerArgsMixin, ServerDispatchMixin):
    def __init__(self):
        self.current_session = SimpleNamespace(session_id="ABC12345", idb_path="/tmp/sample.i64")
        self._pending_analysis = set()
        self._guardrail_strict_writes = False
        self.routes = []

    def _resolve_session_from_idb_ref(self, _ref):
        return self.current_session

    def _handle_wiki(self, args):
        self.routes.append(("wiki", args))
        return {"ok": True, "route": "wiki"}

    def _handle_session(self, args):
        self.routes.append(("session", args))
        return {"ok": True, "route": "session"}

    def _handle_memory_filesystem(self, args):
        self.routes.append(("memory", args))
        return {"ok": True, "route": "memory"}

    def _handle_analysis_plugin_run(self, args):
        self.routes.append(("plugin", args))
        return {"ok": True, "route": "plugin"}

    def _handle_workflow(self, args):
        self.routes.append(("workflow", args))
        return {"ok": True, "route": "workflow"}

    def _handle_blackboard(self, args):
        self.routes.append(("blackboard", args))
        return {"ok": True, "route": "blackboard"}

    def _handle_gadgets_semantic_find(self, args):
        self.routes.append(("gadgets", args))
        return {"ok": True, "route": "gadgets"}

    def _handle_bookmarks(self, args):
        self.routes.append(("bookmarks", args))
        return {"ok": True, "route": "bookmarks"}

    def _handle_background(self, args):
        self.routes.append(("background", args))
        return {"ok": True, "route": "background"}

    def _handle_truncation(self, args):
        self.routes.append(("truncation", args))
        return {"ok": True, "route": "truncation"}

    def _handle_multi_session(self, action, args):
        self.routes.append(("multi_session", action, args))
        return {"ok": True, "route": "multi_session"}

    def _validate_semantic_index_scope(self, _args):
        return None

    def _submit_semantic_index(self, args, idb_ref):
        self.routes.append(("semantic_index", args, idb_ref))
        return {"ok": True, "route": "semantic_index"}

    def _handle_r2(self, args):
        self.routes.append(("r2", args))
        return {"ok": True, "route": "r2"}

    def call_tool(self, tool_name, idb_path, **kwargs):
        self.routes.append(("rpc", tool_name, idb_path, kwargs))
        return {"ok": True, "route": "rpc"}

    def _guardrail_mode_from_args(self, _args):
        return "assist"


def test_execute_tool_inner_routes_host_and_rpc_modes(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    host = _InnerHost()
    assert host._execute_tool_inner("not-a-tool", "not-a-tool", {})["code"] == MCPError.INVALID_ARGS
    assert host._execute_tool_inner("wiki", "wiki", {"action": "topics"})["route"] == "wiki"
    assert host._execute_tool_inner("session", "session", {"action": "list"})["route"] == "session"
    assert host._execute_tool_inner("memory", "memory", {"action": "read_file", "path": "x"})["route"] == "memory"
    assert host._execute_tool_inner("misc", "misc", {"action": "read_file", "path": "x"})["route"] == "memory"
    assert host._execute_tool_inner("analysis", "analysis", {"action": "plugin_run", "name": "p"})["route"] == "plugin"
    assert host._execute_tool_inner("workflow", "workflow", {"action": "run"})["route"] == "workflow"
    assert host._execute_tool_inner("blackboard", "blackboard", {"action": "list"})["route"] == "blackboard"
    assert host._execute_tool_inner("gadgets", "gadgets", {"action": "semantic_find", "query": "api"})["route"] == "gadgets"
    assert host._execute_tool_inner("bookmarks", "bookmarks", {"action": "list"})["route"] == "bookmarks"
    assert host._execute_tool_inner("background", "background", {"action": "status"})["route"] == "background"
    assert host._execute_tool_inner("truncation", "truncation", {"action": "peek", "token": "t"})["route"] == "truncation"
    assert host._execute_tool_inner("multi_session", "multi_session", {"action": "list"})["route"] == "multi_session"
    assert host._execute_tool_inner("intelligence", "intelligence", {"action": "index_fast", "_background": True})["route"] == "semantic_index"
    assert host._execute_tool_inner("r2", "r2", {"action": "strings"})["route"] == "r2"
    assert host._execute_tool_inner("code", "code", {"action": "disasm", "idb": "/tmp/sample.i64"})["route"] == "rpc"


def test_plugins_compatibility_and_argument_boundaries(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    host = _InnerHost()
    listed = host._execute_tool_inner("misc", "plugins", {"action": "list"})
    assert listed["route"] == "rpc"
    assert host.routes[-1][3]["action"] == "plugin_list"
    moved = host._execute_tool_inner("misc", "plugins", {"action": "run"})
    assert moved["code"] == MCPError.ACTION_NOT_FOUND
    unsupported = host._execute_tool_inner("misc", "plugins", {"action": "bad"})
    assert unsupported["code"] == MCPError.ACTION_NOT_FOUND
    host.current_session = None
    assert host._execute_tool_inner("code", "code", None)["code"] == MCPError.SESSION_REQUIRED
    assert host._execute_tool_inner("code", "code", "bad")["code"] == MCPError.INVALID_ARGS


def test_memory_path_symlink_and_input_boundary_helpers(tmp_path):
    root = str(tmp_path)
    assert ServerDispatchMixin._memory_path_has_symlink("", root) is True
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "../outside"), root) is True
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "file"), root) is False

    host = _InnerHost()
    host.current_session = None
    assert host._memory_allow_root() is None
    host._handle_memory_filesystem = ServerDispatchMixin._handle_memory_filesystem.__get__(host)
    assert host._handle_memory_filesystem({"action": "read_file", "path": "x"})["code"] == MCPError.INVALID_ARGS
