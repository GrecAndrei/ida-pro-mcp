"""Cross-mode tests for continuation replay and memory-root resolution."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error
from ida_pro_mcp.host.policy import PolicyDecision
from ida_pro_mcp.host.server import server_dispatch as dispatch_mod
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _ContinuationHost(ServerArgsMixin, ServerDispatchMixin):
    def __init__(self, *, session=True, owner=""):
        self.current_session = (
            SimpleNamespace(session_id="sid", idb_path="/tmp/sample.i64")
            if session
            else None
        )
        self.owner = owner
        self._next_cache = {}
        self._next_cache_ttl_seconds = 1800
        self.calls = []
        self.responses = []
        self.guardrail_result = None
        self.phase_result = None

    def _resolve_policy_mode(self):
        return "off"

    def _truncation_owner_id(self):
        return self.owner

    def _guardrail_strict_gate(self, _tool, _args):
        return self.guardrail_result

    def _blackboard_and_phase_preflight(self, _tool, _args, _ack):
        return self.phase_result

    def call_tool(self, tool_name, idb_path, **kwargs):
        self.calls.append((tool_name, idb_path, kwargs))
        if self.responses:
            return self.responses.pop(0)
        return {"ok": True, "items": [{"addr": "0x1000"}], "_total": 1}


def _cache_pp(host, *, tool="search", args=None, pp=None, next_offset=2):
    host._next_cache["PP-TOKEN"] = {
        "tool": tool,
        "action": "find",
        "args": args or {"pattern": "recv", "grep": "ignored", "limit": 2},
        "post_process": pp or {"limit": 2},
        "next_offset": next_offset,
        "session_id": "sid" if host.current_session else "",
        "owner_id": host.owner,
        "created_at": 1_900_000_000.0,
    }


def test_pp_continuation_replays_stripped_args_and_applies_override():
    host = _ContinuationHost()
    _cache_pp(host)
    host.responses.append(
        {
            "ok": True,
            "items": [
                {"name": "recv", "addr": "0x1000"},
                {"name": "send", "addr": "0x2000"},
            ],
            "_total": 2,
        }
    )

    result = host._handle_next_continuation(
        "search", "PP-TOKEN", {"next_token": "PP-TOKEN", "head": 1}
    )

    assert result["ok"] is True
    assert result["continued_from"] == "PP-TOKEN"
    assert host.calls == [("search", "/tmp/sample.i64", {"action": "find", "pattern": "recv"})]


@pytest.mark.parametrize(
    "entry_update, expected_code",
    [
        ({"tool": "data"}, MCPError.INVALID_ARGS),
        ({"session_id": "other"}, MCPError.TRUNCATION_TOKEN_INVALID),
        ({"owner_id": "other"}, MCPError.TRUNCATION_TOKEN_INVALID),
    ],
)
def test_continuation_rejects_wrong_tool_or_scope(entry_update, expected_code):
    host = _ContinuationHost(owner="agent-a")
    _cache_pp(host, tool="search")
    host._next_cache["PP-TOKEN"].update(entry_update)

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert is_error_result(result)
    assert result["code"] == expected_code
    assert host.calls == []


def test_scoped_caller_cannot_use_unscoped_compatibility_token():
    host = _ContinuationHost()
    _cache_pp(host)
    host._next_cache["PP-TOKEN"].update({"session_id": "", "owner_id": ""})

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert result["code"] == MCPError.TRUNCATION_TOKEN_INVALID
    assert "Unscoped" in result["message"]


def test_tool_level_continuation_forwards_offset_and_mints_next_token():
    host = _ContinuationHost()
    host._next_cache["TOOL-TOKEN"] = {
        "tool": "search",
        "action": "find",
        "args": {"pattern": "recv", "limit": 2, "grep": "not-a-tool-arg"},
        "next_offset": 4,
        "session_id": "sid",
        "owner_id": "",
        "created_at": 1_900_000_000.0,
    }
    host.responses.append(
        {"ok": True, "items": [{"addr": "0x1000"}], "offset": 4, "count": 1, "truncated": True}
    )

    result = host._handle_next_continuation("search", "TOOL-TOKEN", {})

    assert result["ok"] is True
    assert result["continued_from"] == "TOOL-TOKEN"
    assert result["next_offset"] == 5
    assert result["next_token"] in host._next_cache
    assert host.calls[0][2] == {"action": "find", "pattern": "recv", "limit": 2, "offset": 4}


@pytest.mark.parametrize(
    "policy_result, expected_code",
    [
        (SimpleNamespace(decision=PolicyDecision.BLOCK, to_dict=lambda: {"reason": "blocked"}), MCPError.POLICY_DENIED),
        (SimpleNamespace(decision=PolicyDecision.REQUIRE_ACK, to_dict=lambda: {"reason": "ack"}), MCPError.POLICY_DENIED),
    ],
)
def test_continuation_rechecks_policy_before_rpc(monkeypatch, policy_result, expected_code):
    host = _ContinuationHost()
    _cache_pp(host)
    monkeypatch.setattr(dispatch_mod, "evaluate_policy", lambda *args, **kwargs: policy_result)

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert result["code"] == expected_code
    assert host.calls == []


def test_continuation_rejects_policy_evaluation_failure_in_enforcing_mode(monkeypatch):
    host = _ContinuationHost()
    _cache_pp(host)
    host._resolve_policy_mode = lambda: "enforce"
    monkeypatch.setattr(dispatch_mod, "evaluate_policy", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("policy down")))

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert result["code"] == MCPError.POLICY_DENIED
    assert "policy down" in result["details"]["exception"]
    assert host.calls == []


@pytest.mark.parametrize("attribute", ["guardrail_result", "phase_result"])
def test_continuation_replays_write_gates(monkeypatch, attribute):
    host = _ContinuationHost()
    _cache_pp(host, args={"action": "find"}, pp={})
    blocked = make_error(MCPError.INVALID_ARGS, f"{attribute} blocked")
    setattr(host, attribute, blocked)

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert result is blocked
    assert host.calls == []


def test_continuation_requires_an_active_session_after_replay(monkeypatch):
    host = _ContinuationHost(session=False)
    host._next_cache["PP-TOKEN"] = {
        "tool": "search",
        "action": "find",
        "args": {},
        "post_process": {},
        "next_offset": 0,
        "created_at": 1_900_000_000.0,
    }

    result = host._handle_next_continuation("search", "PP-TOKEN", {})

    assert result["code"] == MCPError.SESSION_REQUIRED


def test_memory_root_uses_environment_and_handles_realpath_failure(monkeypatch, tmp_path):
    class _RootHost(ServerDispatchMixin):
        current_session = None

    host = _RootHost()
    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", str(tmp_path))
    assert host._memory_allow_root() == str(tmp_path)

    monkeypatch.setattr(dispatch_mod.os.path, "realpath", lambda _path: (_ for _ in ()).throw(OSError("bad root")))
    assert host._memory_allow_root() is None


def test_memory_path_symlink_helper_rejects_escape_and_value_error(tmp_path, monkeypatch):
    root = str(tmp_path)
    assert ServerDispatchMixin._memory_path_has_symlink("", root) is True
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "../outside"), root) is True
    monkeypatch.setattr(dispatch_mod.os.path, "relpath", lambda *_args: (_ for _ in ()).throw(ValueError("different drives")))
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "file"), root) is True
