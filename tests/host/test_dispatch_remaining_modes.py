"""Composed boundary coverage for the remaining host dispatch modes.

These cases keep the IDA boundary fake, but exercise the same policy, session,
filesystem, pagination, and response paths that a protocol call composes.
"""

from __future__ import annotations

import builtins
import os
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.errors import MCPError, is_error_result
from ida_pro_mcp.host.server import server_dispatch as dispatch_mod
from ida_pro_mcp.host.server.server_args import ServerArgsMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin


class _MemoryHost(ServerDispatchMixin):
    def __init__(self, root, *, session=True):
        self.root = root
        self.current_session = (
            SimpleNamespace(idb_path=str(root / "sample.i64")) if session else None
        )

    def _memory_allow_root(self):
        return str(self.root)


def test_memory_filesystem_maps_io_and_cap_failures(monkeypatch, tmp_path):
    host = _MemoryHost(tmp_path)
    target = tmp_path / "present.txt"
    target.write_text("payload", encoding="utf-8")

    monkeypatch.setattr(dispatch_mod.os.path, "getsize", lambda _path: host._MEMORY_MAX_BYTES + 1)
    too_large = host._handle_memory_filesystem({"action": "read_file", "path": target.name})
    assert too_large["code"] == MCPError.INVALID_ARGS
    assert "cap" in too_large["message"]

    monkeypatch.setattr(dispatch_mod.os.path, "getsize", lambda _path: 1)
    real_open = builtins.open

    def fail_open(*args, **kwargs):
        if args and args[0] == str(target):
            raise OSError("permission denied")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_open)
    io_error = host._handle_memory_filesystem({"action": "read_file", "path": target.name})
    assert io_error["code"] == MCPError.IO_ERROR
    assert "permission denied" in io_error["message"]


def test_memory_filesystem_maps_unexpected_encoding_and_write_failures(monkeypatch, tmp_path):
    host = _MemoryHost(tmp_path)
    (tmp_path / "value.txt").write_text("x", encoding="utf-8")

    unexpected = host._handle_memory_filesystem(
        {"action": "read_file", "path": "value.txt", "encoding": "not-a-codec"}
    )
    assert unexpected["code"] == MCPError.IO_ERROR
    assert unexpected["message"] == "memory tool: operation failed"

    monkeypatch.setattr(dispatch_mod.os, "makedirs", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read-only")))
    write_error = host._handle_memory_filesystem(
        {"action": "write_file", "path": "new/value.txt", "content": "x"}
    )
    assert write_error["code"] == MCPError.IO_ERROR
    assert "read-only" in write_error["message"]


def test_memory_root_uses_session_and_survives_realpath_failure(monkeypatch, tmp_path):
    class _SessionRoot(ServerDispatchMixin):
        def __init__(self):
            self.current_session = SimpleNamespace(idb_path=str(tmp_path / "a" / "sample.i64"))

    host = _SessionRoot()
    assert host._memory_allow_root() == os.path.realpath(tmp_path / "a")

    monkeypatch.setattr(dispatch_mod.os.path, "realpath", lambda *_args: (_ for _ in ()).throw(OSError("bad path")))
    assert host._memory_allow_root() is None


def test_memory_path_symlink_checks_escape_and_each_component(tmp_path):
    root = str(tmp_path)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "file").write_text("x", encoding="utf-8")
    (tmp_path / "link").symlink_to(nested, target_is_directory=True)

    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / "link" / "file"), root)
    assert ServerDispatchMixin._memory_path_has_symlink(str(tmp_path / ".." / "elsewhere"), root)
    assert ServerDispatchMixin._memory_path_has_symlink(str(nested / "file"), root) is False


class _PolicyHost(ServerDispatchMixin):
    def __init__(self, session_mode=None):
        self.current_session = SimpleNamespace(policy_mode=session_mode)


def test_policy_resolution_covers_file_cache_and_session_tightening(monkeypatch, tmp_path):
    config_dir = tmp_path / ".config" / "ida-pro-mcp"
    config_dir.mkdir(parents=True)
    config = config_dir / "policy.json"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    monkeypatch.setattr(dispatch_mod, "_POLICY_CONFIG_CACHE", {})

    config.write_text('{"mode": "permissive"}', encoding="utf-8")
    host = _PolicyHost("strict")
    assert host._policy_baseline_mode() == "permissive"
    assert host._policy_baseline_mode() == "permissive"  # cached stat path
    # ``permissive`` is the operator baseline, so a session cannot tighten it
    # to a mode the policy enum does not consider stricter than assist.
    assert host._resolve_policy_mode() == "assist"

    config.write_text("not-json", encoding="utf-8")
    os.utime(config, None)
    assert host._policy_baseline_mode() == "assist"

    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    assert _PolicyHost("strict")._resolve_policy_mode() == "assist"


def test_policy_baseline_missing_and_cached_parser_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    monkeypatch.setattr(dispatch_mod, "_POLICY_CONFIG_CACHE", {})
    host = _PolicyHost()
    assert host._policy_baseline_mode() == "assist"
    assert host._policy_baseline_mode_cached(None, str(tmp_path / "missing.json")) == "assist"


class _PluginHost(ServerDispatchMixin):
    def __init__(self, result):
        self.current_session = SimpleNamespace(session_id="sid", idb_path="/tmp/a.i64")
        self.session_runtimes = {"sid": {"process": object(), "port": 31337}}
        self.result = result
        self.sent = None

    @staticmethod
    def _runtime_alive(_runtime):
        return True

    def _runtime_record(self, _sid):
        return self.session_runtimes["sid"]

    def _send_rpc_raw(self, payload, port):
        self.sent = (payload, port)
        return self.result

    def _get_session_imagebase(self, _sid):
        return 0x401000


def test_plugin_handler_stamps_error_and_non_dict_results():
    error_host = _PluginHost({"error": True, "code": "PLUGIN_ERROR"})
    result = error_host._handle_analysis_plugin_run({"name": "p", "arg": None})
    assert result["code"] == "PLUGIN_ERROR"
    assert result["_executed_in"]["image_base"] == "0x401000"
    assert error_host.sent[0]["tool"] == "misc"
    assert error_host.sent[0]["args"]["arg"] == 0

    scalar_host = _PluginHost("done")
    assert scalar_host._handle_analysis_plugin_run({"name": "p"}) == "done"


def test_truncation_handler_resolves_target_and_normalizes_store_error(monkeypatch):
    class _TruncHost(ServerArgsMixin, ServerDispatchMixin):
        def __init__(self):
            self.current_session = SimpleNamespace(session_id="active", idb_path="/tmp/a.i64")
            self._next_cache = {}
            self._next_cache_ttl_seconds = 60

        def _resolve_session_from_idb_ref(self, ref):
            if ref == "target":
                return SimpleNamespace(session_id="target")
            raise RuntimeError("bad idb ref")

        def _truncation_owner_id(self):
            return "owner"

    host = _TruncHost()
    observed = {}

    def fake_continue(token, **kwargs):
        observed.update(kwargs)
        return {"error": True, "message": "expired"}

    monkeypatch.setattr(dispatch_mod, "continue_truncated", fake_continue, raising=False)
    # The handler imports from the store module at call time.
    import ida_pro_mcp.host.stores.truncation as truncation

    monkeypatch.setattr(truncation, "continue_truncated", fake_continue)
    result = host._handle_truncation(
        {"action": "continue", "token": "tok", "idb": "target", "offset": "bad", "count": "bad"}
    )
    assert result["code"] == MCPError.TRUNCATION_TOKEN_INVALID
    assert observed["session_id"] == "target"
    assert observed["owner_id"] == "owner"

    # An idb lookup failure falls back to the active session, preserving the
    # token contract instead of turning a transient resolver failure into a crash.
    observed.clear()
    monkeypatch.setattr(truncation, "continue_truncated", lambda _token, **kwargs: observed.update(kwargs) or {"ok": True})
    assert host._handle_truncation({"action": "continue", "token": "tok", "idb": "broken"})["ok"]
    assert observed["session_id"] == "active"


def test_dispatch_gates_fail_open_only_for_explicit_off_and_swallow_helper_faults(monkeypatch):
    class _Gated(ServerDispatchMixin):
        _guardrail_strict_writes = False

        def _resolve_policy_mode(self):
            return os.environ.get("IDA_MCP_POLICY_MODE", "assist")

        def _bb_policy_bump(self):
            raise RuntimeError("blackboard unavailable")

        def _phase_preflight_for_tool(self, _tool, _args):
            raise RuntimeError("phase unavailable")

    host = _Gated()
    assert host._blackboard_and_phase_preflight("search", {}, False) is None

    class _Strict(_Gated):
        def _bb_policy_bump(self):
            return {"strict_mode": True}

        def _bb_policy_check(self, _state):
            return {"ok": False, "reasons": ["missing evidence"], "recommendation": "record it", "policy": {}}

        def _phase_preflight_for_tool(self, _tool, _args):
            return {"error": True, "code": "PHASE_BLOCKED"}

    strict = _Strict()
    blocked = strict._blackboard_and_phase_preflight("search", {}, False)
    assert blocked["code"] == MCPError.INVALID_ARGS
    assert strict._blackboard_and_phase_preflight("search", {}, True) is None

    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "off")
    assert strict._blackboard_and_phase_preflight("search", {}, False) is None


def test_guardrail_enforce_mode_uses_pointer_signal_and_ack():
    class _Guardrail(ServerDispatchMixin):
        _guardrail_strict_writes = False

        def _guardrail_mode_from_args(self, _args):
            return "enforce"

        def _compute_pointer_note_signal(self, _tool, _args, _payload):
            return 2.5

    host = _Guardrail()
    blocked = host._guardrail_strict_gate("segments", {"action": "inspect"})
    assert blocked["code"] == MCPError.INVALID_ARGS
    assert host._guardrail_strict_gate("segments", {"action": "inspect", "_guardrail_ack": True}) is None
    assert host._guardrail_strict_gate("wiki", {"action": "read"}) is None


def test_cache_post_process_next_handles_errors_and_exact_page_boundary():
    class _Cache(ServerArgsMixin, ServerDispatchMixin):
        def __init__(self):
            self._next_cache = {}
            self._next_cache_ttl_seconds = 60

    host = _Cache()
    error = {"error": True, "code": "X"}
    assert host._cache_post_process_next("search", {}, {"limit": 2}, error) is error
    plain = {"ok": True, "_count": 2, "_total": 2}
    assert host._cache_post_process_next("search", {"action": "find"}, {"limit": 2}, plain) is plain
    more = {"ok": True, "_count": 2, "_total": 9, "truncated": False}
    out = host._cache_post_process_next("search", {"action": "find"}, {"limit": 2}, more)
    assert out["next_token"]
    assert host._next_cache[out["next_token"]]["next_offset"] == 2


def test_dispatch_inner_treats_none_as_empty_object():
    class _Inner(ServerArgsMixin, ServerDispatchMixin):
        def _normalize_tool_call_args(self, _tool, value):
            return value

    result = _Inner()._execute_tool_inner("search", "search", None)
    assert is_error_result(result)
    assert result["code"] == MCPError.SESSION_REQUIRED


def test_dispatch_inner_rejects_non_object_arguments():
    class _Inner(ServerArgsMixin, ServerDispatchMixin):
        def _normalize_tool_call_args(self, _tool, value):
            return value

    result = _Inner()._execute_tool_inner("search", "search", "bad")
    assert is_error_result(result)
    assert result["code"] == MCPError.INVALID_ARGS
