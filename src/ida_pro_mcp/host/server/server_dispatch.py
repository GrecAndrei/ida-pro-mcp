#!/usr/bin/env python3
"""Generic dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from typing import Any

from ida_pro_mcp import __version__

from ..config import _bounded_int, _coerce_bool, _is_writable_dir, log_rpc
from ..errors import MCPError, is_error_result, make_error
from ..policy import (
    PolicyDecision,
    build_audit_record,
    evaluate_policy,
    normalize_mode,
    strictest,
)
from ..schemas import (
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOLS,
    _resolve_tool_alias,
)
from .postprocess import apply_post_processing, extract_post_process_params, has_post_process
from .rpc_args import prepare_rpc_args
from .server_client_state import ServerClientStateMixin
from .server_response import truncate_response

# Actions that legitimately walk the IDB at scale (full-program scans,
# embedding pipelines, decompile pumps, multi-region firmware carving,
# bulk-session housekeeping). For these we extend the socket recv
# timeout past the IDA_MCP_RPC_TIMEOUT default so the host doesn't
# kill the connection before IDA finishes.
#
# Each entry is a (tool, action) tuple. Adding a new entry is a one-line
# acknowledgement that the action may take minutes — keep this list
# curated. Anything not in the set gets the IDA_MCP_RPC_TIMEOUT default.
LONG_RUNNING_ACTIONS: set[tuple[str, str]] = {
    # analysis — auto-analysis pumps (canonical hang-risk surface)
    ("analysis", "analyze"),
    ("analysis", "reanalyze"),
    # background — long-poll tasks
    ("background", "wait"),
    # agent — full-program algorithmic analysis

    # summarize — full-binary summary walks
    ("summarize", "binary"),
    ("summarize", "statistics"),
    ("summarize", "imports_by_category"),
    ("summarize", "strings_by_category"),
    ("summarize", "security_posture"),
    ("summarize", "report"),
    # intelligence — embedding-heavy ops
    ("intelligence", "index_fast"),
    ("intelligence", "index_batch"),
    ("intelligence", "index_range"),
    ("intelligence", "index_function"),
    ("intelligence", "refresh_anchors"),
    ("intelligence", "semantic_search"),
    ("intelligence", "similar_functions"),
    # search — full-binary scans, graph BFS, embedding
    ("search", "find"),
    ("search", "bytes"),
    ("search", "string"),
    ("search", "regex"),
    ("search", "nl"),
    ("search", "path"),
    # bindiff — full-binary fingerprint + compare passes
    ("bindiff", "snapshot"),
    ("bindiff", "diff"),
    ("bindiff", "summary"),
    ("bindiff", "function_match"),
    ("bindiff", "patch_analysis"),
    # blackboard — large semantic rebuild / trace operations
    ("blackboard", "semantic_rebuild"),
    ("blackboard", "trace_ingest"),
    ("blackboard", "trace_run"),
    # firmware_view — range / multi-region carves
    ("firmware_view", "smart_carve"),
    ("firmware_view", "multi_region_campaign"),
    ("firmware_view", "campaign"),
    ("firmware_view", "segment_sweep"),
    ("firmware_view", "region_profile"),
    ("firmware_view", "pointer_sweep"),
    ("firmware_view", "scan_region"),
    # funcs — whole-program walks
    ("funcs", "metrics"),
    ("funcs", "suggest_names"),
    ("funcs", "find_similar"),
    # session — bulk housekeeping / full-program operations
    ("session", "idle_purge"),
    ("session", "cleanup_stale"),
    ("session", "macro_run"),
    ("session", "rate_skill"),

    ("workflow", "execute_plan"),
    ("workflow", "plan"),
}

_EMBEDDING_RPC_ACTIONS = {
    "intelligence": {
        "refresh_anchors",
        "classify_text",
        "classify_function",
        "index_function",
        "index_batch",
        "index_fast",
        "index_range",
        "similar_functions",
        "semantic_search",
    },
    "search": {"nl", "behavior", "analyze"},
}


def _long_running_sock_timeout(tool_name: str, rpc_args: dict) -> int:
    """Compute the socket recv timeout for a (tool, action) call.

    Returns -1 (= caller default / ``IDA_MCP_RPC_TIMEOUT``) for
    anything not in ``LONG_RUNNING_ACTIONS``. For whitelist entries,
    returns at least 120s, adds 30s on top of any caller-supplied
    timeout arg, and always clamps to the ``IDA_MCP_RPC_MAX_RECV_TIMEOUT``
    env cap so no caller can pin the dispatcher forever.
    """
    try:
        cap = int(os.environ.get("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "600"))
    except Exception:
        cap = 600
    cap = max(cap, 30)

    action = str(rpc_args.get("action") or "")
    if (tool_name, action) not in LONG_RUNNING_ACTIONS:
        return -1

    if tool_name == "intelligence" and (
        action == "index_batch"
        or (action in {"index_fast", "index_range"} and rpc_args.get("mode") == "full")
    ):
        try:
            full_index_timeout = int(os.environ.get("IDA_MCP_FULL_INDEX_RPC_TIMEOUT", "600"))
        except Exception:
            full_index_timeout = 600
        return min(max(120, full_index_timeout), cap)

    requested = (
        rpc_args.get("timeout")
        or rpc_args.get("max_wait")
        or rpc_args.get("poll_timeout")
    )
    try:
        n = int(requested) if requested is not None else 0
    except Exception:
        n = 0
    candidate = max(120, n + 30) if n else 120
    return min(candidate, cap)


class ServerDispatchMixin(ServerClientStateMixin):
    @staticmethod
    def _runtime_alive(runtime: Any) -> bool:
        """Best-effort runtime liveness check for runtime dict records."""
        if not isinstance(runtime, dict):
            return False
        proc = runtime.get("process")
        if not proc:
            return False
        try:
            return proc.poll() is None
        except Exception:
            return False

    def _policy_baseline_mode(self) -> str:
        """The operator-set policy mode: env var, then config file, then assist.

        The config file is read on every call so it can be changed without
        restarting the bridge.
        """
        env_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        if env_mode:
            return env_mode
        config_path = os.path.expanduser("~/.config/ida-pro-mcp/policy.json")
        try:
            if os.path.exists(config_path):
                with open(config_path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    mode = data.get("mode")
                    if isinstance(mode, str) and mode:
                        return mode
        except Exception as e:
            log_rpc(f"Ignoring unreadable policy config {config_path}: {e}")
        return "assist"

    def _resolve_policy_mode(self) -> str:
        """Resolve the governance policy mode for the current call.

        A session may tighten the operator baseline but never weaken it. The
        baseline is set by whoever runs the bridge; a session value arrives
        over the wire, so letting it relax policy would make the whole engine
        opt-out by request.
        """
        baseline = self._policy_baseline_mode()
        session = getattr(self, "current_session", None)
        session_mode = getattr(session, "policy_mode", None) if session is not None else None
        if isinstance(session_mode, str) and session_mode:
            return str(strictest(baseline, session_mode))
        return str(normalize_mode(baseline))

    def call_tool(self, tool_name, idb_path, **kwargs):
            session = self._resolve_session_from_idb_ref(idb_path)
            if not session:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for idb reference: {idb_path}",
                    hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
                )
            ownership_error = self._ensure_client_owns_session(session)
            if ownership_error:
                return ownership_error

            runtime = self.session_runtimes.get(session.session_id)
            if not self._runtime_alive(runtime):
                log_rpc(
                    f"Session start/restart needed: {session.session_id} -> {session.idb_path}"
                )
                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                runtime = self.session_runtimes.get(session.session_id)
            if not isinstance(runtime, dict):
                return make_error(
                    MCPError.IDA_CRASHED,
                    "Runtime metadata unavailable after startup.",
                )
            port = runtime.get("port")
            if not self._runtime_alive(runtime) or not isinstance(port, int) or port <= 0:
                return make_error(
                    MCPError.IDA_CRASHED,
                    "Runtime metadata invalid or process not alive.",
                    details={"has_process": bool(runtime.get("process")), "port": port},
                )

            _rpc_sock_timeout = None
            try:
                # Reject unknown keys instead of silently stripping them.
                # Silent strip made tuned tool calls look successful while
                # IDA always ran defaults (find_similar, semantic_min_score, …).
                rpc_args = prepare_rpc_args(tool_name, kwargs, TOOL_ARG_SCHEMAS)
                if is_error_result(rpc_args):
                    return rpc_args
                if (
                    (tool_name == "intelligence" and rpc_args.get("action") == "semantic_search")
                    or (tool_name == "search" and rpc_args.get("action") == "nl")
                ):
                    # Session startup performs this match asynchronously, but
                    # a first search may beat that worker. Guarantee exact-
                    # binary reuse here before asking IDA to open its index.
                    with contextlib.suppress(Exception):
                        self._seed_index_from_matching_binary(session)
                # Keep the shared inference process owned by the MCP host.
                # IDA-side tools attach through its lease instead of spawning
                # a child of idat that can survive after the session exits.
                if rpc_args.get("action") in _EMBEDDING_RPC_ACTIONS.get(tool_name, set()):
                    with contextlib.suppress(Exception):
                        self.assembler.ensure_embedding_server()
                _t0 = time.time()
                # Long-running actions get an extended socket recv timeout
                # so the host doesn't kill the connection before IDA
                # finishes. _long_running_sock_timeout also clamps to the
                # IDA_MCP_RPC_MAX_RECV_TIMEOUT cap so no caller can pin
                # the dispatcher forever. Result of -1 means
                # "use IDA_MCP_RPC_TIMEOUT default" (30s).
                _rpc_sock_timeout = _long_running_sock_timeout(tool_name, rpc_args)
                if _rpc_sock_timeout == -1:
                    _rpc_sock_timeout = None
                # Hard wall-clock cap around the RPC itself (not startup /
                # seeding). Anything beyond this gets the process signalled
                # and we surface IDA_TIMEOUT so the user can decide whether
                # to restart — but only when the RPC did not already succeed.
                try:
                    _wallclock_cap = float(
                        os.environ.get("IDA_MCP_RPC_HARD_WALLCLOCK_SEC", "900")
                    )
                except Exception:
                    _wallclock_cap = 900.0
                _wallclock_cap = max(_wallclock_cap, 30.0)
                _rpc_started = time.time()
                try:
                    res = self._send_rpc_with_retry(
                        {"tool": tool_name, "args": rpc_args}, port,
                        recv_timeout=_rpc_sock_timeout,
                    )
                except (ConnectionRefusedError, EOFError) as exc:
                    # Connection-layer failure that exhausted retries. Surface as
                    # runtime error so the agent can decide to restart.
                    return make_error(
                        MCPError.RPC_CONNECTION_ERROR,
                        f"RPC to IDA failed after retries: {exc}",
                        details={"exception_type": type(exc).__name__, "tool": tool_name},
                    )
                # Wall-clock watchdog: only force-kill when the RPC path itself
                # exceeded the cap *and* we somehow still returned without a
                # usable result. Successful payloads must not be discarded.
                _elapsed_wallclock = time.time() - _rpc_started
                if _elapsed_wallclock >= _wallclock_cap and is_error_result(res):
                    try:
                        proc = runtime.get("process") if isinstance(runtime, dict) else None
                        if proc is not None and hasattr(proc, "poll"):
                            alive = proc.poll() is None
                            if alive and hasattr(proc, "terminate"):
                                proc.terminate()
                                try:
                                    proc.wait(timeout=2.0)
                                except Exception:
                                    if hasattr(proc, "kill"):
                                        proc.kill()
                    except Exception as _kill_e:
                        import logging
                        logging.getLogger(__name__).debug(
                            "wallclock watchdog term failed: %s", _kill_e
                        )
                    return make_error(
                        MCPError.IDA_TIMEOUT,
                        f"Tool call exceeded wall-clock cap of {_wallclock_cap:.0f}s "
                        f"(IDA_MCP_RPC_HARD_WALLCLOCK_SEC). The IDA process was "
                        "terminated — the next call will re-spawn it.",
                        recoverable=True,
                        details={
                            "tool": tool_name,
                            "wallclock_cap_sec": _wallclock_cap,
                            "elapsed_sec": round(_elapsed_wallclock, 2),
                        },
                    )
                if _elapsed_wallclock >= _wallclock_cap:
                    log_rpc(
                        f"wallclock cap {_wallclock_cap:.0f}s exceeded for {tool_name} "
                        f"(elapsed={_elapsed_wallclock:.1f}s) but RPC returned successfully"
                    )
                # Other socket errors (TimeoutError, OSError) propagate to the
                # existing handler below, which distinguishes IDA_TIMEOUT from
                # RPC_CONNECTION_ERROR based on the process liveness check.
                _elapsed = time.time() - _t0
                if isinstance(res, dict) and "error" not in res and "ok" not in res:
                    res = {"ok": True, **res}
                # Apply truncation with per-call overrides
                _tc = getattr(self, "_pending_truncation", None) or {}
                if _tc.get("no_truncate"):
                    pass  # skip truncation entirely
                else:
                    _budget = _tc.get("max_tokens") or self.default_truncate_tokens
                    _sid = getattr(self.current_session, "session_id", "") if self.current_session else ""
                    _owner = ""
                    if hasattr(self, "_truncation_owner_id"):
                        _owner = self._truncation_owner_id()
                    res = truncate_response(
                        res,
                        max_tokens=_budget,
                        trunc_offset=_tc.get("trunc_offset"),
                        trunc_limit=_tc.get("trunc_limit"),
                        session_id=_sid,
                        owner_id=_owner,
                    )
                try:
                    _slow_threshold = float(
                        os.environ.get("IDA_MCP_SLOW_CALL_SEC", "5.0")
                    )
                except Exception:
                    _slow_threshold = 5.0
                if _elapsed >= _slow_threshold and isinstance(res, dict):
                    snapshot = self._collect_ida_state_snapshot(
                        runtime=runtime,
                        current_tool=tool_name,
                        current_args=rpc_args,
                        call_started_at=_t0,
                    )
                    snapshot["elapsed_sec"] = round(_elapsed, 2)
                    res.setdefault("_meta", {})
                    res["_meta"]["slow_call"] = True
                    res["_meta"]["ida_state"] = snapshot
                return res
            except Exception as e:
                proc = runtime.get("process")
                exit_code = proc.poll() if proc else None
                if exit_code is not None:
                    return make_error(
                        MCPError.IDA_CRASHED,
                        f"IDA exited with code {exit_code}",
                        details={
                            "log": self._get_ida_diagnostics(
                                runtime.get("stdout_log"),
                                runtime.get("stderr_log"),
                            )
                        },
                    )
                # Process is still alive (poll() is None): the RPC raised, most
                # often a socket timeout from IDA_MCP_RPC_TIMEOUT on a slow call
                # (long decompile, pump, pending analysis) — NOT a crash. Report
                # a recoverable timeout so the caller retries / raises the
                # deadline instead of chasing a nonexistent IDA crash.
                import socket as _socket
                if _rpc_sock_timeout is not None:
                    _recv_to = _rpc_sock_timeout
                else:
                    try:
                        _recv_to = int(os.environ.get("IDA_MCP_RPC_TIMEOUT", "30"))
                    except Exception:
                        _recv_to = 30
                if isinstance(e, (_socket.timeout, TimeoutError, OSError)):
                    return make_error(
                        MCPError.IDA_TIMEOUT,
                        f"IDA did not respond within {_recv_to}s (IDA_MCP_RPC_TIMEOUT). "
                        "The process is still alive; the call likely needs more time. "
                        "Retry, or raise IDA_MCP_RPC_TIMEOUT.",
                        recoverable=True,
                        details={"port": port, "rpc_timeout_sec": _recv_to},
                    )
                return make_error(
                    MCPError.RPC_CONNECTION_ERROR,
                    f"RPC to IDA failed (process alive): {e}",
                    recoverable=True,
                    details={"port": port},
                )

    def _handle_session_health(self, args: dict) -> dict:
            verbose = bool(args.get("verbose", False))
            wiki_root = self._resolve_wiki_root()
            wiki_available = bool(wiki_root and os.path.isdir(wiki_root))
            idat_path = self.idat_exe or ""
            idat_exists = bool(idat_path and os.path.exists(idat_path))
            runtime_states = []
            running = 0
            stale = 0
            # Snapshot under the lock: a concurrent session teardown mutating
            # session_runtimes mid-iteration would raise RuntimeError and fail
            # the health check that exists to report on exactly that state.
            with self._runtime_lock:
                runtime_items = list(self.session_runtimes.items())
            tracked = len(runtime_items)
            for sid, runtime in runtime_items:
                alive = self._runtime_alive(runtime)
                if alive:
                    running += 1
                else:
                    stale += 1
                if verbose:
                    runtime_port = runtime.get("port") if isinstance(runtime, dict) else None
                    runtime_states.append(
                        {
                            "session_id": sid,
                            "alive": alive,
                            "port": runtime_port,
                        }
                    )

            action_counts = {
                str(tool): len(list(actions or []))
                for tool, actions in TOOL_ACTIONS.items()
            }
            max_actions_tool = ""
            max_actions_count = 0
            if action_counts:
                max_actions_tool = max(action_counts, key=action_counts.get)
                max_actions_count = int(action_counts.get(max_actions_tool, 0))
            payload = {
                "ok": True,
                "action": "health",
                "server": {"name": "ida-pro-mcp", "version": __version__},
                "runtime": {
                    "cache_dir": self.cache_dir,
                    "cache_writable": _is_writable_dir(self.cache_dir),
                    "cache_exists": os.path.isdir(self.cache_dir),
                },
                "ida": {
                    "ida_dir": self.ida_dir,
                    "idat_path": idat_path or None,
                    "idat_found": idat_exists,
                },
                "sessions": {
                    "total": len(self.session_mgr.discover_sessions()),
                    "active": self.current_session.session_id
                    if self.current_session
                    else None,
                    "runtime_processes": {
                        "tracked": tracked,
                        "running": running,
                        "stale": stale,
                    },
                },
                "wiki": {"root": wiki_root or None, "available": wiki_available},
                "tools": {
                    "registered": len(TOOLS),
                    "advertised": len(ADVERTISED_TOOLS),
                    "hidden_from_tools_list": len(HIDDEN_TOOLS_IN_LIST),
                    "action_surface": {
                        "tool_count_with_actions": len(action_counts),
                        "total_actions": sum(action_counts.values()),
                        "max_actions_tool": max_actions_tool or None,
                        "max_actions_count": max_actions_count,
                    },
                },
            }
            if verbose:
                payload["sessions"]["runtimes"] = runtime_states
                payload["tools"]["action_counts_by_tool"] = action_counts
            return payload

    _MEMORY_MAX_BYTES = 64 * 1024 * 1024

    def _memory_allow_root(self) -> str | None:
            env_root = os.environ.get("IDA_MCP_MEMORY_ROOT")
            if env_root:
                try:
                    return os.path.realpath(os.path.expanduser(env_root))
                except Exception:
                    return None
            session = getattr(self, "current_session", None)
            idb_path = getattr(session, "idb_path", None) if session else None
            if idb_path:
                try:
                    return os.path.realpath(os.path.dirname(idb_path))
                except Exception:
                    return None
            return None

    @staticmethod
    def _memory_path_has_symlink(abs_path: str, allowed_root: str) -> bool:
            if not abs_path or not allowed_root:
                return True
            try:
                rel = os.path.relpath(abs_path, allowed_root)
            except ValueError:
                return True
            if rel.startswith("..") or os.path.isabs(rel):
                return True
            parts = rel.split(os.sep)
            current = allowed_root
            for part in parts:
                if not part:
                    continue
                current = os.path.join(current, part)
                if os.path.islink(current):
                    return True
            return False

    def _handle_memory_filesystem(self, args: dict) -> dict:
            import os as _os
            action = str(args.get("action") or "").strip().lower()
            path = args.get("path")
            if not isinstance(path, str) or not path.strip():
                return make_error(MCPError.INVALID_ARGS, "path required")
            allowed_root = self._memory_allow_root()
            if not allowed_root:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "memory tool: no allowed root configured (set IDA_MCP_MEMORY_ROOT or open a session).",
                )
            try:
                canonical = _os.path.realpath(_os.path.join(allowed_root, path))
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "memory tool: invalid path")
            common = _os.path.commonpath([allowed_root, canonical])
            if common != allowed_root:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "memory tool: path escapes allowed root",
                )
            if self._memory_path_has_symlink(canonical, allowed_root):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "memory tool: symbolic links are not allowed in path",
                )
            encoding = args.get("encoding") or "utf-8"
            try:
                if action == "read_file":
                    if not _os.path.exists(canonical):
                        return make_error(
                            MCPError.FILE_NOT_FOUND,
                            "File not found",
                            details={"path": canonical},
                        )
                    if not _os.path.isfile(canonical):
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "Not a file",
                            hint="Pass a regular file path, not a directory or device.",
                            details={"path": canonical},
                        )
                    file_size = _os.path.getsize(canonical)
                    if file_size > self._MEMORY_MAX_BYTES:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            f"memory tool: read exceeds {self._MEMORY_MAX_BYTES} byte cap",
                        )
                    enc = str(encoding).strip().lower()
                    if enc == "binary":
                        with open(canonical, "rb") as f:
                            data = f.read()
                        return {
                            "ok": True,
                            "path": canonical,
                            "size": len(data),
                            "content": data.hex(),
                            "encoding": "binary",
                        }
                    with open(canonical, encoding=enc, errors="replace") as f:
                        text = f.read()
                    return {
                        "ok": True,
                        "path": canonical,
                        "size": len(text),
                        "content": text,
                        "encoding": enc,
                    }
                if action == "write_file":
                    parent = _os.path.dirname(canonical)
                    if parent and not _os.path.exists(parent):
                        _os.makedirs(parent, exist_ok=True)
                    content = args.get("content")
                    if content is None:
                        return make_error(MCPError.INVALID_ARGS, "content required for write_file")
                    enc = str(encoding).strip().lower()
                    if enc == "binary":
                        try:
                            raw = bytes.fromhex(str(content))
                        except ValueError:
                            return make_error(
                                MCPError.INVALID_ARGS,
                                "Invalid hex content",
                                hint="Pass content as an even-length hex string when encoding='binary'.",
                            )
                        if len(raw) > self._MEMORY_MAX_BYTES:
                            return make_error(
                                MCPError.INVALID_ARGS,
                                f"memory tool: write exceeds {self._MEMORY_MAX_BYTES} byte cap",
                            )
                        with open(canonical, "wb") as f:
                            f.write(raw)
                        return {
                            "ok": True,
                            "path": canonical,
                            "size": len(raw),
                            "encoding": "binary",
                        }
                    text_content = str(content)
                    if len(text_content.encode(enc, errors="replace")) > self._MEMORY_MAX_BYTES:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            f"memory tool: write exceeds {self._MEMORY_MAX_BYTES} byte cap",
                        )
                    with open(canonical, "w", encoding=enc, errors="replace") as f:
                        f.write(text_content)
                    return {
                        "ok": True,
                        "path": canonical,
                        "size": len(text_content),
                        "encoding": enc,
                    }
            except (OSError, ValueError) as exc:
                return make_error(
                    MCPError.IO_ERROR,
                    f"memory tool: {type(exc).__name__}: {exc}",
                    hint="Check the file path, permissions, and that the file content is well-formed.",
                )
            except Exception:
                return make_error(
                    MCPError.IO_ERROR,
                    "memory tool: operation failed",
                    hint="Retry, or capture a reproduce before reporting an upstream bug.",
                )
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported memory filesystem action: '{action}'",
                hint="Use memory(action='read_file'|'write_file').",
            )

    def _handle_analysis_plugin_run(self, args: dict) -> dict:
            name = args.get("name")
            if not isinstance(name, str) or not name.strip():
                return make_error(MCPError.INVALID_ARGS, "name required for plugin_run")
            arg = args.get("arg", 0)
            try:
                arg = int(arg) if arg is not None else 0
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, f"arg must be int, got {type(arg).__name__}")
            runtime = self.session_runtimes.get(self.current_session.session_id) if self.current_session else None
            if not self._runtime_alive(runtime):
                return make_error(
                    MCPError.IDA_CRASHED,
                    "plugin_run requires a live IDA session; none is active.",
                    hint="Open a session first with ida_open_binary(binary_path='...').",
                )
            return self._send_rpc_raw(
                {"tool": "misc", "args": {"action": "plugin_run", "name": name, "arg": arg}},
                runtime.get("port"),
            )

    def _handle_bookmarks(self, args: dict) -> dict:
            if not self.current_session:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: ida_open_binary(binary_path='path/to/binary')",
                )
            action = str(args.get("action") or "").strip().lower()
            sid = self.current_session.session_id
            mgr = getattr(self, "bookmark_mgr", None)
            if mgr is None:
                return make_error(MCPError.INVALID_ARGS, "Bookmark manager unavailable")
            if action == "add":
                return mgr.add(sid, args)
            if action == "list":
                filters = {
                    key: args.get(key)
                    for key in ("category", "tag", "priority", "query")
                    if args.get(key) is not None
                }
                res = mgr.list(sid, filters)
                return res
            if action == "delete":
                return mgr.delete(sid, args)
            if action == "update":
                return mgr.update(sid, args)
            if action == "clear":
                return mgr.clear(sid)
            if action == "find":
                query = str(args.get("query") or args.get("q") or "").strip()
                if not query:
                    return make_error(MCPError.INVALID_ARGS, "query required")
                return mgr.find(sid, query)
            if action == "export":
                return mgr.export(sid)
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported bookmarks action: '{action}'",
                hint="Bookmarks are not exposed as public operations; use ida_python if code execution is authorized.",
            )

    def _handle_truncation(self, args: dict) -> dict:
            action = str(args.get("action") or "").strip().lower()
            token = args.get("token") or args.get("next_token")
            if not isinstance(token, str) or not token.strip():
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    "Invalid continuation token. Check the token value.",
                )
            token = token.strip()
            sid = getattr(self.current_session, "session_id", "") if self.current_session else ""
            owner = self._truncation_owner_id() if hasattr(self, "_truncation_owner_id") else ""
            from . import server as _server_mod

            if action == "continue":
                field = args.get("field")
                offset = args.get("offset")
                count = args.get("count")
                result = _server_mod.continue_truncated(
                    token,
                    field=field if isinstance(field, str) else None,
                    offset=_bounded_int(offset, 0, min_value=0, max_value=500000)
                    if offset is not None
                    else None,
                    count=_bounded_int(count, 0, min_value=1, max_value=5000)
                    if count is not None
                    else None,
                    session_id=sid,
                    owner_id=owner,
                )
            elif action == "peek":
                result = _server_mod.peek_truncated(token, session_id=sid, owner_id=owner)
            elif action == "search":
                pattern = str(args.get("pattern") or args.get("query") or "").strip()
                field = args.get("field")
                result = _server_mod.search_truncated(
                    token,
                    pattern=pattern,
                    field=field if isinstance(field, str) else None,
                    is_regex=_coerce_bool(args.get("is_regex"), False),
                    case_sensitive=_coerce_bool(args.get("case_sensitive"), False),
                    limit=_bounded_int(args.get("limit", 50), 50, min_value=1, max_value=500),
                    session_id=sid,
                    owner_id=owner,
                )
            elif action == "summary":
                field = args.get("field")
                result = _server_mod.summary_truncated(
                    token,
                    field=field if isinstance(field, str) else None,
                    limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=100),
                    session_id=sid,
                    owner_id=owner,
                )
            else:
                return make_error(
                    MCPError.ACTION_NOT_FOUND,
                    f"Unsupported truncation action: '{action}'",
                    hint="Use truncation(action='continue'|'peek'|'search'|'summary', token='...').",
                )
            if (
                isinstance(result, dict)
                and result.get("error")
                and "code" not in result
            ):
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    result.get("message") or "Invalid continuation token. Check the token value.",
                )
            return result

    def _handle_next_continuation(
        self, tool_name: str, token: str, pp_params: dict
    ) -> dict:
        """Continue pagination from a previous post-processed result.

        Auto-recovers action and args from the cache — the caller only
        needs to pass ``next_token``.
        """
        self._prune_next_cache()
        entry = self._next_cache.get(token)
        if not entry:
            return make_error(
                MCPError.TRUNCATION_TOKEN_INVALID,
                f"next_token '{token}' not found or expired",
                hint="Re-run the original call to get a fresh next_token.",
            )
        cached_tool = str(entry.get("tool") or "")
        if cached_tool and cached_tool != tool_name:
            return make_error(
                MCPError.INVALID_ARGS,
                f"next_token belongs to tool '{cached_tool}', not '{tool_name}'",
            )

        # Recover base args and action from cache.
        base_args = dict(entry.get("args") or {})
        base_args["action"] = entry.get("action")

        # Merge cached PP params with caller overrides (except next_token).
        cached_pp = dict(entry.get("post_process") or {})
        cached_pp["offset"] = entry.get("next_offset", 0)
        for k, v in pp_params.items():
            if k != "next_token" and v is not None:
                cached_pp[k] = v

        # Execute the original tool action — re-run policy so continuation
        # pages cannot bypass the preflight gates that protected page 1.
        try:
            policy_result = evaluate_policy(
                tool_name,
                base_args.get("action"),
                mode=self._resolve_policy_mode(),
                purpose=base_args.get("_purpose") or pp_params.get("_purpose"),
                ack=_coerce_bool(pp_params.get("_risk_ack"), False)
                or _coerce_bool(pp_params.get("_guardrail_ack"), False)
                or _coerce_bool(base_args.get("_risk_ack"), False),
            )
            if policy_result.decision == PolicyDecision.BLOCK:
                return make_error(
                    MCPError.POLICY_DENIED,
                    "Policy blocked this continuation",
                    details=policy_result.to_dict(),
                )
            if policy_result.decision == PolicyDecision.REQUIRE_ACK:
                return make_error(
                    MCPError.POLICY_DENIED,
                    "Policy requires acknowledgement for this continuation",
                    hint="Retry with _risk_ack=true.",
                    details=policy_result.to_dict(),
                )
        except Exception as e:
            mode = self._resolve_policy_mode()
            if str(mode or "").strip().lower() not in {"off", "permissive"}:
                return make_error(
                    MCPError.POLICY_DENIED,
                    "Policy evaluation failed; refusing continuation",
                    details={"exception": str(e)},
                )

        ip = base_args.pop(
            "idb", self.current_session.idb_path if self.current_session else None
        )
        if not ip:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first.",
            )
        result = self.call_tool(tool_name, ip, **base_args)

        if is_error_result(result):
            return result

        result = apply_post_processing(result, cached_pp)
        result = self._cache_post_process_next(tool_name, base_args, cached_pp, result)
        if isinstance(result, dict):
            result["continued_from"] = token
        return result

    def _cache_post_process_next(
        self, tool_name: str, base_args: dict, pp_params: dict, result: Any
    ) -> Any:
        """Cache a continuation token if the result has more pages."""
        if not isinstance(result, dict) or is_error_result(result):
            return result

        count = result.get("_count", 0)
        source_truncated = _coerce_bool(result.get("truncated"), False)
        page_size = pp_params.get("head") or pp_params.get("limit")
        has_more = source_truncated or (
            page_size is not None and count >= int(page_size)
        )

        if not has_more:
            return result

        self._prune_next_cache()
        token = uuid.uuid4().hex[:12].upper()
        current_offset = _bounded_int(
            pp_params.get("offset"), 0, min_value=0, max_value=500_000
        )
        effective_page = int(page_size) if page_size else count

        self._next_cache[token] = {
            "tool": tool_name,
            "action": base_args.get("action"),
            "args": {k: v for k, v in base_args.items() if k != "action"},
            "post_process": {k: v for k, v in pp_params.items() if k != "next_token"},
            "next_offset": current_offset + effective_page,
            "created_at": time.time(),
        }
        result["next_token"] = token
        return result

    def _execute_tool(self, tool_name, args):
            start_ts = time.perf_counter()
            original_tool_name = tool_name
            resolved_tool = _resolve_tool_alias(tool_name)

            # ---- Rate Limiting ----
            allowed, reason = self.rate_limiter.check(resolved_tool)
            if not allowed:
                self.audit.log(
                    tool=resolved_tool,
                    action=str(args.get("action", "")) if isinstance(args, dict) else "",
                    args=args if isinstance(args, dict) else {},
                    result=None,
                    latency_ms=0.0,
                    session_id=getattr(self.current_session, "session_id", None) if self.current_session else None,
                    error=f"rate_limited: {reason}",
                )
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Rate limit exceeded: {reason}",
                    hint="Reduce call frequency or increase limits via IDA_MCP_RATE_LIMIT_* env vars.",
                )

            result = self._execute_tool_inner(resolved_tool, original_tool_name, args)

            # ---- Post-processing pipeline ----
            pp_params = getattr(self, "_pending_pp", None)
            if pp_params and has_post_process(pp_params) and not is_error_result(result):
                try:
                    result = apply_post_processing(result, pp_params)
                    result = self._cache_post_process_next(
                        resolved_tool, args, pp_params, result
                    )
                except Exception as _pp_err:
                    import logging
                    logging.getLogger(__name__).debug("post-process pipeline failed: %s", _pp_err)
            self._pending_pp = {}

            sid = getattr(self.current_session, "session_id", None) if self.current_session else None
            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            action_name = str(args.get("action", "")) if isinstance(args, dict) else ""
            guardrail_mode = self._guardrail_mode_from_args(args) if isinstance(args, dict) else "assist"
            guardrail_blocked = False
            error_str = None
            if isinstance(result, dict):
                err = result.get("error")
                if isinstance(err, dict):
                    guardrail_blocked = (
                        err.get("code") == MCPError.INVALID_ARGS
                        and "guardrail" in str(err.get("message", "")).lower()
                    )
                    error_str = str(err)[:500]
                elif err is not None:
                    error_str = str(err)[:500]
                elif result.get("ok") is False:
                    if (
                        result.get("code") == MCPError.INVALID_ARGS
                        and "guardrail" in str(result.get("message", "")).lower()
                    ):
                        guardrail_blocked = True
                    error_str = str(
                        {
                            "code": result.get("code"),
                            "message": result.get("message"),
                        }
                    )[:500]
            self.audit.log(
                tool=resolved_tool,
                action=action_name,
                args=args if isinstance(args, dict) else {},
                result=result,
                latency_ms=latency_ms,
                session_id=sid,
                guardrail_mode=guardrail_mode,
                guardrail_blocked=guardrail_blocked,
                error=error_str,
            )
            # Live observation for usage intelligence
            if self._usage_intel and sid:
                try:
                    addr = (args.get("addr") or args.get("address")) if isinstance(args, dict) else None
                    self._usage_intel.observe(
                        resolved_tool, action_name, sid,
                        latency_ms=latency_ms, error=error_str, addr=addr,
                    )
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug("usage intel observe failed: %s", _e)
            return result

    def _execute_tool_inner(self, tool_name, original_tool_name, args):
            if tool_name not in TOOLS:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown tool '{tool_name}'",
                    hint="Call tools/list to see available tools.",
                )
            if args is None:
                args = {}
            if not isinstance(args, dict):
                return make_error(MCPError.INVALID_ARGS, "arguments must be an object")
            args = self._normalize_tool_call_args(tool_name, args)

            # ---- Post-processing filter extraction ----
            # Extract PP params before they reach IDA or policy checks.
            # Skip PP extraction for the truncation tool — it has its own
            # offset/count params that conflict with PP's offset/limit.
            if tool_name == "truncation":
                self._pending_pp = {}
            else:
                args, self._pending_pp = extract_post_process_params(args)

            # ---- Truncation control params (captured before IDA strips them) ----
            _trunc_no_truncate = _coerce_bool(args.pop("no_truncate", None), False)
            _trunc_max_tokens = args.pop("max_tokens", None)
            _trunc_offset = args.pop("trunc_offset", None)
            _trunc_limit = args.pop("trunc_limit", None)
            self._pending_truncation = {
                "no_truncate": _trunc_no_truncate,
                "max_tokens": _bounded_int(_trunc_max_tokens, 0, min_value=500, max_value=500000) if _trunc_max_tokens is not None else None,
                "trunc_offset": _bounded_int(_trunc_offset, 0, min_value=0, max_value=500000) if _trunc_offset is not None else None,
                "trunc_limit": _bounded_int(_trunc_limit, 0, min_value=1, max_value=50000) if _trunc_limit is not None else None,
            }

            # ---- next_token continuation (auto-recovers action from cache) ----
            next_token = self._pending_pp.get("next_token")
            if next_token and isinstance(next_token, str) and next_token.strip():
                return self._handle_next_continuation(
                    tool_name, next_token.strip(), self._pending_pp
                )

            sid = getattr(self.current_session, "session_id", None) if self.current_session else None
            # Capture ack before the policy block pops _risk_ack below. The
            # phase gate at the bottom of this function wants to skip when
            # the caller already acknowledged the risk explicitly — but
            # args has _risk_ack popped by the time the gate runs, so we
            # need a captured value. (Bug: LLM passed _risk_ack=true on
            # funcs.create in prove phase and still hit "prove phase
            # requires evidence cards" gate.)
            _risk_ack_passed = bool(_coerce_bool(args.get("_risk_ack"), False)) or _coerce_bool(args.get("_guardrail_ack"), False)

            # ---- Deterministic policy preflight ----
            if tool_name not in {"blackboard", "background"}:
                try:
                    policy_result = evaluate_policy(
                        tool_name,
                        args.get("action"),
                        mode=self._resolve_policy_mode(),
                        purpose=args.get("_purpose"),
                        ack=_coerce_bool(args.get("_risk_ack"), False)
                        or _coerce_bool(args.get("_guardrail_ack"), False),
                    )
                    policy_audit = build_audit_record(policy_result, session_id=sid)
                    policy_details = policy_result.to_dict()
                    if (
                        policy_result.decision != PolicyDecision.ALLOW
                        or policy_result.risk.value != "read"
                        or policy_result.reasons
                        or policy_result.flags
                    ):
                        try:
                            self.audit.log(
                                tool=tool_name,
                                action=str(args.get("action") or ""),
                                args=policy_audit,
                                result=policy_details,
                                latency_ms=0.0,
                                session_id=sid,
                            )
                        except Exception as e:
                            log_rpc(f"Policy audit logging failed for {tool_name}: {e}")
                    if policy_result.decision == PolicyDecision.BLOCK:
                        return make_error(
                            MCPError.POLICY_DENIED,
                            "Policy blocked this tool action",
                            hint="Use an allowed purpose and verify the workflow is authorized.",
                            details=policy_details,
                        )
                    if policy_result.decision == PolicyDecision.REQUIRE_ACK:
                        return make_error(
                            MCPError.POLICY_DENIED,
                            "Policy requires explicit acknowledgement for this tool action",
                            hint="Retry with _risk_ack=true after verifying the action is authorized.",
                            details=policy_details,
                        )
                except Exception as e:
                    log_rpc(f"Policy evaluation failed for {tool_name}: {e}")
                    mode = self._resolve_policy_mode()
                    if str(mode or "").strip().lower() not in {"off", "permissive"}:
                        return make_error(
                            MCPError.POLICY_DENIED,
                            "Policy evaluation failed; refusing tool call",
                            hint="Fix policy configuration or set IDA_MCP_POLICY_MODE=permissive to bypass.",
                            details={"exception": str(e), "tool": tool_name},
                        )
            args.pop("_purpose", None)
            args.pop("_risk_ack", None)

            # ---- Blackboard strict policy preflight (global tool boundary) ----
            # Skipped on _risk_ack=true: explicit ack supersedes the strict
            # blackboard evidence chain requirement.
            # Skipped when policy mode is OFF: all gates disabled.
            try:
                _policy_mode_cached = self._resolve_policy_mode()
                if _policy_mode_cached == "off":
                    pass
                elif (tool_name != "blackboard"
                        and not _risk_ack_passed
                        and hasattr(self, "_bb_policy_bump")
                        and hasattr(self, "_bb_policy_check")):
                    bb_state = self._bb_policy_bump()
                    exempt_tools = {
                        "session",
                        "bookmarks",
                        "background",
                        "batch",
                        "truncation",
                        "blackboard",
                    }
                    phase_name = "scout"
                    if hasattr(self, "_phase_state"):
                        try:
                            phase_name = str((self._phase_state() or {}).get("phase") or "scout")
                        except Exception:
                            phase_name = "scout"
                    should_enforce = bool(bb_state.get("strict_mode"))
                    if hasattr(self, "_bb_policy_enforced_for_phase"):
                        should_enforce = bool(self._bb_policy_enforced_for_phase(bb_state, phase_name))
                    if should_enforce and tool_name not in exempt_tools:
                        check = self._bb_policy_check(bb_state)
                        if not check.get("ok"):
                            return make_error(
                                MCPError.INVALID_ARGS,
                                "Strict blackboard policy gate failed before tool execution",
                                hint=json.dumps(
                                    {
                                        "tool": tool_name,
                                        "reasons": check.get("reasons", []),
                                        "recommendation": check.get("recommendation", ""),
                                    },
                                    ensure_ascii=True,
                                ),
                                details={"policy": check.get("policy", {})},
                            )
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug("governance check failed: %s", _e)

            # ---- Phase-state preflight (adaptive choreography) ----
            # Skipped when _risk_ack=true: the caller already acknowledged the
            # risk explicitly, so demanding a blackboard evidence chain on top
            # is redundant friction.
            # Skipped when policy mode is OFF: all gates disabled.
            try:
                _args_for_phase = args if isinstance(args, dict) else {}
                if (tool_name != "blackboard"
                        and not _risk_ack_passed
                        and _policy_mode_cached != "off"
                        and hasattr(self, "_phase_preflight_for_tool")):
                    phase_block = self._phase_preflight_for_tool(tool_name, _args_for_phase)
                    if isinstance(phase_block, dict) and phase_block.get("error"):
                        return phase_block
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug("phase preflight failed: %s", _e)




            # ---- Silent Tool Rerouting ----
            action = args.get("action", "")
            try:
                from .auto_nudge import get_reroute
                reroute = get_reroute(tool_name, str(action) if action else "", args)
                if reroute:
                    new_tool, new_args = reroute
                    new_args["_rerouted_from"] = f"{tool_name}.{action}"
                    tool_name = new_tool
                    args = new_args
                    action = new_args.get("action", "")
                    # Wire preference feedback: mark this reroute as successful
                    try:
                        from .auto_nudge import record_tool_call as nudge_record
                        idb_key = (self.current_session.idb_path if self.current_session else "")
                        nudge_record(idb_key, "_reroute", f"{tool_name}.{action}",
                                    addr=args.get("addr"), query=args.get("query"))
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug("nudge record failed: %s", _e)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug("tool reroute failed: %s", _e)

            # ---- Stuck Detection (UsageIntelligence DriftDetector) ----
            action = args.get("action", "")
            try:
                sid_for_drift = (getattr(self.current_session, "session_id", None)
                                 if self.current_session else None)
                ui = getattr(self, "_usage_intel", None)
                if sid_for_drift and ui and ui.is_running():
                    signals = ui.drift.check(sid_for_drift)
                    # Only block on LOOP — other signals are warnings, not blockers
                    for sig in signals:
                        if sig.get("type") == "LOOP" and sig.get("severity") == "warning":
                            return {
                                "ok": False,
                                "error": {"code": "STUCK_LOOP", "message": sig["message"]},
                                "_nudge": {
                                    "type": "stuck",
                                    "signal": sig["type"],
                                    "suggestion": "Try a different approach. Read ida://state for orientation.",
                                },
                            }
            except Exception:
                pass

            action = args.get("action")
            if isinstance(action, str):
                action = action.strip()
                args["action"] = action

            guardrail_mode = self._guardrail_mode_from_args(args)
            strict_guardrails = self._guardrail_strict_writes or guardrail_mode == "enforce"
            if strict_guardrails:
                risky_tools = {"modify", "bulk", "annotation", "funcs", "segments", "memory", "data_ops"}
                risky_actions = {
                    "patch_asm",
                    "rename",
                    "set_type",
                    "comment",
                    "apply_type",
                    "rename_stack",
                    "write",
                    "make_code",
                    "make_data",
                    "delete",
                    "change",
                    "set_name",
                    "set_attr",
                    "set_perms",
                    "set_flags",
                }
                ack = _coerce_bool(args.get("_guardrail_ack"), False)
                signal = self._compute_pointer_note_signal(tool_name, args, {})
                act = str(args.get("action") or "").strip().lower()
                if (
                    not ack
                    and tool_name in risky_tools
                    and (act in risky_actions or signal >= 2.0)
                ):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "Guardrail strict mode blocked a risky write without acknowledgement",
                        hint="Retry with _guardrail_ack=true or disable IDA_MCP_GUARDRAIL_STRICT_WRITES.",
                        details={
                            "tool": tool_name,
                            "action": act,
                            "signal": round(signal, 3),
                            "guardrail_mode": guardrail_mode,
                        },
                    )
                if ack:
                    pass  # guardrail ack noted
            if tool_name == "wiki":
                return self._handle_wiki(args)
            if tool_name == "misc":
                action = args.get("action")
                # Backward compatibility for callers still using plugins(...).
                # Route everything through misc to avoid maintaining a duplicate plugins tool.
                if original_tool_name == "plugins":
                    if action == "list":
                        args["action"] = "plugin_list"
                    elif action == "run":
                        return make_error(
                            MCPError.ACTION_NOT_FOUND,
                            "plugins(action='run') moved to analysis(action='plugin_run').",
                            hint="Use analysis(action='plugin_run', name='...', arg=0).",
                        )
                    else:
                        return make_error(
                            MCPError.ACTION_NOT_FOUND,
                            f"Unsupported plugins action: '{action}'",
                            hint="Use misc(action='plugin_list') or analysis(action='plugin_run', name='...', arg=0).",
                        )
            if tool_name == "session":
                return self._handle_session(args)

            if tool_name == "misc" and str(args.get("action") or "").strip() in (
                "read_file",
                "write_file",
            ):
                # Same host-side sandbox as memory filesystem I/O.
                return self._handle_memory_filesystem(args)

            if tool_name == "memory" and str(args.get("action") or "").strip() in ("read_file", "write_file"):
                return self._handle_memory_filesystem(args)

            if tool_name == "analysis" and str(args.get("action") or "").strip() == "plugin_run":
                return self._handle_analysis_plugin_run(args)

            if tool_name == "workflow":
                return self._handle_workflow(args)

            if tool_name == "blackboard":
                return self._handle_blackboard(args)

            if tool_name == "gadgets" and str(args.get("action") or "").strip() == "semantic_find":
                return self._handle_gadgets_semantic_find(args)

            if tool_name == "bookmarks":
                return self._handle_bookmarks(args)

            if tool_name == "background":
                return self._handle_background(args)

            if tool_name == "truncation":
                return self._handle_truncation(args)

            if tool_name == "multi_session":
                action = str(args.get("action") or "").strip()
                return self._handle_multi_session(action, args)

            if tool_name == "intelligence" and str(args.get("action") or "") in {
                "index_fast", "index_batch", "index_range"
            }:
                validation_error = self._validate_semantic_index_scope(args)
                if validation_error:
                    return validation_error
                if _coerce_bool(args.pop("_background", False), False):
                    idb_ref = args.pop(
                        "idb", self.current_session.idb_path if self.current_session else None
                    )
                    if not idb_ref:
                        return make_error(
                            MCPError.SESSION_REQUIRED,
                            "No active session. Open a binary before starting semantic indexing.",
                        )
                    return self._submit_semantic_index(args, idb_ref)

            ip = args.pop(
                "idb", self.current_session.idb_path if self.current_session else None
            )
            if not ip:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: ida_open_binary(binary_path='path/to/binary')",
                )
            return self.call_tool(tool_name, ip, **args)
