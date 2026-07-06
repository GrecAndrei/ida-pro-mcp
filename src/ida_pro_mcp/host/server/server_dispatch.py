#!/usr/bin/env python3
"""Generic dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from ida_pro_mcp import __version__

from ..config import _bounded_int, _coerce_bool, _is_writable_dir, _parse_str_list, log_rpc
from ..errors import MCPError, is_error_result, make_error
from ..policy import PolicyDecision, build_audit_record, evaluate_policy
from ..schemas import (
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOLS,
    WRAPPER_ACTIONS,
    _resolve_tool_alias,
)
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
    ("intelligence", "index_batch"),
    ("intelligence", "index_function"),
    ("intelligence", "refresh_anchors"),
    ("intelligence", "semantic_search"),
    # search — graph BFS / embedding
    ("search", "semantic"),
    ("search", "path"),
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
    # threat_hunt / workflow — composite passes
    ("threat_hunt", "run"),
    ("threat_hunt", "malware"),
    ("threat_hunt", "vuln"),
    ("threat_hunt", "deep"),
    ("threat_hunt", "legacy"),
    ("workflow", "execute_plan"),
    ("workflow", "plan"),
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


class ServerDispatchMixin:
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

    def _resolve_policy_mode(self) -> str:
        """Resolve the governance policy mode.

        Precedence (highest first):
          1. Session-level policy_mode (set via session create or set_policy)
          2. IDA_MCP_POLICY_MODE env var
          3. ~/.config/ida-pro-mcp/policy.json `mode` key (live override,
             readable on every call so the user can change it without
             restarting the bridge)
          4. Default "assist"
        """
        session = getattr(self, "current_session", None)
        if session is not None:
            session_mode = getattr(session, "policy_mode", None)
            if isinstance(session_mode, str) and session_mode:
                return session_mode
        env_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        if env_mode:
            return env_mode
        try:
            config_path = os.path.expanduser("~/.config/ida-pro-mcp/policy.json")
            if os.path.exists(config_path):
                with open(config_path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    mode = data.get("mode")
                    if isinstance(mode, str) and mode:
                        return mode
        except Exception:
            pass
        return "assist"

    def call_tool(self, tool_name, idb_path, **kwargs):
            session = self._resolve_session_from_idb_ref(idb_path)
            if not session:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for idb reference: {idb_path}",
                    hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
                )

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

            try:
                rpc_args = {
                    k: v
                    for k, v in kwargs.items()
                    if not (isinstance(k, str) and k.startswith("_"))
                }
                try:
                    allowed = set((TOOL_ARG_SCHEMAS.get(tool_name) or {}).keys())
                    if allowed:
                        rpc_args = {k: v for k, v in rpc_args.items() if k in allowed}
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug("arg schema filter failed: %s", _e)
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
                # Hard wall-clock cap on the entire call_tool path (RPC +
                # retries + IDA). Anything beyond this gets the process
                # signalled and we surface IDA_TIMEOUT so the user can
                # decide whether to restart.
                try:
                    _wallclock_cap = float(
                        os.environ.get("IDA_MCP_RPC_HARD_WALLCLOCK_SEC", "900")
                    )
                except Exception:
                    _wallclock_cap = 900.0
                _wallclock_cap = max(_wallclock_cap, 30.0)
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
                # Wall-clock watchdog: catches the case where IDA is alive
                # but stuck in an unwatched infinite loop (no socket
                # progress, no timeout firing). Force-kill the process and
                # surface IDA_TIMEOUT so the next call re-spawns.
                _elapsed_wallclock = time.time() - _t0
                if _elapsed_wallclock >= _wallclock_cap:
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
                # Other socket errors (TimeoutError, OSError) propagate to the
                # existing handler below, which distinguishes IDA_TIMEOUT from
                # RPC_CONNECTION_ERROR based on the process liveness check.
                _elapsed = time.time() - _t0
                if isinstance(res, dict) and "error" not in res and "ok" not in res:
                    res = {"ok": True, **res}
                res = truncate_response(res, max_tokens=self.default_truncate_tokens)
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
            for sid, runtime in self.session_runtimes.items():
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
                        "tracked": len(self.session_runtimes),
                        "running": running,
                        "stale": stale,
                    },
                },
                "wiki": {"root": wiki_root or None, "available": wiki_available},
                "tools": {
                    "registered": len(TOOLS),
                    "advertised": len(ADVERTISED_TOOLS),
                    "hidden_from_tools_list": len(HIDDEN_TOOLS_IN_LIST),
                    "wrappers": list(WRAPPER_ACTIONS),
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
                    hint="Open a session first with session(action='create', binary_path='...').",
                )
            return self._send_rpc_raw(
                {"tool": "misc", "args": {"action": "plugin_run", "name": name, "arg": arg}},
                runtime.get("port"),
            )

    def _handle_bookmarks(self, args: dict) -> dict:
            if not self.current_session:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
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
                hint="Use bookmarks(action='list'|'add'|'delete'|'update'|'clear'|'find'|'export').",
            )

    def _handle_truncation(self, args: dict) -> dict:
            action = str(args.get("action") or "").strip().lower()
            if action != "continue":
                return make_error(
                    MCPError.ACTION_NOT_FOUND,
                    f"Unsupported truncation action: '{action}'",
                    hint="Use truncation(action='continue', token='...').",
                )
            token = args.get("token") or args.get("next_token")
            if not isinstance(token, str) or not token.strip():
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    "Invalid continuation token. Check the token value.",
                )
            token = token.strip()
            field = args.get("field")
            offset = args.get("offset")
            count = args.get("count")
            from . import server as _server_mod

            result = _server_mod.continue_truncated(
                token,
                field=field if isinstance(field, str) else None,
                offset=_bounded_int(offset, 0, min_value=0, max_value=500000)
                if offset is not None
                else None,
                count=_bounded_int(count, 0, min_value=1, max_value=5000)
                if count is not None
                else None,
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

    def _grep_value_lines(self, value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [line for line in value.splitlines() if line.strip()]
            if isinstance(value, list):
                out: list[str] = []
                for item in value:
                    if isinstance(item, str):
                        out.extend([line for line in item.splitlines() if line.strip()])
                    elif isinstance(item, dict):
                        out.append(
                            json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                        )
                    else:
                        s = str(item).strip()
                        if s:
                            out.append(s)
                return out
            if isinstance(value, dict):
                out: list[str] = []
                for _k, v in value.items():
                    if isinstance(v, str):
                        for line in v.splitlines():
                            line = line.strip()
                            if line:
                                out.append(line)
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, str) and item.strip():
                                out.append(item.strip())
                if out:
                    return out
                return [json.dumps(value, ensure_ascii=False, separators=(",", ":"))]
            s = str(value).strip()
            return [s] if s else []

    def _grep_collect_lines(
            self, payload: Any, field: str | None = None
        ) -> tuple[list[str], str]:
            if field and isinstance(payload, dict):
                return self._grep_value_lines(payload.get(field)), field
            if isinstance(payload, dict):
                preferred_fields = (
                    "sessions",
                    "bookmarks",
                    "macros",
                    "items",
                    "results",
                    "matches",
                    "functions",
                    "findings",
                    "usages",
                    "callers",
                    "callees",
                    "content",
                    "sections",
                    "names",
                    "strings",
                    "imports",
                    "code_refs",
                    "data_refs",
                )
                for key in preferred_fields:
                    if key in payload:
                        lines = self._grep_value_lines(payload.get(key))
                        if lines:
                            return lines, key
                return self._grep_value_lines(payload), "payload"
            return self._grep_value_lines(payload), "payload"

    def _handle_tool_grep_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(tool_name, args, "grep")
            if source_err:
                return source_err

            explicit_pattern = args.get("grep") or args.get("grep_pattern")
            grep_pattern = explicit_pattern or args.get("pattern") or args.get("query")
            if not isinstance(grep_pattern, str) or not grep_pattern.strip():
                return make_error(
                    MCPError.INVALID_ARGS,
                    "grep pattern required",
                    hint="Set grep='...' (or grep_pattern/pattern/query) with action='grep'.",
                )
            grep_pattern = grep_pattern.strip()

            grep_regex = _coerce_bool(args.get("grep_regex"), False)
            grep_case_sensitive = _coerce_bool(args.get("grep_case_sensitive"), False)
            grep_invert = _coerce_bool(args.get("grep_invert"), False)
            grep_field = args.get("grep_field")
            if grep_field is not None and not isinstance(grep_field, str):
                return make_error(MCPError.INVALID_ARGS, "grep_field must be a string")
            grep_limit = _bounded_int(
                args.get("grep_limit", 200), 200, min_value=1, max_value=5000
            )
            grep_offset = _bounded_int(
                args.get("grep_offset", 0), 0, min_value=0, max_value=500000
            )

            child_args = self._strip_wrapper_args(args)
            if explicit_pattern is None:
                child_args.pop("pattern", None)
                child_args.pop("query", None)
            child_args["action"] = source_action

            source_payload = self._execute_tool(tool_name, child_args)
            if is_error_result(source_payload):
                return source_payload

            lines, used_field = self._grep_collect_lines(source_payload, grep_field)
            if grep_regex:
                flags = 0 if grep_case_sensitive else re.IGNORECASE
                try:
                    rx = re.compile(grep_pattern, flags)
                except re.error as e:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid grep regex: {e}")
                matched = [line for line in lines if bool(rx.search(line)) != grep_invert]
            else:
                needle = grep_pattern if grep_case_sensitive else grep_pattern.lower()
                matched = []
                for line in lines:
                    hay = line if grep_case_sensitive else line.lower()
                    found = needle in hay
                    if found != grep_invert:
                        matched.append(line)

            total = len(matched)
            page = matched[grep_offset : grep_offset + grep_limit]
            is_truncated = (grep_offset + len(page)) < total

            return {
                "ok": True,
                "action": "grep",
                "tool": tool_name,
                "source_action": source_action,
                "field": used_field,
                "pattern": grep_pattern,
                "matches": "\n".join(page),
                "source_count": len(lines),
                "count": len(page),
                "total": total,
                "offset": grep_offset,
                "truncated": is_truncated,
                "next_offset": (grep_offset + len(page)) if is_truncated else None,
            }

    def _handle_tool_pick_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(tool_name, args, "pick")
            if source_err:
                return source_err
            fields = _parse_str_list(args.get("pick_fields"))
            if not fields:
                fields = _parse_str_list(args.get("_response_fields"))
            if not fields:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "action='pick' requires pick_fields",
                    hint=f"Example: {tool_name}(action='pick', source_action='list', pick_fields='functions,count').",
                )
            omit = set(_parse_str_list(args.get("pick_omit")))

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if is_error_result(source_payload):
                return source_payload
            if not isinstance(source_payload, dict):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "pick wrapper requires source payload object",
                    hint="Pick is top-level field projection; use grep/head/tail for line-oriented payloads.",
                )

            selected = {}
            missing: list[str] = []
            for key in fields:
                if key in source_payload:
                    selected[key] = source_payload.get(key)
                else:
                    missing.append(key)
            for key in omit:
                selected.pop(key, None)

            out = {
                "ok": True,
                "action": "pick",
                "tool": tool_name,
                "source_action": source_action,
                "picked": list(selected.keys()),
                **selected,
            }
            if missing:
                out["missing_fields"] = missing
            return out

    def _handle_tool_head_tail_action(
            self, tool_name: str, args: dict, *, tail: bool = False
        ) -> dict:
            wrapper_name = "tail" if tail else "head"
            source_action, source_err = self._wrapper_source_action(
                tool_name, args, wrapper_name
            )
            if source_err:
                return source_err

            default_n = 20
            n_key = "tail_n" if tail else "head_n"
            n = _bounded_int(
                args.get(n_key, default_n), default_n, min_value=1, max_value=5000
            )
            field = args.get("grep_field") or args.get("field")
            if field is not None and not isinstance(field, str):
                return make_error(MCPError.INVALID_ARGS, "field must be a string")

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if is_error_result(source_payload):
                return source_payload

            items, used_field, item_kind = self._collect_wrapper_items(
                source_payload, field
            )
            total = len(items)
            if tail:
                page = items[max(0, total - n) :]
                offset = max(0, total - len(page))
            else:
                page = items[:n]
                offset = 0

            lines = [self._lineify_item(item) for item in page]
            lines = [line for line in lines if line]
            is_truncated = len(page) < total
            out = {
                "ok": True,
                "action": wrapper_name,
                "tool": tool_name,
                "source_action": source_action,
                "field": used_field,
                "matches": "\n".join(lines),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
                "next_offset": (offset + len(page))
                if (not tail and is_truncated)
                else None,
            }
            if _coerce_bool(args.get("include_items"), False):
                out["items"] = page if item_kind == "list" else lines
            return out

    def _handle_tool_next_action(self, tool_name: str, args: dict) -> dict:
            token = args.get("next_token") or args.get("token") or args.get("cursor")
            if not isinstance(token, str) or not token.strip():
                return make_error(
                    MCPError.INVALID_ARGS,
                    "action='next' requires next_token (or token/cursor)",
                    hint=f"Use the next_token returned by {tool_name} or wrapper actions with truncated=true.",
                )
            token = token.strip()
            self._prune_next_cache()
            entry = self._next_cache.get(token)
            if not entry:
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    f"next token '{token}' not found or expired",
                    hint="Re-run the original paginated call to get a fresh next_token.",
                )
            cached_tool = str(entry.get("tool") or "")
            if cached_tool and cached_tool != tool_name:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"next token belongs to tool '{cached_tool}', not '{tool_name}'",
                )

            child_args = dict(entry.get("args") or {})
            child_args["action"] = entry.get("action")
            child_args["offset"] = entry.get("next_offset", child_args.get("offset", 0))

            overrides = dict(args or {})
            for key in ("action", "next_token", "token", "cursor"):
                overrides.pop(key, None)
            child_args.update(overrides)
            result = self._execute_tool(tool_name, child_args)
            if isinstance(result, dict):
                result = dict(result)
                result["continued_from"] = token
            return result

    def _handle_tool_stats_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(
                tool_name, args, "stats"
            )
            if source_err:
                return source_err
            include_payload = _coerce_bool(args.get("stats_include_payload"), False)

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if is_error_result(source_payload):
                return source_payload

            try:
                serialized = json.dumps(
                    source_payload, ensure_ascii=False, separators=(",", ":")
                )
            except Exception:
                serialized = str(source_payload)
            items, used_field, item_kind = self._collect_wrapper_items(source_payload)
            top_keys: list[str] = []
            if isinstance(source_payload, dict):
                top_keys = list(source_payload.keys())[:64]
            stats = {
                "type": type(source_payload).__name__,
                "top_level_keys": top_keys,
                "line_count": len(
                    [line for line in serialized.splitlines() if line.strip()]
                ),
                "char_count": len(serialized),
                "item_count": len(items),
                "item_field": used_field,
                "item_kind": item_kind,
                "has_error": is_error_result(source_payload),
                "truncated": bool(
                    isinstance(source_payload, dict) and source_payload.get("truncated")
                ),
            }
            out = {
                "ok": True,
                "action": "stats",
                "tool": tool_name,
                "source_action": source_action,
                "stats": stats,
            }
            if include_payload:
                out["payload"] = source_payload
            return out

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
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy blocked this tool action",
                            hint="Use an allowed purpose and verify the workflow is authorized.",
                            details=policy_details,
                        )
                    if policy_result.decision == PolicyDecision.REQUIRE_ACK:
                        return make_error(
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy requires explicit acknowledgement for this tool action",
                            hint="Retry with _risk_ack=true after verifying the action is authorized.",
                            details=policy_details,
                        )
                except Exception as e:
                    log_rpc(f"Policy evaluation failed for {tool_name}: {e}")
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
                        "misc",
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
                native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
                has_wrapper_source = any(
                    key in args
                    for key in ("source_action", "target_action", "on", "subaction")
                )
                if action in WRAPPER_ACTIONS:
                    use_wrapper = action not in native_actions
                    if action in ("grep", "pick", "head", "tail", "stats"):
                        use_wrapper = use_wrapper or has_wrapper_source
                    elif action == "next":
                        use_wrapper = use_wrapper or any(
                            key in args for key in ("next_token", "token", "cursor")
                        )
                    if use_wrapper:
                        if action == "grep":
                            return self._handle_tool_grep_action(tool_name, args)
                        if action == "pick":
                            return self._handle_tool_pick_action(tool_name, args)
                        if action == "head":
                            return self._handle_tool_head_tail_action(
                                tool_name, args, tail=False
                            )
                        if action == "tail":
                            return self._handle_tool_head_tail_action(
                                tool_name, args, tail=True
                            )
                        if action == "next":
                            return self._handle_tool_next_action(tool_name, args)
                        if action == "stats":
                            return self._handle_tool_stats_action(tool_name, args)

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

            if tool_name == "memory" and str(args.get("action") or "").strip() in ("read_file", "write_file"):
                return self._handle_memory_filesystem(args)

            if tool_name == "analysis" and str(args.get("action") or "").strip() == "plugin_run":
                return self._handle_analysis_plugin_run(args)

            if tool_name == "threat_hunt":
                return self._handle_threat_hunt(args)

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

            ip = args.pop(
                "idb", self.current_session.idb_path if self.current_session else None
            )
            if not ip:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
                )
            return self.call_tool(tool_name, ip, **args)


