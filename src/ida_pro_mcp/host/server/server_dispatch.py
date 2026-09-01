#!/usr/bin/env python3
"""Generic dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
import uuid
from typing import Any

from ida_pro_mcp import __version__

from ..config import (
    RPC_QUEUE_TIMEOUT_SECONDS,
    _bounded_int,
    _coerce_bool,
    _is_writable_dir,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error
from ..policy import (
    PolicyDecision,
    ack_from_args,
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
from .postprocess import (
    PP_KEYS,
    apply_post_processing,
    has_post_process,
    prepare_args_for_postprocess,
)
from .rate_limit import is_rate_limit_exempt
from .rpc_args import prepare_rpc_args
from .server_client_state import ServerClientStateMixin
from .server_response import truncate_response
from .server_runtime import RpcQueueTimeout

# D1: cached parsed policy config, keyed by (mtime_ns, size) of the config
# file. Re-parsed only when the file changes; missing files are re-probed
# (stat) each call, which is far cheaper than open+parse.
_POLICY_CONFIG_CACHE: dict[str, tuple[tuple[int, int], str]] = {}
_POLICY_CONFIG_CACHE_LOCK = threading.RLock()

# D3: tools that natively paginate with offset/count and report a pre-slice
# `total`. A pure PP page-slice (offset+limit, no grep/tail) is forwarded to
# these so IDA returns only the requested page instead of the full list.
# Only the listed actions are safe: they are the paged list views.
_SLICE_FORWARDABLE_TOOLS: dict[str, frozenset[str]] = {
    "data": frozenset(
        {"functions", "globals", "strings", "imports", "exports", "annotations"}
    ),
    "funcs": frozenset({"list"}),
}

# Actions that legitimately walk the IDB at scale (full-program scans,
# embedding pipelines, decompile pumps, bulk-session housekeeping). For these we extend the socket recv
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
    ("search", "constants"),
    # blackboard — trace operations
    ("blackboard", "trace_ingest"),
    ("blackboard", "trace_run"),
    # funcs — whole-program walks
    ("funcs", "metrics"),
    ("funcs", "suggest_names"),
    ("funcs", "find_similar"),

    ("workflow", "execute_plan"),
    ("workflow", "plan"),
    # r2 — raw-binary sidecar engine: whole-file word scans + windowed
    # multi-arch disassembly can exceed the default RPC recv timeout.
    ("r2", "vxrefs"),
    ("r2", "disassemble_hypothesis"),
}

# (tool, action) pairs blocked while a session is in safe mode (IDA
# auto-analysis still running). Safe mode blocks anything that would invoke
# full-binary analysis, index a half-analyzed database, or execute arbitrary
# scripts; manual small-area operations (disassembly, reads, strings, xrefs,
# per-function decompilation, comment/rename writes) stay available. The
# gate lifts automatically once analysis completes.
SAFE_MODE_BLOCKED_TOOLS: set[str] = {"misc"}  # misc: python/idc/plugin_run run arbitrary code
SAFE_MODE_BLOCKED_ACTIONS: set[tuple[str, str]] = {
    # analysis engine invocations (set_processor/loader/architecture force a
    # fresh load or full reanalysis; reanalyze/run/analyze pump auto-analysis)
    ("analysis", "set_processor"),
    ("analysis", "set_loader_options"),
    ("analysis", "set_architecture"),
    ("analysis", "reanalyze"),
    ("analysis", "run"),
    ("analysis", "analyze"),
    # plugin_run executes arbitrary IDA plugin code — same capability as the
    # blocked misc/plugin_run, just routed via the analysis tool.
    ("analysis", "plugin_run"),
    # decompile-everything indexing / semantic products over partial data
    ("intelligence", "index_fast"),
    ("intelligence", "index_batch"),
    ("intelligence", "index_range"),
    ("intelligence", "index_function"),
    ("intelligence", "refresh_anchors"),
    ("intelligence", "semantic_search"),
    ("intelligence", "similar_functions"),
    # whole-program automated workflow runs
    ("workflow", "execute_plan"),
    ("workflow", "triage_fast"),
    ("workflow", "malware_deep"),
    ("workflow", "vuln_audit"),
    ("workflow", "recon_sweep"),
    # symbol loads can trigger full reanalysis of the database
    ("symbols", "load_pdb"),
    ("symbols", "load_dwarf"),
    # segments(action='analyze') runs auto-analysis over the segment
    ("segments", "analyze"),
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
    env cap so no caller can pin the dispatcher forever.  A user-raised
    ``IDA_MCP_RPC_TIMEOUT`` default also raises the floor: operators who
    configure a 300s default expect long scans to survive at least that
    long, not to die at the 120s built-in floor.
    """
    try:
        cap = int(os.environ.get("IDA_MCP_RPC_MAX_RECV_TIMEOUT", "600"))
    except Exception:
        cap = 600
    cap = max(cap, 30)
    try:
        env_default = int(os.environ.get("IDA_MCP_RPC_TIMEOUT", "30"))
    except Exception:
        env_default = 30
    floor = max(120, env_default)

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
        return min(max(floor, full_index_timeout), cap)

    requested = (
        rpc_args.get("timeout")
        or rpc_args.get("max_wait")
        or rpc_args.get("poll_timeout")
    )
    try:
        n = int(requested) if requested is not None else 0
    except Exception:
        n = 0
    candidate = max(floor, n + 30) if n else floor
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

        The config file is re-read only when its (mtime_ns, size) changes, so
        an operator can edit it live without paying 2-5 disk reads + a JSON
        parse on every tool call (previously done per call via
        _resolve_policy_mode, itself invoked up to 4-6 times per call).
        """
        env_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        if env_mode:
            return env_mode
        config_path = os.path.expanduser("~/.config/ida-pro-mcp/policy.json")
        try:
            try:
                _st = os.stat(config_path)
            except OSError:
                # No file (or unreadable stat): a missing config must still be
                # detected if it appears later, so only cache the "missing"
                # state keyed on the path's absence — a config created after
                # the first call is picked up on the next call.
                return self._policy_baseline_mode_cached(None, config_path)
            key = (_st.st_mtime_ns, _st.st_size)
            with _POLICY_CONFIG_CACHE_LOCK:
                cached = _POLICY_CONFIG_CACHE.get(config_path)
                if cached is not None and cached[0] == key:
                    return cached[1]
            mode = self._policy_baseline_mode_cached(key, config_path)
            with _POLICY_CONFIG_CACHE_LOCK:
                _POLICY_CONFIG_CACHE[config_path] = (key, mode)
            return mode
        except Exception as e:
            log_rpc(f"Ignoring unreadable policy config {config_path}: {e}")
            return "assist"

    @staticmethod
    def _policy_baseline_mode_cached(
        _key: tuple[int, int] | None, config_path: str
    ) -> str:
        """Parse ``policy.json`` and return its mode (no cache read/write).

        Split out so the read path can reuse it for the cold-miss and
        missing-file cases. ``_key`` is informational only — it keeps the two
        call sites symmetric and makes the intent explicit.
        """
        try:
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

    def _safe_mode_active(self, sid: str) -> bool:
        """True while *sid*'s IDA auto-analysis is still completing."""
        pending = getattr(self, "_pending_analysis", None)
        if not isinstance(pending, set):
            return False
        return sid in pending

    def _safe_mode_gate(self, sid: str, tool_name: str, action: str) -> dict | None:
        """Return an error response when (tool, action) is blocked in safe mode.

        Safe mode blocks full-binary analysis, decompile-everything indexing,
        and arbitrary script execution while a session's auto-analysis is
        still running; manual small-area operations stay available. Lifts
        automatically once analysis completes.
        """
        if not sid or not self._safe_mode_active(sid):
            return None
        if tool_name in SAFE_MODE_BLOCKED_TOOLS:
            return make_error(
                MCPError.SAFE_MODE,
                f"Tool '{tool_name}' is blocked while IDA auto-analysis is running",
                recoverable=True,
                hint=(
                    "This operation can run arbitrary code or trigger full "
                    "analysis of a database that is still being analyzed. "
                    "Poll ida_session_status until safe_mode clears, then retry."
                ),
                details={"session_id": sid, "tool": tool_name},
            )
        if (tool_name, action) in SAFE_MODE_BLOCKED_ACTIONS:
            return make_error(
                MCPError.SAFE_MODE,
                f"{tool_name}(action='{action}') is blocked while IDA auto-analysis is running",
                recoverable=True,
                hint=(
                    "This operation invokes full-binary analysis or indexes a "
                    "half-analyzed database. Manual small-area operations "
                    "(disassembly, reads, per-function decompilation) remain "
                    "available. Poll ida_session_status until safe_mode clears."
                ),
                details={"session_id": sid, "tool": tool_name, "action": action},
            )
        return None

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

            _sid = session.session_id

            # Safe-mode gate: block full-binary analysis / indexing / script
            # execution while this session's auto-analysis is still running.
            safe_gate = self._safe_mode_gate(
                _sid, tool_name, str(kwargs.get("action") or "")
            )
            if safe_gate is not None:
                return safe_gate

            # A rebuild/recovery restart is in flight for this session
            # (reload-on-completion was removed in the lifecycle revamp: the
            # completing runtime IS the serving runtime); calls would race the
            # restart.
            reload_active = getattr(self, "_session_reload_active", None)
            if callable(reload_active) and reload_active(_sid):
                return make_error(
                    MCPError.IDA_BUSY,
                    "Session is being rebuilt/reloaded; retry in a moment.",
                    recoverable=True,
                    hint="Poll ida_session_status until safe_mode clears.",
                    details={"session_id": _sid},
                )

            runtime = self._runtime_record(session.session_id)
            if not self._runtime_alive(runtime):
                log_rpc(
                    f"Session start/restart needed: {session.session_id} -> {session.idb_path}"
                )
                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                runtime = self._runtime_record(session.session_id)
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
            # Defensive defaults: the wall-clock watchdog below must be safe to
            # consult from the outer exception handler even if the RPC setup
            # raised before these were assigned inside the try.
            _rpc_started = 0.0
            _wallclock_cap = 900.0
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
                _sid = session.session_id
                # Track the request on the session's RPC lane so health and
                # the watchdog can report queue depth. Requests to different
                # sessions run in parallel; requests to the same session
                # serialize on its rpc_lock below.
                inflight = getattr(self, "_session_inflight_calls", None)
                if isinstance(inflight, dict):
                    # Guard the read-modify-write: this runs on request threads
                    # AND batch/index worker threads concurrently, and handle_request
                    # mutates the same dict under _runtime_lock. Without the lock a
                    # lost update inflates the count and the paired decrement can
                    # pop a counter still owned by another live call.
                    with self._runtime_lock:
                        inflight[_sid] = int(inflight.get(_sid, 0) or 0) + 1
                try:
                    res = self._send_rpc_with_retry(
                        {"tool": tool_name, "args": rpc_args}, port,
                        recv_timeout=_rpc_sock_timeout,
                        queue_timeout=(
                            None
                            if RPC_QUEUE_TIMEOUT_SECONDS <= 0
                            else RPC_QUEUE_TIMEOUT_SECONDS
                        ),
                    )
                except RpcQueueTimeout:
                    return make_error(
                        MCPError.IDA_BUSY,
                        "IDA runtime is busy with another request",
                        recoverable=True,
                        hint=(
                            "Wait for the in-flight call to finish, or reduce "
                            "parallel calls to this session. Increase "
                            "IDA_MCP_RPC_QUEUE_TIMEOUT (seconds) for deeper queues."
                        ),
                        details={
                            "session_id": _sid,
                            "queue_timeout": RPC_QUEUE_TIMEOUT_SECONDS,
                            "tool": tool_name,
                        },
                    )
                except (
                    ConnectionRefusedError,
                    ConnectionResetError,
                    ConnectionAbortedError,
                    EOFError,
                ) as exc:
                    # Connection-layer failure that exhausted retries. Surface as
                    # runtime error so the agent can decide to restart.
                    return make_error(
                        MCPError.RPC_CONNECTION_ERROR,
                        f"RPC to IDA failed after retries: {exc}",
                        details={"exception_type": type(exc).__name__, "tool": tool_name},
                    )
                finally:
                    if isinstance(inflight, dict):
                        with self._runtime_lock:
                            remaining = int(inflight.get(_sid, 0) or 0) - 1
                            if remaining > 0:
                                inflight[_sid] = remaining
                            else:
                                inflight.pop(_sid, None)
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
                # Stamp arbitrary-code responses with the session they actually
                # ran in. On a shared MCP connection a call aimed at the wrong
                # session previously returned cleanly — the response now
                # self-identifies so a wrong image base is visible instead of
                # silently attributing code to the shared active session.
                # Applies to success and error responses alike (the error still
                # tells you where it ran).
                if (
                    isinstance(res, dict)
                    and tool_name == "misc"
                    and str(rpc_args.get("action") or "") in {"python", "idc", "plugin_run"}
                ):
                    try:
                        _img_base = self._get_session_imagebase(session.session_id)
                    except Exception:
                        _img_base = None
                    res["_executed_in"] = {
                        "session_id": session.session_id,
                        "idb_path": getattr(session, "idb_path", None),
                        "image_base": hex(_img_base) if _img_base else None,
                    }
                # ---- D3: post-process BEFORE truncation ----
                # PP's offset/limit/grep must see the full (untruncated) RPC
                # result. Applying it after truncation sliced a truncated
                # window, so pages beyond the first and grep matches past the
                # truncation budget were silently lost. Runs only for fresh
                # calls (_pending_pp carries no next_token here); next_token
                # continuations drive their own PP in _handle_next_continuation.
                _pp = getattr(self, "_pending_pp", None)
                if (
                    _pp
                    and has_post_process(_pp)
                    and not _pp.get("next_token")
                    and not (isinstance(res, dict) and res.get("_post_processed"))
                    and not is_error_result(res)
                ):
                    try:
                        if _pp.get("_forwarded_offset") is not None:
                            # The tool already skipped the PP offset server-side;
                            # re-applying it would double-skip. Pagination still
                            # uses the original offset (see _cache_post_process_next).
                            _apply_pp = {
                                k: v for k, v in _pp.items()
                                if k != "offset"
                            }
                        else:
                            _apply_pp = _pp
                        res = apply_post_processing(res, _apply_pp)
                    except Exception as _pp_err:
                        import logging
                        logging.getLogger(__name__).debug(
                            "post-process pipeline failed: %s", _pp_err
                        )
                # Apply truncation with per-call overrides
                _tc = getattr(self, "_pending_truncation", None) or {}
                if _tc.get("no_truncate"):
                    pass  # skip truncation entirely
                else:
                    _budget = _tc.get("max_tokens") or self.default_truncate_tokens
                    # Scope the truncation token to the session the call
                    # actually ran in (idb-resolved above), not the shared
                    # active default. On a multiplexed connection the two can
                    # differ; minting under current_session attributed the
                    # token to the wrong session. _handle_truncation resolves
                    # idb the same way so continuation still matches.
                    _sid = session.session_id
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
                # Wall-clock hard cap on the RPC path itself. The watchdog block
                # above only fires when a dict actually came back over the wire;
                # a hung IDA raises socket.timeout out of _send_rpc_with_retry,
                # which lands here. The cap must still apply, or a whitelisted
                # long action with a generous recv timeout would run past the
                # documented cap with the process left alive.
                if time.time() - _rpc_started >= _wallclock_cap:
                    try:
                        if proc is not None and hasattr(proc, "poll"):
                            if proc.poll() is None and hasattr(proc, "terminate"):
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
                            "elapsed_sec": round(time.time() - _rpc_started, 2),
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
            with self._runtime_lock:
                inflight = getattr(self, "_session_inflight_calls", None)
                inflight_snapshot = (
                    dict(inflight) if isinstance(inflight, dict) else {}
                )
            queued_total = 0
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
                            "rpc_queued": int(inflight_snapshot.get(sid, 0) or 0),
                        }
                    )
                queued_total += int(inflight_snapshot.get(sid, 0) or 0)

            action_counts = {
                str(tool): len(list(actions or []))
                for tool, actions in TOOL_ACTIONS.items()
            }
            max_actions_tool = ""
            max_actions_count = 0
            if action_counts:
                max_actions_tool = max(action_counts, key=action_counts.get)
                max_actions_count = int(action_counts.get(max_actions_tool, 0))
            # Session-store discovery is best-effort: a corrupt session dir or
            # an I/O error must never crash the very endpoint that exists to
            # report unhealthy state. Surface the failure in the payload and
            # report 0 discovered sessions instead of raising out of the
            # envelope (call_tool's try/except does not wrap host-side session
            # handlers).
            session_total = 0
            session_discovery_error = None
            try:
                session_total = len(self.session_mgr.discover_sessions())
            except Exception as _discover_e:
                import logging
                logging.getLogger(__name__).debug(
                    "session discovery failed during health: %s", _discover_e
                )
                session_discovery_error = str(_discover_e)
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
                    "total": session_total,
                    "discovery_error": session_discovery_error,
                    "active": self.current_session.session_id
                    if self.current_session
                    else None,
                    "runtime_processes": {
                        "tracked": tracked,
                        "running": running,
                        "stale": stale,
                    },
                    "rpc_queued_calls": queued_total,
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
            # Resolve the session the plugin actually runs in. Every other tool
            # honors args.get('idb') via call_tool's _resolve_session_from_idb_ref;
            # on a shared MCP connection a call aimed at another session must run
            # there — not in the shared active session — and must pass the same
            # ownership guard call_tool enforces.
            target = self.current_session if self.current_session else None
            idb_ref = args.get("idb")
            if idb_ref:
                resolved = self._resolve_session_from_idb_ref(idb_ref)
                if resolved is None:
                    return make_error(
                        MCPError.FILE_NOT_FOUND,
                        f"No session found for idb reference: {idb_ref}",
                        hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
                    )
                ownership_error = self._ensure_client_owns_session(resolved)
                if ownership_error:
                    return ownership_error
                target = resolved
            if target is None:
                return make_error(
                    MCPError.IDA_CRASHED,
                    "plugin_run requires a live IDA session; none is active.",
                    hint="Open a session first with ida_open_binary(binary_path='...').",
                )
            runtime = self._runtime_record(target.session_id)
            if not self._runtime_alive(runtime):
                return make_error(
                    MCPError.IDA_CRASHED,
                    "plugin_run requires a live IDA session; none is active.",
                    hint="Open a session first with ida_open_binary(binary_path='...').",
                )
            result = self._send_rpc_raw(
                {"tool": "misc", "args": {"action": "plugin_run", "name": name, "arg": arg}},
                runtime.get("port"),
            )
            # Stamp arbitrary-code responses with the session they ran in, so a
            # call aimed at the wrong session self-identifies instead of silently
            # attributing code to the shared active session.
            if isinstance(result, dict):
                try:
                    _img_base = self._get_session_imagebase(target.session_id)
                except Exception:
                    _img_base = None
                result["_executed_in"] = {
                    "session_id": target.session_id,
                    "idb_path": getattr(target, "idb_path", None),
                    "image_base": hex(_img_base) if _img_base else None,
                }
            return result

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
                hint="Bookmark mutation isn't a public op; list via idb(action='bookmarks'); manage via misc(action='python') if code execution is authorized.",
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
            # Truncation tokens are minted against the idb-resolved session the
            # original call ran in (call_tool), so resolve idb here too — falling
            # back to the shared active default only when no idb was supplied.
            # Without this the two would drift on a multiplexed connection and a
            # legitimately-scoped token would fail to resolve.
            sid = ""
            if args.get("idb"):
                _trunc_target = None
                try:
                    _trunc_target = self._resolve_session_from_idb_ref(args.get("idb"))
                except Exception:
                    _trunc_target = None
                if _trunc_target is not None:
                    sid = _trunc_target.session_id
            if not sid:
                sid = getattr(self.current_session, "session_id", "") if self.current_session else ""
            owner = self._truncation_owner_id() if hasattr(self, "_truncation_owner_id") else ""
            # Direct import: the truncation stores live in ..stores.truncation.
            # (Previously ``from . import server as _server_mod`` then
            # ``_server_mod.continue_truncated`` — but the server module does not
            # re-export those functions, so every continue/peek/search/summary
            # action raised AttributeError.)
            from ..stores.truncation import (
                continue_truncated,
                peek_truncated,
                search_truncated,
                summary_truncated,
            )

            if action == "continue":
                field = args.get("field")
                offset = args.get("offset")
                count = args.get("count")
                result = continue_truncated(
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
                result = peek_truncated(token, session_id=sid, owner_id=owner)
            elif action == "search":
                pattern = str(args.get("pattern") or args.get("query") or "").strip()
                field = args.get("field")
                result = search_truncated(
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
                result = summary_truncated(
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
        with self._next_cache_lock():
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

        # Two token flavours share this cache:
        #   * PP-pagination tokens (minted by _cache_post_process_next) carry a
        #     "post_process" entry; the host re-fetches the full result and
        #     advances the host-side slice.
        #   * tool-level tokens (minted by _cache_next_page for a server-side
        #     truncated result) carry no "post_process" entry; the tool itself
        #     paginates, so the advanced offset must be forwarded as a real
        #     tool arg instead of being applied as a host-side slice.
        tool_level_token = "post_process" not in entry
        cached_pp = dict(entry.get("post_process") or {})
        if tool_level_token:
            if entry.get("next_offset") is not None:
                base_args["offset"] = entry.get("next_offset")
        else:
            cached_pp["offset"] = entry.get("next_offset", 0)
        for k, v in pp_params.items():
            if k != "next_token" and v is not None:
                cached_pp[k] = v

        # Never replay post-processing keys as real IDA args: prepare_rpc_args
        # rejects keys absent from the tool schema (head/grep/tail/pick/field),
        # and limit/offset would be double-applied if they reached the tool.
        # PP tokens strip all of them (they are driven host-side via cached_pp);
        # tool-level tokens keep schema-backed limit/offset (the tool's own
        # cursor) and strip only the rest.
        schema = TOOL_ARG_SCHEMAS.get(tool_name, {}) or {}
        if tool_level_token:
            for k in list(base_args.keys()):
                if k in PP_KEYS and k not in schema:
                    base_args.pop(k, None)
        else:
            for k in list(base_args.keys()):
                if k in PP_KEYS:
                    base_args.pop(k, None)

        # Execute the original tool action — re-run policy so continuation
        # pages cannot bypass the preflight gates that protected page 1.
        try:
            policy_result = evaluate_policy(
                tool_name,
                base_args.get("action"),
                mode=self._resolve_policy_mode(),
                purpose=base_args.get("_purpose") or pp_params.get("_purpose"),
                ack=ack_from_args(pp_params) or ack_from_args(base_args),
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

        # The continuation replays a prior page's tool call: enforce the same
        # gates page 1 ran (guardrail strict write, blackboard strict, phase
        # preflight) so a risky write cannot slip through on page 2 via token
        # replay. Policy was re-evaluated above with the recovered acks;
        # call_tool below re-checks safe mode and ownership.
        _replay_ack = ack_from_args(base_args)
        _gr_err = self._guardrail_strict_gate(tool_name, base_args)
        if _gr_err is not None:
            return _gr_err
        _bb_phase_err = self._blackboard_and_phase_preflight(
            tool_name, base_args, _replay_ack
        )
        if _bb_phase_err is not None:
            return _bb_phase_err

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

        if tool_level_token:
            # Tool-level pagination: the tool drives its own cursor, so a
            # host-side slice would double-skip. Mint the next token from the
            # raw offset/count the tool reported on this page, preserving the
            # (already PP-stripped) tool args for the next replay.
            if isinstance(result, dict) and _coerce_bool(result.get("truncated"), False):
                try:
                    _off = int(result.get("offset", 0) or 0)
                    _cnt = int(result.get("count", 0) or 0)
                except Exception:
                    _off = _cnt = 0
                if _cnt > 0 and _off + _cnt > _off:
                    self._prune_next_cache()
                    _t2 = uuid.uuid4().hex[:12].upper()
                    with self._next_cache_lock():
                        self._next_cache[_t2] = {
                            "tool": tool_name,
                            "action": base_args.get("action"),
                            "args": {k: v for k, v in base_args.items() if k != "action"},
                            "next_offset": _off + _cnt,
                            "created_at": time.time(),
                        }
                    result["next_token"] = _t2
                    result["next_offset"] = _off + _cnt
        else:
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
        # `_total` is the pre-slice item count (after grep, before
        # head/tail/offset); `_count` alone is the post-slice length and would
        # falsely signal "more" whenever the slice came back exactly full.
        total = result.get("_total", count)
        source_truncated = _coerce_bool(result.get("truncated"), False)
        page_size = pp_params.get("head") or pp_params.get("limit")
        current_offset = _bounded_int(
            pp_params.get("offset"), 0, min_value=0, max_value=500_000
        )
        has_more = source_truncated or (
            page_size is not None and total > (current_offset + count)
        )

        if not has_more:
            return result

        self._prune_next_cache()
        token = uuid.uuid4().hex[:12].upper()
        effective_page = int(page_size) if page_size else count

        with self._next_cache_lock():
            self._next_cache[token] = {
                "tool": tool_name,
                "action": base_args.get("action"),
                "args": {k: v for k, v in base_args.items() if k != "action"},
                "post_process": {
                    k: v
                    for k, v in pp_params.items()
                    if k not in {"next_token", "_forwarded_offset"}
                },
                "next_offset": current_offset + effective_page,
                "created_at": time.time(),
            }
        result["next_token"] = token
        return result

    def _execute_tool(self, tool_name, args):
            start_ts = time.perf_counter()
            original_tool_name = tool_name
            resolved_tool = _resolve_tool_alias(tool_name)

            # Resolve the session this call targets (idb= ref or the shared
            # active default) up front, before _execute_tool_inner mutates and
            # pops "idb" from args. Audit and usage-intel must attribute the
            # call to the session it actually runs in — on a multiplexed
            # connection the two can differ.
            _target_session = None
            if isinstance(args, dict) and args.get("idb"):
                try:
                    _target_session = self._resolve_session_from_idb_ref(args.get("idb"))
                except Exception:
                    _target_session = None
            _exec_sid = (
                getattr(_target_session, "session_id", None)
                if _target_session is not None
                else (
                    getattr(self.current_session, "session_id", None)
                    if self.current_session
                    else None
                )
            )

            # ---- Rate Limiting ----
            # D9: cheap host-only bookkeeping (status polls, truncation
            # continue, blackboard reads) is exempt from the token buckets —
            # it does no IDA RPC and is legitimately called in tight loops.
            # Everything else (including host-only writes) keeps the hard
            # RATE_LIMIT so a spamming agent cannot exhaust host resources.
            _rl_action = (
                str(args.get("action", "")) if isinstance(args, dict) else ""
            )
            _rl_exempt = is_rate_limit_exempt(resolved_tool, _rl_action)
            allowed = True
            reason = ""
            if not _rl_exempt:
                allowed, reason = self.rate_limiter.check(resolved_tool)
            if not allowed:
                self.audit.log(
                    tool=resolved_tool,
                    action=_rl_action,
                    args=args if isinstance(args, dict) else {},
                    result=None,
                    latency_ms=0.0,
                    session_id=_exec_sid,
                    error=f"rate_limited: {reason}",
                )
                return make_error(
                    MCPError.RATE_LIMIT,
                    f"Rate limit exceeded: {reason}",
                    recoverable=True,
                    hint="Reduce call frequency or increase limits via IDA_MCP_RATE_LIMIT_* env vars.",
                )

            result = self._execute_tool_inner(resolved_tool, original_tool_name, args)

            # ---- Post-processing pipeline ----
            # D3: for RPC tools, call_tool already applied PP *before*
            # truncation and stamped `_post_processed`; here we only mint the
            # continuation token. Host-only tools (session/blackboard/…)
            # returned directly from _execute_tool_inner with PP still pending,
            # so this block applies it.
            pp_params = getattr(self, "_pending_pp", None)
            if pp_params and has_post_process(pp_params) and not is_error_result(result):
                try:
                    if not (isinstance(result, dict) and result.get("_post_processed")):
                        if pp_params.get("_forwarded_offset") is not None:
                            _apply_pp = {
                                k: v for k, v in pp_params.items() if k != "offset"
                            }
                        else:
                            _apply_pp = pp_params
                        result = apply_post_processing(result, _apply_pp)
                    # Cache the args that will actually be replayed by a
                    # continuation (normalized, PP keys stripped). Using the raw
                    # caller args here would replay head/grep/limit into call_tool
                    # on page 2, where prepare_rpc_args rejects them or the tool
                    # double-applies the slice.
                    cache_args = getattr(self, "_pending_tool_args", None)
                    if not isinstance(cache_args, dict):
                        cache_args = args
                    result = self._cache_post_process_next(
                        resolved_tool, cache_args, pp_params, result
                    )
                except Exception as _pp_err:
                    import logging
                    logging.getLogger(__name__).debug("post-process pipeline failed: %s", _pp_err)
            self._pending_pp = {}
            self._pending_tool_args = {}

            sid = _exec_sid
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
                    # make_error-style envelope: {"error": True, "code": ...,
                    # "message": ...} lands here because `err` is the boolean
                    # True and code/message live on the envelope itself.
                    code = result.get("code")
                    message = result.get("message")
                    if (
                        code == MCPError.INVALID_ARGS
                        and "guardrail" in str(message or "").lower()
                    ):
                        guardrail_blocked = True
                    if code is not None or message is not None:
                        error_str = str(
                            {"code": code, "message": message}
                        )[:500]
                    else:
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
            # Audit logging is best-effort: a disk/permission/serialization
            # failure must never fail a tool call that already produced a valid
            # result. AuditLogger.log() is itself resilient, but guard here too
            # so the policy-audit and usage-intel paths stay consistent.
            try:
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
            except Exception as e:
                log_rpc(f"Audit logging failed for {resolved_tool}: {e}")
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

    def _guardrail_strict_gate(self, tool_name: str, args: dict) -> dict | None:
        """Guardrail strict-mode risky-write gate.

        Returns an error envelope to block the call, or None to allow it.
        Factored out of ``_execute_tool_inner`` so a next_token continuation
        (which replays a page-1 call) enforces the same gate instead of
        re-executing a risky write without acknowledgement.
        """
        # _guardrail_mode_from_args lives on ServerResponseMixin; guard with
        # getattr so partial mixin compositions (and unit-test harnesses) stay
        # non-strict instead of raising, matching the hasattr guards used for
        # the blackboard/phase helpers below.
        guardrail_mode = ""
        _mode_fn = getattr(self, "_guardrail_mode_from_args", None)
        if callable(_mode_fn):
            guardrail_mode = _mode_fn(args)
        strict_guardrails = bool(getattr(self, "_guardrail_strict_writes", False)) or guardrail_mode == "enforce"
        if not strict_guardrails:
            return None
        risky_tools = {"modify", "annotation", "funcs", "segments", "memory"}
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
        return None

    def _blackboard_and_phase_preflight(
        self, tool_name: str, args: dict, risk_ack_passed: bool
    ) -> dict | None:
        """Blackboard strict-mode + phase-state preflight gates.

        Returns an error envelope to reject the call, or None to continue.
        Mirrors the gates run for the original (page-1) dispatch so a
        next_token continuation cannot bypass them. Both gates are skipped on
        explicit ack and when policy mode is OFF.
        """
        policy_mode = ""
        try:
            policy_mode = self._resolve_policy_mode()
            if policy_mode == "off":
                return None
            if (tool_name != "blackboard"
                    and not risk_ack_passed
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
        try:
            args_for_phase = args if isinstance(args, dict) else {}
            if (tool_name != "blackboard"
                    and not risk_ack_passed
                    and policy_mode != "off"
                    and hasattr(self, "_phase_preflight_for_tool")):
                phase_block = self._phase_preflight_for_tool(tool_name, args_for_phase)
                if isinstance(phase_block, dict) and phase_block.get("error"):
                    return phase_block
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug("phase preflight failed: %s", _e)
        return None

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
            if is_error_result(args):
                return args

            scope_error = self._agent_scope_error(tool_name, args.get("action"))
            if scope_error is not None:
                return scope_error

            # Agent SSO: ``agent`` is a host-level identity tag, never an IDA
            # argument. It is normally popped in the tools/call dispatcher;
            # this is a defensive strip for any non-protocol path that feeds
            # args straight into dispatch.
            args.pop("agent", None)

            # ---- Post-processing filter extraction ----
            # Extract PP params before they reach IDA or policy checks.
            # Native collisions (code.limit, types.struct_member_add offset,
            # truncation offset/count) stay on the tool call.
            args, self._pending_pp = prepare_args_for_postprocess(tool_name, args)

            # ---- D3: forward the page-slice to natively-paging tools ----
            # When the PP is a *pure* page-slice (offset + limit/head, no
            # grep/tail/pick/field that must see every item) and the tool
            # supports offset/count natively and reports a pre-slice `total`,
            # forward the slice so IDA returns only the requested page instead
            # of the full list. The host-side PP then applies with offset=0
            # (the tool already skipped) and pagination bookkeeping uses the
            # original offset (see _cache_post_process_next). Marked via the
            # `_forwarded_offset` key on _pending_pp so it travels with the
            # per-request context.
            self._pending_pp.pop("_forwarded_offset", None)
            if self._pending_pp and not self._pending_pp.get("next_token"):
                _forwardable_actions = _SLICE_FORWARDABLE_TOOLS.get(tool_name)
                if _forwardable_actions and args.get("action") in _forwardable_actions:
                    _pp = self._pending_pp
                    _off = _pp.get("offset")
                    _lim = _pp.get("limit")
                    if _lim is None:
                        _lim = _pp.get("head")
                    # D3: for these tools the page size frequently arrives as a
                    # native `count` — the caller's `limit` is aliased to
                    # `count` by arg normalization (data/funcs schema uses
                    # `count`) before PP extraction, so it never lands in pp.
                    # Treat that native count as the page size, but only when
                    # pp itself carries no limit/head (conflicting sizes).
                    _native_count = args.get("count")
                    _lim_from_count = _lim is None and _native_count is not None
                    if _lim_from_count:
                        _lim = _native_count
                    _pp_has_size = (
                        _pp.get("limit") is not None or _pp.get("head") is not None
                    )
                    _pure_slice = (
                        _off is not None
                        and _lim is not None
                        and "offset" not in args
                        and not (_native_count is not None and _pp_has_size)
                        and not any(
                            k in _pp
                            for k in (
                                "grep", "grep_regex", "grep_invert",
                                "grep_case", "tail", "pick", "field",
                            )
                        )
                    )
                    if _pure_slice:
                        try:
                            _off_i, _lim_i = int(_off), int(_lim)
                        except Exception:
                            _off_i = _lim_i = None
                        if (
                            _off_i is not None and _lim_i is not None
                            and _off_i >= 0 and _lim_i > 0
                        ):
                            args["offset"] = _off_i
                            args["count"] = _lim_i
                            _forwarded_pp = {**_pp, "_forwarded_offset": _off_i}
                            if _lim_from_count:
                                # The page size lives in args (native count),
                                # not pp; record it so the host-side envelope
                                # still builds and pagination bookkeeping has
                                # a limit.
                                _forwarded_pp["limit"] = _lim_i
                            self._pending_pp = _forwarded_pp

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

            # Snapshot the exact args that will reach call_tool (normalized,
            # PP keys and host-only control keys already stripped) so a page-1
            # continuation token can replay them without re-introducing keys
            # IDA would reject or double-apply. Consumed by _execute_tool's
            # post-processing pipeline when it caches the next_token.
            #
            # D3: a forwarded offset/count must NOT be replayed — a continuation
            # re-fetches the full result and advances the host-side slice, so
            # replaying the tool-side cursor would double-advance the page.
            self._pending_tool_args = dict(args)
            if self._pending_pp.get("_forwarded_offset") is not None:
                self._pending_tool_args.pop("offset", None)
                self._pending_tool_args.pop("count", None)

            # ---- next_token continuation (auto-recovers action from cache) ----
            next_token = self._pending_pp.get("next_token")
            if next_token and isinstance(next_token, str) and next_token.strip():
                continuation = self._handle_next_continuation(
                    tool_name, next_token.strip(), self._pending_pp
                )
                # The continuation already ran the post-processing pipeline and
                # cached its own next token. Clear the pending state so
                # _execute_tool does not re-apply PP / re-cache the result (a
                # second pass would mint a broken token that clobbers the good
                # one and breaks the pagination chain).
                self._pending_pp = {}
                self._pending_tool_args = {}
                return continuation

            sid = getattr(self.current_session, "session_id", None) if self.current_session else None
            # Resolve the idb-targeted session up front: on a multiplexed
            # connection it can differ from the shared active default, and
            # audit / policy / safe-mode / drift must all attribute the call to
            # the session it actually runs in (the same resolution call_tool
            # performs). Falls back to current_session when no idb is supplied.
            _gate_sid = sid
            _idb_ref = args.get("idb")
            if _idb_ref:
                _gate_target = self._resolve_session_from_idb_ref(_idb_ref)
                if _gate_target is not None:
                    _gate_sid = _gate_target.session_id
            # Capture ack before the policy block pops _risk_ack below. The
            # phase gate at the bottom of this function wants to skip when
            # the caller already acknowledged the risk explicitly — but
            # args has _risk_ack popped by the time the gate runs, so we
            # need a captured value. (Bug: LLM passed _risk_ack=true on
            # funcs.create in prove phase and still hit "prove phase
            # requires evidence cards" gate.)
            _risk_ack_passed = ack_from_args(args)

            # ---- Deterministic policy preflight ----
            # Runs for every tool, including blackboard/background: the policy
            # registry classifies blackboard as WRITE_IDB (and script/plugin_run
            # pairs as LOCAL_CODE_EXEC), so exempting them here made those
            # classifications unreachable at dispatch (a caller could
            # clear/delete a blackboard or queue a script with no ack and no
            # policy audit record).
            try:
                policy_result = evaluate_policy(
                    tool_name,
                    args.get("action"),
                    mode=self._resolve_policy_mode(),
                    purpose=args.get("_purpose"),
                    ack=ack_from_args(args),
                )
                policy_audit = build_audit_record(policy_result, session_id=_gate_sid)
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
                            session_id=_gate_sid,
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
            args.pop("risk_ack", None)

            # ---- Safe mode gate (analysis still running) ----
            # While a session's IDA auto-analysis is still completing, block
            # anything that would invoke full-binary analysis, index the
            # half-analyzed database, or run arbitrary scripts. The agent
            # keeps manual small-area operations (disassembly, reads,
            # strings, xrefs, per-function decompilation) until safe mode
            # lifts automatically once analysis completes.
            #
            # Gate on the session actually being targeted (resolved up front
            # into _gate_sid). On a shared connection the idb-targeted session
            # can differ from the shared active default — blocking against the
            # active session would wrongly stop python/analysis against a
            # completed target (or wrongly allow a still-analyzing target).
            # Ownership is still enforced downstream in call_tool.
            safe_gate = self._safe_mode_gate(
                _gate_sid, tool_name, str(args.get("action") or "")
            )
            if safe_gate is not None:
                return safe_gate

            # ---- Blackboard strict + phase-state preflight (global boundaries) ----
            # Skipped on _risk_ack=true: explicit ack supersedes the strict
            # blackboard evidence-chain requirement. Skipped when policy mode
            # is OFF: all gates disabled. Factored into a helper so next_token
            # continuations enforce the same gates (see _handle_next_continuation).
            _bb_phase_err = self._blackboard_and_phase_preflight(
                tool_name, args, _risk_ack_passed
            )
            if _bb_phase_err is not None:
                return _bb_phase_err

            # ---- Stuck Detection (UsageIntelligence DriftDetector) ----
            # The drift signal is advisory by default: LOOP is emitted as a
            # warning notification (usage.py) but is NOT a hard block, because
            # a call-stream heuristic cannot reliably distinguish a stuck agent
            # from a legitimate worklist (e.g. decompiling N functions, or an
            # address-less detector re-run).  Set IDA_MCP_STUCK_LOOP_BLOCK=1 to
            # opt the hard block back in.
            action = args.get("action", "")
            _stuck_loop_block = os.environ.get("IDA_MCP_STUCK_LOOP_BLOCK") == "1"
            try:
                # Attribute the drift signal to the idb-targeted session the
                # call actually runs in, not the shared active default — the
                # stuck-loop lens must not see another session's calls on a
                # multiplexed connection. _gate_sid is resolved from idb above.
                sid_for_drift = _gate_sid
                ui = getattr(self, "_usage_intel", None)
                if sid_for_drift and ui and ui.is_running():
                    signals = ui.drift.check(sid_for_drift)
                    # Only block on LOOP — other signals are warnings, not blockers
                    for sig in signals:
                        if (_stuck_loop_block
                                and sig.get("type") == "LOOP"
                                and sig.get("severity") == "warning"):
                            err = make_error(
                                MCPError.STUCK_LOOP,
                                sig.get("message") or "Repeated identical analysis steps detected.",
                                recoverable=True,
                                hint="Change approach. Read ida_session_state for orientation.",
                            )
                            err["_nudge"] = {
                                "type": "stuck",
                                "signal": sig.get("type"),
                                "suggestion": "Try a different approach. Read ida_session_state for orientation.",
                            }
                            return err
            except Exception:
                pass

            action = args.get("action")
            if isinstance(action, str):
                action = action.strip()
                args["action"] = action

            guardrail_err = self._guardrail_strict_gate(tool_name, args)
            if guardrail_err is not None:
                return guardrail_err
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
                # Restore the captured risk-ack: the policy block above pops
                # `_risk_ack` from args (line ~1507), but the blackboard handler
                # legitimately gates host-side IDB writes on it (e.g. the
                # publish_findings dry-run gate). Underscore meta keys are
                # skipped by RPC admission, so this never leaks to the IDA side.
                args["_risk_ack"] = _risk_ack_passed
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

            if tool_name == "r2":
                # Host-side raw-binary sidecar engine (Architecture A, Phase 1):
                # subprocess-only, never touches the IDB, works during safe_mode
                # and when IDA is down. Mandatory branch — without it the r2 tool
                # would forward to IDA, which has no r2 backend.
                return self._handle_r2(args)

            ip = args.pop(
                "idb", self.current_session.idb_path if self.current_session else None
            )
            if not ip:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: ida_open_binary(binary_path='path/to/binary')",
                )
            return self.call_tool(tool_name, ip, **args)
