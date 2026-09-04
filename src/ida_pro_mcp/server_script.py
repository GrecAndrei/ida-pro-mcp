"""
IDA RPC Server
Designed for stability in IDA 9.2 headless mode.
Uses non-blocking sockets for connection handling, but tool execution remains synchronous.
"""
import hmac
import inspect
import json
import math
import os
import queue
import re
import select
import socket
import sys

# HEARTBEAT
import tempfile
import threading
import time
from typing import Annotated, Literal, get_args, get_origin


def _start_live_trace():
    """Trace project lines in IDA without requiring packages inside IDA.

    The live harness runs this file in IDA's embedded interpreter, which is a
    separate process and may not have the host virtualenv's coverage package.
    A tiny opt-in ``sys.settrace`` collector keeps that boundary measurable
    while remaining inert for ordinary IDA launches.
    """
    if os.environ.get("IDA_MCP_LIVE_COVERAGE") != "1":
        return None
    output = os.environ.get("IDA_MCP_LIVE_TRACE_FILE", "")
    if not output:
        coverage_file = os.environ.get("IDA_MCP_LIVE_COVERAGE_FILE", "")
        output = f"{coverage_file}.ida-trace" if coverage_file else ""
    if not output:
        return None
    source_root = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    lines = {}
    filename_in_project = {}

    def _trace(frame, event, _arg):
        if event == "line":
            filename = frame.f_code.co_filename
            included = filename_in_project.get(filename)
            if included is None:
                real_filename = os.path.realpath(filename)
                included = real_filename == source_root or real_filename.startswith(source_root + os.sep)
                filename_in_project[filename] = included
                filename = real_filename
            if included:
                lines.setdefault(filename, set()).add(frame.f_lineno)
        return _trace

    sys.settrace(_trace)
    threading.settrace(_trace)
    return output, lines


_LIVE_TRACE = _start_live_trace()


def _save_live_trace():
    """Flush the optional line trace before IDA tears down its interpreter."""
    if _LIVE_TRACE is None:
        return
    output, lines = _LIVE_TRACE
    try:
        trace_path = f"{output}.{os.getpid()}.json"
        with open(trace_path, "w", encoding="utf-8") as trace_file:
            json.dump({name: sorted(values) for name, values in lines.items()}, trace_file)
    except Exception as exc:
        print(f"Live trace save failed: {exc}", file=sys.stderr)

# Per-session heartbeat file (the host passes IDA_MCP_SESSION_LOG_DIR). All
# sessions used to share one /tmp/ida_mcp_heartbeat.txt, and a full /tmp
# (ENOSPC) then crashed every session on its next log write — see the many
# "No space left on device" tracebacks in old session logs. The write is now
# best-effort so a storage failure can never take down the RPC server.
ALIVE_FILE = os.path.join(
    os.environ.get("IDA_MCP_SESSION_LOG_DIR") or os.environ.get("TEMP") or tempfile.gettempdir(),
    "ida_mcp_heartbeat.txt",
)

def log_ev(msg):
    try:
        with open(ALIVE_FILE, "a") as f: f.write(f"[{time.ctime()}] {msg}\n")
    except Exception:
        pass  # a failed heartbeat write (ENOSPC, EACCES) must never kill IDA
    print(msg)

try:
    import ida_segment
    import idautils
    import idc
    log_ev("IDA modules imported")
except Exception as e:
    log_ev(f"CRITICAL: {e}")
    sys.exit(1)

# Path Setup
script_path = os.path.abspath(__file__)
_src_root = os.path.dirname(os.path.dirname(script_path))
_pkg_root = os.path.join(_src_root, "ida_pro_mcp")
_mcp_root = os.path.join(_pkg_root, "ida_mcp")
_tools_root = os.path.join(_mcp_root, "tools")
for p in [_src_root, _pkg_root, _mcp_root, _tools_root]:
    if p not in sys.path: sys.path.insert(0, p)

try:
    from ida_pro_mcp.ida_mcp import compat as _compat
    _compat.shim_ida_segment_helpers()
    _compat.shim_ida_funcs_helpers()
except Exception:
    pass

# IDA_MCP_BYPASS_SYNC is set by the host runtime (server_runtime.py) when
# launching IDA. Do not force it here at module import: the env var
# disables the @idaread/@idawrite safety wrapper globally, so it should
# only be active for code paths that opt in via the bypass_sync()
# context manager in ida_mcp.sync.

TOOLS = {}
# Actual port the bridge bound to. Set in run_server(); surfaced in ping
# responses so the host can learn the real port if it had to fall back to
# an ephemeral one (TOCTOU self-heal: if the host pre-allocated port was
# taken between host-close and our bind, we bind 0 and report back).
_BOUND_PORT = None
_SERVER_READY = threading.Event()
TOOL_ALIASES = {
    # Dispatcher advertises the tool as 'governance'; IDA-side file is
    # 'governance_engine.py' (the file is the engine implementation).
    "governance": "governance_engine",
}
_ERROR_DETAIL_LEVEL = str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
if _ERROR_DETAIL_LEVEL not in {"none", "basic", "full"}:
    _ERROR_DETAIL_LEVEL = "basic"
_SESSION_TOKEN = str(os.environ.get("IDA_MCP_SESSION_TOKEN", "") or "")
try:
    _MAX_RPC_REQUEST_BYTES = int(os.environ.get("IDA_MCP_MAX_RPC_REQUEST_BYTES", "1048576"))
except Exception:
    _MAX_RPC_REQUEST_BYTES = 1048576
_MAX_RPC_REQUEST_BYTES = max(4096, min(_MAX_RPC_REQUEST_BYTES, 64 * 1024 * 1024))
try:
    _MAX_RPC_RESPONSE_BYTES = int(os.environ.get("IDA_MCP_MAX_RPC_RESPONSE_BYTES", str(256 * 1024 * 1024)))
except Exception:
    _MAX_RPC_RESPONSE_BYTES = 256 * 1024 * 1024
_MAX_RPC_RESPONSE_BYTES = max(65536, min(_MAX_RPC_RESPONSE_BYTES, 512 * 1024 * 1024))

# Startup-analysis state. The __main__ flow binds the RPC listener and answers
# pings BEFORE auto-analysis of an opaque raw blob finishes, so the host's
# liveness probe never mistakes a long startup analysis for a crashed IDA.
# Tool calls that arrive while startup analysis is still running are answered
# with ANALYSIS_INCOMPLETE (mirroring the host-side safe_mode gate) instead of
# touching a half-analyzed IDB. The event starts SET so standalone/test
# invocations that never run the __main__ startup path are never gated.
_STARTUP_DONE = threading.Event()
_STARTUP_DONE.set()
_STARTUP_ANALYSIS_ERROR = None

# Set when the bridge receives a real ``type=="shutdown"`` request from the
# host's cleanup path. run_server()'s accept loop polls it so the process can
# wind down cleanly (best-effort save_database merges the unpacked .id0/.id1
# sidecars into the .i64) instead of being killed with those sidecars abandoned
# on disk. The event starts CLEARED; standalone/test invocations that never
# run run_server() are unaffected.
_SHUTDOWN_EVENT = threading.Event()

# Tool-dispatch handoff between the RPC listener thread and the MAIN thread.
# IDA 9.x enforces main-thread-only access for most of its API surface
# (hexrays decompilation, ida_auto, save_database, even idautils.Functions).
# After startup analysis completes, the listener thread must NOT call tool
# functions itself: it reads the request, pushes (request, result_queue) onto
# _TOOL_QUEUE, and waits on the per-request queue. The main thread's idle loop
# (below, after _run_startup_analysis) drains _TOOL_QUEUE and executes
# process_single there, so tool bodies always run on the main thread. Pings and
# pre-startup requests (ANALYSIS_INCOMPLETE / shutdown-gate) never enter the
# queue — they are answered inline on the listener thread, which is what keeps
# the host's liveness probe alive during a long startup auto-analysis.
_TOOL_QUEUE = queue.Queue()  # entries: (request_dict, result_queue.Queue)

# Bridge-originated errors (UNAUTHORIZED / INVALID_REQUEST / REQUEST_TOO_LARGE
# / INTERNAL / ANALYSIS_INCOMPLETE) go through the same factory as tool errors
# so they carry the same category/recoverable shape on the wire. Falls back to
# a plain envelope when the shared factory is not importable (standalone mode).
try:
    from ida_pro_mcp.ida_mcp.error_handling import (
        _sanitize_exception_message,
        make_error as _shared_make_error,
    )
except Exception:  # pragma: no cover - standalone import fallback
    try:
        from error_handling import _sanitize_exception_message, make_error as _shared_make_error
    except Exception:
        _shared_make_error = None
        _sanitize_exception_message = None


def _trim_text(text, max_len=300):
    if not isinstance(text, str):
        return text
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}...(+{len(text) - max_len} chars)"


def _compact_detail_value(value, max_items=16):
    if isinstance(value, list):
        kept = value[:max_items]
        return kept, len(value) - len(kept)
    if isinstance(value, str):
        return _trim_text(value), 0
    return value, 0


def _compact_error_details(details):
    if not details:
        return None
    if _ERROR_DETAIL_LEVEL == "full":
        return details
    if _ERROR_DETAIL_LEVEL == "none":
        return None
    if not isinstance(details, dict):
        return _trim_text(str(details))
    out = {}
    for key, value in details.items():
        if key in {"traceback", "raw_bytes", "hexdump_full", "raw_request", "raw_response"}:
            continue
        compacted, remaining = _compact_detail_value(value)
        out[key] = compacted
        if remaining > 0:
            out[f"{key}_more"] = remaining
    return out or None


def _canonical_tool_name(name):
    if not isinstance(name, str):
        return name
    return TOOL_ALIASES.get(name, name)


def _ensure_ida_mcp_packages():
    import types

    def _ensure_ns(name, path):
        mod = sys.modules.get(name)
        if mod is None:
            mod = types.ModuleType(name)
            mod.__path__ = [path]
            mod.__package__ = name
            sys.modules[name] = mod
        elif not hasattr(mod, "__path__"):
            mod.__path__ = [path]
        return mod

    support_root = os.path.join(_mcp_root, "support")
    _ensure_ns("ida_mcp", _mcp_root)
    _ensure_ns("ida_mcp.tools", _tools_root)
    _ensure_ns("ida_mcp.support", support_root)


def _try_load_single_tool(name):
    import importlib

    canonical = _canonical_tool_name(name)
    if canonical in TOOLS:
        return TOOLS[canonical], canonical, None
    _ensure_ida_mcp_packages()
    try:
        module = importlib.import_module(f"ida_mcp.tools.{canonical}")
        if hasattr(module, canonical):
            tool_func = getattr(module, canonical)
            TOOLS[canonical] = tool_func
            return tool_func, canonical, None
        return None, canonical, f"module 'ida_mcp.tools.{canonical}' missing callable '{canonical}'"
    except Exception as e:
        return None, canonical, str(e)


def load_tools():
    try:
        import importlib

        _ensure_ida_mcp_packages()
        tools_dir = _tools_root
        for f in os.listdir(tools_dir):
            if not f.endswith(".py") or f in {"__init__.py", "_common.py"}:
                continue
            name = f[:-3]
            try:
                module = importlib.import_module(f"ida_mcp.tools.{name}")
                if hasattr(module, name):
                    TOOLS[name] = getattr(module, name)
            except Exception as e:
                log_ev(f"Load error {name}: {e}")
        for alias, target in TOOL_ALIASES.items():
            if target in TOOLS:
                TOOLS[alias] = TOOLS[target]
        log_ev(f"Loaded {len(TOOLS)} tools")
    except Exception as e:
        log_ev(f"Tool load error: {e}")

def _extract_literal(param_type):
    origin = get_origin(param_type)
    if origin is Annotated:
        param_type = get_args(param_type)[0]
        origin = get_origin(param_type)
    if origin is Literal:
        return list(get_args(param_type))
    return None

def _tool_signature_info(tool_func):
    try:
        sig = inspect.signature(tool_func)
    except Exception:
        return {"params": [], "required": [], "actions": []}
    params = []
    required = []
    for name, p in sig.parameters.items():
        if name == "kwargs" or p.kind == inspect.Parameter.VAR_KEYWORD:
            continue
        params.append(name)
        if p.default is inspect.Parameter.empty:
            required.append(name)
    actions = []
    try:
        hints = getattr(tool_func, "__annotations__", {})
        if "action" in hints:
            actions = _extract_literal(hints["action"]) or []
    except Exception:
        actions = []
    return {"params": params, "required": required, "actions": actions}

def _suggest_choice(value, choices):
    if not value or not choices:
        return None
    try:
        from ida_pro_mcp.services import best_match
    except ImportError:
        import difflib
        matches = difflib.get_close_matches(str(value), choices, n=1, cutoff=0.6)
    else:
        matches = best_match(str(value), list(choices), n=1, cutoff=0.6)
    return matches[0] if matches else None

def _build_error(tool_name, message, code="INVALID_ARGS", details=None, hint=None, recoverable=False):
    """Build a bridge-originated error envelope.

    Routes through the shared error factory (when importable) so bridge errors
    carry the same ``category``/``recoverable`` shape as tool errors, letting
    the host's client-side matching on ``error.category`` behave uniformly for
    both. Falls back to a plain envelope in standalone mode.
    """
    if _shared_make_error is not None:
        res = _shared_make_error(code, message, hint=hint, details=None, recoverable=recoverable)
    else:
        res = {"error": True, "code": code, "category": "runtime", "message": message, "recoverable": bool(recoverable)}
        if hint:
            res["hint"] = hint
    if details:
        compacted = _compact_error_details(details)
        if compacted:
            res["details"] = compacted
    return res

def _handle_shutdown():
    """Best-effort save + accept-loop stop for the host's cleanup path.

    The host sends ``{"type": "shutdown"}`` (with the session token, injected
    by ``_send_rpc_raw``) on session teardown and then kills the IDA process
    tree shortly after. Previously the bridge had no ``shutdown`` branch, so
    the request fell through to tool dispatch and was answered with an
    INVALID_REQUEST error — the IDB was never saved and the unpacked
    .id0/.id1 sidecars were abandoned when the host killed the process.

    Now we set the shutdown event (run_server's accept loop exits on it) and
    best-effort ``save_database`` so the sidecars are merged into the .i64.
    The save is gated on ``_STARTUP_DONE``: while startup analysis is still
    running the MAIN thread owns the IDB (auto_wait/reanalysis), so a
    save_database from this (listener) thread would race it. After startup the
    main thread idles, so saving here is the single IDA operation in flight.
    """
    _SHUTDOWN_EVENT.set()
    saved = False
    if _STARTUP_DONE.is_set():
        try:
            import ida_loader as _ida_loader
            _idb_target = os.environ.get("IDA_MCP_IDB_PATH", "") or ""
            saved = bool(_ida_loader.save_database(_idb_target, 0))
        except Exception as e:
            log_ev(f"Shutdown save_database failed: {e}")
    else:
        log_ev("Shutdown during startup analysis; skipping save_database")
    # The host may terminate the IDA process tree immediately after receiving
    # this response, so flush the optional live trace before returning.
    _save_live_trace()
    return {
        "ok": True,
        "shutdown": True,
        "saved": saved,
        "analysis_complete": _STARTUP_DONE.is_set(),
    }

def process_single(r):
    if not isinstance(r, dict):
        return _build_error("bridge", "Invalid request format", code="INVALID_REQUEST")

    if r.get("type") == "ping":
        # Ping is intentionally unauthenticated: it is a liveness / port
        # discovery probe (the host pings before routing a real request).
        return {
            "pong": True,
            "port": _BOUND_PORT,
            "analyzing": not _STARTUP_DONE.is_set(),
            "startup_error": _STARTUP_ANALYSIS_ERROR,
        }

    # Session-token auth is mandatory, never optional-on-empty: the host
    # injects a token for every managed session (server_runtime.py), and a
    # bridge launched without one must refuse tool calls instead of leaving
    # arbitrary tool execution (incl. python code exec) open to any local
    # process that can reach the RPC socket.
    if not _SESSION_TOKEN:
        return _build_error(
            "auth",
            "No session token configured; refusing unauthenticated request",
            code="UNAUTHORIZED",
            hint="Launch via the host-managed session runtime, which sets IDA_MCP_SESSION_TOKEN.",
        )
    provided = str(r.get("session_token") or "")
    if not provided or not hmac.compare_digest(provided, _SESSION_TOKEN):
        return _build_error(
            "auth",
            "Unauthorized session token",
            code="UNAUTHORIZED",
            hint="Use the host-managed authenticated session runtime.",
        )

    # Control-plane shutdown: the host's cleanup path sends {"type":
    # "shutdown"} to let IDA persist the IDB before it kills the process tree.
    # It is authenticated like every non-ping message, and is handled BEFORE
    # the startup gate so a session can be torn down even mid-startup-analysis.
    if r.get("type") == "shutdown":
        return _handle_shutdown()

    tool_name = r.get("tool")
    args = r.get("args", {})
    if not isinstance(tool_name, str) or not tool_name:
        return _build_error(
            "bridge",
            "Invalid request: 'tool' must be a non-empty string",
            code="INVALID_REQUEST",
            details={"tool": type(tool_name).__name__},
        )
    if not isinstance(args, dict):
        # tool_func(**args) would raise TypeError for a non-mapping 'args'; the
        # failure is the caller's protocol mistake, not a tool bug — classify it
        # as INVALID_ARGS up front instead of letting it surface as a generic
        # internal error (or a crash).
        return _build_error(
            "bridge",
            "Invalid request: 'args' must be a JSON object mapping argument names to values",
            code="INVALID_ARGS",
            details={"args_type": type(args).__name__},
            hint="Pass the tool's arguments as a JSON object, e.g. {\"args\": {\"address\": \"0x401000\"}}.",
        )
    if not _STARTUP_DONE.is_set():
        # The listener is bound before startup analysis finishes so the host's
        # liveness probe succeeds; tool calls arriving during that window must
        # not touch a half-analyzed IDB. Mirror the host-side safe_mode gate.
        return _build_error(
            "bridge",
            "IDA is still running startup analysis on this binary; tool calls are paused until it completes",
            code="ANALYSIS_INCOMPLETE",
            hint="Retry in a few seconds, or poll the host session status until analysis completes.",
            details={"analyzing": True},
            recoverable=True,
        )
    log_ev(f"Calling tool: {tool_name}")
    try:
        canonical_tool = _canonical_tool_name(tool_name)
        if canonical_tool not in TOOLS:
            loaded_tool, loaded_name, load_err = _try_load_single_tool(tool_name)
            if loaded_tool:
                canonical_tool = loaded_name
                TOOLS[tool_name] = loaded_tool
                TOOLS[canonical_tool] = loaded_tool

        if canonical_tool not in TOOLS:
            available_tools = sorted(TOOLS.keys())
            res = _build_error(
                tool_name,
                f"Tool not found: {tool_name}",
                code="TOOL_NOT_FOUND",
                details={
                    "available_tools": available_tools[:20],
                    "available_tools_more": max(0, len(available_tools) - 20),
                    "canonical_tool": canonical_tool,
                    "load_error": load_err if 'load_err' in locals() else None,
                },
            )
        else:
            tool_func = TOOLS[canonical_tool]
            siginfo = _tool_signature_info(tool_func)
            # Pre-validate action if possible
            if "action" in args and siginfo["actions"]:
                action = args.get("action")
                if action not in siginfo["actions"]:
                    suggestion = _suggest_choice(action, siginfo["actions"])
                    details = {"available_actions": siginfo["actions"]}
                    if suggestion:
                        details["suggested_action"] = suggestion
                    res = _build_error(
                        tool_name,
                        f"Unknown action: {action}",
                        details=details,
                        hint="Use a valid action for this tool.",
                    )
                else:
                    res = tool_func(**args)
            else:
                res = tool_func(**args)

            if isinstance(res, dict) and res.get("error"):
                # Augment INVALID_ARGS with available actions/args and suggestions
                if res.get("code") in ("INVALID_ARGS", "UNKNOWN_ERROR"):
                    res.setdefault("details", {})
                    details = res["details"]
                    if siginfo.get("actions"):
                        details.setdefault("available_actions", siginfo["actions"])
                        action = args.get("action")
                        if action and action not in siginfo["actions"]:
                            suggestion = _suggest_choice(action, siginfo["actions"])
                            if suggestion:
                                details.setdefault("suggested_action", suggestion)
                                res.setdefault("hint", "Use a valid action for this tool.")
                    if siginfo.get("params"):
                        details.setdefault("available_args", siginfo["params"])
                    # Missing arg hint from message
                    msg = res.get("message", "")
                    m = re.search(r"([a-zA-Z_]+) required", msg)
                    if m:
                        missing_arg = m.group(1)
                        details.setdefault("missing_arg", missing_arg)
                        details.setdefault("required_args", siginfo.get("required", []))
                        res.setdefault("hint", "Provide the missing required argument.")
        # Tool-originated error dicts carry tool-produced details that may hold
        # large, sensitive, or non-serializable payloads (tracebacks, raw hex).
        # Compact them before they reach the wire so a verbose failure inside a
        # tool can never crash the bridge or leak a giant blob.
        if isinstance(res, dict) and res.get("error"):
            details = res.get("details")
            if isinstance(details, dict) or details:
                compacted = _compact_error_details(details)
                if compacted:
                    res["details"] = compacted
                else:
                    res.pop("details", None)
        return res
    except Exception as e:
        # Attach helpful hints for common arg mistakes
        tool_func = TOOLS.get(tool_name) if isinstance(tool_name, str) else None
        siginfo = _tool_signature_info(tool_func) if tool_func else {"params": [], "required": [], "actions": []}
        msg = _sanitize_exception_message(e) if _sanitize_exception_message is not None else str(e)
        details = {"available_args": siginfo.get("params", [])}
        hint = None
        is_user_error = False

        # Unexpected keyword argument
        m = re.search(r"unexpected keyword argument '([^']+)'", msg)
        if m:
            is_user_error = True
            bad_arg = m.group(1)
            suggestion = _suggest_choice(bad_arg, siginfo.get("params", []))
            details["unexpected_arg"] = bad_arg
            if suggestion:
                details["suggested_arg"] = suggestion
            hint = "Remove the unexpected argument or use the suggested name."

        # Missing required positional argument
        m = re.search(r"missing .* required positional argument: '([^']+)'", msg)
        if m:
            is_user_error = True
            missing_arg = m.group(1)
            details["required_args"] = siginfo.get("required", [])
            details["missing_arg"] = missing_arg
            hint = "Provide the missing required argument."

        # A TypeError from the tool (bad argument type, wrong call shape) is a
        # caller-controllable failure: classify it INVALID_ARGS with a clear
        # message, never the generic "Internal server error" hint that would
        # make the agent re-check the right thing for the wrong reason.
        if isinstance(e, TypeError) and not is_user_error:
            is_user_error = True
            hint = "The tool raised a TypeError — check the types of the arguments you passed."

        # Only argument-parsing failures are user errors.  Everything else — a
        # decompiler exception, an IDA SDK error, or a genuine tool bug — must
        # not be mislabeled INVALID_ARGS (which would send the agent back to
        # re-check its arguments); classify it as an internal failure instead.
        code = "INVALID_ARGS" if is_user_error else "UNKNOWN_ERROR"
        if not is_user_error:
            hint = "Internal server error — not caused by your request arguments."
        return _build_error(tool_name, msg, code=code, details=details, hint=hint)


# Tool calls must execute on the MAIN thread (see _TOOL_QUEUE docstring). This
# is the listener-thread side of the handoff: queue the request and block until
# the main thread has executed it and posted the result. A generous timeout is
# a safety net for a dying main thread; in normal operation the main thread
# always drains promptly and posts before this would ever fire.
_TOOL_DISPATCH_TIMEOUT_S = 600

def _rpc_handled_inline(r):
    """True when *r* can be answered on the listener thread without the IDB.

    Pings are pure liveness/port discovery (no IDB access). Anything arriving
    before ``_STARTUP_DONE`` is gated by ``process_single`` itself (tool calls
    -> ANALYSIS_INCOMPLETE, shutdown -> save skipped), so it never touches a
    half-analyzed IDB either. Once startup is done, every non-ping request —
    tool calls AND shutdown (its ``save_database`` is main-thread-only) — is
    handed to the main thread.
    """
    return not isinstance(r, dict) or r.get("type") == "ping" or not _STARTUP_DONE.is_set()


def _dispatch_on_main_thread(req):
    """Run *req*'s processing on the main thread and return its result."""
    result_q = queue.Queue(maxsize=1)
    _TOOL_QUEUE.put((req, result_q))
    try:
        return result_q.get(timeout=_TOOL_DISPATCH_TIMEOUT_S)
    except queue.Empty:
        return _build_error(
            "bridge",
            "Tool dispatch timed out waiting for the main thread",
            code="INTERNAL",
            hint="The IDA main thread did not drain the dispatch queue in time.",
        )

def _drain_tool_queue():
    """Main-thread idle-loop body: execute every queued request in order."""
    while True:
        try:
            req, result_q = _TOOL_QUEUE.get_nowait()
        except queue.Empty:
            return
        try:
            result_q.put(process_single(req))
        except Exception as e:
            msg = _sanitize_exception_message(e) if _sanitize_exception_message is not None else str(e)
            result_q.put(_build_error("bridge", "Tool dispatch failed: " + msg, code="INTERNAL"))


def _recv_exact(conn, length):
    """Receive exactly *length* bytes or return None on an early close."""
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(min(length - len(data), 65536))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)

def _resolve_port():
    """Return a valid loopback listener port, falling back on bad env input."""
    try:
        port = int(os.environ.get("IDA_MCP_PORT", "13337"))
    except (TypeError, ValueError):
        return 13337
    return port if 0 <= port <= 65535 else 13337


def run_server():
    global _BOUND_PORT
    _SERVER_READY.clear()
    port = _resolve_port()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    # Bind with ephemeral fallback. The host pre-allocates a free port and
    # hands it to us via IDA_MCP_PORT, but there is a TOCTOU window between
    # the host closing its probe socket and our bind. If the port was taken
    # in that window, fall back to an ephemeral port (0) and report the
    # actual bound port back to the host in the ping response so it can
    # route subsequent RPCs to the right place instead of failing.
    bound_port = None
    for try_port in (port, 0):
        try:
            server_sock.bind(('127.0.0.1', try_port))
            bound_port = server_sock.getsockname()[1]
            break
        except OSError as e:
            if try_port == 0:
                raise
            log_ev(f"Port {try_port} unavailable ({e}); falling back to ephemeral")
    _BOUND_PORT = bound_port
    # Execution is deliberately synchronous inside one IDA process, but a
    # deeper accept queue prevents concurrent host probes from being refused.
    # The host serializes real work per runtime and parallelizes across IDAs.
    server_sock.listen(64)
    port_file = str(os.environ.get("IDA_MCP_PORT_FILE", "") or "").strip()
    if port_file:
        tmp_port_file = port_file + ".tmp"
        try:
            with open(tmp_port_file, "w", encoding="ascii") as port_fh:
                port_fh.write(str(bound_port))
                port_fh.flush()
                os.fsync(port_fh.fileno())
            os.replace(tmp_port_file, port_file)
        except Exception as e:
            log_ev(f"Failed to publish RPC port: {e}")
    log_ev(f"Listening on {bound_port}")
    _SERVER_READY.set()

    while not _SHUTDOWN_EVENT.is_set():
        conn = None
        try:
            # Poll for new connection
            readable, _, _ = select.select([server_sock], [], [], 0.05)
            if not readable:
                time.sleep(0.01)
                continue

            conn, _ = server_sock.accept()
            conn.settimeout(5.0) # 5s timeout for the actual request data
            log_ev("Connection accepted")

            raw_len = _recv_exact(conn, 4)
            if not raw_len:
                continue

            length = int.from_bytes(raw_len, 'big')
            if length <= 0 or length > _MAX_RPC_REQUEST_BYTES:
                res = _build_error(
                    "bridge",
                    f"Invalid request size: {length}",
                    code="REQUEST_TOO_LARGE",
                    details={"max_bytes": _MAX_RPC_REQUEST_BYTES},
                    hint="Reduce payload size or increase IDA_MCP_MAX_RPC_REQUEST_BYTES for trusted local sessions.",
                )
                resp_json = json.dumps(res, separators=(",", ":")).encode("utf-8")
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
                continue
            data = _recv_exact(conn, length)
            if data is None:
                res = _build_error(
                    "bridge",
                    "Truncated request body",
                    code="INVALID_REQUEST",
                    details={"expected": length},
                    hint="Ensure full request payload is sent with proper length prefix.",
                )
                resp_json = json.dumps(res, separators=(",", ":")).encode("utf-8")
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
                continue

            req = json.loads(data.decode('utf-8'))

            # Tool dispatch must happen on the MAIN thread (IDA 9.x
            # main-thread-only APIs). Pings and pre-startup requests are
            # answered inline so the host's liveness probe stays responsive;
            # everything else post-startup is queued to the main thread, whose
            # idle loop (after _run_startup_analysis) executes it and posts the
            # result back. This restores the invariant that tool bodies run on
            # the main thread even though the accept loop lives on the listener.
            try:
                if isinstance(req, list):
                    res = [
                        process_single(r) if _rpc_handled_inline(r) else _dispatch_on_main_thread(r)
                        for r in req
                    ]
                else:
                    res = process_single(req) if _rpc_handled_inline(req) else _dispatch_on_main_thread(req)
                resp_json = json.dumps(res, separators=(",", ":")).encode('utf-8')
            except Exception as e:
                # A tool result that json.dumps cannot serialize (e.g. a set,
                # bytes, or a non-encodable object) must surface as a crisp
                # error envelope, never a dropped connection — the host reads a
                # mid-request socket close as "IDA may have crashed" and tears
                # the whole session down.
                ser = _build_error(
                    "bridge",
                    "Response serialization failed: " + (_sanitize_exception_message(e) if _sanitize_exception_message is not None else str(e)),
                    code="INTERNAL",
                    hint="The tool returned a non-serializable result; check the tool's output shape.",
                )
                resp_json = json.dumps(ser, separators=(",", ":")).encode('utf-8')
            if len(resp_json) > _MAX_RPC_RESPONSE_BYTES:
                too_big = _build_error(
                    "bridge",
                    f"Response too large: {len(resp_json)} bytes exceeds the {_MAX_RPC_RESPONSE_BYTES}-byte cap",
                    code="RESULT_TOO_LARGE",
                    hint="Narrow the query scope (limit / pagination / start-end) to shrink the response.",
                    details={"max_bytes": _MAX_RPC_RESPONSE_BYTES},
                )
                resp_json = json.dumps(too_big, separators=(",", ":")).encode('utf-8')
            conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)

            log_ev("Request finished")
        except TimeoutError: log_ev("Socket timeout")
        except KeyboardInterrupt: break
        except Exception as e: log_ev(f"Loop error: {e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception as _e:
                    log_ev(f"Socket close failed: {_e}")

def _apply_pre_analysis_options():
    """Apply processor/bitness/endian/loader_options BEFORE auto-analysis."""
    raw = os.environ.get("IDA_MCP_PRE_ANALYSIS_OPTS", "{}")
    try:
        opts = json.loads(raw)
    except Exception:
        return
    if not opts:
        return

    # Skip for existing IDBs unless the host explicitly requests forced
    # pre-analysis application (used for architecture-sensitive firmware sessions).
    if os.environ.get("IDA_MCP_USE_EXISTING_IDB") == "1" and os.environ.get("IDA_MCP_FORCE_PRE_ANALYSIS_OPTS") != "1":
        return

    import ida_ida
    import ida_loader
    import idaapi

    processor = opts.get("processor")
    bitness = opts.get("bitness")
    endian = opts.get("endian")
    loader = opts.get("loader")
    loader_options = opts.get("value") or opts.get("loader_options")
    flags = opts.get("flags")

    changed = []
    warnings_list = []

    # Normalize architecture aliases via shared host helper when available.
    try:
        from ida_pro_mcp.services import normalize_arch_options as _norm_arch
        _norm, _meta = _norm_arch(
            {
                "processor": processor,
                "bitness": bitness,
                "endian": endian,
                "loader": loader,
                "value": loader_options,
                "flags": flags,
            }
        )
        processor = _norm.get("processor")
        bitness = _norm.get("bitness")
        endian = _norm.get("endian")
        loader = _norm.get("loader")
        loader_options = _norm.get("value") or _norm.get("loader_options")
        flags = _norm.get("flags")
    except Exception:
        # Fallback: keep prior values unchanged.
        pass

    # Processor
    if processor:
        try:
            current = ""
            if hasattr(idaapi, "get_inf_structure"):
                try:
                    inf = idaapi.get_inf_structure()
                    current = getattr(inf, "procname", "") if inf else ""
                except Exception as _e:
                    log_ev(f"get_inf_structure failed: {_e}")
            if current != processor:
                proc_flags = flags if flags is not None else getattr(
                    idaapi, "SETPROC_LOADER_NON_FATAL", idaapi.SETPROC_LOADER
                )
                ok = idaapi.set_processor_type(processor, proc_flags)
                changed.append(f"processor={processor} (ok={ok})")
            else:
                changed.append(f"processor={processor} (already set)")
        except Exception as e:
            warnings_list.append(f"processor={processor}: {e}")

    # Bitness
    if bitness is not None:
        try:
            if hasattr(ida_ida, "inf_set_app_bitness"):
                ida_ida.inf_set_app_bitness(int(bitness))
                changed.append(f"bitness={bitness}")
            else:
                warnings_list.append("inf_set_app_bitness unavailable")
        except Exception as e:
            warnings_list.append(f"bitness={bitness}: {e}")

    # Endian
    if endian:
        try:
            if hasattr(ida_ida, "inf_set_be"):
                be = str(endian).lower() in (
                    "be", "big", "big_endian", "big-endian", "bigendian", "1", "true"
                )
                le = str(endian).lower() in (
                    "le", "little", "little_endian", "little-endian", "littleendian", "0", "false"
                )
                if be or le:
                    ida_ida.inf_set_be(be)
                    changed.append(f"endian={'be' if be else 'le'}")
                else:
                    warnings_list.append(f"endian={endian}: invalid value")
            else:
                warnings_list.append("inf_set_be unavailable")
        except Exception as e:
            warnings_list.append(f"endian={endian}: {e}")

    # Stack size (best-effort before auto-analysis)
    stack_size = opts.get("stack_size")
    if stack_size is not None:
        try:
            if hasattr(ida_ida, "inf_set_ssize"):
                ida_ida.inf_set_ssize(int(stack_size))
                changed.append(f"stack_size={stack_size}")
            else:
                warnings_list.append("inf_set_ssize unavailable")
        except Exception as e:
            warnings_list.append(f"stack_size={stack_size}: {e}")

    # Processor options (e.g. ARM CPU type or MIPS ISA variant).  Applied via
    # the processor-options directive: idc.set_processor_options on older IDA;
    # ida_idp.process_config_directive on 9.3/9.4 (idc.set_processor_options
    # does not exist in the idat runtime — verified live on both).
    processor_options = opts.get("processor_options")
    if processor_options:
        try:
            _opts_applied = False
            if hasattr(idc, "set_processor_options"):
                idc.set_processor_options(str(processor_options))
                _opts_applied = True
            else:
                import ida_idp as _ida_idp
                if hasattr(_ida_idp, "process_config_directive"):
                    _ida_idp.process_config_directive(str(processor_options))
                    _opts_applied = True
            if _opts_applied:
                changed.append(f"processor_options={processor_options}")
            else:
                warnings_list.append("processor_options: no processor-option API in this runtime")
        except Exception as e:
            warnings_list.append(f"processor_options: {e}")

    # memory_model: the host contract documents 0=flat / 1=16-bit segmented /
    # 2=32-bit segmented, but IDA 9.x removed the memory-model attribute from
    # the API (no ida_ida.inf_set_mtype, no idc.INF_MTYPE, no idainfo.mtype —
    # verified live on 9.3 and 9.4; the MT_* constants are gone with it).
    # Apply it only if a future IDA reintroduces the setter; otherwise warn
    # instead of silently dropping it.
    memory_model = opts.get("memory_model")
    if memory_model is not None:
        try:
            if hasattr(ida_ida, "inf_set_mtype"):
                _mt_encoding = {0: 6, 1: 3, 2: 4}  # flat / MT_16 / MT_32
                mtype = _mt_encoding.get(int(memory_model))
                if mtype is None:
                    warnings_list.append(
                        f"memory_model={memory_model}: invalid value "
                        "(0=flat, 1=16-bit segmented, 2=32-bit segmented)"
                    )
                elif ida_ida.inf_set_mtype(mtype):
                    changed.append(f"memory_model={memory_model}")
                else:
                    warnings_list.append(f"memory_model={memory_model}: inf_set_mtype rejected")
            else:
                warnings_list.append(
                    f"memory_model={memory_model}: not supported by this IDA build "
                    "(memory-model API removed in IDA 9.x; ignored)"
                )
        except Exception as e:
            warnings_list.append(f"memory_model={memory_model}: {e}")

    # Loader options (best-effort before auto_wait)
    if loader_options and loader:
        try:
            if hasattr(ida_loader, "set_loader_options"):
                opts_str = loader_options
                if isinstance(opts_str, dict):
                    opts_str = ";".join(f"{k}={v}" for k, v in opts_str.items())
                ok = ida_loader.set_loader_options(loader, opts_str)
                changed.append(f"loader_options={ok}")
            else:
                warnings_list.append("set_loader_options unavailable")
        except Exception as e:
            warnings_list.append(f"loader_options: {e}")

    proc_lower = str(processor or "").lower()
    # Segment and Thumb fixes only apply to raw blobs (loader=bin / filetype f_BIN).
    # ELF/PE/Mach-O loaders already set segment types correctly; forcing SEG_CODE
    # on data segments breaks analysis. T=1 only applies to 32-bit ARM (Thumb mode
    # doesn't exist on AArch64).
    try:
        _filetype = idaapi.get_inf_structure().filetype if hasattr(idaapi, "get_inf_structure") else -1
        _f_bin = getattr(idaapi, "f_BIN", 0)
        _is_raw_load = (_filetype == _f_bin) or (str(loader or "").lower() == "bin")
    except Exception:
        _is_raw_load = False
    if _is_raw_load and proc_lower:
        try:
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                try:
                    cur_class = ida_segment.get_segm_class(seg)
                    if cur_class != "CODE":
                        ida_segment.set_segm_class(seg, "CODE")
                        changed.append(f"segment_class={cur_class}→CODE")
                except Exception as _e:
                    log_ev(f"set_segm_class failed for {hex(seg.start_ea)}: {_e}")
                try:
                    if seg.type != idaapi.SEG_CODE:
                        seg.type = idaapi.SEG_CODE
                        ida_segment.update_segm(seg)
                        changed.append("SEG_CODE type set")
                except Exception as _e:
                    log_ev(f"SEG_CODE type set failed for {hex(seg.start_ea)}: {_e}")
                try:
                    if not (seg.perm & idaapi.SEGPERM_EXEC):
                        seg.perm |= idaapi.SEGPERM_EXEC
                        ida_segment.update_segm(seg)
                        changed.append("SEGPERM_EXEC added")
                except Exception as _e:
                    log_ev(f"SEGPERM_EXEC set failed for {hex(seg.start_ea)}: {_e}")
                if bitness == 32:
                    try:
                        if hasattr(seg, "bitness") and seg.bitness != 1:
                            seg.bitness = 1
                            ida_segment.update_segm(seg)
                            changed.append("segment_bitness=32")
                    except Exception as _e:
                        try:
                            ida_segment.set_segm_addressing(seg, 1)
                            changed.append("segment_addressing=32bit")
                        except Exception as _e2:
                            log_ev(f"segment bitness set failed for {hex(seg.start_ea)}: {_e} / {_e2}")
            # Thumb T=1: only for 32-bit ARM raw blobs (AArch64 has no Thumb mode)
            if "arm" in proc_lower and bitness != 64:
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if seg:
                        try:
                            sr_auto = getattr(idc, "SR_auto", 2)
                            idc.split_sreg_range(seg.start_ea, "T", 1, sr_auto)
                            changed.append(f"T=1 set for {hex(seg.start_ea)}")
                        except Exception as _e:
                            log_ev(f"T=1 split_sreg_range fallback failed for {hex(seg.start_ea)}: {_e}")
        except Exception:
            log_ev("Segment fix failed (non-fatal)")

    if changed:
        log_ev(f"Pre-analysis options applied: {', '.join(changed)}")
    if warnings_list:
        log_ev(f"Pre-analysis warnings: {', '.join(warnings_list)}")


def _startup_analysis_timeout():
    """Read the bounded startup-analysis budget without accepting NaN or infinity."""
    try:
        timeout = float(os.environ.get("IDA_MCP_STARTUP_ANALYSIS_TIMEOUT", "120.0"))
    except (TypeError, ValueError):
        return 120.0
    if not math.isfinite(timeout):
        return 120.0
    return max(5.0, min(timeout, 600.0))


def _bounded_auto_wait(timeout=None):
    """Wait for IDA auto-analysis without blocking forever on unknown-size raw
    blobs.

    ``ida_auto.auto_wait()`` returns only when the analysis queue is empty,
    which on an opaque raw .bin (or a hostile/broken blob) can take unbounded
    time. Instead, poll ``ida_auto.get_auto_state()`` and give up once the
    deadline passes so the server can serve whatever analysis completed. The
    host's own safe_mode gate (polled via the ping's ``analyzing`` flag) covers
    the remainder.
    """
    if timeout is None:
        timeout = _startup_analysis_timeout()
    else:
        timeout = max(5.0, min(timeout, 600.0))
    try:
        import ida_auto as _ida_auto
    except ImportError:
        return
    if not hasattr(_ida_auto, "auto_wait"):
        return
    if not hasattr(_ida_auto, "get_auto_state"):
        # No way to introspect progress; do one blocking wait (legacy behavior).
        try:
            _ida_auto.auto_wait()
        except Exception as e:
            log_ev(f"auto_wait failed: {e}")
        return
    au_none = getattr(_ida_auto, "AU_NONE", -1)
    deadline = time.monotonic() + timeout
    last_beat = time.monotonic()
    while True:
        try:
            state = int(_ida_auto.get_auto_state())
        except Exception:
            # Cannot introspect; fall back to a single blocking wait.
            try:
                _ida_auto.auto_wait()
            except Exception as e:
                log_ev(f"auto_wait fallback failed: {e}")
            return
        if state == au_none:
            return
        now = time.monotonic()
        if now - last_beat >= 10.0:
            log_ev(f"still analyzing (auto state {state})...")
            last_beat = now
        if now >= deadline:
            log_ev(f"auto-analysis still running after {timeout:.0f}s; serving partial analysis")
            return
        time.sleep(0.5)


def _run_startup_analysis():
    """Perform bounded startup analysis on the MAIN thread.

    The RPC listener is already bound when this runs (see __main__), so the
    host's liveness probe succeeds and ping reports ``analyzing: true`` while
    an opaque raw blob is still being analyzed. Tool calls that arrive during
    this window are gated with ANALYSIS_INCOMPLETE by process_single.

    auto_wait is deliberately on the main thread: IDA's auto-analysis is driven
    by the main thread's request loop, so this is what keeps analysis pumping
    for unknown-size raw blobs. The listener thread serves pings / gated tool
    calls meanwhile.
    """
    global _STARTUP_ANALYSIS_ERROR
    try:
        import ida_auto as _ida_auto

        log_ev("Waiting for initial auto-analysis (bounded)...")
        if hasattr(_ida_auto, "auto_wait"):
            _bounded_auto_wait()
        else:
            log_ev("ida_auto.auto_wait unavailable; analysis continues in background.")

        _is_reuse_spawn = os.environ.get("IDA_MCP_USE_EXISTING_IDB") == "1"
        if _is_reuse_spawn:
            # IDB is already built and was upgraded by the original session;
            # re-running reanalysis + a full save on every reuse is wasted I/O
            # and can add minutes to reuse startup on large binaries.
            log_ev("IDB reuse detected; skipping startup reanalysis and save.")
        elif _SHUTDOWN_EVENT.is_set():
            # The host requested shutdown while auto_wait was still running;
            # the process is being torn down, so reanalysis + save would be
            # wasted I/O racing the kill.
            log_ev("Shutdown requested during startup; skipping reanalysis and save.")
        else:
            try:
                from ida_pro_mcp.ida_mcp.tools.analysis import (
                    _auto_reanalyze_text_segments,
                    _ensure_entry_point_functions,
                )
                rean = _auto_reanalyze_text_segments(wait_seconds=120.0)
                if rean.get("scheduled", 0):
                    log_ev(
                        f"Auto-reanalysis: {rean.get('scheduled', 0)} range(s); "
                        f"funcs {rean.get('functions_before', 0)} -> {rean.get('functions_after', 0)}, "
                        f"code bytes {rean.get('defined_code_bytes_before', 0)} -> "
                        f"{rean.get('defined_code_bytes_after', 0)} "
                        f"(coverage {rean.get('coverage_pct_before', 0.0):.1f}% -> "
                        f"{rean.get('coverage_pct_after', 0.0):.1f}%)"
                    )
                _ensure_entry_point_functions()
            except Exception as _e:
                log_ev(f"Auto-reanalysis skipped: {_e}")

            # Persist the upgraded IDB at the canonical session path so the
            # MCP host and reuse spawns find it via session.idb_path. Saving at
            # the empty string path writes next to the source binary which
            # leaves the sessions-dir metadata idb_exists=false and breaks
            # reuse detection.
            if not _SHUTDOWN_EVENT.is_set():
                try:
                    import ida_loader as _ida_loader
                    _idb_target = os.environ.get("IDA_MCP_IDB_PATH", "")
                    if _idb_target:
                        _ida_loader.save_database(_idb_target, 0)
                        log_ev(f"IDB saved to {_idb_target} after reanalysis.")
                    else:
                        _ida_loader.save_database("", 0)
                        log_ev("IDB saved (default path) after reanalysis.")
                except Exception as _e:
                    log_ev(f"save_database after reanalysis failed: {_e}")
            else:
                log_ev("Shutdown arrived during reanalysis; skipping post-reanalysis save.")
    except ImportError:
        log_ev("idaapi/ida_auto not importable; skipping reanalysis.")
    except Exception as _e:
        _STARTUP_ANALYSIS_ERROR = str(_e)
        log_ev(f"Startup analysis failed: {_e}")
    finally:
        _STARTUP_DONE.set()
        log_ev("Startup analysis finished.")


if __name__ == "__main__":
    _apply_pre_analysis_options()
    load_tools()

    # Start the RPC listener on a DEDICATED thread and answer pings BEFORE the
    # blocking startup analysis, so the host's liveness probe never mistakes a
    # long auto-analysis of an opaque raw blob for a crashed IDA. The MAIN
    # thread then runs auto_wait: IDA's auto-analysis is driven by the main
    # thread's request loop, so waiting for it there is what keeps analysis
    # pumping on unknown-size blobs. Tool calls that arrive before _STARTUP_DONE
    # is set are answered with ANALYSIS_INCOMPLETE (mirroring the host-side
    # safe_mode gate). After startup the listener thread keeps reading requests
    # but queues every non-ping call to the main thread (via _TOOL_QUEUE),
    # because IDA 9.x refuses main-thread-only APIs from any other thread —
    # see _TOOL_QUEUE's docstring. The host's startup ping timeout
    # (IDA_MCP_STARTUP_TIMEOUT, default 240s) accommodates the auto_wait.
    _STARTUP_DONE.clear()
    listener_thread = threading.Thread(target=run_server, name="rpc-listener", daemon=True)
    listener_thread.start()

    log_ev("Starting server...")
    _run_startup_analysis()

    # Startup analysis is complete. Keep the process alive until the host
    # sends a shutdown request (which stops the accept loop and best-effort
    # saves the IDB) or kills the process tree. The listener is a daemon
    # thread, so this main-thread join is what keeps the RPC server serving.
    #
    # The loop joins the LISTENER thread, not the shutdown event: the event is
    # set at the very START of _handle_shutdown, before its save_database runs
    # and before the shutdown response is sent. Returning from __main__ on the
    # event alone would let the interpreter kill the daemon listener mid-save
    # (daemon threads are not joined at exit) — abandoning the very .id0/.id1
    # sidecars the handler exists to merge. Joining the thread lets the
    # shutdown handler finish save_database and deliver the response; the
    # accept loop then exits on the event and the thread ends on its own.
    #
    # While we wait, the main thread drains _TOOL_QUEUE: the listener thread
    # reads requests but never executes tool bodies (IDA 9.x main-thread-only
    # APIs), so this loop is what actually runs each tool call — on the main
    # thread — and posts the result back for the listener to send. The short
    # join timeout bounds how long a queued tool call waits to start (~50ms).
    while listener_thread.is_alive():
        _drain_tool_queue()
        listener_thread.join(timeout=0.05)
    _save_live_trace()
