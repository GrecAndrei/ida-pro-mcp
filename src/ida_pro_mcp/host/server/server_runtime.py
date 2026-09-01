#!/usr/bin/env python3
"""Runtime/session orchestration helpers for IDAMCPServer."""

from __future__ import annotations

import contextlib
import glob
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import (
    _bounded_int,
    _normalize_session_id,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error
from .server_runtime_leases import (
    ServerRuntimeLeasesMixin,
    _lease_pid,
    _process_start_token,
    _runtime_lease_io_lock,
)
from .session import Session

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Processors that imply a raw-binary/firmware load (no native container format).
# Mirrored in _build_ida_command (-Tbin) and the post-load fix_segments step.

# IDA loader names that produce correctly-typed segments natively; for these the
# post-load segment repair must NOT run (it would force data segments to
# SEG_CODE+EXEC and, for 64-bit PEs, downgrade .text to 32-bit -> MERR_ONLY64).
NATIVE_LOADERS = (
    "pe", "pe64", "elf", "elf64", "macho", "macho64",
    "coff", "ar", "omf", "dos", "dos/exe",
)

# IDBs at or above this size are treated as "large" for teardown/checkpoint
# purposes: the graceful-shutdown save and the periodic checkpoint both get the
# extended budget instead of the fast 2s SIGKILL default.
_LARGE_IDB_CHECKPOINT_THRESHOLD = 256 * 1024 * 1024

# Cap on the synchronous shutdown-save RPC timeout: the SIGKILL grace is the
# real deadline, so a hung runtime is never blocked on for longer than this.
_SHUTDOWN_SAVE_RPC_CAP = 60.0

# Focused mixin hosts may omit IDAMCPServer.__init__, so protect lazy runtime
# lock creation too.  The normal server path creates the lock eagerly.
_RUNTIME_STATE_LOCK_INIT = threading.Lock()


def _resolve_max_rpc_bytes() -> int:
    try:
        cap = int(os.environ.get("IDA_MCP_MAX_RPC_BYTES", str(64 * 1024 * 1024)))
    except (TypeError, ValueError):
        cap = 64 * 1024 * 1024
    return max(4096, min(cap, 256 * 1024 * 1024))


MAX_RPC_REQUEST_SIZE = _resolve_max_rpc_bytes()


def _resolve_startup_timeout() -> int:
    """Resolve the IDA startup grace period, falling back to 240s on bad input.

    Mirrors the tolerant parsing used for other host env knobs so a typo like
    ``IDA_MCP_STARTUP_TIMEOUT=300s`` degrades to the default instead of raising
    a bare ValueError mid-launch.
    """
    try:
        timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "240"))
    except (TypeError, ValueError):
        timeout = 240
    return max(1, timeout)


class RpcQueueTimeout(TimeoutError):
    """Raised when a session's RPC lane stays busy past the queue bound.

    Subclasses TimeoutError so existing callers that treat queue exhaustion
    as a timeout (shutdown paths with ``queue_timeout=0``) keep working.
    Dispatch distinguishes it from socket recv timeouts to report IDA_BUSY
    instead of a false IDA_TIMEOUT/IDA_CRASHED."""


class RpcPayloadTooLarge(ValueError):
    """Raised when an RPC request or response exceeds MAX_RPC_REQUEST_SIZE.

    Subclasses ValueError for backward compatibility with generic handlers,
    but is catchable by its own type so the dispatch layer can surface a
    SIZE_LIMIT_EXCEEDED user error instead of a misleading connection error.
    """



def _popen_new_session_kwargs() -> dict:
    """Return the kwargs that put a Popen child in its own process group.

    Without this, os.killpg() on POSIX will signal the MCP server's own
    group (taking out the parent) and taskkill /T on Windows will walk
    siblings instead of just the IDA tree.
    """
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _kill_process_tree(proc: subprocess.Popen, grace_seconds: float = 2.0) -> None:
    """Kill a subprocess and all of its descendants.

    On Windows, ``Popen.terminate()``/``Popen.kill()`` only signals the direct
    child.  IDA's ``idat.exe`` is a tiny launcher that spawns ``ida.exe`` as a
    separate process, so killing the launcher leaves the real IDA process
    orphaned, holding the unpacked .id0/.id1 files open.  We use ``taskkill
    /T /F`` to walk the process tree.

    On POSIX, ``os.killpg`` against a process started in a new process group
    will signal the whole tree.
    """
    if proc is None:
        return
    pid = proc.pid
    if pid is None:
        return
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(pid)],
                capture_output=True,
                timeout=grace_seconds + 3,
            )
        with contextlib.suppress(Exception):
            proc.wait(timeout=grace_seconds)
        return
    # POSIX: child must be in its own process group (set via
    # _popen_new_session_kwargs in the matching Popen call).  Do this even
    # if the direct IDA launcher has already exited: its llama-server child
    # can still be alive in that process group. If the group is gone,
    # ProcessLookupError makes this a harmless no-op.
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        log_rpc(f"Process group already gone for pid {pid}; nothing to kill")
        return
    except Exception as exc:
        log_rpc(f"killpg(SIGTERM) failed for pid {pid}: {exc}")
    # The direct idat launcher can exit in milliseconds while ida.exe /
    # llama-server keep running in the same process group, so waiting only on
    # the direct child is not enough: the SIGKILL escalation below would never
    # run for survivors. Poll the process group (killpg(pid, 0) is a liveness
    # probe on the group) until it drains or the grace budget is exhausted,
    # reaping the direct child opportunistically along the way.
    deadline = time.time() + grace_seconds
    while time.time() < deadline:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return  # group drained
        except Exception:
            return  # cannot probe group; best-effort done
        with contextlib.suppress(Exception):
            proc.wait(timeout=0.05)  # reap the direct child if it has exited
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        log_rpc(f"Process group vanished before SIGKILL for pid {pid}")
    except Exception as exc:
        log_rpc(f"killpg(SIGKILL) failed for pid {pid}: {exc}")


class ServerRuntimeMixin(ServerRuntimeLeasesMixin):
    def _runtime_state_lock(self) -> threading.RLock:
        """Return the lock protecting the in-process runtime table.

        Keep this small compatibility implementation on the runtime mixin as
        well as the client-state mixin: focused hosts often compose runtime
        and response helpers without constructing the full server class.
        """
        lock = getattr(self, "_runtime_lock", None)
        if lock is None:
            with _RUNTIME_STATE_LOCK_INIT:
                lock = getattr(self, "_runtime_lock", None)
                if lock is None:
                    lock = threading.RLock()
                    self._runtime_lock = lock
        return lock

    def _runtime_record(self, session_id: Any) -> dict[str, Any] | None:
        """Read one runtime record without racing table mutation."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            if not isinstance(runtimes, dict):
                return None
            record = runtimes.get(str(session_id))
            return record if isinstance(record, dict) else None

    def _runtime_items_snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        """Return a stable runtime-table snapshot for work outside the lock."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            if not isinstance(runtimes, dict):
                return []
            return [
                (str(session_id), record)
                for session_id, record in runtimes.items()
                if isinstance(record, dict)
            ]

    def _runtime_update(self, session_id: Any, **updates: Any) -> bool:
        """Atomically update fields on an existing runtime record."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            record = runtimes.get(str(session_id)) if isinstance(runtimes, dict) else None
            if not isinstance(record, dict):
                return False
            record.update(updates)
            return True

    def _runtime_owner_path(self, sid: str) -> str:
            return os.path.join(self._runtime_lease_dir, f"SID_{sid}.owner.json")

    def _claim_runtime_ownership(self, sid: str) -> str | None:
            """Atomically claim exclusive ownership of one session IDB."""
            path = self._runtime_owner_path(sid)
            owner_pid = os.getpid()
            record = json.dumps(
                {
                    "session_id": sid,
                    "owner_pid": owner_pid,
                    "owner_id": self._runtime_owner_id,
                    "owner_start_token": _process_start_token(owner_pid),
                    "created_at": time.time(),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            tmp_path = f"{path}.{self._runtime_owner_id}.{owner_pid}.tmp"
            # The hard link makes publication atomic. The stable sidecar lock
            # also makes stale-owner inspection and removal one transaction;
            # without it, a new host could claim the path between our liveness
            # check and os.remove(), leaving both hosts believing they own it.
            with _runtime_lease_io_lock(path):
                for _ in range(2):
                    try:
                        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        try:
                            os.write(fd, record)
                        finally:
                            os.close(fd)
                        try:
                            os.link(tmp_path, path)
                            return path
                        except FileExistsError:
                            pass
                    finally:
                        with contextlib.suppress(OSError):
                            os.unlink(tmp_path)

                    # Someone else holds the lease; decide whether they are alive.
                    try:
                        with open(path, encoding="utf-8") as owner_fh:
                            owner = json.load(owner_fh)
                    except FileNotFoundError:
                        continue  # released between our link and this read
                    except Exception as e:
                        # Cannot happen from an in-flight claim now that the lease
                        # is published atomically, so this is a damaged file.
                        log_rpc(f"Discarding unreadable runtime lease {path}: {e}")
                        owner = {}
                    if not isinstance(owner, dict):
                        log_rpc(f"Discarding malformed runtime lease {path}")
                        owner = {}
                    if str(owner.get("owner_id") or "") == self._runtime_owner_id:
                        return path
                    existing_pid = _lease_pid(owner.get("owner_pid"))
                    if existing_pid > 0:
                        try:
                            os.kill(existing_pid, 0)
                        except ProcessLookupError:
                            pass  # holder is gone; reclaim below
                        except Exception:
                            return None
                        else:
                            expected_start = str(
                                owner.get("owner_start_token") or ""
                            ).strip()
                            if expected_start:
                                actual_start = _process_start_token(existing_pid)
                                if not actual_start:
                                    return None
                                if actual_start == expected_start:
                                    return None
                                # The recorded PID was recycled; reclaim it.
                            else:
                                return None
                    with contextlib.suppress(OSError):
                        os.remove(path)
                return None

    def _release_runtime_ownership(self, sid: str) -> None:
            path = self._runtime_owner_path(sid)
            with _runtime_lease_io_lock(path):
                try:
                    with open(path, encoding="utf-8") as owner_fh:
                        owner = json.load(owner_fh)
                except Exception:
                    return
                if not isinstance(owner, dict):
                    return
                if str(owner.get("owner_id") or "") != self._runtime_owner_id:
                    return
                with contextlib.suppress(OSError):
                    os.remove(path)

    def _ida_binary_names(self) -> list[str]:
            if sys.platform == "win32":
                base_names = ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]
            else:
                base_names = ["idat", "idat64", "ida", "ida64"]
            ida_dir = getattr(self, "_ida_dir", None)
            if not ida_dir:
                return base_names
            existing = []
            for name in base_names:
                path = os.path.join(ida_dir, name)
                if os.path.isfile(path):
                    existing.append(name)
            return existing + [n for n in base_names if n not in existing]

    def _is_executable_file(self, path: str) -> bool:
            if not path:
                return False
            if not os.path.isfile(path):
                return False
            if os.name == "nt":
                return True
            return os.access(path, os.X_OK)

    def _detect_ida_dir(self):
            for env_name in ("IDADIR", "IDA_DIR"):
                env_dir = os.environ.get(env_name)
                if not env_dir:
                    continue
                env_dir = os.path.realpath(os.path.expanduser(env_dir))
                if os.path.isdir(env_dir):
                    return env_dir
                if self._is_executable_file(env_dir):
                    return os.path.dirname(env_dir)

            env_idat = os.environ.get("IDA_MCP_IDAT")
            if env_idat:
                env_idat = os.path.realpath(os.path.expanduser(env_idat))
                if self._is_executable_file(env_idat):
                    return os.path.dirname(env_idat)

            cands: list[str] = []
            if sys.platform == "win32":
                cands.extend(
                    [
                        r"C:\Program Files\IDA Professional 9.2",
                        r"C:\Program Files\IDA Pro 9.2",
                        r"C:\Program Files\IDA Professional 9.1",
                        r"C:\Program Files\IDA Pro 9.1",
                        r"C:\Program Files\IDA Professional 9.0",
                        r"C:\Program Files\IDA Pro 9.0",
                        r"C:\Program Files\IDA Professional",
                        r"C:\Program Files\IDA Pro",
                    ]
                )
            elif sys.platform == "linux":
                home = str(Path.home())
                patterns = [
                    "/opt/ida*",
                    "/opt/IDA*",
                    "/opt/idapro*",
                    "/opt/IDAPro*",
                    "/usr/local/ida*",
                    "/usr/local/IDA*",
                    "/usr/local/idapro*",
                    "/usr/local/IDAPro*",
                    os.path.join(home, "ida*"),
                    os.path.join(home, "IDA*"),
                    os.path.join(home, "idapro*"),
                    os.path.join(home, "IDAPro*"),
                ]
                for pattern in patterns:
                    cands.extend(glob.glob(pattern))
            else:
                # macOS and other Unix-like platforms
                cands.extend(
                    [
                        "/Applications/IDA Professional 9.2.app/Contents/MacOS",
                        "/Applications/IDA Pro 9.2.app/Contents/MacOS",
                        "/Applications/IDA Professional.app/Contents/MacOS",
                        "/Applications/IDA Pro.app/Contents/MacOS",
                    ]
                )

            binary_names = self._ida_binary_names()
            for c in cands:
                c = os.path.realpath(os.path.expanduser(c))
                if not os.path.isdir(c):
                    continue
                for name in binary_names:
                    if self._is_executable_file(os.path.join(c, name)):
                        return c

            for name in binary_names:
                resolved = shutil.which(name)
                if resolved:
                    return os.path.dirname(os.path.realpath(resolved))
            return ""

    def _find_idat(self):
            env_idat = os.environ.get("IDA_MCP_IDAT")
            if env_idat:
                env_idat = os.path.realpath(os.path.expanduser(env_idat))
                if self._is_executable_file(env_idat):
                    return env_idat

            if not self.ida_dir:
                self.ida_dir = self._detect_ida_dir()

            for name in self._ida_binary_names():
                if self.ida_dir:
                    p = os.path.join(self.ida_dir, name)
                    if self._is_executable_file(p):
                        return p
                resolved = shutil.which(name)
                if resolved and self._is_executable_file(resolved):
                    return os.path.realpath(resolved)

            return ""

    def _tail_text_file(self, path: str | None, tail_lines: int = 40) -> str:
            if not path:
                return ""
            if not os.path.exists(path):
                return ""
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                return "".join(lines[-max(1, int(tail_lines)) :]).strip()
            except Exception:
                return ""

    def _get_ida_diagnostics(
            self, stdout_log=None, stderr_log=None, tail_lines: int = 40
        ):
            out_log = stdout_log or os.path.join(self.cache_dir, "ida_stdout.log")
            err_log = stderr_log
            if err_log is None and out_log:
                # Best effort: derive sibling stderr path for per-session logs.
                # Handles both the legacy "ida_stdout_<sid>.log" form and the
                # current "ida_stdout.log" / "ida_stderr.log" names.
                err_guess = out_log.replace("ida_stdout", "ida_stderr")
                if err_guess != out_log:
                    err_log = err_guess
            out_tail = self._tail_text_file(out_log, tail_lines=tail_lines)
            err_tail = self._tail_text_file(err_log, tail_lines=tail_lines)
            if not out_tail and not err_tail:
                return "No log available."
            blocks = []
            if out_tail:
                blocks.append(f"[stdout]\n{out_tail}")
            if err_tail:
                blocks.append(f"[stderr]\n{err_tail}")
            return "\n\n".join(blocks)

    def _collect_ida_state_snapshot(
        self,
        runtime: dict | None = None,
        stdout_log: str | None = None,
        stderr_log: str | None = None,
        current_tool: str | None = None,
        current_args: dict | None = None,
        call_started_at: float | None = None,
        tail_lines: int = 5,
        include_process_stats: bool = True,
    ) -> dict:
        """
        Build a compact snapshot of what IDA is doing right now, suitable for
        attaching to long-running tool call responses and `session(status)`.

        Always returns a dict. No exception is raised on failure — partial
        data is better than no data.
        """
        snapshot: dict = {
            "ts": time.time(),
        }
        if current_tool is not None:
            snapshot["current_tool"] = current_tool
        if current_args is not None:
            try:
                args_str = json.dumps(current_args, default=str)
                if len(args_str) > 200:
                    args_str = args_str[:197] + "..."
                snapshot["current_args"] = args_str
            except Exception:
                snapshot["current_args"] = "<unserializable>"
        if call_started_at is not None:
            snapshot["call_elapsed_sec"] = round(time.time() - float(call_started_at), 2)

        proc = None
        if isinstance(runtime, dict):
            proc = runtime.get("process")
        if proc is None:
            snapshot["process_alive"] = False
        else:
            try:
                exit_code = proc.poll()
                if exit_code is not None:
                    snapshot["process_alive"] = False
                    snapshot["process_exit_code"] = int(exit_code)
                else:
                    snapshot["process_alive"] = True
                    snapshot["process_pid"] = int(proc.pid) if proc.pid else None
                    if include_process_stats:
                        try:
                            import resource  # POSIX
                            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
                            # RUSAGE_CHILDREN is cumulative across every reaped
                            # child of the whole host process — not specific to
                            # this session. Label the keys host-wide so callers
                            # reading session(status) are not misled.
                            snapshot["host_rusage_cpu_user_sec"] = round(ru.ru_utime, 2)
                            snapshot["host_rusage_cpu_sys_sec"] = round(ru.ru_stime, 2)
                            snapshot["host_rusage_maxrss_kb"] = int(ru.ru_maxrss)
                        except Exception:
                            pass
                        try:
                            with open(f"/proc/{int(proc.pid)}/stat", "rb") as _sf:
                                parts = _sf.read().split()
                            if len(parts) > 23:
                                snapshot["process_state"] = parts[2].decode("ascii", errors="ignore")
                                snapshot["process_utime_ticks"] = int(parts[13])
                                snapshot["process_stime_ticks"] = int(parts[14])
                                snapshot["process_threads"] = int(parts[19])
                        except Exception:
                            pass
            except Exception as e:
                snapshot["process_alive"] = None
                snapshot["process_error"] = str(e)[:200]

        if not stdout_log and isinstance(runtime, dict):
            stdout_log = runtime.get("stdout_log")
        if not stderr_log and isinstance(runtime, dict):
            stderr_log = runtime.get("stderr_log")
        if not stderr_log and stdout_log:
            err_guess = stdout_log.replace("ida_stdout", "ida_stderr")
            if err_guess != stdout_log:
                stderr_log = err_guess
        if stdout_log:
            tail = self._tail_text_file(stdout_log, tail_lines=tail_lines)
            if tail:
                snapshot["ida_stdout_tail"] = tail
        if stderr_log:
            tail = self._tail_text_file(stderr_log, tail_lines=tail_lines)
            if tail:
                snapshot["ida_stderr_tail"] = tail

        return snapshot

    def _send_rpc_raw(
        self,
        request,
        port,
        timeout=5,
        auth_token: str | None = None,
        recv_timeout: int | None = None,
        queue_timeout: float | None = None,
    ):
            """Send one request through the target IDA runtime's RPC lane.

            IDA executes SDK work synchronously and its bridge accepts one
            request at a time. Serializing per runtime prevents watchdogs,
            indexing workers, and overlapping LLM calls from filling the
            listener backlog and producing false timeouts. Locks are scoped
            per runtime, so different IDA processes remain fully parallel.
            """
            import socket

            rpc_lock = None
            token = auth_token
            with self._runtime_lock:
                for runtime in self.session_runtimes.values():
                    if int(runtime.get("port") or 0) != int(port):
                        continue
                    rpc_lock = runtime.get("rpc_lock")
                    if rpc_lock is None:
                        rpc_lock = threading.Lock()
                        runtime["rpc_lock"] = rpc_lock
                    if not token:
                        token = str(runtime.get("auth_token") or "")
                    break

            acquired = False
            if rpc_lock is not None:
                if queue_timeout is None:
                    rpc_lock.acquire()
                    acquired = True
                else:
                    acquired = rpc_lock.acquire(
                        timeout=max(0.0, float(queue_timeout))
                    )
                if not acquired:
                    raise RpcQueueTimeout(
                        f"IDA runtime on port {port} is busy with another request"
                    )

            s = None
            try:
                payload = dict(request) if isinstance(request, dict) else request
                if token and isinstance(payload, dict):
                    payload["session_token"] = token
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if len(data) > MAX_RPC_REQUEST_SIZE:
                    raise RpcPayloadTooLarge(
                        f"RPC request exceeds {MAX_RPC_REQUEST_SIZE} byte cap"
                    )
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect(("127.0.0.1", port))
                s.sendall(len(data).to_bytes(4, "big") + data)
                # Recv timeout: caller-supplied > env default (IDA_MCP_RPC_TIMEOUT, default 30s).
                # Long-running actions (analysis/wait etc.) pass recv_timeout= to stay alive.
                try:
                    _env_recv = int(os.environ.get("IDA_MCP_RPC_TIMEOUT", "30"))
                except Exception:
                    _env_recv = 30
                if recv_timeout is None:
                    recv_timeout = _env_recv
                recv_timeout = max(1, recv_timeout)
                s.settimeout(recv_timeout)
                lb = b""
                while len(lb) < 4:
                    c = s.recv(4 - len(lb))
                    if not c:
                        raise EOFError()
                    lb += c
                rl = int.from_bytes(lb, "big")
                if rl > MAX_RPC_REQUEST_SIZE:
                    raise RpcPayloadTooLarge(
                        f"RPC response exceeds {MAX_RPC_REQUEST_SIZE} byte cap"
                    )
                rd = b""
                while len(rd) < rl:
                    c = s.recv(min(4096, rl - len(rd)))
                    if not c:
                        raise EOFError()
                    rd += c
                return json.loads(rd.decode("utf-8"))
            finally:
                if s is not None:
                    s.close()
                if acquired:
                    rpc_lock.release()

    def _send_rpc_with_retry(
        self,
        request,
        port: int,
        *,
        max_retries: int | None = None,
        base_backoff: float = 0.15,
        timeout: int = 5,
        auth_token: str | None = None,
        recv_timeout: int | None = None,
        queue_timeout: float | None = None,
    ) -> dict:
        """Call ``_send_rpc_raw`` with bounded retry on transient connection errors.

        Retries are bounded to transient connection errors (socket-level
        failures and EOF) — they do NOT retry on IDA-side errors that
        came back over the wire. Each retry sleeps for ``base_backoff *
        (attempt + 1)`` (linear) by default; the caller can swap that
        strategy in tests by passing ``base_backoff=0``.

        Controlled by ``IDA_MCP_RPC_MAX_RETRIES`` (default 2). Set 0 to
        disable retries entirely.
        """
        if max_retries is None:
            try:
                max_retries = int(os.environ.get("IDA_MCP_RPC_MAX_RETRIES", "2"))
            except Exception:
                max_retries = 2
        max_retries = max(0, max_retries)

        import time as _time
        last_exc: Exception | None = None
        attempts = max_retries + 1
        for attempt in range(attempts):
            try:
                return self._send_rpc_raw(
                    request, port,
                    timeout=timeout,
                    auth_token=auth_token,
                    recv_timeout=recv_timeout,
                    queue_timeout=queue_timeout,
                )
            except (ConnectionRefusedError, EOFError, ConnectionResetError, ConnectionAbortedError) as exc:
                # Transient connection-layer failures that suggest the
                # runtime came back online recently (or was momentarily
                # busy). Retry with linear backoff.
                last_exc = exc
                if attempt >= max_retries:
                    break
                _time.sleep(base_backoff * (attempt + 1))
            except (TimeoutError, OSError):
                # Timeouts and other OS-layer errors are NOT retried —
                # they're surfaced as IDA_TIMEOUT / RPC_CONNECTION_ERROR
                # so the caller can distinguish "IDA was busy" from
                # "IDA went away".
                raise
            except RpcPayloadTooLarge as exc:
                # Not retryable: the payload exceeds the cap regardless of
                # connection state, so retrying would only repeat the failure.
                # Return a size-limit user error instead of letting a bare
                # ValueError escape into the RPC_CONNECTION_ERROR classification.
                return make_error(
                    MCPError.SIZE_LIMIT_EXCEEDED,
                    str(exc),
                    hint=(
                        f"Raise IDA_MCP_MAX_RPC_BYTES (current {MAX_RPC_REQUEST_SIZE}) "
                        "if this payload is legitimate."
                    ),
                    details={"max_rpc_bytes": MAX_RPC_REQUEST_SIZE},
                )
        # Out of attempts — surface the last transient failure.
        raise last_exc  # type: ignore[misc]

    def _kill_ida_process(self, runtime: dict, grace_sec: float = 3.0) -> dict:
        """
        Forcefully terminate the IDA process associated with a session runtime.
        Tries SIGTERM, then SIGKILL after grace_sec. Returns a status dict.
        """
        result: dict = {
            "attempted": False,
            "terminated": False,
            "signaled": None,
        }
        proc = runtime.get("process") if isinstance(runtime, dict) else None
        if proc is None:
            result["error"] = "no_process_in_runtime"
            return result
        result["attempted"] = True
        result["pid"] = int(proc.pid) if proc.pid else None
        try:
            exit_code = proc.poll()
        except Exception:
            exit_code = None
        if exit_code is not None:
            result["terminated"] = True
            result["signaled"] = "already_exited"
            result["exit_code"] = int(exit_code)
            return result
        try:
            proc.terminate()
            result["signaled"] = "SIGTERM"
        except Exception as e:
            result["terminate_error"] = str(e)[:200]
        try:
            proc.wait(timeout=grace_sec)
            result["terminated"] = True
            result["exit_code"] = proc.returncode
            return result
        except subprocess.TimeoutExpired:
            pass  # expected: escalate to SIGKILL below
        except Exception as e:
            result["wait_error"] = str(e)[:200]
        try:
            proc.kill()
            result["signaled"] = "SIGKILL"
        except Exception as e:
            result["kill_error"] = str(e)[:200]
        try:
            proc.wait(timeout=grace_sec)
            result["terminated"] = True
            result["exit_code"] = proc.returncode
        except Exception as e:
            result["final_wait_error"] = str(e)[:200]
        return result

    def _extract_library_init_failure(self, diag: str) -> dict | None:
            if not isinstance(diag, str) or not diag.strip():
                return None
            low = diag.lower()
            has_phrase = ("library init failed" in low) or (
                "library initialization failed" in low
            )
            err_code = None
            m_err = re.search(r"\berr(?:or)?\s*[:=]?\s*(\d+)\b", low)
            if m_err:
                try:
                    err_code = int(m_err.group(1))
                except Exception:
                    err_code = None
            has_err2 = bool(re.search(r"\berr(?:or)?\s*[:=]?\s*2\b", low))
            if not has_phrase and not has_err2:
                return None

            causes: list[str] = []
            hints: list[str] = []
            if (
                "cannot open shared object file" in low
                or "no such file or directory" in low
                or "failed to load shared library" in low
            ):
                causes.append("Missing shared runtime library (loader error).")
                hints.append(
                    "Verify IDA runtime dependencies are installed and loadable (ldd on idat64)."
                )
            if "glibcxx" in low or "cxxabi" in low:
                causes.append("C++ runtime ABI mismatch (libstdc++ / libc++ conflict).")
                hints.append(
                    "Unset conflicting LD_LIBRARY_PATH entries or use system-compatible libstdc++."
                )
            if "qt.qpa.plugin" in low or "xcb" in low or "qt platform plugin" in low:
                causes.append("Qt platform/plugin initialization failure.")
                hints.append(
                    "Check Qt plugin paths and system GUI/runtime deps (e.g. xcb plugin packages)."
                )
            if (
                "wrong elf class" in low
                or "bad cpu type" in low
                or "exec format error" in low
            ):
                causes.append("Binary/runtime architecture mismatch.")
                hints.append(
                    "Use the correct IDA binary for host architecture and compatible target runtime."
                )
            if "permission denied" in low:
                causes.append(
                    "Filesystem permission error while loading runtime components."
                )
                hints.append(
                    "Fix file execute/read permissions on IDA installation and plugins."
                )
            if "plugin" in low and "failed" in low:
                causes.append(
                    "A plugin failed during startup and broke library initialization."
                )
                hints.append("Disable third-party plugins and retry startup.")
            if "python" in low and ("init" in low or "module" in low):
                causes.append("Embedded Python/runtime initialization mismatch.")
                hints.append(
                    "Ensure no conflicting PYTHONHOME/PYTHONPATH overrides are injected."
                )
            if (
                "no space left on device" in low
                or "not enough space" in low
                or "enospc" in low
            ):
                causes.append("Insufficient disk space (ENOSPC) during initialization.")
                hints.append(
                    "Free disk space on the IDA/cache volume — unpacked IDB "
                    "sidecars can consume many GB; check df -h and the "
                    "IDA_MCP_CACHE_DIR location."
                )
            if not causes:
                causes.append("Generic library initialization failure.")
                hints.append("Inspect stdout/stderr tails for missing dependency details.")

            return {
                "detected": True,
                "error_code": err_code,
                "err2": bool(has_err2 or (err_code == 2)),
                "causes": causes,
                "recommendations": hints,
            }

    def _is_library_init_err2(self, diag: str) -> bool:
            info = self._extract_library_init_failure(diag)
            if not info:
                return False
            if info.get("error_code") == 2:
                return True
            if info.get("err2"):
                return True
            # Preserve previous behavior: phrase alone still triggers recovery path.
            return bool(info.get("detected"))

    def _is_orphan_locked_db_open_failure(self, diag: str) -> bool:
            """True when IDA aborted *reopening an existing database* because an
            orphaned process still holds the unpacked sidecars (.id0/.id1/.nam).

            That lock surfaces as "Resource temporarily unavailable" on the .id0
            file after IDA notices the unpacked DB "did not close properly", and
            IDA then exits with "Database initialization failed with error 4".

            Deliberately does NOT match bare "error 4" — that code also fires for
            an unrelated forced-processor mismatch on an existing IDB, which this
            recovery path cannot fix and should not try to.
            """
            if not isinstance(diag, str) or not diag.strip():
                return False
            low = diag.lower()
            if "resource temporarily unavailable" not in low:
                return False
            return (
                "did not close properly" in low
                or "database initialization failed" in low
                or "database init failed" in low
            )

    def _normalize_ida_args(
            self, ida_args: str | list[str] | None
        ) -> list[str]:
            if ida_args is None:
                return []
            if isinstance(ida_args, str):
                parts = shlex.split(ida_args)
            elif isinstance(ida_args, list):
                parts = []
                for p in ida_args:
                    if p is None:
                        continue
                    part = str(p)
                    # Explicitly reject empty entries after normalization.
                    if part == "":
                        raise ValueError("ida_args cannot include empty entries")
                    parts.append(part)
            else:
                raise ValueError("ida_args must be a string or list of strings")
            cleaned = []
            # Reserved for server-managed script/log/output IDB wiring.
            forbidden_prefixes = ("-S", "-L", "-o")
            for arg in parts:
                # shlex.split can emit empty entries for quoted-empty args
                # (e.g. 'a "" b'), so reject them here for both input forms.
                if arg == "":
                    raise ValueError("ida_args cannot include empty entries")
                if "\x00" in arg:
                    raise ValueError("ida_args cannot include null bytes")
                # Args are passed via subprocess list (no shell), so metacharacters aren't interpreted.
                if any(
                    (ord(ch) < 32 and ch not in ("\t", "\n", "\r")) or ch == "\x7f"
                    for ch in arg
                ):
                    raise ValueError("ida_args cannot include control characters")
                if any(arg.startswith(prefix) for prefix in forbidden_prefixes):
                    raise ValueError(f"ida_args cannot include {arg} (reserved by server)")
                if arg == "-A":
                    log_rpc("Ignoring redundant -A flag in ida_args")
                    continue
                cleaned.append(arg)
            return cleaned

    @staticmethod
    def _pop_first(mapping: dict, keys: list[str], default: Any = None) -> Any:
            for key in keys:
                if key in mapping:
                    return mapping.pop(key)
            return default

    def _load_session_macros(self):
            self._session_macros = {}
            try:
                with open(self._macro_path, encoding="utf-8") as f:
                    raw = json.load(f)
            except FileNotFoundError:
                return
            except Exception:
                return
            if not isinstance(raw, dict):
                return
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                name = str(value.get("name") or key).strip()
                data = value.get("data")
                if not name or not isinstance(data, dict):
                    continue
                self._session_macros[key.lower()] = {
                    "name": name,
                    "data": data,
                    "updated_at": value.get("updated_at"),
                }

    def _save_session_macros(self):
            try:
                tmp = self._macro_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._session_macros, f, indent=2, ensure_ascii=False)
                os.replace(tmp, self._macro_path)
            except Exception:
                pass

    def _normalize_macro_name(self, value: Any) -> str | None:
            if value is None:
                return None
            name = str(value).strip()
            if not name:
                return None
            name = re.sub(r"\s+", " ", name)[:80]
            return name or None

    def _record_activity(
            self,
            tool_name: str,
            call_args: Any,
            result: Any,
            *,
            session_id: str | None = None,
        ):
            if not isinstance(call_args, dict):
                return
            if not isinstance(result, dict) or is_error_result(result):
                return
            sid = session_id
            if not sid:
                sid = _normalize_session_id(call_args.get("session_id"))
            if not sid and self.current_session:
                sid = self.current_session.session_id
            if not sid:
                return
            runtime_lock = getattr(self, "_runtime_lock", None)
            if runtime_lock is None:
                self._session_last_activity[sid] = time.time()
            else:
                with runtime_lock:
                    self._session_last_activity[sid] = time.time()

            action = call_args.get("action")
            if not isinstance(action, str):
                action = ""

            # Auto-nudge tracking. UsageIntelligence.observe is NOT called here:
            # the dispatch path (server_dispatch._execute_tool) already feeds the
            # rich observation (latency + error) once per tool call, and calling
            # it again here would double-count every call into the drift stats.
            # This method keeps last-activity tracking (above) plus the
            # auto_nudge fallback for builds with no usage intelligence wired.
            try:
                ui = getattr(self, "_usage_intel", None)
                if ui is None:
                    from .auto_nudge import record_tool_call
                    record_tool_call(
                        sid,
                        tool_name,
                        action,
                        addr=call_args.get("addr"),
                        query=call_args.get("query") or call_args.get("pattern"),
                    )
            except Exception:
                pass

            addresses: list[str] = []
            for field in ("addr", "address", "ea"):
                raw_addr = call_args.get(field)
                if isinstance(raw_addr, int):
                    addresses.append(hex(raw_addr))
                elif isinstance(raw_addr, str):
                    addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addr)[:4])
            raw_addrs = call_args.get("addrs")
            if isinstance(raw_addrs, str):
                addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addrs)[:8])
            elif isinstance(raw_addrs, list):
                for raw_addr in raw_addrs[:8]:
                    if isinstance(raw_addr, int):
                        addresses.append(hex(raw_addr))
                    elif isinstance(raw_addr, str):
                        addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addr)[:2])
            if isinstance(result.get("items"), list):
                for item in result["items"][:16]:
                    if not isinstance(item, dict):
                        continue
                    addr = item.get("address") or item.get("addr")
                    if addr is None and isinstance(item.get("address_ea"), int):
                        addr = hex(item.get("address_ea"))
                    if isinstance(addr, str) and addr.startswith("0x"):
                        addresses.append(addr.lower())
            matches = result.get("matches")
            if isinstance(matches, str):
                addresses.extend(re.findall(r"0x[0-9a-fA-F]+", matches)[:16])
            deduped_addresses: list[str] = []
            seen = set()
            for addr in addresses:
                a = addr.lower()
                if a in seen:
                    continue
                seen.add(a)
                deduped_addresses.append(a)

            entry = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "session_id": sid,
                "tool": tool_name,
                "action": action,
                "addresses": deduped_addresses[:8],
                "topic": result.get("resolved_topic") or result.get("topic"),
                "target": result.get("target")
                or result.get("query")
                or result.get("pattern"),
            }
            lock = getattr(self, "_activity_log_lock", None)
            if lock is None:
                lock = threading.Lock()
                self._activity_log_lock = lock
            with lock:
                # Append by rebuilding the list rather than mutating it in
                # place: concurrent readers (e.g. session get_activity_log)
                # copy/iterate the current object and must never observe an
                # in-place resize, and the lock prevents lost updates between
                # concurrent writers.
                self._activity_log = (self._activity_log + [entry])[-self._activity_log_max :]

            # Also persist into session skill/activity store so dashboard counters,
            # phase progression, and dead-end detection reflect real tool usage.
            with contextlib.suppress(Exception):
                self.session_mgr.log_activity(
                    sid,
                    tool=tool_name,
                    action=action or "",
                    result=json.dumps(
                        {
                            "addresses": deduped_addresses[:4],
                            "topic": entry.get("topic"),
                            "target": entry.get("target"),
                        },
                        ensure_ascii=False,
                    )[:400],
                )

    def _build_recent_workset(
            self,
            sid: str,
            n: int,
            include_bookmarks: bool,
            include_items: bool,
        ) -> dict:
            n = _bounded_int(n, 20, min_value=1, max_value=200)
            entries: list[dict[str, Any]] = []
            seen = set()
            lock = getattr(self, "_activity_log_lock", None)
            if lock is None:
                lock = threading.Lock()
                self._activity_log_lock = lock
            with lock:
                # Snapshot under the same lock the writer uses so a concurrent
                # append/replace cannot resize the list mid-iteration.
                activity_rows = list(reversed(self._activity_log))
            for row in activity_rows:
                if row.get("session_id") != sid:
                    continue
                key = (
                    row.get("tool"),
                    row.get("action"),
                    tuple(row.get("addresses") or []),
                    row.get("topic"),
                    row.get("target"),
                )
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    {
                        "kind": "activity",
                        "ts": row.get("ts"),
                        "tool": row.get("tool"),
                        "action": row.get("action"),
                        "addresses": row.get("addresses") or [],
                        "topic": row.get("topic"),
                        "target": row.get("target"),
                    }
                )
                if len(entries) >= n:
                    break

            if include_bookmarks:
                bm_res = self.bookmark_mgr.list(sid, {"limit": max(1, n), "offset": 0})
                for bm in bm_res.get("bookmarks", [])[:n]:
                    if not isinstance(bm, dict):
                        continue
                    entries.append(
                        {
                            "kind": "bookmark",
                            "ts": bm.get("timestamp"),
                            "address": bm.get("addr"),
                            "name": bm.get("name"),
                            "category": bm.get("category"),
                            "tags": bm.get("tags") or [],
                        }
                    )
                    if len(entries) >= (n * 2):
                        break

            lines: list[str] = []
            for item in entries:
                if item.get("kind") == "bookmark":
                    lines.append(
                        f"{item.get('ts', '')}  bookmark  {item.get('address', '')}  {item.get('name', '')}".strip()
                    )
                    continue
                addr_part = ",".join(item.get("addresses") or [])
                tail_parts = [item.get("tool"), item.get("action")]
                if addr_part:
                    tail_parts.append(addr_part)
                if item.get("topic"):
                    tail_parts.append(str(item.get("topic")))
                elif item.get("target"):
                    tail_parts.append(str(item.get("target")))
                tail = "  ".join([p for p in tail_parts if p])
                lines.append(f"{item.get('ts', '')}  {tail}".strip())

            out = {
                "ok": True,
                "action": "recent_workset",
                "session_id": sid,
                "workset": "\n".join(lines),
                "count": len(entries),
            }
            if include_items:
                out["items"] = entries
            return out

    def _update_session_indexing_metadata(self, session_id: str, **updates: Any) -> None:
            try:
                update = getattr(self.session_mgr, "update_session_metadata", None)
                if callable(update):
                    update(session_id, **updates)
                    return

                # Compatibility for focused mixin hosts and older injected
                # session stores. The real SessionManager takes the atomic
                # read/modify/write path above.
                sess = self.session_mgr.sessions.get(session_id)
                if not sess:
                    return
                current = dict(getattr(sess, "metadata", None) or {})
                if all(current.get(key) == value for key, value in updates.items()):
                    return
                current.update(updates)
                sess.metadata = current
                self.session_mgr._save_metadata(sess)
            except Exception:
                pass

    def _persist_session_fields(self, session: Session, **updates: Any) -> None:
            """Persist runtime-owned fields without saving a stale session copy."""
            for key, value in updates.items():
                setattr(session, key, value)
            update = getattr(self.session_mgr, "update_session", None)
            if callable(update):
                update(session.session_id, **updates)
                return
            # Compatibility for focused mixin hosts and older injected stores.
            self.session_mgr._save_metadata(session)

    # ------------------------------------------------------------------
    # Analysis-state observability
    #
    # The host refuses to block on IDA auto-analysis (it starts the RPC
    # server immediately and lets analysis run in the background), so callers
    # are blind between "create" and "ready". These helpers give an honest
    # picture of what IDA is doing RIGHT NOW, sourced from IDA's own
    # auto_is_ok() via the idb(action='state') RPC — not from the host's
    # idle-indexing worker, which is an orthogonal process whose state was
    # previously (mis)reported as "analysis_ready".
    # ------------------------------------------------------------------

    def _query_ida_state(self, sid: str, timeout: float = 3.0) -> dict | None:
            """Fresh, honest IDA state snapshot via idb(action='state').

            Returns the idb_state() dict (analysis.is_ok, analysis.active,
            inventory.functions_qty, ...) or None if the runtime is gone or
            the RPC fails. Cheap: O(1) SDK calls, no function iteration.
            """
            with self._runtime_lock:
                runtime = self.session_runtimes.get(sid)
            if not self._runtime_alive(runtime):
                return None
            port = runtime.get("port") if isinstance(runtime, dict) else None
            if not isinstance(port, int) or port <= 0:
                return None
            try:
                res = self._send_rpc_raw(
                    {"tool": "idb", "args": {"action": "state"}},
                    port,
                    timeout=timeout,
                    auth_token=runtime.get("auth_token") if isinstance(runtime, dict) else None,
                    queue_timeout=0,
                )
            except Exception:
                return None
            if isinstance(res, dict) and not is_error_result(res) and res.get("ok"):
                return res
            return None

    def _start_analysis_watchdog(self, session_id: str, server_port: int) -> None:
            """Start a per-session host thread that watches IDA's real analysis
            progress and flags the session as 'stalled' when the process is
            alive but analysis stops advancing. Idempotent: restarting a
            session replaces any prior watchdog for it.
            """
            self._stop_analysis_watchdog(session_id, join_timeout=0.2)
            stop_event = threading.Event()

            interval = float(getattr(self, "_analysis_watchdog_interval", 5))
            stall_threshold = float(getattr(self, "_analysis_watchdog_stall_seconds", 120))

            def _worker() -> None:
                last_funcs: int | None = None
                stall_since: float | None = None  # ts when progress last stalled
                self._update_session_indexing_metadata(
                    session_id,
                    analysis_state="starting",
                    analysis_stall_seconds=0,
                    analysis_is_ok=None,
                    analysis_functions_qty=None,
                )
                log_rpc(f"[watchdog] Started for {session_id}")
                while not stop_event.wait(interval):
                    with self._runtime_lock:
                        runtime = self.session_runtimes.get(session_id)
                    if not self._runtime_alive(runtime):
                        return
                    state = self._query_ida_state(session_id, timeout=float(interval))
                    if not state:
                        # RPC failed but process alive — keep watching; treat
                        # as no signal rather than declaring stalled.
                        continue
                    analysis = state.get("analysis") or {}
                    inventory = state.get("inventory") or {}
                    is_ok = bool(analysis.get("is_ok"))
                    active = bool(analysis.get("active"))
                    funcs = inventory.get("functions_qty")
                    try:
                        funcs_i = int(funcs) if funcs is not None else None
                    except Exception:
                        funcs_i = None

                    now = time.time()
                    if is_ok:
                        # Analysis queue is empty — done (for now).
                        stall_since = None
                        verdict = "ready"
                    else:
                        # Analysis in progress. Stall if function count has
                        # not advanced since the last poll. (func count can be
                        # None early in load — don't count that as progress.)
                        progressed = (
                            funcs_i is not None
                            and last_funcs is not None
                            and funcs_i > last_funcs
                        )
                        if progressed or last_funcs is None:
                            stall_since = None
                            verdict = "analyzing"
                        elif stall_since is None:
                            stall_since = now
                            verdict = "analyzing"
                        else:
                            verdict = "analyzing"
                        if stall_since is not None:
                            stall_sec = now - stall_since
                            # analysis.active (from the idb state RPC) means
                            # IDA's auto-analysis worker is actively running a
                            # pass. Legitimate passes (FLIRT signature
                            # matching, struct/TAIL layout, decompilation) can
                            # run for minutes without adding a single function,
                            # so a flat function count is only "stalled" when
                            # analysis is NOT actively running.
                            if stall_sec >= stall_threshold and not active:
                                verdict = "stalled"
                                log_rpc(
                                    f"[watchdog] {session_id} STALLED: no "
                                    f"function-count progress for {int(stall_sec)}s "
                                    f"(funcs={funcs_i}, active={active})"
                                )

                    last_funcs = funcs_i
                    stall_sec_report = (
                        round(time.time() - stall_since, 1) if stall_since else 0
                    )
                    self._update_session_indexing_metadata(
                        session_id,
                        analysis_state=verdict,
                        analysis_stall_seconds=stall_sec_report,
                        analysis_is_ok=is_ok,
                        analysis_active=active,
                        analysis_functions_qty=funcs_i,
                    )

            t = threading.Thread(
                target=_worker,
                daemon=True,
                name=f"ida-watchdog-{session_id}",
            )
            with self._analysis_watchdog_lock:
                self._analysis_watchdog_stop_events[session_id] = stop_event
                self._analysis_watchdog_threads[session_id] = t
            t.start()

    def _stop_analysis_watchdog(self, session_id: str, join_timeout: float = 1.0) -> None:
            with self._analysis_watchdog_lock:
                stop_event = self._analysis_watchdog_stop_events.pop(session_id, None)
                thread = self._analysis_watchdog_threads.pop(session_id, None)
            if stop_event is not None:
                stop_event.set()
            if thread and thread.is_alive() and thread is not threading.current_thread():
                with contextlib.suppress(Exception):
                    thread.join(timeout=max(0.0, float(join_timeout or 0.0)))

    # ------------------------------------------------------------------
    # Session teardown flag (replaces the thread-ident _session_closing
    # tombstone) + graceful-shutdown grace + stale-runtime retirement +
    # periodic analysis checkpointing.
    # ------------------------------------------------------------------

    def _begin_session_teardown(self, sid: str) -> None:
            """Mark *sid* as having a close/delete in flight.

            A boolean close-in-progress flag (not a thread-ident tombstone):
            ``_start_server`` refuses to launch — and the registration-time
            recheck aborts a launch already booting — while the flag is set, so
            a session close can never be resurrected as an orphan IDA process
            after its session is deleted. Unlike the tombstone it is cleared
            unconditionally once teardown completes (``_end_session_teardown``),
            so a later re-open of the same path is never blocked.
            """
            runtime_lock = getattr(self, "_runtime_lock", None)
            if runtime_lock is None:
                self._begin_session_teardown_unlocked(sid)
            else:
                with runtime_lock:
                    self._begin_session_teardown_unlocked(sid)

    def _begin_session_teardown_unlocked(self, sid: str) -> None:
            flags = getattr(self, "_session_teardown", None)
            if not isinstance(flags, set):
                self._session_teardown = set()
                flags = self._session_teardown
            flags.add(sid)

    def _end_session_teardown(self, sid: str) -> None:
            """Clear the close-in-progress flag for *sid* (idempotent)."""
            runtime_lock = getattr(self, "_runtime_lock", None)
            if runtime_lock is None:
                self._end_session_teardown_unlocked(sid)
            else:
                with runtime_lock:
                    self._end_session_teardown_unlocked(sid)

    def _end_session_teardown_unlocked(self, sid: str) -> None:
            flags = getattr(self, "_session_teardown", None)
            if isinstance(flags, set):
                flags.discard(sid)

    @contextlib.contextmanager
    def _teardown_session(self, sid: str):
            """Context manager: hold the close-in-progress flag across a
            teardown+delete, clearing it unconditionally (even on error) once
            the delete completes."""
            self._begin_session_teardown(sid)
            try:
                yield
            finally:
                self._end_session_teardown(sid)

    def _session_teardown_active(self, sid: str) -> bool:
            """True when a close/delete is in flight for *sid*.

            Reads the close-in-progress flag. When the full server is composed,
            the server_session mixin shadows ``_session_is_closing`` over the
            same attribute; the getattr keeps a bare runtime-only mixin host
            (which has no session mixin) working.
            """
            is_closing = getattr(self, "_session_is_closing", None)
            if callable(is_closing):
                return bool(is_closing(sid))
            runtime_lock = getattr(self, "_runtime_lock", None)
            if runtime_lock is None:
                return self._session_teardown_active_unlocked(sid)
            with runtime_lock:
                return self._session_teardown_active_unlocked(sid)

    def _session_teardown_active_unlocked(self, sid: str) -> bool:
            flags = getattr(self, "_session_teardown", None)
            return isinstance(flags, set) and sid in flags

    def _retire_dead_runtime(self, sid: str) -> None:
            """Close a dead runtime's log handles and drop its stale port/token
            before a fresh spawn, WITHOUT releasing ownership or marking the
            session as closing.

            A previously-crashed runtime stays in ``session_runtimes`` (dead) so
            the ownership lease is not dropped mid-spawn; this retires the
            pieces that would otherwise leak (two fds per failed run) or be
            published stale (port/token) once the fresh runtime registers.
            """
            with self._runtime_lock:
                runtime = self.session_runtimes.get(sid)
                if not isinstance(runtime, dict):
                    return
                for fh in runtime.get("log_handles", []):
                    with contextlib.suppress(Exception):
                        fh.close()
                runtime["log_handles"] = []
                runtime.pop("port", None)
                runtime.pop("auth_token", None)

    def _shutdown_grace_seconds(self, sid: str, runtime: dict) -> float:
            """Extended SIGKILL grace for a large / mid-analysis IDB.

            A graceful-shutdown save_database on a multi-hundred-MB IDB can take
            well over the default 2s; SIGKILLing too early abandons the unpacked
            sidecars and the next open hits "Database initialization failed with
            error 4". Small/quiet IDBs keep the fast default so a hung runtime
            is not lingered on.
            """
            default = 2.0
            try:
                extended = float(
                    getattr(self, "large_idb_shutdown_grace_seconds", 30.0) or 30.0
                )
            except Exception:
                extended = 30.0
            idb_path = runtime.get("idb_path") if isinstance(runtime, dict) else None
            if idb_path:
                try:
                    size = os.path.getsize(idb_path)
                except Exception:
                    size = None
                if size is not None and size >= _LARGE_IDB_CHECKPOINT_THRESHOLD:
                    return max(default, extended)
            # Mid-analysis: the watchdog records analysis_state == 'analyzing'
            # in session metadata; an in-flight save on a still-analyzing IDB
            # deserves the extended grace even if it is not yet "large".
            try:
                mgr = getattr(self, "session_mgr", None)
                sessions = getattr(mgr, "sessions", None) if mgr is not None else None
                sess = sessions.get(sid) if isinstance(sessions, dict) else None
                meta = getattr(sess, "metadata", None) if sess is not None else None
            except Exception:
                meta = None
            if isinstance(meta, dict) and meta.get("analysis_state") == "analyzing":
                return max(default, extended)
            return default

    def _shutdown_rpc_save_timeout(self, grace: float) -> float:
            """RPC timeout budget for the synchronous shutdown save.

            Capped so a hung runtime is not blocked on indefinitely (the SIGKILL
            grace is the real deadline); never below 1s so the save has a floor.
            """
            try:
                grace = max(1.0, float(grace or 0.0))
            except Exception:
                grace = 1.0
            return min(grace, _SHUTDOWN_SAVE_RPC_CAP)

    # ------------------------------------------------------------------
    # Periodic analysis checkpointing
    # ------------------------------------------------------------------

    def _checkpoint_save_interval(self) -> float:
            """Checkpoint cadence from the ``checkpoint_save_seconds`` knob."""
            try:
                interval = float(getattr(self, "checkpoint_save_seconds", 5.0) or 5.0)
            except Exception:
                interval = 5.0
            return max(1.0, interval)

    def _start_analysis_checkpoint_timer(self, session_id: str, server_port: int) -> None:
            """Start a per-session periodic saver that checkpoints the IDB
            (analysis(action='save_idb')) so the on-disk database tracks the
            in-memory state. Idempotent: restarting a session replaces any prior
            timer for it. Consumes the ``checkpoint_save_seconds`` knob."""
            self._stop_analysis_checkpoint_timer(session_id, join_timeout=0.2)
            stop_event = threading.Event()
            interval = self._checkpoint_save_interval()

            def _worker() -> None:
                while not stop_event.wait(interval):
                    self._run_analysis_checkpoint(session_id)

            t = threading.Thread(
                target=_worker,
                daemon=True,
                name=f"ida-ckpt-{session_id}",
            )
            with self._runtime_lock:
                stop_events = getattr(self, "_analysis_checkpoint_stop_events", None)
                if not isinstance(stop_events, dict):
                    self._analysis_checkpoint_stop_events = {}
                    stop_events = self._analysis_checkpoint_stop_events
                threads = getattr(self, "_analysis_checkpoint_threads", None)
                if not isinstance(threads, dict):
                    self._analysis_checkpoint_threads = {}
                    threads = self._analysis_checkpoint_threads
                stop_events[session_id] = stop_event
                threads[session_id] = t
            t.start()

    def _stop_analysis_checkpoint_timer(self, session_id: str, join_timeout: float = 1.0) -> None:
            with self._runtime_lock:
                stop_events = getattr(self, "_analysis_checkpoint_stop_events", None)
                threads = getattr(self, "_analysis_checkpoint_threads", None)
                stop_event = (
                    stop_events.pop(session_id, None)
                    if isinstance(stop_events, dict)
                    else None
                )
                thread = (
                    threads.pop(session_id, None)
                    if isinstance(threads, dict)
                    else None
                )
            if stop_event is not None:
                stop_event.set()
            if thread and thread.is_alive() and thread is not threading.current_thread():
                with contextlib.suppress(Exception):
                    thread.join(timeout=max(0.0, float(join_timeout or 0.0)))

    def _run_analysis_checkpoint(self, session_id: str) -> None:
            """Perform one analysis checkpoint: save the DB and record the
            progress marker.

            Skips when the runtime is not alive, the analysis gate is still
            pending (startup — the save would hit the bridge's
            ANALYSIS_INCOMPLETE gate and is pointless before analysis settles),
            or the save RPC fails. The ``analysis(action='save_idb')`` surface
            is shared with the graceful-shutdown path.
            """
            with self._runtime_lock:
                runtime = self.session_runtimes.get(session_id)
            if not isinstance(runtime, dict):
                return
            proc = runtime.get("process")
            try:
                alive = bool(proc and proc.poll() is None)
            except Exception:
                alive = False
            if not alive:
                return
            analysis_complete = getattr(self, "_analysis_is_complete", None)
            if callable(analysis_complete) and not analysis_complete(session_id):
                return
            port = runtime.get("port")
            auth_token = runtime.get("auth_token")
            if not (isinstance(port, int) and port > 0):
                return
            try:
                res = self._send_rpc_raw(
                    {"tool": "analysis", "args": {"action": "save_idb"}},
                    port,
                    timeout=self._checkpoint_save_interval(),
                    auth_token=auth_token,
                    queue_timeout=0,
                )
            except Exception as exc:
                log_rpc(f"[checkpoint] save failed for {session_id}: {exc}")
                return
            if not (isinstance(res, dict) and not is_error_result(res)):
                return
            self._record_analysis_checkpoint(session_id)

    def _record_analysis_checkpoint(self, session_id: str) -> None:
            """Persist the per-session analysis-progress marker so a later
            resume can report how stale the on-disk IDB is."""
            try:
                state = self._query_ida_state(session_id, timeout=2.0)
            except Exception:
                state = None
            funcs = None
            if isinstance(state, dict):
                inventory = state.get("inventory") or {}
                try:
                    funcs = int(inventory.get("functions_qty"))
                except Exception:
                    funcs = None
            updater = getattr(self, "_update_session_indexing_metadata", None)
            if callable(updater):
                with contextlib.suppress(Exception):
                    # Timezone-aware UTC, rendered as the same Z-suffixed naive
                    # form the staleness reader (_checkpoint_staleness_warning)
                    # parses — avoids the deprecated datetime.utcnow().
                    now_utc = datetime.now(UTC)
                    checkpointed_at = now_utc.replace(tzinfo=None).isoformat() + "Z"
                    updater(
                        session_id,
                        analysis_checkpointed_at=checkpointed_at,
                        analysis_progress=funcs,
                    )

    def _json_safe_value(self, value: Any) -> Any:
            """Recursively convert non-JSON-safe values to safe representations."""
            if isinstance(value, bytes):
                try:
                    return value.decode("utf-8")
                except Exception:
                    return {"_bytes_hex": value.hex()}
            if isinstance(value, bytearray):
                return self._json_safe_value(bytes(value))
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    try:
                        key = k if isinstance(k, str) else str(k)
                    except Exception:
                        key = "<non_string_key>"
                    out[key] = self._json_safe_value(v)
                return out
            if isinstance(value, (list, tuple)):
                return [self._json_safe_value(v) for v in value]
            if isinstance(value, set):
                return [self._json_safe_value(v) for v in value]
            return value

    def _render_payload_text(self, payload: Any) -> str:
            """Render a JSON-safe result as readable text without JSON escaping.

            Gemini displays an MCP text block verbatim inside a Vertex function
            response. A JSON string therefore leaves quoted source code and
            newlines looking double-escaped (for example ``\\\"`` and ``\\n``).
            This renderer keeps the same information while reserving JSON for
            ``structuredContent``.
            """
            value = self._json_safe_value(payload)

            def _scalar(item: Any) -> str:
                if item is None:
                    return "null"
                if item is True:
                    return "true"
                if item is False:
                    return "false"
                return str(item)

            def _fence(text: str) -> str:
                fence = "```"
                while fence in text:
                    fence += "`"
                return fence

            def _lines(item: Any, indent: int = 0) -> list[str]:
                prefix = " " * indent
                if isinstance(item, dict):
                    if not item:
                        return [f"{prefix}(empty)"]
                    rendered: list[str] = []
                    for key, child in item.items():
                        label = str(key)
                        if isinstance(child, (dict, list)):
                            rendered.append(f"{prefix}{label}:")
                            rendered.extend(_lines(child, indent + 2))
                        elif isinstance(child, str) and "\n" in child:
                            fence = _fence(child)
                            rendered.append(f"{prefix}{label}:")
                            rendered.append(f"{prefix}{fence}text")
                            rendered.extend(f"{prefix}{line}" for line in child.splitlines())
                            rendered.append(f"{prefix}{fence}")
                        else:
                            rendered.append(f"{prefix}{label}: {_scalar(child)}")
                    return rendered
                if isinstance(item, list):
                    if not item:
                        return [f"{prefix}(empty)"]
                    rendered = []
                    for child in item:
                        if isinstance(child, (dict, list)):
                            rendered.append(f"{prefix}-")
                            rendered.extend(_lines(child, indent + 2))
                        elif isinstance(child, str) and "\n" in child:
                            fence = _fence(child)
                            rendered.append(f"{prefix}-")
                            rendered.append(f"{prefix}  {fence}text")
                            rendered.extend(f"{prefix}  {line}" for line in child.splitlines())
                            rendered.append(f"{prefix}  {fence}")
                        else:
                            rendered.append(f"{prefix}- {_scalar(child)}")
                    return rendered
                return [f"{prefix}{_scalar(item)}"]

            return "\n".join(_lines(value))

    def _preload_ida_args(self, session) -> list[str]:
        """CLI load-args for a NEW database (processor/loader/baseaddr/...).

        Shared by the idat command builder and the idalib worker's
        ``open_database(args=...)`` so both backends load with the same
        architecture from the start.  These flags only make sense before
        the database exists; existing-IDB opens pass no preload args.
        """
        opts = session.analysis_options or {}
        out: list[str] = []
        ida_prefixes = {str(a)[:2] for a in (session.ida_args or [])}
        if opts.get("processor") and "-p" not in ida_prefixes:
            out.append(f"-p{opts['processor']}")
        loader = opts.get("loader")
        _t_emitted = False
        if loader and "-T" not in ida_prefixes:
            out.append(f"-T{loader}")
            _t_emitted = True
        elif not loader and "-T" not in ida_prefixes:
            # Sniff the file magic — if it's a known container format let
            # IDA's native loader handle it; otherwise force -Tbin so raw
            # blobs load correctly regardless of processor/architecture.
            # Explicit loader= always overrides this (handled above).
            _bin_path = session.binary_path or ""
            _is_native = False
            try:
                with open(_bin_path, "rb") as _fh:
                    _magic = _fh.read(4)
                if (_magic[:4] == b"\x7fELF"           # ELF
                        or _magic[:2] in (b"MZ", b"ZM")  # PE/DOS
                        or _magic[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
                                          b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                          b"\xfe\xed\xfa\xce")):  # Mach-O
                    _is_native = True
            except Exception:
                pass
            if not _is_native:
                out.append("-Tbin")
                _t_emitted = True
        # Apply inferred load base so IDA maps the binary at the correct
        # address from the start (e.g. AIC8800D80 WFFW at 0x120000).
        if opts.get("baseaddr") is not None and "-b" not in ida_prefixes:
            # baseaddr arrives as a string like "0x400000" or an int.
            # IDA -b flag is in 16-byte paragraphs, not bytes.
            # Addresses < 16 (e.g. 0x8) would collapse to paragraph 0 and
            # load at 0x0 — pass the raw byte address as a paragraph-1 value
            # via the idb_id offset instead (IDA accepts 0-based hex paragraphs).
            # Simplest correct fix: pass the byte address directly when it is
            # not paragraph-aligned, IDA accepts fractional-paragraph values
            # as a raw linear address when the value is prefixed with 0x and
            # exceeds the paragraph size. For sub-paragraph addresses we just
            # emit the byte address verbatim — IDA treats -b as a linear base
            # when no paragraph boundary applies.
            with contextlib.suppress(TypeError, ValueError):
                _base = int(str(opts["baseaddr"]), 0)
                if _base % 16 == 0:
                    out.append(f"-b{_base // 16:#x}")
                else:
                    # Non-paragraph-aligned: pass byte address directly.
                    out.append(f"-b{_base:#x}")
        # skip_analysis=true: pass -c to create IDB without running auto-analysis.
        # Use for large/raw binaries where analysis blocks indefinitely.
        # After session create, call analysis(action='run') to trigger manually.
        if opts.get("skip_analysis") or opts.get("no_analysis"):
            if "-c" not in (session.ida_args or []):
                out.append("-c")
        # Force a specific file format parser (e.g. bin, elf, pe, macho,
        # ihex, srec). IDA's file-type switch is -T, not -F — a previous
        # -F emission made every launch abort with "Unknown switch '-F'"
        # (the i64 was never created, so every resume re-crashed). Only
        # emitted when no -T (loader/raw) was already added.
        input_format = opts.get("input_format")
        if input_format and not _t_emitted:
            out.append(f"-T{input_format}")
        # Override the entry point address. IDA's entry-point switch is
        # -i (hex), not -e.
        entry_point = opts.get("entry_point")
        if entry_point is not None and "-i" not in ida_prefixes:
            with contextlib.suppress(TypeError, ValueError):
                if isinstance(entry_point, str):
                    out.append(f"-i{entry_point.strip()}")
                else:
                    out.append(f"-i{int(entry_point):x}")
        # rebase_to: the previous emission used -R, which in IDA means
        # "load MS Windows resources" (wrong). There is no post-load
        # rebase switch; a target load address is expressed with -b (the
        # same switch baseaddr uses), so map rebase_to there when no
        # explicit baseaddr was given.
        rebase_to = opts.get("rebase_to")
        if (
            rebase_to is not None
            and opts.get("baseaddr") is None
            and "-b" not in ida_prefixes
        ):
            with contextlib.suppress(TypeError, ValueError):
                _rebase = int(str(rebase_to), 0)
                if _rebase % 16 == 0:
                    out.append(f"-b{_rebase // 16:#x}")
                else:
                    out.append(f"-b{_rebase:#x}")
        # The following options have NO idat command-line equivalent:
        #   processor_options  -P is IDA's "pack database" switch
        #   stack_size         -s is not an idat switch
        #   memory_model       -m is not an idat switch
        # Emitting any of them made IDA reject the command line and abort
        # (or silently do the wrong thing), so they are intentionally not
        # passed on the CLI. They are best applied after load via the
        # pre-analysis hook / a follow-up session(action=...) call.
        for _drop_key in ("processor_options", "stack_size", "memory_model"):
            if opts.get(_drop_key) is not None:
                log_rpc(
                    f"Ignoring {_drop_key}={opts.get(_drop_key)!r}: no idat CLI "
                    f"switch exists for it (previous -P/-s/-m emissions were invalid)"
                )
        return out

    def _build_ida_command(
            self, session, log_file, script_path, use_existing_idb: bool, effective_idb_path: str | None = None
        ):
            cmd = [self.idat_exe, "-A"]
            cmd.extend(session.ida_args or [])

            # For new databases, inject processor/loader CLI flags so IDA loads
            # with the correct architecture from the start instead of defaulting
            # to metapc and requiring a post-load switch.
            if not use_existing_idb:
                cmd.extend(self._preload_ida_args(session))

            cmd.append(f"-S{script_path}")
            cmd.append(f"-L{log_file}")
            if use_existing_idb:
                # For packed .i64, effective_idb_path is the binary_path (the packed .i64)
                idb_to_open = effective_idb_path or session.idb_path
                cmd.append(idb_to_open)
            else:
                cmd.append(f"-o{session.idb_path}")
                if session.binary_path:
                    cmd.append(session.binary_path)
            return cmd

    def _idalib_python_dir(self) -> str:
        """Directory containing the ``idapro`` package for the detected install."""
        if self.ida_dir:
            candidate = os.path.join(self.ida_dir, "idalib", "python")
            if os.path.isdir(os.path.join(candidate, "idapro")):
                return candidate
            # A non-ida-mcp scratch copy next to the install (dev layouts).
            for sub in ("idalib",):
                p = os.path.join(self.ida_dir, sub, "python")
                if os.path.isdir(p):
                    return p
        for candidate in (
            os.path.join(self.ida_dir, "idalib", "python"),
            os.path.join(os.path.dirname(self.idat_exe), "idalib", "python"),
        ):
            if self.ida_dir or self.idat_exe:
                if os.path.isdir(os.path.join(candidate, "idapro")):
                    return candidate
        return ""

    def _build_idalib_command(self, session, script_path, use_existing_idb: bool,
                              effective_idb_path: str | None = None, log_file: str = ""):
        """Worker command for the idalib backend.

        The worker process (``ida_pro_mcp.ida_mcp.idalib_worker``) imports
        ``idapro``, opens the target database via
        ``open_database(..., enable_history=True)``, then runs
        ``server_script.py``'s ``__main__`` unchanged.  Everything else —
        the ``IDA_MCP_*`` env, the port handoff, the ping protocol, leases
        and teardown — is identical to the idat backend, so the host treats
        the worker exactly like an idat runtime.
        """
        # SCRIPT_DIR is host/server/; the import root (the directory
        # containing the ida_pro_mcp package) is three levels up.
        package_root = os.path.dirname(os.path.dirname(os.path.dirname(SCRIPT_DIR)))
        cmd = [sys.executable, "-m", "ida_pro_mcp.idalib_worker"]
        open_spec = {
            "file": (effective_idb_path or session.idb_path)
            if use_existing_idb
            else (session.binary_path or ""),
            "existing": bool(use_existing_idb),
            "skip_analysis": bool(
                (session.analysis_options or {}).get("skip_analysis")
                or (session.analysis_options or {}).get("no_analysis")
            ),
            "server_script": script_path,
        }
        # Preload load-args mirror the idat CLI (processor/loader/baseaddr/
        # entry/rebase/skip). -o names the output IDB for new databases;
        # -L redirects IDA's own log to the session log dir for diagnostics.
        args: list[str] = []
        if not use_existing_idb:
            args.extend(self._preload_ida_args(session))
        if not use_existing_idb and session.idb_path:
            args.append(f"-o{session.idb_path}")
        if log_file:
            args.append(f"-L{log_file}")
        open_spec["args"] = " ".join(args)
        return cmd, open_spec, package_root

    @staticmethod
    def _runtime_backend() -> str:
        """Runtime backend in effect: ``idat`` (default) or ``idalib``."""
        return (os.environ.get("IDA_MCP_RUNTIME") or "idat").strip().lower()

    def _is_idalib_runtime(self) -> bool:
        return self._runtime_backend() == "idalib"

    def _backup_idb(self, idb_path: str) -> str | None:
            if not idb_path or not os.path.exists(idb_path):
                return None
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{idb_path}.corrupt.{timestamp}"
            try:
                os.replace(idb_path, backup_path)
                log_rpc(f"Backed up corrupt IDB to {backup_path}")
                return backup_path
            except Exception as e:
                log_rpc(f"Failed to backup corrupt IDB {idb_path}: {e}")
                return None

    def _cleanup_stale_idb_family(self, idb_path: str) -> None:
            """Remove stale sidecar files that can block fresh IDB creation."""
            if not idb_path:
                return
            base, ext = os.path.splitext(idb_path)
            family_exts = [
                ".id0",
                ".id1",
                ".nam",
                ".til",
                ".dmp",
                ".asm",
                ".i64",
                ".idb",
            ]
            for fam_ext in family_exts:
                path = f"{base}{fam_ext}"
                if not os.path.exists(path):
                    continue
                try:
                    os.remove(path)
                    log_rpc(f"Removed stale IDB artifact: {path}")
                except Exception as e:
                    log_rpc(f"Failed to remove stale IDB artifact {path}: {e}")
    @staticmethod
    def _argv_targets_path(argv, target_norm: str) -> bool:
            """True when *target_norm* appears on the command line as an EXACT
            argument — a positional file/IDB path or the value of an ``-o`` switch
            (attached ``-o<path>`` or next-token ``-o <path>``). Substring
            containment is deliberately NOT matched: a target like
            ``/tmp/SID_AB12CDEF_foo.bin.i64`` must not kill an unrelated process
            whose cmdline merely contains that path as a prefix or fragment.
            """
            tokens = [str(a) for a in (argv or []) if str(a)]
            for idx, tok in enumerate(tokens):
                low = tok.lower()
                if low == target_norm:
                    return True
                if low.startswith("-o"):
                    body = low[2:]
                    if body.startswith("="):
                        body = body[1:]
                    if body and body == target_norm:
                        return True
                    if not body and idx + 1 < len(tokens) and tokens[idx + 1].lower() == target_norm:
                        return True
            return False

    def _live_runtime_pids(self) -> set[int]:
            """PIDs of the live IDA runtimes this host owns, so the orphan
            killer never signals a process that belongs to a currently-served
            session (its cmdline legitimately carries the session IDB path)."""
            live: set[int] = set()
            snapshot = getattr(self, "_runtime_items_snapshot", None)
            runtimes = snapshot() if callable(snapshot) else []
            for _sid, runtime in runtimes:
                proc = runtime.get("process")
                try:
                    if proc is not None and proc.poll() is None:
                        pid = getattr(proc, "pid", None)
                        if pid:
                            live.add(int(pid))
                except Exception:
                    continue
            return live

    def _terminate_ida_processes_for_path(self, target_path: str) -> list[int]:
            """Best-effort terminate any idat/ida processes whose command line
            references the given target by an EXACT argument match (positional
            IDB/file path or ``-o`` value). Returns the list of PIDs that were
            killed. Used to recover from orphaned IDA processes that still hold
            the IDB / unpacked sidecars.
            """
            killed: list[int] = []
            if not target_path:
                return killed
            target_norm = os.path.realpath(os.path.abspath(target_path)).lower()
            if not target_norm:
                return killed
            live_pids = self._live_runtime_pids()

            candidate_pids: list[int] = []
            try:
                import psutil as _ps
            except Exception:
                _ps = None

            if _ps is not None:
                # Preferred path: psutil's process_iter filters by name cheaply.
                try:
                    for proc in _ps.process_iter(["pid", "name", "cmdline"]):
                        try:
                            name = (proc.info.get("name") or "").lower()
                        except Exception:
                            name = ""
                        if "ida" not in name and "idat" not in name:
                            continue
                        try:
                            cmdline_parts = proc.info.get("cmdline") or []
                        except Exception:
                            cmdline_parts = []
                        if not self._argv_targets_path(cmdline_parts, target_norm):
                            continue
                        try:
                            pid = int(proc.info.get("pid") or 0)
                        except Exception:
                            pid = 0
                        if pid and pid not in live_pids:
                            candidate_pids.append(pid)
                except Exception:
                    pass
            elif sys.platform == "win32":
                # Windows without psutil: wmic /taskkill (kept from the original
                # implementation; wmic does not exist on POSIX).
                try:
                    out = subprocess.run(
                        ["wmic", "process", "where", "name like '%idat%' or name like '%ida%'",
                         "get", "ProcessId,CommandLine", "/format:list"],
                        capture_output=True, text=True, timeout=10,
                    )
                    block_pid = None
                    for line in (out.stdout or "").splitlines():
                        line = line.rstrip()
                        if line.lower().startswith("processid"):
                            try:
                                block_pid = int(line.split(":", 1)[1].strip())
                            except Exception:
                                block_pid = None
                        elif line.lower().startswith("commandline"):
                            cmd = line.split(":", 1)[1].strip()
                            try:
                                cmd_parts = shlex.split(cmd)
                            except Exception:
                                cmd_parts = []
                            if (
                                block_pid
                                and block_pid not in live_pids
                                and self._argv_targets_path(cmd_parts, target_norm)
                            ):
                                candidate_pids.append(block_pid)
                            block_pid = None
                        else:
                            block_pid = None
                except Exception:
                    pass
            else:
                # POSIX without psutil: scan /proc/*/cmdline. Dependency-free and
                # works on every Linux box. psutil is not a dependency, and the old
                # wmic fallback made this method a silent no-op on Linux.
                expected_names = {n.lower() for n in self._ida_binary_names()}
                try:
                    entries = os.listdir("/proc")
                except Exception:
                    entries = []
                for entry in entries:
                    if not entry.isdigit():
                        continue
                    try:
                        with open(f"/proc/{entry}/cmdline", "rb") as fh:
                            raw = fh.read().decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    cmdline_parts = raw.split("\x00")
                    if not self._argv_targets_path(cmdline_parts, target_norm):
                        continue
                    try:
                        exe_name = os.path.basename(
                            os.path.realpath(f"/proc/{entry}/exe")
                        ).lower()
                    except Exception:
                        exe_name = ""
                    if exe_name not in expected_names:
                        continue
                    pid = int(entry)
                    if pid not in live_pids:
                        candidate_pids.append(pid)

            for pid in candidate_pids:
                try:
                    if sys.platform == "win32":
                        subprocess.run(
                            ["taskkill", "/T", "/F", "/PID", str(pid)],
                            capture_output=True, timeout=5,
                        )
                    else:
                        try:
                            # Only signal the whole group when the process leads
                            # its own process group (started via
                            # start_new_session). A stale process that shares
                            # another group (e.g. launched manually from a
                            # shell) must not have that group killed — killpg
                            # would take out the MCP server or the whole
                            # terminal session.
                            if os.getpgid(pid) == pid:
                                os.killpg(pid, signal.SIGTERM)
                            else:
                                os.kill(pid, signal.SIGTERM)
                        except Exception:
                            with contextlib.suppress(ProcessLookupError):
                                os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                    log_rpc(f"Terminated stale IDA pid={pid} holding {target_norm}")
                except Exception as e:
                    log_rpc(f"Failed to terminate stale IDA pid={pid}: {e}")
            return killed

    def _nuclear_reset(self, idb_path, aggressive: bool = False):
            if not idb_path:
                return

            base = idb_path.rsplit(".", 1)[0]

            lock_exts = [
                ".mcp.lock",  # Legacy MCP session lock for exclusive IDB access
                ".lock",
            ]
            all_exts = [
                ".id0",
                ".id1",
                ".id2",
                ".id3",
                ".id4",
                ".nam",
                ".til",
                ".idb_info",
                ".seg",
                ".sig",
                ".ids",
            ]

            cleanup_exts = all_exts if aggressive else lock_exts
            for ext in cleanup_exts:
                try:
                    p = base + ext
                    if os.path.exists(p):
                        os.remove(p)
                        log_rpc(f"Cleaned up temp file: {p}")
                except Exception as e:
                    log_rpc(f"Failed to clean up {base + ext}: {e}")

            if aggressive and os.path.exists(idb_path):
                try:
                    if os.path.getsize(idb_path) < 100:
                        log_rpc(f"IDB appears corrupted (too small): {idb_path}")
                        os.remove(idb_path)
                        log_rpc(f"Removed corrupted IDB: {idb_path}")
                except Exception as e:
                    log_rpc(f"Failed to check IDB size: {e}")

    def _start_server(self, session):
            # Per-session mutex: prevent two concurrent callers from both
            # seeing runtime-dead and launching duplicate IDA processes.
            sid = session.session_id
            if getattr(self, "_shutdown_requested", False):
                return make_error(
                    MCPError.IDA_BUSY,
                    "The MCP host is shutting down; refusing to start IDA.",
                    recoverable=True,
                    hint="Retry after creating a new MCP host connection.",
                    details={"session_id": sid},
                )
            with self._runtime_lock:
                if not hasattr(self, "_session_startup_locks"):
                    self._session_startup_locks = {}
                if sid not in self._session_startup_locks:
                    import threading as _threading
                    # Reentrant because recovery paths can call
                    # _cleanup_runtime from inside _start_server's lifecycle
                    # section; a plain Lock would deadlock the owning thread.
                    self._session_startup_locks[sid] = _threading.RLock()
            startup_lock = self._session_startup_locks[sid]
            with startup_lock:
                # Re-check after acquiring — a concurrent caller may have
                # already started the runtime while we were waiting.
                if self._runtime_alive(self._runtime_record(sid)):
                    return {"ok": True, "idb_path": session.idb_path, "_already_running": True}
                # A session close/delete is in flight for this sid (the
                # close-in-progress flag). _start_server refuses ONLY while
                # close is actually running — the flag is cleared unconditionally
                # once teardown completes, so a deliberate relaunch (safe-mode
                # reload, retry after a failed apply, recovery, or a fresh open
                # of the same path) is allowed the moment the delete is done.
                # An automatic restart racing the delete must not resurrect the
                # session as an orphan IDA process.
                if self._session_teardown_active(sid):
                    return make_error(
                        MCPError.IDA_BUSY,
                        "Session is being closed; refusing to auto-restart it.",
                        recoverable=True,
                        hint=(
                            "The session is being closed by another caller. "
                            "Retry after it finishes, or open the binary again "
                            "to create a fresh session."
                        ),
                        details={"session_id": sid},
                    )
                ownership_path = self._claim_runtime_ownership(sid)
                if not ownership_path:
                    return make_error(
                        MCPError.FILE_LOCKED,
                        "This session is active in another MCP client.",
                        hint=(
                            "Open the binary in this client to create an independent "
                            "session, or close the other client before switching here."
                        ),
                        details={"session_id": sid},
                    )
                try:
                    # h02 3a / dispatch handoff: every fresh spawn re-enters
                    # safe mode so a call_tool auto-restart of a dead runtime
                    # cannot bypass the analysis gate. Idempotent — paths that
                    # already pended (create/reopen/rebuild) are unaffected and
                    # the watcher set guards double-spawn. Bare-mixin unit
                    # hosts that do not compose the session mixin skip it.
                    mark_pending = getattr(self, "_mark_analysis_pending", None)
                    if callable(mark_pending):
                        mark_pending(session)
                    # h02 1b: before the fresh spawn, retire the pieces of any
                    # previously-crashed runtime (log fds, stale port/token)
                    # WITHOUT releasing ownership or marking the session closing.
                    self._retire_dead_runtime(sid)
                    result = self._start_server_inner(session)
                except Exception:
                    self._release_runtime_ownership(sid)
                    raise
                if is_error_result(result):
                    self._release_runtime_ownership(sid)
                return result

    def _start_server_inner(self, session):
            opts = session.analysis_options or {}
            preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
            has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
            self._nuclear_reset(
                session.idb_path, aggressive=bool(opts.get("aggressive_cleanup"))
            )

            # Validate IDA installation
            idalib_runtime = self._is_idalib_runtime()
            if idalib_runtime:
                idalib_python_dir = self._idalib_python_dir()
                if not idalib_python_dir:
                    return make_error(
                        MCPError.FILE_NOT_FOUND,
                        "idalib runtime requested (IDA_MCP_RUNTIME=idalib) but the "
                        "idapro Python package was not found under the IDA install. "
                        "Run py-activate-idalib.py -d <install_dir> and check "
                        "<install>/idalib/python exists.",
                        details={"ida_dir": self.ida_dir, "idat_exe": self.idat_exe},
                    )
            elif not self.idat_exe or not self._is_executable_file(self.idat_exe):
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    "IDA executable not found. Set IDADIR or IDA_MCP_IDAT, or ensure idat64/idat is in PATH.",
                    details={"ida_dir": self.ida_dir, "idat_exe": self.idat_exe},
                )

            # Let IDA bind port 0 itself, then publish the kernel-selected port
            # through a unique handoff file.  Pre-selecting and releasing a
            # port here created a TOCTOU race during concurrent launches.
            server_port = 0
            session_dir = self.session_mgr.get_session_artifact_dir(session.session_id)
            port_file = os.path.join(
                session_dir,
                f"ida_rpc_{session.session_id}_{self._runtime_owner_id[:12]}.port",
            )
            with contextlib.suppress(OSError):
                os.remove(port_file)

            # server_script.py lives at the package root (ida_pro_mcp/).
            # SCRIPT_DIR is host/server/, so the package root is two levels up.
            script_path = os.path.join(os.path.dirname(os.path.dirname(SCRIPT_DIR)), "server_script.py")

            # Environment for IDA
            env = os.environ.copy()
            ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
            if ida_runtime_dir:
                env["IDADIR"] = ida_runtime_dir
            env["IDA_MCP_PORT"] = str(server_port)
            env["IDA_MCP_PORT_FILE"] = port_file
            session_token = secrets.token_urlsafe(32)
            env["IDA_MCP_SESSION_TOKEN"] = session_token
            # Note: IDA_MCP_BYPASS_SYNC is intentionally NOT set globally — it
            # disables the @idaread/@idawrite execute_sync safety wrapper for
            # every call. Server code that must run off the main thread opts in
            # via the scoped bypass_sync() context manager (server_script.py).
            env["IDA_MCP_SESSION_ID"] = session.session_id
            env["IDA_MCP_CACHE_DIR"] = self.cache_dir
            env["IDA_MCP_IDB_PATH"] = session.idb_path
            env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
            # For packed .i64 IDBs, never force pre-analysis architecture
            # overrides onto an existing database — the IDB already encodes the
            # correct processor/bitness, and forcing a different processor here
            # causes IDA to unload the existing IDP module and abort with
            # "Database initialization failed with error 4".
            force_preload = has_preload_request and not getattr(session, "packed_idb", False)
            env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if force_preload else "0"

            # Determine whether to open existing IDB or create new one
            # Packed .i64 databases should be opened directly as existing IDBs
            if getattr(session, "packed_idb", False):
                use_existing_idb = True
                # Use the binary_path (the packed .i64) as the IDB to open
                effective_idb_path = session.binary_path
            else:
                use_existing_idb = os.path.exists(session.idb_path)
                effective_idb_path = session.idb_path
            env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"

            sid_tag = session.session_id
            log_dir = self.session_mgr.get_session_log_dir(sid_tag)
            env["IDA_MCP_SESSION_LOG_DIR"] = log_dir
            log_file = os.path.join(log_dir, "ida_mcp.log")
            stdout_log = os.path.join(log_dir, "ida_stdout.log")
            stderr_log = os.path.join(log_dir, "ida_stderr.log")

            # Launch IDA: Open existing IDB if present, otherwise analyze binary
            if use_existing_idb:
                log_rpc(f"Opening existing session IDB: {effective_idb_path}")
                # A previous IDA instance killed before it could close cleanly
                # (host SIGKILL/crash) survives as an orphan holding the unpacked
                # siblings (.id0/.id1/.nam/.til) next to the packed .i64. The next
                # launch then fails with "Resource temporarily unavailable" on .id0
                # and aborts with "Database initialization failed with error 4".
                # Kill those orphans so the reopen can take the lock. This runs for
                # every existing-IDB open (not just packed IDBs): we already hold the
                # ownership lease here, and matching on the session-specific idb path
                # (present in every IDA cmdline) cannot touch another live session.
                # We intentionally do NOT delete the sibling files - they are IDA's
                # working state (a re-openable cache) and on a 3 GB+ IDB thrashing
                # them on every launch wastes GB of disk I/O. If the siblings are
                # corrupted, IDA will surface the error and the user can clean manually.
                killed = self._terminate_ida_processes_for_path(effective_idb_path)
                if killed:
                    log_rpc(
                        f"Pre-launch cleanup killed {len(killed)} stale IDA process(es) "
                        f"for {effective_idb_path}"
                    )
            else:
                log_rpc(
                    f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
                )
                # Ensure session directory exists
                os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
                self._cleanup_stale_idb_family(session.idb_path)
            if idalib_runtime:
                cmd, idalib_open_spec, package_root = self._build_idalib_command(
                    session, script_path, use_existing_idb, effective_idb_path, log_file=log_file
                )
                env["IDA_MCP_IDALIB_PYTHON_DIR"] = idalib_python_dir
                env["IDA_MCP_IDALIB_OPEN"] = json.dumps(idalib_open_spec)
                _cur_pypath = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = (
                    package_root + (os.pathsep + _cur_pypath if _cur_pypath else "")
                )
            else:
                cmd = self._build_ida_command(
                    session, log_file, script_path, use_existing_idb, effective_idb_path
                )

            log_rpc(f"Launching IDA: {' '.join(cmd)}")

            stdout_fh = open(stdout_log, "a", encoding="utf-8")
            stderr_fh = open(stderr_log, "a", encoding="utf-8")
            _handles_transferred = False
            server_process = None
            try:
                server_process = subprocess.Popen(
                    cmd,
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    env=env,
                    **_popen_new_session_kwargs(),
                )

                # WAIT FOR STARTUP using ping
                startup_timeout = _resolve_startup_timeout()
                start_time = time.time()
                ida_crashed = False
                exit_code = None
                actual_port = 0
                while time.time() - start_time < startup_timeout:
                    exit_code = server_process.poll()
                    if exit_code is not None:
                        ida_crashed = True
                        break

                    try:
                        if actual_port <= 0 and os.path.isfile(port_file):
                            with open(port_file, encoding="ascii") as port_fh:
                                actual_port = int(port_fh.read().strip())
                        if actual_port <= 0:
                            time.sleep(0.05)
                            continue
                        res = self._send_rpc_raw(
                            {"type": "ping"},
                            actual_port,
                            timeout=0.5,
                            auth_token=session_token,
                        )
                        if res.get("pong"):
                            actual_port = int(res.get("port") or actual_port)
                            log_rpc(
                                f"IDA RPC listener is ready for {session.idb_path} on port {actual_port}"
                            )
                            # A session close/delete may have begun from another
                            # thread while IDA was starting. Registering now
                            # would orphan the fresh runtime once close's
                            # delete_session runs, so abort the launch instead —
                            # _handles_transferred is still False, so the finally
                            # below kills the process and closes the fds.
                            if self._session_teardown_active(session.session_id):
                                return make_error(
                                    MCPError.IDA_BUSY,
                                    "Session is being closed; aborting IDA launch.",
                                    recoverable=True,
                                    details={"session_id": session.session_id},
                                )
                            runtime = {
                                "process": server_process,
                                "port": actual_port,
                                "idb_path": session.idb_path,
                                "stdout_log": stdout_log,
                                "stderr_log": stderr_log,
                                "ida_log": log_file,
                                "auth_token": session_token,
                                "rpc_lock": threading.Lock(),
                                "log_handles": [stdout_fh, stderr_fh],
                            }
                            with self._runtime_lock:
                                self.session_runtimes[session.session_id] = runtime
                            with contextlib.suppress(OSError):
                                os.remove(port_file)
                            self._write_runtime_lease(session.session_id, runtime)
                            _handles_transferred = True
                            # No close-in-progress flag to clear here: the flag is
                            # set only while a close/delete is running and is
                            # cleared unconditionally when that delete completes,
                            # so a later restart is never refused by a stale mark.
                            try:
                                apply_res = self._apply_session_options(session, runtime)
                            except Exception:
                                # A runtime that dies mid-apply raises out of
                                # _apply_session_options (the _send_rpc_raw calls
                                # are not individually wrapped). If it escapes
                                # here, the runtime stays registered with its log
                                # fds open while _start_server drops the ownership
                                # lease — an isolation hole and a 2-fd leak per
                                # failed apply. Tear the runtime down first.
                                self._cleanup_runtime(session.session_id)
                                raise
                            if is_error_result(apply_res):
                                self._cleanup_runtime(session.session_id)
                                return apply_res
                            # Start lightweight host services immediately. The
                            # vestigial idle-index worker is gone: indexing state
                            # is honestly reported as disabled (the semantic
                            # index is only ever built on demand or reused).
                            self._start_session_background_services(session, actual_port)
                            return {
                                "ok": True,
                                "idb_path": session.idb_path,
                                "current_options": apply_res.get("current_options"),
                                "apply_steps": apply_res.get("apply_steps"),
                                "steps_done": apply_res.get("steps_done"),
                                "analysis_in_progress": True,
                                "indexing_state": "disabled",
                                "hint": "IDA RPC is ready. Auto-analysis continues in background; the semantic index is built on demand or reused from a matching binary.",
                            }
                    except Exception:
                        pass
                    time.sleep(0.5)

                if ida_crashed:
                    diag = self._get_ida_diagnostics(stdout_log, stderr_log)
                    if self._is_library_init_err2(diag) or self._is_orphan_locked_db_open_failure(diag):
                        return self._attempt_session_recovery(session, diag, server_port)
                    lib_init = self._extract_library_init_failure(diag)
                    details = {"log": diag}
                    if lib_init:
                        details["library_init"] = lib_init
                    return make_error(
                        MCPError.IDA_CRASHED,
                        f"IDA exited with code {exit_code}",
                        details=details,
                    )

                return make_error(
                    MCPError.IDA_TIMEOUT,
                    f"IDA failed to initialize within {startup_timeout}s",
                    hint=(
                        "Increase IDA_MCP_STARTUP_TIMEOUT (current "
                        f"{startup_timeout}s) if the binary is large or your "
                        "machine is slow. Check the IDA log in stderr_log for "
                        "the exact startup phase that hangs."
                    ),
                )
            finally:
                # On any non-success return, the log handles were never
                # handed off to a registered runtime — close them so we do
                # not leak file descriptors across repeated failed starts.
                if not _handles_transferred:
                    with contextlib.suppress(OSError):
                        os.remove(port_file)
                    if server_process is not None:
                        with contextlib.suppress(Exception):
                            _kill_process_tree(server_process)
                    for fh in (stdout_fh, stderr_fh):
                        with contextlib.suppress(Exception):
                            fh.close()

    def _launch_and_wait(self, session, server_port, sanitize_env: bool = False):
            # SCRIPT_DIR is host/server/; server_script.py is at the package root.
            script_path = os.path.join(os.path.dirname(os.path.dirname(SCRIPT_DIR)), "server_script.py")
            env = os.environ.copy()
            ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
            if ida_runtime_dir:
                env["IDADIR"] = ida_runtime_dir
            # Recovery launches use the same race-free port handoff as normal
            # launches. The server_port argument is retained for compatibility
            # with callers but is intentionally not reused.
            recovery_tag = "clean" if sanitize_env else "normal"
            session_dir = self.session_mgr.get_session_artifact_dir(session.session_id)
            port_file = os.path.join(
                session_dir,
                f"ida_rpc_{session.session_id}_{self._runtime_owner_id[:12]}_{recovery_tag}.port",
            )
            with contextlib.suppress(OSError):
                os.remove(port_file)
            env["IDA_MCP_PORT"] = "0"
            env["IDA_MCP_PORT_FILE"] = port_file
            session_token = secrets.token_urlsafe(32)
            env["IDA_MCP_SESSION_TOKEN"] = session_token
            # IDA_MCP_BYPASS_SYNC is intentionally NOT set globally; scoped
            # callers opt in via the bypass_sync() context manager.
            env["IDA_MCP_SESSION_ID"] = session.session_id
            env["IDA_MCP_CACHE_DIR"] = self.cache_dir
            env["IDA_MCP_IDB_PATH"] = session.idb_path
            env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
            opts = session.analysis_options or {}
            preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
            has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
            # Mirror _start_server_inner: never force pre-analysis architecture
            # overrides onto a packed .i64, or IDA aborts with "Database
            # initialization failed with error 4" and recovery loops forever.
            force_preload = has_preload_request and not getattr(session, "packed_idb", False)
            env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if force_preload else "0"
            # Packed .i64 databases should be opened directly as existing IDBs
            if getattr(session, "packed_idb", False):
                use_existing_idb = True
                effective_idb_path = session.binary_path
            else:
                use_existing_idb = os.path.exists(session.idb_path)
                effective_idb_path = session.idb_path
            env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"
            if sanitize_env:
                for k in (
                    "LD_LIBRARY_PATH",
                    "DYLD_LIBRARY_PATH",
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "QT_PLUGIN_PATH",
                    "QT_QPA_PLATFORM_PLUGIN_PATH",
                ):
                    env.pop(k, None)
            sid_tag = session.session_id
            log_dir = self.session_mgr.get_session_log_dir(sid_tag)
            env["IDA_MCP_SESSION_LOG_DIR"] = log_dir
            log_file = os.path.join(log_dir, "ida_mcp.log")
            stdout_log = os.path.join(log_dir, "ida_stdout.log")
            stderr_log = os.path.join(log_dir, "ida_stderr.log")

            if use_existing_idb:
                log_rpc(f"Opening existing session IDB: {effective_idb_path}")
            else:
                log_rpc(
                    f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
                )
                os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
            if self._is_idalib_runtime():
                idalib_python_dir = self._idalib_python_dir()
                if not idalib_python_dir:
                    return make_error(
                        MCPError.FILE_NOT_FOUND,
                        "idalib runtime requested (IDA_MCP_RUNTIME=idalib) but the "
                        "idapro Python package was not found under the IDA install.",
                        details={"ida_dir": self.ida_dir},
                    )
                cmd, idalib_open_spec, package_root = self._build_idalib_command(
                    session, script_path, use_existing_idb, effective_idb_path,
                    log_file=log_file,
                )
                env["IDA_MCP_IDALIB_PYTHON_DIR"] = idalib_python_dir
                env["IDA_MCP_IDALIB_OPEN"] = json.dumps(idalib_open_spec)
                if sanitize_env:
                    env.pop("PYTHONPATH", None)
                _cur_pypath = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = (
                    package_root + (os.pathsep + _cur_pypath if _cur_pypath else "")
                )
            else:
                cmd = self._build_ida_command(session, log_file, script_path, use_existing_idb, effective_idb_path)

            stdout_fh = open(stdout_log, "a", encoding="utf-8")
            stderr_fh = open(stderr_log, "a", encoding="utf-8")
            _handles_transferred = False
            server_process = None
            try:
                server_process = subprocess.Popen(
                    cmd,
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    env=env,
                    **_popen_new_session_kwargs(),
                )

                startup_timeout = _resolve_startup_timeout()
                start_time = time.time()
                actual_port = 0
                while time.time() - start_time < startup_timeout:
                    exit_code = server_process.poll()
                    if exit_code is not None:
                        diag = self._get_ida_diagnostics(stdout_log, stderr_log)
                        return make_error(
                            MCPError.IDA_CRASHED,
                            f"IDA runtime exited with code {exit_code} during startup",
                            details={
                                "exit_code": exit_code,
                                "log": diag,
                                "library_init": self._extract_library_init_failure(diag),
                                "sanitize_env": sanitize_env,
                            },
                            hint="Inspect the IDA log; common causes: missing IDAPython, broken plugin, missing license.",
                        )

                    try:
                        if actual_port <= 0 and os.path.isfile(port_file):
                            with open(port_file, encoding="ascii") as port_fh:
                                actual_port = int(port_fh.read().strip())
                        if actual_port <= 0:
                            time.sleep(0.05)
                            continue
                        res = self._send_rpc_raw(
                            {"type": "ping"},
                            actual_port,
                            timeout=0.5,
                            auth_token=session_token,
                        )
                        if res.get("pong"):
                            actual_port = int(res.get("port") or actual_port)
                            log_rpc(
                                f"IDA RPC listener is ready for {session.idb_path} on port {actual_port}"
                            )
                            # Same abort-on-close guard as _start_server_inner: a
                            # recovery relaunch that races a session close must
                            # not register a runtime the close will orphan.
                            if self._session_teardown_active(session.session_id):
                                return make_error(
                                    MCPError.IDA_BUSY,
                                    "Session is being closed; aborting IDA launch.",
                                    recoverable=True,
                                    details={"session_id": session.session_id},
                                )
                            runtime = {
                                "process": server_process,
                                "port": actual_port,
                                "idb_path": session.idb_path,
                                "stdout_log": stdout_log,
                                "stderr_log": stderr_log,
                                "ida_log": log_file,
                                "auth_token": session_token,
                                "rpc_lock": threading.Lock(),
                                "log_handles": [stdout_fh, stderr_fh],
                            }
                            with self._runtime_lock:
                                self.session_runtimes[session.session_id] = runtime
                            with contextlib.suppress(OSError):
                                os.remove(port_file)
                            self._write_runtime_lease(session.session_id, runtime)
                            _handles_transferred = True
                            # No close-in-progress flag to clear here (see the
                            # _start_server_inner registration path).
                            return {"ok": True, "idb_path": session.idb_path, "port": actual_port}
                    except Exception:
                        pass
                    time.sleep(0.5)

                return make_error(
                    MCPError.IDA_TIMEOUT,
                    "Runtime startup timed out before the runtime reported a port.",
                    hint="Increase IDA_MCP_STARTUP_TIMEOUT or check the IDB log for clues.",
                )
            finally:
                if not _handles_transferred:
                    with contextlib.suppress(OSError):
                        os.remove(port_file)
                    if server_process is not None:
                        with contextlib.suppress(Exception):
                            _kill_process_tree(server_process)
                    for fh in (stdout_fh, stderr_fh):
                        with contextlib.suppress(Exception):
                            fh.close()

    def _attempt_session_recovery(self, session, diag, server_port):
            opts = session.analysis_options or {}
            lib_init = self._extract_library_init_failure(diag)
            if opts.get("recover") is False:
                details = {"log": diag, "recovery_attempted": False}
                if lib_init:
                    details["library_init"] = lib_init
                if self._is_orphan_locked_db_open_failure(diag):
                    details["orphan_locked_db"] = True
                return make_error(
                    MCPError.IDA_CRASHED,
                    "IDA startup failed and recovery is disabled.",
                    details=details,
                )
            if lib_init:
                log_rpc(
                    f"Detected library init failure (err={lib_init.get('error_code')}) "
                    f"causes={lib_init.get('causes')} - attempting recovery..."
                )
            elif self._is_orphan_locked_db_open_failure(diag):
                log_rpc(
                    "Detected orphaned IDA process locking the unpacked database "
                    "- killing it and attempting recovery..."
                )
            else:
                log_rpc("Detected startup failure - attempting recovery...")
            self._cleanup_runtime(session.session_id)
            # The failed launch never registered a runtime, so _cleanup_runtime
            # released the exclusive ownership lease (it only keeps it while a
            # runtime exists in session_runtimes). Re-claim it before relaunching
            # so a second MCP client cannot claim the same IDB while this
            # recovery is in flight — the guard the .owner.json lease exists for.
            ownership_path = self._claim_runtime_ownership(session.session_id)
            if not ownership_path:
                return make_error(
                    MCPError.FILE_LOCKED,
                    "This session became active in another MCP client during recovery.",
                    hint=(
                        "Close the other client, then retry opening the binary "
                        "in this client."
                    ),
                    details={"session_id": session.session_id},
                )
            time.sleep(1)

            backup_path = None
            if opts.get("backup_on_recover", True):
                backup_path = self._backup_idb(session.idb_path)
            self._nuclear_reset(
                session.idb_path, aggressive=bool(opts.get("aggressive_cleanup", True))
            )

            # The failed launch is usually an orphan IDA process still holding
            # the unpacked siblings (.id0/.id1/.nam/.til) next to the packed .i64
            # from a previous crashed run. Kill those processes so the next attempt
            # can open the siblings for read/write. Runs for every recovery (packed
            # and regular sessions alike).
            # We intentionally do NOT delete the sibling files - they are
            # IDA's working state and on a 3 GB+ IDB thrashing them on every
            # recovery wastes GB of disk I/O. If the siblings are corrupted,
            # IDA will surface the error and the user can clean manually.
            # Match the path the orphan's cmdline actually references: for a
            # packed IDB that is the packed file itself (binary_path); for a
            # regular session it is the unpacked idb_path (the only path IDA's
            # launch command line carries for an existing-IDB open).
            if getattr(session, "packed_idb", False):
                kill_target = session.binary_path
            else:
                kill_target = session.idb_path
            killed = self._terminate_ida_processes_for_path(kill_target)
            if killed:
                log_rpc(
                    f"Recovery killed {len(killed)} stale IDA process(es) "
                    f"holding {kill_target}"
                )

            # For packed IDBs, IDA always unpacks fresh sidecars from the .i64 —
            # stale .id0/.id1/.nam/.til left by the crashed process must be removed
            # or the next open will fail with "Resource temporarily unavailable".
            if getattr(session, "packed_idb", False) and session.binary_path:
                _packed_base = os.path.splitext(session.binary_path)[0]
                for _sidecar_ext in (".id0", ".id1", ".nam", ".til"):
                    _sidecar = f"{_packed_base}{_sidecar_ext}"
                    if os.path.exists(_sidecar):
                        try:
                            os.remove(_sidecar)
                            log_rpc(f"Recovery removed stale sidecar: {_sidecar}")
                        except Exception as _e:
                            log_rpc(f"Recovery could not remove {_sidecar}: {_e}")

            if not session.binary_path or not os.path.exists(session.binary_path):
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    "Recovery requires the original binary path (missing or invalid).",
                    details={
                        "binary_path": session.binary_path,
                        "backup": backup_path,
                        "log": diag,
                    },
                )

            self._persist_session_fields(session, analysis_applied=False)

            result = self._launch_and_wait(session, server_port)
            if "error" in result and result.get("library_init"):
                # One extra attempt with sanitized runtime env to avoid host LD/Python contamination.
                retry_result = self._launch_and_wait(
                    session, server_port, sanitize_env=True
                )
                if "error" not in retry_result:
                    result = retry_result
                else:
                    result["sanitized_retry"] = retry_result
            if "error" in result:
                details = {"log": diag, "backup": backup_path, "recovery_attempted": True}
                if lib_init:
                    details["library_init"] = lib_init
                if isinstance(result.get("sanitized_retry"), dict):
                    details["sanitized_retry"] = {
                        "exit_code": result["sanitized_retry"].get("exit_code"),
                        "library_init": result["sanitized_retry"].get("library_init"),
                    }
                return make_error(
                    MCPError.IDA_CRASHED,
                    "IDA failed to recover the session after cleanup.",
                    details=details,
                )

            runtime = self._runtime_record(session.session_id)
            if runtime:
                try:
                    apply_res = self._apply_session_options(session, runtime)
                except Exception:
                    # Same leak as the primary launch path: an exception out of
                    # _apply_session_options leaves the recovered runtime
                    # registered with open fds while ownership is released.
                    self._cleanup_runtime(session.session_id)
                    raise
                if is_error_result(apply_res):
                    return apply_res
                result["current_options"] = apply_res.get("current_options")
                # Recovered sessions need the same host-side services as a fresh
                # launch (analysis watchdog + semantic-index reuse); the normal
                # path starts them from _start_server_inner only, so do it here.
                try:
                    self._start_session_background_services(
                        session, runtime.get("port")
                    )
                except Exception as exc:
                    log_rpc(
                        f"[recovery] background services failed for "
                        f"{session.session_id}: {exc}"
                    )

            if backup_path:
                result["backup"] = backup_path
            return result

    def _apply_session_options(self, session, runtime):
            opts = session.analysis_options or {}
            if not opts:
                return {"ok": True}
            if session.analysis_applied and opts.get("apply_once", True):
                log_rpc(
                    f"Skipping analysis options for session {session.session_id} (already applied)"
                )
                return {
                    "ok": True,
                    "skipped": True,
                    "note": "analysis_options already applied",
                }

            port = runtime.get("port")
            if not port:
                return make_error(MCPError.IDA_CRASHED, "Missing runtime port")

            # Stream apply progress so a long create() is not a black box.
            # The MCP stdio server is serial, so a client cannot poll
            # session(status) mid-create; instead we emit live progress
            # notifications and mirror the current step into session metadata.
            apply_steps: list[dict[str, Any]] = []

            def _progress(step: str, status: str = "start", detail: Any = None) -> None:
                with contextlib.suppress(Exception):
                    self._update_session_indexing_metadata(
                        session.session_id,
                        apply_progress={
                            "step": step,
                            "status": status,
                            "ts": time.time(),
                        },
                    )
                try:
                    params: dict[str, Any] = {
                        "progressToken": f"apply:{session.session_id}",
                        "progress": {"step": step, "status": status},
                    }
                    if detail is not None:
                        params["progress"]["detail"] = detail
                    self._send_notification(
                        {"method": "notifications/progress", "params": params}
                    )
                except Exception:
                    pass

            def _record(step: str, res: Any) -> None:
                ok = True
                if isinstance(res, dict):
                    ok = not is_error_result(res)
                apply_steps.append({"step": step, "ok": ok})
                _progress(step, "done" if ok else "error")

            actions = []
            options_payload = {}
            if isinstance(opts.get("options"), dict):
                options_payload.update(opts.get("options") or {})
            for key in ("baseaddr", "start_ea", "min_ea", "max_ea"):
                if key in opts and opts[key] is not None:
                    options_payload[key] = opts[key]
            if options_payload:
                actions.append({"action": "set_options", "options": options_payload})

            _arch_payload = {}
            for k in ("processor", "bitness", "endian", "flags"):
                v = opts.get(k)
                if v is None or (isinstance(v, str) and not v.strip()) or v == 0:
                    continue
                _arch_payload[k] = v
            if _arch_payload:
                actions.append({"action": "set_architecture", **_arch_payload})

            loader_value = opts.get("value")
            if loader_value is None and "loader_options" in opts:
                loader_value = opts.get("loader_options")
            if loader_value is not None:
                loader_args = {"action": "set_loader_options", "value": loader_value}
                if opts.get("loader"):
                    loader_args["loader"] = opts["loader"]
                actions.append(loader_args)

            extra_actions = opts.get("analysis_actions")
            if isinstance(extra_actions, list):
                for action_args in extra_actions:
                    if isinstance(action_args, dict) and action_args.get("action"):
                        actions.append(action_args)

            reanalyze = opts.get("reanalyze")

            if actions:
                _progress("apply_options", "start", detail=[a.get("action") for a in actions if isinstance(a, dict)])
            for action_args in actions:
                res = self._send_rpc_raw({"tool": "analysis", "args": action_args}, port)
                if is_error_result(res):
                    _record(action_args.get("action", "apply_options"), res)
                    return res
                _record(action_args.get("action", "apply_options"), res)


            # reanalyze runs on the action path unless explicitly disabled, and
            # ALSO when it is the only requested option — analysis_options=
            # {"reanalyze": True} alone is a legitimate "re-run auto-analysis
            # after load" request and must not be silently dropped just because
            # no other options produced actions.
            want_reanalyze = (
                (bool(actions) and (reanalyze is None or reanalyze))
                or bool(reanalyze)
            )
            if want_reanalyze:
                _progress("reanalyze", "start")
                reanalyze_args = {"action": "reanalyze"}
                if opts.get("start") is not None:
                    reanalyze_args["start"] = opts.get("start")
                if opts.get("end") is not None:
                    reanalyze_args["end"] = opts.get("end")
                res = self._send_rpc_raw({"tool": "analysis", "args": reanalyze_args}, port)
                if is_error_result(res):
                    _record("reanalyze", res)
                    return res
                _record("reanalyze", res)

            bootstrap_knowledge = {"imported_symbol_count": 0}
            _progress("bootstrap_knowledge", "start")
            try:
                import_res = self._send_rpc_raw(
                    {
                        "tool": "knowledge",
                        "args": {
                            "action": "import_symbols",
                            "min_confidence": float(opts.get("symbol_import_min_confidence", 0.8)),
                            "limit": int(opts.get("symbol_import_limit", 200)),
                        },
                    },
                    port,
                )
                if isinstance(import_res, dict) and not is_error_result(import_res):
                    bootstrap_knowledge["imported_symbol_count"] = int(import_res.get("imported", 0) or 0)
            except Exception:
                pass
            _record("bootstrap_knowledge", {"ok": True})

            if opts.get("apply_once", True):
                session.analysis_applied = True
            self._persist_session_fields(
                session, analysis_applied=session.analysis_applied
            )
            _progress("verify_architecture", "start")
            current_options = {}
            with contextlib.suppress(Exception):
                current_options = self._send_rpc_raw(
                    {"tool": "analysis", "args": {"action": "get_options"}}, port
                )

            # Strict verification for architecture-sensitive loads.
            try:
                expected_proc = opts.get("processor")
                expected_bits = opts.get("bitness")
                expected_end = opts.get("endian")
                got = current_options.get("result") if isinstance(current_options, dict) else None
                if isinstance(got, dict):
                    got_proc = str(got.get("procname") or "").strip().lower()
                    got_bits = got.get("app_bitness")
                    got_be = got.get("is_be")
                    mismatches = []
                    if expected_proc is not None:
                        eproc = str(expected_proc).strip().lower()
                        if got_proc and got_proc != eproc:
                            mismatches.append(f"processor expected={eproc} got={got_proc}")
                    if expected_bits is not None:
                        try:
                            if int(got_bits) != int(expected_bits):
                                mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                        except Exception:
                            mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                    if expected_end is not None:
                        end_norm = str(expected_end).strip().lower()
                        want_be = end_norm in ("be", "big", "big_endian", "big-endian", "bigendian", "1", "true")
                        if got_be is not None and bool(got_be) != bool(want_be):
                            mismatches.append(f"endian expected={'be' if want_be else 'le'} got={'be' if bool(got_be) else 'le'}")
                    if mismatches:
                        return make_error(
                            MCPError.IDA_ERROR,
                            "Architecture preload did not stick after analysis option application",
                            details={
                                "mismatches": mismatches,
                                "expected": {"processor": expected_proc, "bitness": expected_bits, "endian": expected_end},
                                "current_options": got,
                                "hint": "Create a fresh session with architecture block and avoid reusing existing IDBs for incompatible binaries.",
                            },
                        )
            except Exception:
                pass
            _record("verify_architecture", {"ok": True})
            # Persist the apply transcript so session(status) can show what the
            # (black-box) startup actually did, and clear the live marker.
            with contextlib.suppress(Exception):
                self._update_session_indexing_metadata(
                    session.session_id,
                    apply_progress=None,
                    last_apply_steps=apply_steps,
                    last_apply_at=time.time(),
                )
            return {
                "ok": True,
                "current_options": current_options if not is_error_result(current_options) else None,
                "bootstrap_knowledge": bootstrap_knowledge,
                "apply_steps": apply_steps,
                "steps_done": len(apply_steps),
            }

    def _start_session_background_services(self, session, server_port: int) -> None:
            session_id = str(getattr(session, "session_id", "") or "").strip()
            if not session_id:
                return
            with self._runtime_lock:
                self._session_last_activity[session_id] = time.time()
            self._update_session_indexing_metadata(
                session_id,
                indexing_mode="none",
                indexing_state="disabled",
                hot_indexed_count=0,
                indexing_complete=True,
            )
            # Watchdog gives the host an honest picture of IDA's analysis
            # progress (and stalls).  It makes ONE lightweight idb(action='state')
            # call every 5 s — cheap enough not to starve auto-analysis.
            self._start_analysis_watchdog(session_id, server_port)

            # Periodic analysis checkpointing: save_database every
            # checkpoint_save_seconds once analysis completes, and persist the
            # per-session progress marker so a later resume can report staleness.
            self._start_analysis_checkpoint_timer(session_id, server_port)

            # Reuse an exact-content compatible semantic index without
            # coupling this IDA process to another session's live database.
            # Hashing and SQLite backup stay off the session-open path.
            def _reuse_index() -> None:
                try:
                    reused = self._seed_index_from_matching_binary(session)
                    self._update_session_indexing_metadata(
                        session_id,
                        semantic_index_reuse=reused,
                        indexing_state="reused" if reused.get("reused") else "idle",
                    )
                except Exception as exc:
                    log_rpc(f"[semantic-index] reuse scan failed for {session_id}: {exc}")

            threading.Thread(
                target=_reuse_index,
                daemon=True,
                name=f"semantic-reuse-{session_id}",
            ).start()

    def _cleanup_runtime(self, sid):
            # Disconnect, shutdown, and crash-recovery paths can converge on
            # the same SID. Serialize the complete teardown with the same
            # per-session lifecycle lock used by _start_server so a second
            # caller cannot send a duplicate shutdown, kill a newly started
            # replacement, or release ownership behind the first caller.
            with self._runtime_lock:
                locks = getattr(self, "_session_startup_locks", None)
                if not isinstance(locks, dict):
                    locks = {}
                    self._session_startup_locks = locks
                lifecycle_lock = locks.get(sid)
                if lifecycle_lock is None:
                    lifecycle_lock = threading.RLock()
                    locks[sid] = lifecycle_lock
            with lifecycle_lock:
                self._cleanup_runtime_locked(sid)

    def _cleanup_runtime_locked(self, sid):
            # Stop host-side helpers for this session BEFORE tearing down the
            # process tree: the analysis-completion watcher (ida-an-<sid>), the
            # per-session analysis watchdog, and the periodic checkpoint saver
            # (ida-ckpt-<sid>) all poll a live runtime and must not outlive it.
            self._stop_analysis_watchdog(sid, join_timeout=0.5)
            stop_watcher = getattr(self, "_stop_analysis_watcher", None)
            if callable(stop_watcher):
                stop_watcher(sid, join_timeout=0.2)
            self._stop_analysis_checkpoint_timer(sid, join_timeout=0.2)
            with self._runtime_lock:
                self._session_last_activity.pop(sid, None)
                self._session_inflight_calls.pop(sid, None)
            # The per-session startup lock is deliberately NOT popped here:
            # _start_server grabs it by reference and a concurrent caller may
            # still hold it, so removing it would let two threads acquire
            # DIFFERENT locks for the same sid and spawn duplicate IDA
            # processes. The dict grows by one Lock per sid ever launched — a
            # bounded, race-free cost.
            with self._runtime_lock:
                runtime = self.session_runtimes.get(sid, None)
            self._remove_runtime_lease(sid)
            if not runtime:
                self._release_runtime_ownership(sid)
                return
            proc = runtime.get("process")
            port = runtime.get("port")
            # Large / mid-analysis IDBs get a longer SIGKILL grace so a
            # graceful-shutdown save_database has time to merge the unpacked
            # sidecars; the shutdown RPC gets the same budget so the
            # synchronous save is not cut short by a 1s timeout.
            grace = self._shutdown_grace_seconds(sid, runtime)
            if proc:
                with contextlib.suppress(Exception):
                    # Send the graceful shutdown BEFORE removing the runtime
                    # from the registry: _send_rpc_raw resolves the per-runtime
                    # serialization lock by scanning session_runtimes, so an
                    # early pop makes queue_timeout=0 dead code — the shutdown
                    # would queue behind an in-flight call instead of failing
                    # fast so we can kill directly.
                    shutdown_res = self._send_rpc_raw(
                        {"type": "shutdown"},
                        port,
                        timeout=self._shutdown_rpc_save_timeout(grace),
                        queue_timeout=0,
                    )
                    # Wait for save confirmation: the shutdown response carries
                    # saved=bool. A False/absent saved (startup-analysis race or
                    # an unresponsive lane) is handled by the SIGKILL grace
                    # budget below rather than blocking cleanup.
                    if isinstance(shutdown_res, dict) and not shutdown_res.get("saved"):
                        log_rpc(
                            f"Shutdown save not confirmed for {sid} "
                            f"(grace={grace}s); proceeding to kill"
                        )
                # Use _kill_process_tree so the full idat.exe -> ida.exe
                # tree is terminated; otherwise ida.exe can be left
                # orphaned holding the unpacked .id0/.id1 files.
                _kill_process_tree(proc, grace_seconds=grace)
            for fh in runtime.get("log_handles", []):
                with contextlib.suppress(Exception):
                    fh.close()
            with self._runtime_lock:
                self.session_runtimes.pop(sid, None)
            # Ownership is released only after the old process and its file
            # handles are gone, so another host cannot race onto the same IDB.
            self._release_runtime_ownership(sid)

    def _cleanup_all_runtimes(self):
            with self._runtime_lock:
                runtime_sids = list(self.session_runtimes.keys())
            for sid in runtime_sids:
                self._cleanup_runtime(sid)
            self._adopt_or_cleanup_stale_runtime_leases()

    def _resolve_session_from_idb_ref(self, idb_ref: Any) -> Session | None:
            """Resolve idb references from session id, SID_* idb id/name, path, or basename."""
            if not isinstance(idb_ref, str):
                return None
            raw = idb_ref.strip()
            if not raw:
                return None

            sid = _normalize_session_id(raw)
            if sid:
                session = self.session_mgr.get_session(sid)
                if session:
                    return session

            base = os.path.basename(raw)
            # SID_* filenames encode the canonical 8-char session id (SESSION_ID_RE).
            sid_match = re.match(r"^SID_([A-Za-z0-9]{8})(?:_|$)", base)
            if sid_match:
                session = self.session_mgr.get_session(sid_match.group(1).upper())
                if session:
                    return session

            found = self.session_mgr.find_session_by_path(raw)
            if found:
                return found

            wanted = base.lower()
            if not wanted:
                return None
            matches = [
                session
                for session in self.session_mgr.discover_sessions()
                if os.path.basename(session.idb_path or "").lower() == wanted
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                # Multiple sessions share this idb basename (e.g. the same
                # binary opened as two SID dirs). The winner is not resolvable
                # from a bare basename, and picking arbitrarily can route the
                # call — or, via call_tool's auto-restart, launch IDA — against
                # the wrong IDB. Force the caller to disambiguate instead.
                log_rpc(
                    f"Ambiguous idb basename {wanted!r}: matches {len(matches)} "
                    f"sessions; require session_id/SID/path"
                )
            return None
