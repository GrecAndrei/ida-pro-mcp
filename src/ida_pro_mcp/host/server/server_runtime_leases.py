#!/usr/bin/env python3
"""Runtime lease and lifecycle helpers for IDAMCPServer."""

from __future__ import annotations

import atexit
import contextlib
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None

from ..config import (
    _RUNTIME_LEASE_RE,
    PROCESS_TERMINATION_TIMEOUT_SECONDS,
    RUNTIME_LEASE_HEARTBEAT_SECONDS,
    RUNTIME_LEASE_TTL,
    _env_float,
    _normalize_session_id,
    log_rpc,
)


def _lease_pid(value: object) -> int:
    """Parse a lease PID conservatively, returning zero for invalid values."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value > 0 else 0
    text = str(value or "").strip()
    if not text or not text.isascii() or not text.isdigit():
        return 0
    try:
        pid = int(text)
    except (TypeError, ValueError, OverflowError):
        return 0
    return pid if pid > 0 else 0


def _lease_timestamp(value: object) -> float:
    """Parse a finite lease timestamp, returning zero for invalid values."""
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return timestamp if math.isfinite(timestamp) and timestamp >= 0.0 else 0.0


def _process_start_token(pid: int) -> str:
    """Return Linux ``/proc`` start-time identity for *pid*, when available."""
    if not sys.platform.startswith("linux") or pid <= 0:
        return ""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
            data = handle.read()
        end = data.rfind(")")
        tail = data[end + 1 :].split() if end >= 0 else []
        # ``tail`` starts at proc-stat field 3 (state); starttime is field 22.
        return tail[19] if len(tail) > 19 else ""
    except (OSError, ValueError):
        return ""


def _resolve_stale_cleanup_budget() -> float:
    """Bound total time spent killing stale runtime leases at host startup.

    Every stubborn orphan can take ~PROCESS_TERMINATION_TIMEOUT_SECONDS to
    escalate; on a shared cache with many orphans this would block the server
    from serving its first request. The budget defers remaining kills to the
    next startup instead.
    """
    return _env_float(
        "IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", 10.0, min_value=1.0
    )


STALE_CLEANUP_BUDGET_SECONDS = _resolve_stale_cleanup_budget()

# Lease files are shared by daemon connections and can also be shared by
# multiple MCP host processes.  A separate lock file remains stable while the
# lease itself is atomically replaced, so readers/writers cannot interleave a
# compare-and-remove transaction with a fresh lease publication.
_RUNTIME_LEASE_IO_LOCK = threading.RLock()


def _lease_pid(value: object) -> int:
    """Parse a persisted PID without truncating unsafe numeric values."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.isascii() and value.isdigit():
            with contextlib.suppress(ValueError):
                return int(value)
    return 0


def _lease_timestamp(value: object) -> float:
    """Parse a lease timestamp; non-finite values are always stale."""
    try:
        timestamp = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return timestamp if math.isfinite(timestamp) else 0.0


def _process_start_token(pid: int) -> str:
    """Return Linux's PID-reuse-resistant process start token."""
    if sys.platform != "linux" or pid <= 0:
        return ""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as proc_stat:
            data = proc_stat.read()
    except (OSError, UnicodeError):
        return ""
    end = data.rfind(")")
    if end < 0:
        return ""
    fields = data[end + 1 :].split()
    # The field after the command name is state (3); starttime is field 22,
    # which is offset 19 in the tail after the final closing parenthesis.
    return fields[19] if len(fields) > 19 else ""


@contextmanager
def _runtime_lease_io_lock(path: str):
    """Serialize one lease transaction in-process and, on POSIX, across hosts."""
    with _RUNTIME_LEASE_IO_LOCK:
        lock_fd = None
        try:
            if fcntl is not None:
                lock_fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            if lock_fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    os.close(lock_fd)


class ServerRuntimeLeasesMixin:
    def _runtime_lease_path(self, sid: str) -> str:
            return os.path.join(self._runtime_lease_dir, f"SID_{sid}.lease.json")

    def _write_runtime_lease_record(self, path: str, lease: dict) -> None:
            with _runtime_lease_io_lock(path):
                self._write_runtime_lease_record_unlocked(path, lease)

    @staticmethod
    def _write_runtime_lease_record_unlocked(path: str, lease: dict) -> None:
            tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(lease, f, indent=2)
                    f.flush()
                os.replace(tmp, path)
            except Exception:
                with contextlib.suppress(OSError):
                    os.remove(tmp)

    def _write_runtime_lease(self, sid: str, runtime: dict) -> None:
            proc = runtime.get("process")
            if not proc:
                return
            lease = {
                "session_id": sid,
                "pid": int(proc.pid),
                "port": int(runtime.get("port") or 0),
                "idat_exe": str(self.idat_exe or ""),
                "owner_pid": os.getpid(),
                "owner_id": str(getattr(self, "_runtime_owner_id", "") or ""),
                "process_start_token": _process_start_token(int(proc.pid)),
                "owner_start_token": _process_start_token(os.getpid()),
                "updated_at": time.time(),
            }
            path = self._runtime_lease_path(sid)
            self._write_runtime_lease_record(path, lease)

    def _remove_runtime_lease(self, sid: str) -> None:
            path = self._runtime_lease_path(sid)
            with _runtime_lease_io_lock(path), contextlib.suppress(OSError):
                os.remove(path)

    def _remove_runtime_lease_if_pid_matches(self, sid: str, pid: int | None) -> None:
            """Remove a runtime lease only if it still records this pid.

            Between the heartbeat's identity check and the removal, a fresh
            runtime for the same sid can be registered and its lease rewritten
            with a new pid. Removing unconditionally would delete the fresh
            lease and leave the shared cache without an ownership record for a
            live runtime.
            """
            if not pid:
                return
            path = self._runtime_lease_path(sid)
            with _runtime_lease_io_lock(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        lease = json.load(f)
                except Exception:
                    return
                if not isinstance(lease, dict):
                    return
                try:
                    lease_pid = _lease_pid(lease.get("pid"))
                except Exception:  # pragma: no cover - defensive for odd mappings
                    lease_pid = 0
                if lease_pid != pid:
                    return
                with contextlib.suppress(OSError):
                    os.remove(path)

    def _kill_stale_pid(self, pid: int) -> bool:
            """Best-effort terminate a stale PID.

            Returns True when PID is already absent or was terminated.
            Returns False when the process state cannot be verified or terminated.
            """
            if pid <= 0:
                return False
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            deadline = time.time() + PROCESS_TERMINATION_TIMEOUT_SECONDS
            while time.time() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return True
                except Exception:
                    return False
                time.sleep(0.1)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            try:
                os.kill(pid, 0)
                return False
            except ProcessLookupError:
                return True
            except Exception:
                return False

    @staticmethod
    def _parse_proc_stat(data: str) -> dict | None:
            """Parse the numeric fields of a ``/proc/<pid>/stat`` line.

            The ``comm`` field may contain spaces and parentheses, so the
            kernel's ``pid (comm) state ppid pgrp session ...`` layout is
            parsed after the final ')': state, ppid, pgrp, session follow the
            command name.
            """
            end = data.rfind(")")
            if end < 0:
                return None
            tail = data[end + 1 :].split()
            if len(tail) < 4:
                return None
            try:
                return {
                    "state": tail[0],
                    "ppid": int(tail[1]),
                    "pgrp": int(tail[2]),
                    "session": int(tail[3]),
                }
            except (TypeError, ValueError):
                return None

    def _proc_is_ida_named(self, pid: int) -> bool:
            """Best-effort Linux identity: is ``pid`` an ida/idat binary?"""
            if pid is None or pid <= 0:
                return False
            names = {n.lower() for n in self._ida_binary_names()}
            try:
                exe = os.path.realpath(f"/proc/{pid}/exe")
                if os.path.basename(exe).lower() in names:
                    return True
            except Exception:
                pass
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().decode("utf-8", errors="ignore")
                parts = [p for p in cmdline.split("\x00") if p]
                if parts and os.path.basename(parts[0]).lower() in names:
                    return True
            except Exception:
                pass
            return False

    def _proc_group_has_ida_member(self, pgid: int) -> bool:
            """Whether any member of process group ``pgid`` is an IDA binary."""
            if pgid is None or pgid <= 0:
                return False
            try:
                entries = os.listdir("/proc")
            except Exception:
                return False
            for entry in entries:
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/stat", "rb") as f:
                        parsed = self._parse_proc_stat(
                            f.read().decode("utf-8", errors="ignore")
                        )
                except Exception:
                    continue
                if not parsed or parsed["pgrp"] != pgid:
                    continue
                if self._proc_is_ida_named(int(entry)):
                    return True
            return False

    def _proc_group_has_live_member(self, pgid: int) -> bool:
            """Whether process group ``pgid`` still has a running (non-zombie)
            member.

            A zombie keeps the pgid visible to killpg, so the drain check in
            ``_kill_stale_process_group`` must not treat a group whose members
            have all exited but not yet been reaped as still-alive — otherwise
            a killed tree whose direct child is waiting for its (dead) parent's
            reaper would never drain and would be reported as a kill failure.
            """
            if pgid is None or pgid <= 0:
                return False
            try:
                entries = os.listdir("/proc")
            except Exception:
                return True  # cannot enumerate: assume still live
            for entry in entries:
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/stat", "rb") as f:
                        parsed = self._parse_proc_stat(
                            f.read().decode("utf-8", errors="ignore")
                        )
                except Exception:
                    continue
                if not parsed or parsed["pgrp"] != pgid:
                    continue
                if parsed["state"] != "Z":
                    return True
            return False

    def _runtime_tree_still_alive(self, pid: int) -> bool:
            """True while an ida-named descendant of the launcher is alive.

            The runtime's ``process`` is the idat launcher, which can exit in
            milliseconds while its real IDA child keeps running (holding the
            unpacked .id0/.id1). A launcher exit must not drop the session
            lease early, so the heartbeat keeps the lease until the whole tree
            is gone.

            POSIX: the launcher is started with start_new_session, so it leads
            its own process group and the child inherits that pgid even after
            being reparented to init on the launcher's exit. We probe the group
            AND require an ida-named member, so an unrelated process group that
            happens to reuse the launcher's PID is never mistaken for our tree.
            Windows: walk the ParentProcessId chain for an ida-named descendant.
            """
            if pid is None or pid <= 0:
                return False
            if sys.platform == "win32":
                return self._win32_ida_descendant_alive(pid)
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return False  # the whole tree is gone
            except Exception:
                # Cannot probe (e.g. EPERM): keep the lease rather than drop it
                # for a tree we cannot inspect; stale cleanup reclaims later.
                return True
            return self._proc_group_has_ida_member(pid)

    def _win32_process_map(self) -> tuple[dict[int, list[int]], dict[int, str]]:
            """Return ``(children_by_ppid, name_by_pid)`` for win32 processes.

            Best-effort: an empty map is returned on any enumeration failure so
            callers fall back to the conservative "keep the lease" behaviour.
            """
            children: dict[int, list[int]] = {}
            names: dict[int, str] = {}
            try:
                out = subprocess.run(
                    ["wmic", "process", "get", "ProcessId,ParentProcessId,Name",
                     "/format:list"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception:
                return children, names
            name = None
            ppid = None
            procid = None

            def _flush() -> None:
                nonlocal name, ppid, procid
                if procid is not None:
                    if ppid is not None:
                        children.setdefault(ppid, []).append(procid)
                    names[procid] = name or ""
                name, ppid, procid = None, None, None

            for line in (out.stdout or "").splitlines():
                if not line.strip():
                    _flush()
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "name":
                    name = value.lower()
                elif key == "parentprocessid":
                    try:
                        ppid = int(value)
                    except (TypeError, ValueError):
                        ppid = None
                elif key == "processid":
                    try:
                        procid = int(value)
                    except (TypeError, ValueError):
                        procid = None
            _flush()
            return children, names

    def _win32_ida_descendant_alive(self, pid: int) -> bool:
            """Whether an ida-named descendant of ``pid`` is live on Windows."""
            if pid is None or pid <= 0:
                return False
            children, names = self._win32_process_map()
            expected_names = {n.lower() for n in self._ida_binary_names()}
            frontier = [pid]
            seen = {pid}
            while frontier:
                nxt: list[int] = []
                for parent in frontier:
                    for child in children.get(parent, []):
                        if child in seen:
                            continue
                        seen.add(child)
                        if os.path.basename(names.get(child) or "").lower() in expected_names:
                            return True
                        nxt.append(child)
                frontier = nxt
            return False

    def _collect_descendant_pids(self, pid: int, max_depth: int = 8) -> list[int]:
            """pgrep -P style descendant enumeration via parent-PID links.

            On Linux this scans ``/proc/*/stat``; other POSIX platforms fall
            back to ``pgrep -P``; Windows uses the wmic parent map. Descendants
            are bounded by ``max_depth`` so a pathologically deep tree cannot
            stall the caller.
            """
            if pid is None or pid <= 0:
                return []
            if sys.platform == "win32":
                children, _names = self._win32_process_map()
                out: list[int] = []
                frontier = [pid]
                depth = 0
                while frontier and depth < max_depth:
                    depth += 1
                    nxt: list[int] = []
                    for parent in frontier:
                        for child in children.get(parent, []):
                            out.append(child)
                            nxt.append(child)
                    frontier = nxt
                return out
            if sys.platform != "linux":
                # macOS/BSD fallback.
                out = []
                frontier = [pid]
                depth = 0
                while frontier and depth < max_depth:
                    depth += 1
                    nxt: list[int] = []
                    for parent in frontier:
                        try:
                            res = subprocess.run(
                                ["pgrep", "-P", str(parent)],
                                capture_output=True,
                                text=True,
                                timeout=5,
                            )
                        except Exception:
                            continue
                        for tok in (res.stdout or "").split():
                            try:
                                child = int(tok)
                            except ValueError:
                                continue
                            out.append(child)
                            nxt.append(child)
                    frontier = nxt
                return out
            children_by_ppid: dict[int, list[int]] = {}
            try:
                entries = os.listdir("/proc")
            except Exception:
                return []
            for entry in entries:
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/stat", "rb") as f:
                        parsed = self._parse_proc_stat(
                            f.read().decode("utf-8", errors="ignore")
                        )
                except Exception:
                    continue
                if parsed:
                    children_by_ppid.setdefault(parsed["ppid"], []).append(int(entry))
            out: list[int] = []
            frontier = [pid]
            depth = 0
            while frontier and depth < max_depth:
                depth += 1
                nxt: list[int] = []
                for parent in frontier:
                    for child in children_by_ppid.get(parent, []):
                        out.append(child)
                        nxt.append(child)
                frontier = nxt
            return out

    def _kill_stale_process_group(self, pgid: int) -> bool:
            """SIGTERM a process group, wait for it to drain, then SIGKILL.

            The group is only signalled after the recorded pid has been
            identity-verified as an IDA launcher AND confirmed to lead its own
            process group (start_new_session), so the group is exclusively this
            IDA tree — never an unrelated group the launcher shared.

            A member that exited but is still a zombie keeps the pgid visible
            to killpg, so the drain check also treats a group whose members are
            all zombies as drained (they are gone; whoever is responsible for
            reaping them will collect them).
            """
            if pgid is None or pgid <= 0:
                return False
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            deadline = time.time() + PROCESS_TERMINATION_TIMEOUT_SECONDS
            while time.time() < deadline:
                try:
                    os.killpg(pgid, 0)
                except ProcessLookupError:
                    return True  # drained
                except Exception:
                    return True  # cannot probe; best-effort done
                if not self._proc_group_has_live_member(pgid):
                    return True  # only zombies remain; the tree is gone
                time.sleep(0.1)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                return True
            except Exception:
                return False
            try:
                os.killpg(pgid, 0)
                return False
            except ProcessLookupError:
                return True
            except Exception:
                return False

    def _kill_stale_process_tree(self, pid: int) -> bool:
            """Terminate an identity-verified IDA launcher and its process tree.

            Called only after ``_is_expected_ida_process`` confirmed the
            recorded pid is an IDA binary. Killing just the recorded pid leaves
            its ida child (the idat -> ida launcher pair) holding the unpacked
            .id0/.id1 files open; terminating the whole tree frees them so the
            next open can take the lock.

            Windows: ``taskkill /T /F`` walks the tree natively.
            POSIX: when the launcher leads its own process group it was started
            with start_new_session, so the tree IS the group — signal the group
            (this also reaches children reparented to init when the launcher
            exited). Otherwise signal the recorded pid plus any descendants
            still linked by parent PID, never touching an unrelated group.
            """
            if pid is None or pid <= 0:
                return False
            if sys.platform == "win32":
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["taskkill", "/T", "/F", "/PID", str(pid)],
                        capture_output=True,
                        timeout=PROCESS_TERMINATION_TIMEOUT_SECONDS + 3,
                    )
                return self._kill_stale_pid(pid)
            try:
                pgid = os.getpgid(pid)
            except Exception:
                pgid = None
            if pgid == pid:
                return self._kill_stale_process_group(pid)
            for child in self._collect_descendant_pids(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child, signal.SIGKILL)
            return self._kill_stale_pid(pid)

    def _is_expected_ida_process(self, pid: int, lease: dict) -> bool:
            if pid <= 0:
                return False
            if sys.platform != "linux":
                # No /proc identity to verify here. Best-effort name check via
                # the platform process lister; if it cannot confirm an IDA-named
                # process, refuse to signal the pid (a recycled PID could belong
                # to any unrelated program).
                return self._platform_pid_is_ida_process(pid, lease)
            expected_path = str(
                lease.get("idat_exe") or getattr(self, "idat_exe", "") or ""
            ).strip()
            proc_exe = f"/proc/{pid}/exe"
            proc_cmdline = f"/proc/{pid}/cmdline"
            expected_names = {n.lower() for n in self._ida_binary_names()}
            if expected_path:
                expected_path = os.path.realpath(os.path.expanduser(expected_path))
                expected_names.add(os.path.basename(expected_path).lower())
            expected_start = str(lease.get("process_start_token") or "").strip()
            if expected_start:
                # A matching executable name is not enough: a recycled PID can
                # point at another idat64 binary. A lease written by this
                # version records Linux's process start time, so require the
                # same process instance whenever that evidence is available.
                if _process_start_token(pid) != expected_start:
                    return False
            try:
                actual_exe = os.path.realpath(proc_exe)
            except Exception:
                actual_exe = ""
            if actual_exe:
                base = os.path.basename(actual_exe).lower()
                if expected_path:
                    try:
                        if (
                            os.path.exists(expected_path)
                            and os.path.exists(actual_exe)
                            and os.path.samefile(expected_path, actual_exe)
                        ):
                            return True
                    except Exception:
                        pass
                    # /proc exposes a real executable path. If it is present
                    # and differs from the recorded path, a same-named binary
                    # from another IDA installation is not our runtime.
                    if os.path.exists(actual_exe):
                        return False
                elif base in expected_names:
                    return True
            try:
                with open(proc_cmdline, "rb") as f:
                    cmdline = f.read().decode("utf-8", errors="ignore")
            except Exception:
                return False
            parts = [p for p in cmdline.split("\x00") if p]
            if not parts:
                return False
            first = os.path.basename(parts[0]).lower()
            if first in expected_names:
                return True
            return any(os.path.basename(part).lower() in expected_names for part in parts)

    def _platform_pid_is_ida_process(self, pid: int, lease: dict) -> bool:
            """Best-effort non-Linux identity check for a recorded runtime PID.

            Confirms the process image name against the known IDA binary names
            (and the recorded ``idat_exe``). Any failure to inspect the process
            returns False so the stale-lease cleanup never signals a PID whose
            identity it could not verify.
            """
            expected_names = {n.lower() for n in self._ida_binary_names()}
            expected_path = str(
                lease.get("idat_exe") or getattr(self, "idat_exe", "") or ""
            ).strip()
            if expected_path:
                expected_names.add(
                    os.path.basename(os.path.realpath(os.path.expanduser(expected_path))).lower()
                )
            try:
                if sys.platform == "win32":
                    out = subprocess.run(
                        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    line = (out.stdout or "").strip()
                    if not line:
                        return False
                    # CSV row: "Image Name","PID","Session Name",...
                    image = line.split('","', 1)[0].strip('"').lower()
                    return bool(image) and os.path.basename(image) in expected_names
                out = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "comm="],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                name = (out.stdout or "").strip().lower()
                if not name:
                    return False
                return os.path.basename(name) in expected_names
            except Exception:
                return False

    @staticmethod
    def _lease_has_live_foreign_owner(lease: dict) -> bool:
            """Whether a different live MCP host still owns this lease.

            A shared cache may be used by multiple stdio hosts.  An expired
            heartbeat alone is not enough authority for one host to terminate
            an IDA process owned by another host that is still alive.
            Legacy leases without an owner retain the existing stale-cleanup
            behavior.
            """
            owner_pid = _lease_pid(lease.get("owner_pid"))
            if owner_pid <= 0 or owner_pid == os.getpid():
                return False
            try:
                os.kill(owner_pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                # We cannot inspect a process owned by another user, so never
                # risk terminating the IDA process it claims to own.
                return True
            except Exception:
                return False
            expected_start = str(lease.get("owner_start_token") or "").strip()
            if expected_start:
                # A dead host's PID may have been recycled. Treat an
                # uninspectable owner conservatively, but allow reclamation
                # once the kernel proves that the PID is a new process.
                actual_start = _process_start_token(owner_pid)
                if not actual_start:
                    return True
                if actual_start != expected_start:
                    return False
            return True

    def _remove_lease_if_unchanged(self, path: str, expected_updated: float) -> bool:
            """Remove a stale lease only if it has not been rewritten since read.

            Between reading a stale lease and removing it, a fresh runtime for
            the same sid can be registered (its lease is rewritten with a new
            ``updated_at``). Re-reading the file before ``os.remove`` keeps that
            fresh lease intact instead of deleting a live runtime's coverage.
            """
            with _runtime_lease_io_lock(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        lease = json.load(f)
                except Exception:
                    return False
                if not isinstance(lease, dict):
                    return False
                updated = _lease_timestamp(lease.get("updated_at"))
                if updated != expected_updated:
                    return False
                with contextlib.suppress(OSError):
                    os.remove(path)
                    return True
                return False

    def _rewrite_lease_if_unchanged(self, path: str, lease: dict, expected_updated: float) -> bool:
            """Write a lease update only if it has not been rewritten since read.

            Between reading a stale lease and writing the ``terminate_failed``
            backoff marker, a fresh runtime for the same sid can be registered
            (its lease is rewritten with a new ``updated_at``). Re-reading the
            file before the atomic replace keeps that fresh lease intact instead
            of clobbering a live runtime's ownership record.
            """
            with _runtime_lease_io_lock(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        current = json.load(f)
                except Exception:
                    return False
                if not isinstance(current, dict):
                    return False
                updated = _lease_timestamp(current.get("updated_at"))
                if updated != expected_updated:
                    return False
                self._write_runtime_lease_record_unlocked(path, lease)
                return True

    def _cleanup_stale_runtime_leases(self) -> None:
            try:
                entries = os.listdir(self._runtime_lease_dir)
            except Exception:
                return
            now = time.time()
            cleanup_deadline = now + STALE_CLEANUP_BUDGET_SECONDS
            skip_count = 0
            removed_count = 0
            kept_count = 0
            for name in entries:
                m = _RUNTIME_LEASE_RE.fullmatch(name)
                if not m:
                    continue
                path = os.path.join(self._runtime_lease_dir, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        lease = json.load(f)
                except Exception:
                    with _runtime_lease_io_lock(path), contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                if not isinstance(lease, dict):
                    # JSON scalars/arrays are damaged lease records, not
                    # ownership claims. Remove them without ever reading a PID.
                    with _runtime_lease_io_lock(path), contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                sid = _normalize_session_id(lease.get("session_id"))
                sid_from_name = m.group(1)
                if not sid or sid != sid_from_name:
                    # Malformed/mismatched lease metadata: drop it and do not signal any PID.
                    with _runtime_lease_io_lock(path), contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                pid = _lease_pid(lease.get("pid"))
                updated = _lease_timestamp(lease.get("updated_at"))
                with self._runtime_lock:
                    tracked = bool(sid and sid in self.session_runtimes)
                if tracked:
                    continue
                expired = (now - updated) > RUNTIME_LEASE_TTL
                with self._runtime_lock:
                    tracked_after = bool(sid and sid in self.session_runtimes)
                if tracked_after:
                    continue
                if not expired:
                    continue
                if self._lease_has_live_foreign_owner(lease):
                    kept_count += 1
                    continue
                if pid <= 0:
                    if self._remove_lease_if_unchanged(path, updated):
                        removed_count += 1
                    else:
                        kept_count += 1  # rewritten mid-cleanup: leave it
                    continue
                # Confirm the recorded pid is (still) a process before touching
                # anything: a recycled PID could belong to an unrelated program
                # and must never be signalled.
                alive = None
                try:
                    os.kill(pid, 0)
                    alive = True
                except ProcessLookupError:
                    alive = False
                except Exception:
                    alive = None  # cannot probe (e.g. EPERM)
                if alive is False:
                    # Recorded pid is gone — nothing to kill. Drop the stale
                    # lease instead of letting it accumulate forever.
                    if self._remove_lease_if_unchanged(path, updated):
                        removed_count += 1
                    else:
                        kept_count += 1
                    continue
                if time.time() >= cleanup_deadline:
                    # Budget exhausted: defer remaining identity checks/kills to
                    # the next startup so a host with many orphans can still
                    # serve the first request.
                    skip_count += 1
                    continue
                if not self._is_expected_ida_process(pid, lease):
                    if alive is True:
                        # PID was recycled to an unrelated live process: never
                        # signal it, but drop the stale lease so it cannot
                        # accumulate either.
                        if self._remove_lease_if_unchanged(path, updated):
                            removed_count += 1
                        else:
                            kept_count += 1
                    else:
                        # Liveness unknown and identity unverifiable — keep the
                        # lease for a later pass rather than risk a wrong kill.
                        skip_count += 1
                    continue
                # Terminate the recorded pid AND its process tree so an
                # orphaned idat -> ida child cannot keep the unpacked
                # .id0/.id1 files open and FILE_LOCK a later open. The recorded
                # pid was identity-verified as an IDA binary above; the
                # tree-kill only signals the recorded pid, processes that
                # provably descend from it, or (when it leads its own process
                # group) that group — never an unrelated group it shared.
                killed = self._kill_stale_process_tree(pid)
                if killed:
                    if self._remove_lease_if_unchanged(path, updated):
                        removed_count += 1
                    else:
                        # Lease was rewritten mid-cleanup (a fresh runtime for
                        # this sid appeared) — leave it alone.
                        kept_count += 1
                else:
                    # Keep lease for retry, but back off immediate repeated
                    # kill attempts. Re-check that the lease was not rewritten
                    # (a new owner claimed this sid) during the kill window
                    # before writing the backoff marker over it.
                    lease["updated_at"] = now
                    lease["last_error"] = "terminate_failed"
                    # Guarded write: a no-op when the lease was rewritten
                    # mid-cleanup, preserving the fresh owner's record.
                    self._rewrite_lease_if_unchanged(path, lease, updated)
                    kept_count += 1
            if skip_count or removed_count or kept_count:
                log_rpc(
                    f"Stale lease cleanup: skipped={skip_count} removed={removed_count} kept={kept_count}"
                )

    def _adopt_or_cleanup_stale_runtime_leases(self) -> None:
            # Backward-compatible alias; method now only performs cleanup.
            self._cleanup_stale_runtime_leases()

    def _lease_heartbeat_loop(self) -> None:
            while True:
                if self._lease_thread_stop.wait(RUNTIME_LEASE_HEARTBEAT_SECONDS):
                    break
                if self._shutdown_requested:
                    break
                with self._runtime_lock:
                    runtime_items = list(self.session_runtimes.items())
                for sid, runtime in runtime_items:
                    if self._shutdown_requested:
                        break
                    try:
                        with self._runtime_lock:
                            if self.session_runtimes.get(sid) is not runtime:
                                continue
                        proc = runtime.get("process")
                        if not proc:
                            continue
                        if proc.poll() is None:
                            self._write_runtime_lease(sid, runtime)
                        elif proc.pid and self._runtime_tree_still_alive(proc.pid):
                            # The idat launcher exited but its ida child (the
                            # real analysis process) is still alive holding the
                            # unpacked .id0/.id1. Keep the lease fresh so a
                            # launcher exit does not drop coverage early;
                            # stale cleanup reclaims the tree after the TTL
                            # once it is truly gone.
                            self._write_runtime_lease(sid, runtime)
                        else:
                            # Guarded removal: a fresh runtime may have been
                            # registered for this sid (its lease rewritten)
                            # since the identity check above — never delete a
                            # live runtime's lease.
                            self._remove_runtime_lease_if_pid_matches(sid, proc.pid)
                    except Exception as e:
                        # A single raised exception must not kill the daemon
                        # heartbeat thread (nothing would ever restart it), or
                        # the host's live runtimes silently stop refreshing
                        # their leases. Log and continue on the next tick.
                        log_rpc(f"Runtime lease heartbeat failed for {sid}: {e}")

    def _start_runtime_lease_heartbeat(self) -> None:
            if self._lease_thread and self._lease_thread.is_alive():
                return
            # Clear any stop signal left by a prior stop/shutdown so a fresh
            # thread actually beats instead of exiting on the stale event. Each
            # server instance owns its own event (server.py), so this never
            # clears another instance's stop.
            self._lease_thread_stop.clear()
            self._lease_thread = threading.Thread(
                target=self._lease_heartbeat_loop,
                name="ida-mcp-runtime-lease-heartbeat",
                daemon=True,
            )
            self._lease_thread.start()

    def _stop_runtime_lease_heartbeat(self) -> None:
            self._lease_thread_stop.set()
            t = self._lease_thread
            if t and t.is_alive():
                t.join(timeout=1.0)

    def _register_lifecycle_handlers(self) -> None:
            # Register shutdown for every instance, not just the first one in
            # the process. atexit registration is per-handler, not class-level,
            # and shutdown() is idempotent (guarded by self._shutdown), so a
            # second+ instance must not be skipped — a class flag would leave
            # its runtimes leaking on normal exit.
            atexit.register(self.shutdown)
            for sig_name in ("SIGINT", "SIGTERM"):
                sig = getattr(signal, sig_name, None)
                if sig is None:
                    continue
                try:
                    signal.signal(sig, self._handle_termination_signal)
                except Exception as e:
                    log_rpc(f"Failed to register handler for {sig_name}: {e}")

    def _handle_termination_signal(self, signum, frame):
            self._shutdown_requested = True
            self._lease_thread_stop.set()
            # A stdio client may have to terminate a host blocked on input.
            # Release owned IDA and embedding subprocesses before that forced
            # exit can orphan them.
            self.shutdown()

    def shutdown(self) -> None:
            if self._shutdown:
                return
            self._shutdown = True
            self._shutdown_requested = True
            self._stop_runtime_lease_heartbeat()
            # Stop analysis-completion watchers and background runtime spawns,
            # and clear the pending/complete sets, via the existing helper
            # (server.py's _stop_analysis_completion_watchers) when the
            # composing server provides it. This runs before runtime teardown so
            # a background thread cannot re-spawn an IDA process after
            # _cleanup_all_runtimes has finished killing them. Bare-mixin hosts
            # that do not compose the session mixin are a no-op.
            stop_watchers = getattr(self, "_stop_analysis_completion_watchers", None)
            if callable(stop_watchers):
                with contextlib.suppress(Exception):
                    stop_watchers()
            # Stop host-owned inference first. Runtime cleanup can wait on IDA
            # long enough for stdio clients to escalate to SIGTERM; leaving
            # this until the end allowed llama-server to be orphaned.
            try:
                if hasattr(self, "assembler") and self.assembler is not None:
                    self.assembler.stop()
            except Exception as e:
                log_rpc(f"Failed to stop intelligence embedder: {e}")
            self._cleanup_all_runtimes()
            # Stop usage intelligence
            if getattr(self, "_usage_intel", None):
                with contextlib.suppress(Exception):
                    self._usage_intel.stop()
            # Persist memory tiers
            try:
                indexes = getattr(self, "_insight_indexes", None)
                if isinstance(indexes, dict):
                    for index in indexes.values():
                        index.save()
                elif hasattr(self, "_insight_index"):
                    self._insight_index.save()
            except Exception as e:
                log_rpc(f"Failed to save insight index: {e}")
            try:
                if hasattr(self, "_global_facts"):
                    self._global_facts.close()
            except Exception as e:
                log_rpc(f"Failed to close global facts DB: {e}")
            # Release the audit file handle so it is not leaked when the host
            # is torn down via signal/atexit/finally. AuditLogger.close() is
            # idempotent, so it is safe if shutdown() runs more than once.
            try:
                if hasattr(self, "audit") and self.audit is not None:
                    self.audit.close()
            except Exception as e:
                log_rpc(f"Failed to close audit logger: {e}")
