#!/usr/bin/env python3
"""Runtime lease and lifecycle helpers for IDAMCPServer."""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time

from ..config import (
    _RUNTIME_LEASE_RE,
    PROCESS_TERMINATION_TIMEOUT_SECONDS,
    RUNTIME_LEASE_HEARTBEAT_SECONDS,
    RUNTIME_LEASE_TTL,
    _normalize_session_id,
    log_rpc,
)


def _resolve_stale_cleanup_budget() -> float:
    """Bound total time spent killing stale runtime leases at host startup.

    Every stubborn orphan can take ~PROCESS_TERMINATION_TIMEOUT_SECONDS to
    escalate; on a shared cache with many orphans this would block the server
    from serving its first request. The budget defers remaining kills to the
    next startup instead.
    """
    try:
        budget = float(os.environ.get("IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", "10"))
    except (TypeError, ValueError):
        budget = 10.0
    return max(1.0, budget)


STALE_CLEANUP_BUDGET_SECONDS = _resolve_stale_cleanup_budget()


class ServerRuntimeLeasesMixin:
    def _runtime_lease_path(self, sid: str) -> str:
            return os.path.join(self._runtime_lease_dir, f"SID_{sid}.lease.json")

    def _write_runtime_lease_record(self, path: str, lease: dict) -> None:
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(lease, f, indent=2)
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
                "updated_at": time.time(),
            }
            path = self._runtime_lease_path(sid)
            self._write_runtime_lease_record(path, lease)

    def _remove_runtime_lease(self, sid: str) -> None:
            with contextlib.suppress(OSError):
                os.remove(self._runtime_lease_path(sid))

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
            try:
                with open(path, encoding="utf-8") as f:
                    lease = json.load(f)
            except Exception:
                return
            try:
                lease_pid = int(lease.get("pid") or 0)
            except Exception:
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
            try:
                actual_exe = os.path.realpath(proc_exe)
            except Exception:
                actual_exe = ""
            if actual_exe:
                base = os.path.basename(actual_exe).lower()
                if base in expected_names:
                    return True
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
            try:
                owner_pid = int(lease.get("owner_pid") or 0)
            except Exception:
                return False
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
            return True

    def _remove_lease_if_unchanged(self, path: str, expected_updated: float) -> bool:
            """Remove a stale lease only if it has not been rewritten since read.

            Between reading a stale lease and removing it, a fresh runtime for
            the same sid can be registered (its lease is rewritten with a new
            ``updated_at``). Re-reading the file before ``os.remove`` keeps that
            fresh lease intact instead of deleting a live runtime's coverage.
            """
            try:
                with open(path, encoding="utf-8") as f:
                    lease = json.load(f)
            except Exception:
                return False
            try:
                updated = float(lease.get("updated_at") or 0.0)
            except Exception:
                updated = 0.0
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
            try:
                with open(path, encoding="utf-8") as f:
                    current = json.load(f)
            except Exception:
                return False
            try:
                updated = float(current.get("updated_at") or 0.0)
            except Exception:
                updated = 0.0
            if updated != expected_updated:
                return False
            self._write_runtime_lease_record(path, lease)
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
                    with contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                sid = _normalize_session_id(lease.get("session_id"))
                sid_from_name = m.group(1)
                if not sid or sid != sid_from_name:
                    # Malformed/mismatched lease metadata: drop it and do not signal any PID.
                    with contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                try:
                    pid = int(lease.get("pid") or 0)
                except Exception:
                    pid = 0
                try:
                    updated = float(lease.get("updated_at") or 0.0)
                except Exception:
                    updated = 0.0
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
                # Signal only the recorded pid, never the whole process tree.
                # The stale path has no Popen and only identity-verifies the
                # recorded pid (it may not be a process-group leader), so
                # killing the tree here could signal an unrelated group. The
                # tracked teardown path (server_runtime.py) uses
                # _kill_process_tree where the group is guaranteed; the price
                # here is that an orphaned idat.exe -> ida.exe child can keep
                # the unpacked .id0/.id1 files open and FILE_LOCK a later open.
                killed = self._kill_stale_pid(pid)
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
