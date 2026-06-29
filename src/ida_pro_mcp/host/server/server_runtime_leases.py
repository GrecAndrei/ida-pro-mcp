#!/usr/bin/env python3
"""Runtime lease and lifecycle helpers for IDAMCPServer."""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import signal
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
                "updated_at": time.time(),
            }
            path = self._runtime_lease_path(sid)
            self._write_runtime_lease_record(path, lease)

    def _remove_runtime_lease(self, sid: str) -> None:
            with contextlib.suppress(OSError):
                os.remove(self._runtime_lease_path(sid))

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
                return True
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
            for part in parts:
                if os.path.basename(part).lower() in expected_names:
                    return True
            return False

    def _cleanup_stale_runtime_leases(self) -> None:
            try:
                entries = os.listdir(self._runtime_lease_dir)
            except Exception:
                return
            now = time.time()
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
                if pid <= 0:
                    with contextlib.suppress(OSError):
                        os.remove(path)
                    continue
                if not self._is_expected_ida_process(pid, lease):
                    skip_count += 1
                    continue
                killed = self._kill_stale_pid(pid)
                if killed:
                    with contextlib.suppress(OSError):
                        os.remove(path)
                    removed_count += 1
                else:
                    # Keep lease for retry, but back off immediate repeated kill attempts.
                    lease["updated_at"] = now
                    lease["last_error"] = "terminate_failed"
                    self._write_runtime_lease_record(path, lease)
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
                    with self._runtime_lock:
                        if self.session_runtimes.get(sid) is not runtime:
                            continue
                    proc = runtime.get("process")
                    if not proc:
                        continue
                    if proc.poll() is None:
                        self._write_runtime_lease(sid, runtime)
                    else:
                        self._remove_runtime_lease(sid)

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
            cls = self.__class__
            if not cls._atexit_registered:
                atexit.register(self.shutdown)
                cls._atexit_registered = True
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

    def shutdown(self) -> None:
            if self._shutdown:
                return
            self._shutdown = True
            self._shutdown_requested = True
            self._stop_runtime_lease_heartbeat()
            # Stop all analysis engines
            for sid in list(getattr(self, "_analysis_engines", {}).keys()):
                with contextlib.suppress(Exception):
                    self._stop_analysis_engine(sid)
            self._cleanup_all_runtimes()
            # Stop usage intelligence
            if getattr(self, "_usage_intel", None):
                with contextlib.suppress(Exception):
                    self._usage_intel.stop()
            # Persist memory tiers
            try:
                if hasattr(self, "_insight_index"):
                    self._insight_index.save()
            except Exception as e:
                log_rpc(f"Failed to save insight index: {e}")
            try:
                if hasattr(self, "_global_facts"):
                    self._global_facts.close()
            except Exception as e:
                log_rpc(f"Failed to close global facts DB: {e}")
            try:
                if hasattr(self, "assembler") and self.assembler is not None:
                    self.assembler.stop()
            except Exception as e:
                log_rpc(f"Failed to stop intelligence embedder: {e}")

